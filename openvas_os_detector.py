"""
OpenVAS OS Detection Module for VAPT Scanner Pro
=================================================
Detects actual operating systems (Ubuntu, Windows, Red Hat/CentOS/Rocky, and others)
by combining multiple fingerprinting techniques:

  1. OpenVAS / GVM integration  — authoritative OS info from a running OpenVAS daemon
  2. Nmap OS fingerprinting     — -O with aggressive guesses
  3. Service-banner heuristics  — SSH, HTTP, SMB/RDP banner analysis
  4. CPE parsing                — Common Platform Enumeration from nmap output
  5. TTL analysis               — fallback heuristic from ping responses

Priority order: OpenVAS → Nmap -O → CPE → Banner → TTL

Usage
-----
    from openvas_os_detector import detect_os, enrich_result_with_os

    # In bulk_scan_engine.scan_single_ip(), after nmap_data is parsed:
    os_info = detect_os(ip, nmap_output=nmap_raw_output)
    result['os']         = os_info['os_name']
    result['os_detail']  = os_info            # full dict attached to result
"""

import re
import subprocess
import shutil
import platform
import socket
import struct
import os
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
#  OS CLASSIFICATION CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# Canonical OS families used throughout the app
OS_UBUNTU    = "Ubuntu Linux"
OS_REDHAT    = "Red Hat Enterprise Linux"
OS_CENTOS    = "CentOS Linux"
OS_ROCKY     = "Rocky Linux"
OS_FEDORA    = "Fedora Linux"
OS_DEBIAN    = "Debian Linux"
OS_WINDOWS   = "Windows"
OS_MACOS     = "macOS"
OS_FREEBSD   = "FreeBSD"
OS_LINUX     = "Linux"
OS_UNKNOWN   = "Unknown"

# Map of keyword patterns → canonical OS name
# Evaluated in order; first match wins
_BANNER_OS_PATTERNS = [
    # Ubuntu (must come before generic Debian/Linux)
    (re.compile(r'ubuntu', re.I),                                   OS_UBUNTU),
    # Red Hat family
    (re.compile(r'red\s?hat|rhel', re.I),                           OS_REDHAT),
    (re.compile(r'centos', re.I),                                    OS_CENTOS),
    (re.compile(r'rocky\s*linux|rocky', re.I),                      OS_ROCKY),
    (re.compile(r'fedora', re.I),                                    OS_FEDORA),
    (re.compile(r'oracle\s*linux', re.I),                           "Oracle Linux"),
    (re.compile(r'alma\s*linux', re.I),                             "AlmaLinux"),
    # Debian
    (re.compile(r'debian', re.I),                                    OS_DEBIAN),
    # Windows
    (re.compile(r'windows\s*(server|xp|vista|7|8|10|11|nt|2000|2003|2008|2012|2016|2019|2022)', re.I), OS_WINDOWS),
    (re.compile(r'microsoft|windows', re.I),                         OS_WINDOWS),
    # macOS / Darwin
    (re.compile(r'mac\s*os|darwin|macos', re.I),                    OS_MACOS),
    # BSD
    (re.compile(r'freebsd', re.I),                                   OS_FREEBSD),
    (re.compile(r'openbsd', re.I),                                   "OpenBSD"),
    (re.compile(r'netbsd', re.I),                                    "NetBSD"),
    # Generic Linux (last Linux fallback)
    (re.compile(r'linux', re.I),                                     OS_LINUX),
]

# CPE OS prefix → canonical name
_CPE_OS_MAP = {
    'cpe:/o:canonical:ubuntu':                        OS_UBUNTU,
    'cpe:/o:redhat:enterprise_linux':                 OS_REDHAT,
    'cpe:/o:redhat:rhel':                             OS_REDHAT,
    'cpe:/o:centos:centos':                           OS_CENTOS,
    'cpe:/o:rocky_linux':                             OS_ROCKY,
    'cpe:/o:fedoraproject:fedora':                    OS_FEDORA,
    'cpe:/o:debian:debian_linux':                     OS_DEBIAN,
    'cpe:/o:microsoft:windows':                       OS_WINDOWS,
    'cpe:/o:apple:mac_os_x':                          OS_MACOS,
    'cpe:/o:apple:macos':                             OS_MACOS,
    'cpe:/o:freebsd:freebsd':                         OS_FREEBSD,
    'cpe:/o:linux:linux_kernel':                      OS_LINUX,
}


# ─────────────────────────────────────────────────────────────────────────────
#  HELPER UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def _has_root():
    """Return True if running as root (needed for nmap -O and raw ping)."""
    try:
        return os.geteuid() == 0
    except (AttributeError, OSError):
        return False


def _check_tool(name):
    return shutil.which(name) is not None


def _classify_os_string(text):
    """
    Match a free-form OS string against known patterns.
    Returns (canonical_name, version_hint) where version_hint may be ''.
    """
    if not text:
        return OS_UNKNOWN, ''

    for pattern, canonical in _BANNER_OS_PATTERNS:
        if pattern.search(text):
            # Try to extract version number from the text
            ver_match = re.search(
                r'(\d+(?:\.\d+){0,3})',
                text[pattern.search(text).end():]  # look after the OS keyword
            )
            version = ver_match.group(1) if ver_match else ''
            return canonical, version

    return OS_UNKNOWN, ''


def _parse_cpe_os(nmap_output):
    """
    Extract OS CPE strings from nmap output and return canonical OS name.
    CPE lines look like:  |  cpe:/o:canonical:ubuntu_linux:20.04
    """
    cpe_re = re.compile(r'cpe:/o:[^\s\|\"\']+', re.I)
    for cpe in cpe_re.findall(nmap_output or ''):
        cpe_lower = cpe.lower()
        for prefix, canonical in _CPE_OS_MAP.items():
            if cpe_lower.startswith(prefix):
                # Pull version after the last ':'
                ver_match = re.search(r':(\d[\d.]+)$', cpe_lower)
                version = ver_match.group(1) if ver_match else ''
                return canonical, version, cpe
    return None, '', ''


def _parse_nmap_os_section(nmap_output):
    """
    Parse nmap output for OS detection lines:
      - 'OS details: ...'
      - 'Running: ...'
      - 'Aggressive OS guesses: ...'
      - 'Service Info: OS: ...'
    Returns (canonical_name, version, raw_string).
    """
    patterns = [
        re.compile(r'^OS details:\s*(.+)$', re.M),
        re.compile(r'^Running:\s*(.+)$', re.M),
        re.compile(r'^Aggressive OS guesses:\s*(.+?)(?:\(|$)', re.M),
        re.compile(r'Service Info:.*?OS:\s*([^;,\n]+)', re.I),
    ]
    for pat in patterns:
        m = pat.search(nmap_output or '')
        if m:
            raw = m.group(1).strip()
            canonical, version = _classify_os_string(raw)
            if canonical != OS_UNKNOWN:
                return canonical, version, raw
    return None, '', ''


def _get_ttl_os_hint(ip):
    """
    Send one ICMP echo and check TTL in reply.
    Linux/Unix: initial TTL ~64   → on same LAN arrives ≥ 60
    Windows:    initial TTL ~128  → arrives ≥ 120
    Cisco/BSD:  initial TTL ~255  → arrives ≥ 240

    Returns (os_hint_string, ttl_value) or (None, None) on failure.
    Uses subprocess ping (no raw sockets needed).
    """
    try:
        if platform.system().lower() == 'windows':
            cmd = ['ping', '-n', '1', ip]
            ttl_re = re.compile(r'TTL=(\d+)', re.I)
        else:
            cmd = ['ping', '-c', '1', '-W', '2', ip]
            ttl_re = re.compile(r'ttl=(\d+)', re.I)

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        output = (proc.stdout or '') + (proc.stderr or '')
        m = ttl_re.search(output)
        if not m:
            return None, None
        ttl = int(m.group(1))
        if ttl >= 100:    # Windows 128, allows for up to 28 hops
            hint = OS_WINDOWS
        elif ttl >= 60:   # Linux 64, allows for up to 4 hops
            hint = OS_LINUX
        else:
            hint = None
        return hint, ttl
    except Exception:
        return None, None


# ─────────────────────────────────────────────────────────────────────────────
#  BANNER-BASED OS DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def _os_from_service_banners(ports_list):
    """
    Analyse service version strings from nmap port data to extract OS clues.
    ports_list: list of dicts with 'service', 'version' keys.

    Priority: SSH → HTTP Server header → SMB → RDP
    Returns (canonical_name, version, source_note).
    """
    for port_info in (ports_list or []):
        svc     = (port_info.get('service') or '').lower()
        version = (port_info.get('version') or '')

        # SSH banner: "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5"
        if 'ssh' in svc and version:
            canonical, ver = _classify_os_string(version)
            if canonical != OS_UNKNOWN:
                return canonical, ver, f"SSH banner: {version[:80]}"

        # HTTP Server: "Apache/2.4.41 (Ubuntu)" or "Microsoft-IIS/10.0"
        if svc in ('http', 'https', 'http-alt', 'ssl/http') and version:
            canonical, ver = _classify_os_string(version)
            if canonical != OS_UNKNOWN:
                return canonical, ver, f"HTTP banner: {version[:80]}"

        # MySQL/MariaDB banners often contain OS info
        if 'mysql' in svc or 'mariadb' in svc:
            canonical, ver = _classify_os_string(version)
            if canonical != OS_UNKNOWN:
                return canonical, ver, f"DB banner: {version[:80]}"

        # SMB/NetBIOS: Windows
        if svc in ('microsoft-ds', 'netbios-ssn', 'msrpc', 'smb') or port_info.get('port') in ('445', '139', '135'):
            return OS_WINDOWS, '', 'SMB/NetBIOS service detected'

        # RDP: Windows
        if svc in ('ms-wbt-server', 'rdp') or port_info.get('port') == '3389':
            return OS_WINDOWS, '', 'RDP service detected'

        # WinRM: Windows
        if svc in ('wsman', 'winrm') or port_info.get('port') in ('5985', '5986'):
            return OS_WINDOWS, '', 'WinRM service detected'

    return None, '', ''


# ─────────────────────────────────────────────────────────────────────────────
#  OPENVAS / GVM INTEGRATION
# ─────────────────────────────────────────────────────────────────────────────

def _openvas_get_os(ip, gvm_socket=None, gvm_host='127.0.0.1', gvm_port=9390,
                   gvm_user='admin', gvm_password='admin', timeout=30):
    """
    Query a running OpenVAS / GVM daemon for OS information about a specific IP.

    OpenVAS stores OS detection results in its KB (knowledge base) under
    the NVT "Host Details" (OID 1.3.6.1.4.1.25623.1.0.103997) and in
    the report XML under <host><detail><name>best_os_txt</name></detail></host>.

    Connection modes:
      - Unix socket:  gvm_socket='/run/gvmd/gvmd.sock'  (preferred, same host)
      - TCP/TLS:      gvm_host + gvm_port                (remote or containerized)

    Returns dict with keys: os_name, os_version, os_cpe, confidence, source
    or None if OpenVAS is unavailable / host not in any completed task.
    """
    # ── Try python-gvm library first (the official GVM Python client) ─────────
    try:
        from gvm.connections import UnixSocketConnection, TLSConnection
        from gvm.protocols.gmp import Gmp
        from gvm.transforms import EtreeTransform

        if gvm_socket and os.path.exists(gvm_socket):
            connection = UnixSocketConnection(path=gvm_socket, timeout=timeout)
        else:
            connection = TLSConnection(hostname=gvm_host, port=gvm_port, timeout=timeout)

        with Gmp(connection, transform=EtreeTransform()) as gmp:
            gmp.authenticate(gvm_user, gvm_password)

            # Search all finished tasks for a report containing this IP
            tasks_xml = gmp.get_tasks(filter_string="status=Done rows=100")
            task_ids = [t.get('id') for t in tasks_xml.findall('.//task')
                        if t.get('id')]

            for task_id in task_ids[:20]:  # check up to 20 recent tasks
                try:
                    report_xml = gmp.get_reports(
                        filter_string=f"task_id={task_id} rows=1",
                        details=True,
                        ignore_pagination=False,
                    )
                    # Find host element matching our IP
                    for host_el in report_xml.findall('.//host'):
                        ip_el = host_el.find('ip')
                        if ip_el is None or (ip_el.text or '').strip() != ip:
                            continue

                        os_info = {'os_name': OS_UNKNOWN, 'os_version': '',
                                   'os_cpe': '', 'confidence': 0,
                                   'source': 'OpenVAS'}

                        for detail in host_el.findall('.//detail'):
                            name_el  = detail.find('name')
                            value_el = detail.find('value')
                            if name_el is None or value_el is None:
                                continue
                            name  = (name_el.text  or '').strip()
                            value = (value_el.text or '').strip()

                            if name == 'best_os_txt' and value:
                                canonical, ver = _classify_os_string(value)
                                os_info['os_name']    = canonical
                                os_info['os_version'] = ver
                                os_info['confidence'] = 90
                                os_info['raw']        = value

                            elif name == 'best_os_cpe' and value:
                                os_info['os_cpe'] = value
                                # Try CPE classification as confirmation
                                for prefix, canonical in _CPE_OS_MAP.items():
                                    if value.lower().startswith(prefix):
                                        if os_info['os_name'] == OS_UNKNOWN:
                                            os_info['os_name'] = canonical
                                        break

                            elif name == 'hostname' and value:
                                os_info['hostname'] = value

                        if os_info['os_name'] != OS_UNKNOWN:
                            return os_info

                except Exception:
                    continue

    except ImportError:
        pass  # python-gvm not installed; fall through to raw XML-RPC
    except Exception as _gvm_err:
        # OpenVAS not running or unreachable — silently skip
        pass

    # ── Fallback: raw GMP XML over TCP (no python-gvm dependency) ────────────
    try:
        import ssl
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode    = ssl.CERT_NONE

        with socket.create_connection((gvm_host, gvm_port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=gvm_host) as sock:

                def _send(xml_str):
                    payload = xml_str.encode('utf-8')
                    sock.sendall(payload)

                def _recv_all():
                    chunks = []
                    while True:
                        chunk = sock.recv(65536)
                        if not chunk:
                            break
                        chunks.append(chunk)
                        if b'</get_reports_response>' in b''.join(chunks):
                            break
                        if b'</authenticate_response>' in b''.join(chunks):
                            break
                    return b''.join(chunks).decode('utf-8', errors='replace')

                # Authenticate
                _send(f'<authenticate><credentials>'
                      f'<username>{gvm_user}</username>'
                      f'<password>{gvm_password}</password>'
                      f'</credentials></authenticate>')
                auth_resp = _recv_all()
                if 'status="200"' not in auth_resp:
                    return None

                # Get most recent report containing this IP
                _send('<get_reports filter="rows=5 first=1 sort-reverse=date" details="1"/>')
                reports_resp = _recv_all()

                # Find best_os_txt for our IP
                ip_block_re = re.compile(
                    r'<host>.*?<ip>' + re.escape(ip) + r'</ip>.*?</host>',
                    re.DOTALL
                )
                for block in ip_block_re.findall(reports_resp):
                    os_txt_m = re.search(r'<name>best_os_txt</name>\s*<value>([^<]+)</value>', block)
                    os_cpe_m = re.search(r'<name>best_os_cpe</name>\s*<value>([^<]+)</value>', block)
                    if os_txt_m:
                        raw_os   = os_txt_m.group(1).strip()
                        cpe_str  = os_cpe_m.group(1).strip() if os_cpe_m else ''
                        canonical, ver = _classify_os_string(raw_os)
                        return {
                            'os_name':    canonical,
                            'os_version': ver,
                            'os_cpe':     cpe_str,
                            'confidence': 90,
                            'source':     'OpenVAS (XML)',
                            'raw':        raw_os,
                        }
    except Exception:
        pass

    return None  # OpenVAS unavailable


# ─────────────────────────────────────────────────────────────────────────────
#  NMAP OS SCAN (dedicated invocation if not already done)
# ─────────────────────────────────────────────────────────────────────────────

def _nmap_os_scan(ip, open_ports=None, timeout=120):
    """
    Run a targeted nmap -O scan against the IP.
    If open_ports list is supplied, restrict to those ports (faster).
    Returns raw nmap stdout string or ''.
    Requires root (or Windows with npcap).
    """
    if not _check_tool('nmap'):
        return ''
    if not _has_root() and platform.system().lower() != 'windows':
        # Cannot do -O without root — skip this step
        return ''

    port_arg = []
    if open_ports:
        port_arg = ['-p', ','.join(str(p) for p in open_ports[:50])]

    cmd = ['nmap', '-T4', '-Pn', '-O', '--osscan-guess',
           '--max-os-tries', '2'] + port_arg + [ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout or ''
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return ''


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

def detect_os(ip, nmap_output='', ports_list=None, open_ports=None,
              openvas_config=None):
    """
    Detect the actual OS of a host using a multi-layer approach.

    Parameters
    ----------
    ip            : str   — target IP address
    nmap_output   : str   — raw nmap stdout (already scanned, optional)
    ports_list    : list  — parsed port dicts from parse_nmap_output()
    open_ports    : list  — list of open port number strings (e.g. ['22','80'])
    openvas_config: dict  — OpenVAS connection settings (optional):
                           {'socket': '/run/gvmd/gvmd.sock',
                            'host': '127.0.0.1', 'port': 9390,
                            'user': 'admin', 'password': 'admin'}

    Returns
    -------
    dict with keys:
        os_name      : canonical OS name (e.g. "Ubuntu Linux")
        os_version   : version string   (e.g. "20.04")
        os_family    : broad family     ("linux" | "windows" | "bsd" | "macos" | "unknown")
        os_cpe       : CPE string if available
        confidence   : int 0-100
        source       : detection method used
        ttl          : TTL value if measured
        raw          : raw OS string from scanner
        detection_chain : list of methods tried in order
    """
    result = {
        'os_name':         OS_UNKNOWN,
        'os_version':      '',
        'os_family':       'unknown',
        'os_cpe':          '',
        'confidence':      0,
        'source':          'none',
        'ttl':             None,
        'raw':             '',
        'detection_chain': [],
    }

    def _set(name, version, cpe, confidence, source, raw=''):
        result['os_name']    = name
        result['os_version'] = version
        result['os_cpe']     = cpe
        result['confidence'] = confidence
        result['source']     = source
        result['raw']        = raw
        result['os_family']  = _family(name)

    def _family(name):
        nl = name.lower()
        if 'windows' in nl:  return 'windows'
        if any(x in nl for x in ('ubuntu','debian','redhat','centos','rocky',
                                  'fedora','oracle','alma','linux')):
            return 'linux'
        if 'macos' in nl or 'darwin' in nl:  return 'macos'
        if 'bsd' in nl:  return 'bsd'
        return 'unknown'

    chain = result['detection_chain']

    # ── STEP 1: OpenVAS (highest trust) ──────────────────────────────────────
    chain.append('openvas')
    ova_cfg = openvas_config or {}
    ova = _openvas_get_os(
        ip,
        gvm_socket   = ova_cfg.get('socket', ''),
        gvm_host     = ova_cfg.get('host',   '127.0.0.1'),
        gvm_port     = int(ova_cfg.get('port', 9390)),
        gvm_user     = ova_cfg.get('user',   'admin'),
        gvm_password = ova_cfg.get('password', 'admin'),
    )
    if ova and ova.get('os_name', OS_UNKNOWN) != OS_UNKNOWN:
        _set(ova['os_name'], ova.get('os_version',''),
             ova.get('os_cpe',''), ova.get('confidence', 90),
             ova.get('source','OpenVAS'), ova.get('raw',''))
        result['ttl'] = None
        return result

    # ── STEP 2: Nmap CPE in existing output ───────────────────────────────────
    chain.append('nmap_cpe')
    if nmap_output:
        cpe_name, cpe_ver, cpe_str = _parse_cpe_os(nmap_output)
        if cpe_name:
            _set(cpe_name, cpe_ver, cpe_str, 85, 'Nmap CPE', cpe_str)
            return result

    # ── STEP 3: Nmap OS section in existing output ────────────────────────────
    chain.append('nmap_os_section')
    if nmap_output:
        nm_name, nm_ver, nm_raw = _parse_nmap_os_section(nmap_output)
        if nm_name:
            _set(nm_name, nm_ver, '', 80, 'Nmap OS Detection', nm_raw)
            return result

    # ── STEP 4: Dedicated nmap -O scan (if root available) ───────────────────
    chain.append('nmap_os_scan')
    os_nmap_out = _nmap_os_scan(ip, open_ports=open_ports)
    if os_nmap_out:
        # Try CPE first in the new output
        cpe_name, cpe_ver, cpe_str = _parse_cpe_os(os_nmap_out)
        if cpe_name:
            _set(cpe_name, cpe_ver, cpe_str, 85, 'Nmap -O CPE', cpe_str)
            return result
        # Then OS section
        nm_name, nm_ver, nm_raw = _parse_nmap_os_section(os_nmap_out)
        if nm_name:
            _set(nm_name, nm_ver, '', 80, 'Nmap -O', nm_raw)
            return result

    # ── STEP 5: Service banner heuristics ─────────────────────────────────────
    chain.append('service_banners')
    if ports_list:
        bn_name, bn_ver, bn_note = _os_from_service_banners(ports_list)
        if bn_name:
            _set(bn_name, bn_ver, '', 70, f'Service Banner ({bn_note})', bn_note)
            return result

    # ── STEP 6: TTL heuristic (lowest confidence) ─────────────────────────────
    chain.append('ttl')
    ttl_hint, ttl_val = _get_ttl_os_hint(ip)
    result['ttl'] = ttl_val
    if ttl_hint:
        _set(ttl_hint, '', '', 40, f'TTL heuristic (TTL={ttl_val})', f'TTL={ttl_val}')
        return result

    # No detection succeeded
    result['os_family'] = 'unknown'
    return result


def enrich_result_with_os(result, openvas_config=None):
    """
    Enrich a scan_single_ip() result dict in-place with accurate OS detection.

    Replaces result['os'] (raw nmap string) with the canonical OS name,
    and adds result['os_detail'] with the full detection info dict.

    Call this from bulk_scan_engine.scan_single_ip() after nmap parsing:

        from openvas_os_detector import enrich_result_with_os
        result = enrich_result_with_os(result, openvas_config=cfg)

    Parameters
    ----------
    result         : dict  — scan_single_ip() result dict (modified in place)
    openvas_config : dict  — optional OpenVAS/GVM connection settings

    Returns
    -------
    The modified result dict (also modified in place).
    """
    ip          = result.get('ip', '')
    ports_list  = result.get('ports', [])
    open_ports  = result.get('open_ports', [])

    # We don't re-run nmap — pass whatever raw output is already stored
    # bulk_scan_engine stores nmap_output in result['_nmap_raw'] when available
    nmap_output = result.get('_nmap_raw', '')

    os_info = detect_os(
        ip,
        nmap_output   = nmap_output,
        ports_list    = ports_list,
        open_ports    = open_ports,
        openvas_config = openvas_config,
    )

    # Update the top-level 'os' field with canonical name + version
    canonical = os_info['os_name']
    version   = os_info['os_version']
    if canonical != OS_UNKNOWN:
        result['os'] = f"{canonical} {version}".strip() if version else canonical

    result['os_detail'] = os_info
    result['os_family'] = os_info['os_family']
    return result


# ─────────────────────────────────────────────────────────────────────────────
#  OPENVAS AVAILABILITY CHECK  (call once at startup)
# ─────────────────────────────────────────────────────────────────────────────

def check_openvas_available(gvm_socket='/run/gvmd/gvmd.sock',
                             gvm_host='127.0.0.1', gvm_port=9390,
                             gvm_user='admin', gvm_password='admin',
                             timeout=10):
    """
    Test whether an OpenVAS / GVM daemon is reachable and can authenticate.
    Returns dict: { 'available': bool, 'version': str, 'method': str, 'error': str }
    """
    info = {'available': False, 'version': '', 'method': '', 'error': ''}

    # Try python-gvm library
    try:
        from gvm.connections import UnixSocketConnection, TLSConnection
        from gvm.protocols.gmp import Gmp
        from gvm.transforms import EtreeTransform

        if gvm_socket and os.path.exists(gvm_socket):
            conn = UnixSocketConnection(path=gvm_socket, timeout=timeout)
            info['method'] = f'Unix socket: {gvm_socket}'
        else:
            conn = TLSConnection(hostname=gvm_host, port=gvm_port, timeout=timeout)
            info['method'] = f'TCP {gvm_host}:{gvm_port}'

        with Gmp(conn, transform=EtreeTransform()) as gmp:
            ver_xml = gmp.get_version()
            version = ver_xml.findtext('.//version') or 'unknown'
            gmp.authenticate(gvm_user, gvm_password)
            info['available'] = True
            info['version']   = version
            return info
    except ImportError:
        info['error'] = 'python-gvm not installed'
    except Exception as e:
        info['error'] = str(e)

    # Fallback: raw TCP
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((gvm_host, gvm_port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=gvm_host) as tls:
                tls.sendall(b'<get_version/>')
                data = tls.recv(4096).decode('utf-8', errors='replace')
                ver  = re.search(r'<version>([^<]+)</version>', data)
                info['available'] = True
                info['version']   = ver.group(1) if ver else 'unknown'
                info['method']    = f'TCP (raw) {gvm_host}:{gvm_port}'
                info['error']     = ''
    except Exception as e:
        info['error'] = str(e)

    return info


# ─────────────────────────────────────────────────────────────────────────────
#  STANDALONE TEST
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import sys
    import json

    target_ip = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'

    print(f"\n[*] Testing OpenVAS OS Detector against {target_ip}")
    print("=" * 60)

    # 1. Check OpenVAS availability
    print("\n[1] Checking OpenVAS availability...")
    ova_status = check_openvas_available()
    print(f"    Available : {ova_status['available']}")
    print(f"    Version   : {ova_status['version']}")
    print(f"    Method    : {ova_status['method']}")
    if ova_status['error']:
        print(f"    Error     : {ova_status['error']}")

    # 2. Detect OS
    print(f"\n[2] Detecting OS for {target_ip}...")
    os_info = detect_os(target_ip)
    print(f"    OS Name    : {os_info['os_name']}")
    print(f"    OS Version : {os_info['os_version']}")
    print(f"    OS Family  : {os_info['os_family']}")
    print(f"    Confidence : {os_info['confidence']}%")
    print(f"    Source     : {os_info['source']}")
    print(f"    TTL        : {os_info['ttl']}")
    print(f"    Detection  : {' → '.join(os_info['detection_chain'])}")
    print(f"\n    Full result:\n{json.dumps(os_info, indent=4)}")