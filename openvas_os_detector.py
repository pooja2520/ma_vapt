"""
OpenVAS OS Detection Module for VAPT Scanner Pro
=================================================
Detects actual operating systems (Ubuntu, Windows, Red Hat/CentOS/Rocky, and others)
by combining multiple fingerprinting techniques:

  1. OpenVAS / GVM integration  — authoritative OS info from a running OpenVAS daemon
  2. Nmap OS fingerprinting     — -O with aggressive guesses (root) OR -sV banner scan (non-root)
  3. Service-banner heuristics  — SSH, HTTP, SMB/RDP banner analysis
  4. CPE parsing                — Common Platform Enumeration from nmap output
  5. TTL analysis               — fallback heuristic from ping responses

Priority order: OpenVAS → Nmap CPE → Nmap OS section → Service Banners → Nmap scan → TTL

BUGS FIXED vs v1:
  #1  Standalone __main__ test now runs a real nmap -sV scan before calling detect_os(),
      so CPE/banner layers actually receive data instead of always falling to TTL.
  #2  _nmap_os_scan() now has a non-root fallback: runs 'nmap -sV -sC' which provides
      Service Info: OS and CPE lines without needing raw socket / root access.
  #3  _nmap_os_scan() now also adds -sV to the root/-O path so banner data is
      collected alongside OS fingerprint results.
  #4  check_openvas_available() now checks os.path.exists() before attempting
      UnixSocketConnection — fixes misleading 'Method: Unix socket' when file absent.
  #5  Service banners step moved BEFORE dedicated nmap scan so existing parsed
      port data is checked first (faster, no extra subprocess).
"""

import re
import subprocess
import shutil
import platform
import socket
import os
import json
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
#  OS CLASSIFICATION CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

OS_UBUNTU  = "Ubuntu Linux"
OS_REDHAT  = "Red Hat Enterprise Linux"
OS_CENTOS  = "CentOS Linux"
OS_ROCKY   = "Rocky Linux"
OS_FEDORA  = "Fedora Linux"
OS_DEBIAN  = "Debian Linux"
OS_WINDOWS = "Windows"
OS_MACOS   = "macOS"
OS_FREEBSD = "FreeBSD"
OS_LINUX   = "Linux"
OS_UNKNOWN = "Unknown"

# Keyword patterns → canonical OS name (evaluated in order, first match wins)
_BANNER_OS_PATTERNS = [
    (re.compile(r'ubuntu',                                                             re.I), OS_UBUNTU),
    (re.compile(r'red\s?hat|rhel',                                                     re.I), OS_REDHAT),
    (re.compile(r'centos',                                                             re.I), OS_CENTOS),
    (re.compile(r'rocky\s*linux|rocky',                                                re.I), OS_ROCKY),
    (re.compile(r'fedora',                                                             re.I), OS_FEDORA),
    (re.compile(r'oracle\s*linux',                                                     re.I), "Oracle Linux"),
    (re.compile(r'alma\s*linux',                                                       re.I), "AlmaLinux"),
    (re.compile(r'debian',                                                             re.I), OS_DEBIAN),
    (re.compile(r'windows\s*(server|xp|vista|7|8|10|11|nt|2000|2003|2008|2012|2016|2019|2022)', re.I), OS_WINDOWS),
    (re.compile(r'microsoft|windows',                                                  re.I), OS_WINDOWS),
    (re.compile(r'mac\s*os|darwin|macos',                                              re.I), OS_MACOS),
    (re.compile(r'freebsd',                                                            re.I), OS_FREEBSD),
    (re.compile(r'openbsd',                                                            re.I), "OpenBSD"),
    (re.compile(r'netbsd',                                                             re.I), "NetBSD"),
    (re.compile(r'linux',                                                              re.I), OS_LINUX),
]

# CPE OS prefix → canonical name
_CPE_OS_MAP = {
    'cpe:/o:canonical:ubuntu':          OS_UBUNTU,
    'cpe:/o:redhat:enterprise_linux':   OS_REDHAT,
    'cpe:/o:redhat:rhel':               OS_REDHAT,
    'cpe:/o:centos:centos':             OS_CENTOS,
    'cpe:/o:rocky_linux':               OS_ROCKY,
    'cpe:/o:fedoraproject:fedora':      OS_FEDORA,
    'cpe:/o:debian:debian_linux':       OS_DEBIAN,
    'cpe:/o:microsoft:windows':         OS_WINDOWS,
    'cpe:/o:apple:mac_os_x':            OS_MACOS,
    'cpe:/o:apple:macos':               OS_MACOS,
    'cpe:/o:freebsd:freebsd':           OS_FREEBSD,
    'cpe:/o:linux:linux_kernel':        OS_LINUX,
}


# ─────────────────────────────────────────────────────────────────────────────
#  HELPER UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def _has_root():
    try:
        return os.geteuid() == 0
    except (AttributeError, OSError):
        return False


def _check_tool(name):
    return shutil.which(name) is not None


def _classify_os_string(text):
    """Match free-form OS string → (canonical_name, version_hint)."""
    if not text:
        return OS_UNKNOWN, ''
    for pattern, canonical in _BANNER_OS_PATTERNS:
        m = pattern.search(text)
        if m:
            ver_match = re.search(r'(\d+(?:\.\d+){0,3})', text[m.end():])
            version = ver_match.group(1) if ver_match else ''
            return canonical, version
    return OS_UNKNOWN, ''


def _parse_cpe_os(nmap_output):
    """
    Extract OS CPE strings from nmap output.
    CPE lines look like: cpe:/o:canonical:ubuntu_linux:20.04
    Returns (canonical, version, cpe_string) or (None, '', '').
    """
    cpe_re = re.compile(r'cpe:/o:[^\s\|\"\']+', re.I)
    for cpe in cpe_re.findall(nmap_output or ''):
        cpe_lower = cpe.lower()
        for prefix, canonical in _CPE_OS_MAP.items():
            if cpe_lower.startswith(prefix):
                ver_match = re.search(r':(\d[\d.]+)$', cpe_lower)
                version = ver_match.group(1) if ver_match else ''
                return canonical, version, cpe
    return None, '', ''


def _parse_nmap_os_section(nmap_output):
    """
    Parse nmap output for OS detection lines.
    Checks: 'OS details:', 'Running:', 'Aggressive OS guesses:', 'Service Info: OS:'
    Returns (canonical_name, version, raw_string) or (None, '', '').
    """
    patterns = [
        re.compile(r'^OS details:\s*(.+)$',                     re.M),
        re.compile(r'^Running:\s*(.+)$',                        re.M),
        re.compile(r'^Aggressive OS guesses:\s*(.+?)(?:\(|$)',  re.M),
        re.compile(r'Service Info:.*?OS:\s*([^;,\n]+)',         re.I),
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
    TTL-based OS hint from ping.
    TTL >= 100 → Windows (initial TTL 128)
    TTL 60-99  → Linux   (initial TTL 64)
    Returns (os_hint_string, ttl_int) or (None, None).
    """
    try:
        if platform.system().lower() == 'windows':
            cmd    = ['ping', '-n', '1', ip]
            ttl_re = re.compile(r'TTL=(\d+)', re.I)
        else:
            cmd    = ['ping', '-c', '1', '-W', '2', ip]
            ttl_re = re.compile(r'ttl=(\d+)', re.I)

        proc   = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        output = (proc.stdout or '') + (proc.stderr or '')
        m      = ttl_re.search(output)
        if not m:
            return None, None
        ttl = int(m.group(1))
        if ttl >= 100:
            return OS_WINDOWS, ttl
        elif ttl >= 60:
            return OS_LINUX, ttl
        return None, ttl
    except Exception:
        return None, None


# ─────────────────────────────────────────────────────────────────────────────
#  BANNER-BASED OS DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def _os_from_service_banners(ports_list):
    """
    Analyse nmap service version strings for OS clues.
    Priority: SSH → HTTP → DB → SMB → RDP → WinRM
    Returns (canonical_name, version, source_note) or (None, '', '').
    """
    for port_info in (ports_list or []):
        svc     = (port_info.get('service') or '').lower()
        version = (port_info.get('version') or '')
        port    = str(port_info.get('port') or '')

        # SSH: "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)"
        if 'ssh' in svc and version:
            canonical, ver = _classify_os_string(version)
            if canonical != OS_UNKNOWN:
                return canonical, ver, f"SSH banner: {version[:80]}"

        # HTTP: "Apache/2.4.41 (Ubuntu)" or "Microsoft-IIS/10.0"
        if svc in ('http', 'https', 'http-alt', 'ssl/http') and version:
            canonical, ver = _classify_os_string(version)
            if canonical != OS_UNKNOWN:
                return canonical, ver, f"HTTP banner: {version[:80]}"

        # MySQL / MariaDB
        if ('mysql' in svc or 'mariadb' in svc) and version:
            canonical, ver = _classify_os_string(version)
            if canonical != OS_UNKNOWN:
                return canonical, ver, f"DB banner: {version[:80]}"

        # SMB / NetBIOS → Windows
        if svc in ('microsoft-ds', 'netbios-ssn', 'msrpc', 'smb') or port in ('445', '139', '135'):
            return OS_WINDOWS, '', 'SMB/NetBIOS service'

        # RDP → Windows
        if svc in ('ms-wbt-server', 'rdp') or port == '3389':
            return OS_WINDOWS, '', 'RDP service'

        # WinRM → Windows
        if svc in ('wsman', 'winrm') or port in ('5985', '5986'):
            return OS_WINDOWS, '', 'WinRM service'

    return None, '', ''


# ─────────────────────────────────────────────────────────────────────────────
#  NMAP SCAN  (root: -O fingerprint | non-root: -sV banner scan)
# ─────────────────────────────────────────────────────────────────────────────

def _nmap_os_scan(ip, open_ports=None, timeout=120):
    """
    Run nmap against ip to collect OS information.

    ROOT path (or Windows with npcap):
        nmap -O --osscan-guess -sV --version-intensity 7
        → full OS fingerprint + service banners

    NON-ROOT path (WSL / regular Linux user):
        nmap -sV -sC --version-intensity 9
              --script ssh-hostkey,http-server-header,smb-os-discovery,banner
        → SSH/HTTP/SMB banners + Service Info: OS: lines + CPE strings
        → no raw sockets needed, works without root

    FIX #2 & #3 vs v1: non-root path added; -sV added to root path.

    Returns raw nmap stdout string (empty on failure).
    """
    if not _check_tool('nmap'):
        return ''

    port_arg = []
    if open_ports:
        port_arg = ['-p', ','.join(str(p) for p in open_ports[:50])]

    if _has_root() or platform.system().lower() == 'windows':
        # Full OS fingerprint + service versions
        cmd = (
            ['nmap', '-T4', '-Pn', '-O', '--osscan-guess',
             '--max-os-tries', '2', '-sV', '--version-intensity', '7']
            + port_arg + [ip]
        )
    else:
        # Non-root: banner + script scan — captures SSH OS strings, SMB info, HTTP headers
        # Also includes smb-os-discovery which reveals Windows version without root
        cmd = (
            ['nmap', '-T4', '-Pn', '-sV', '-sC',
             '--version-intensity', '9',
             '--script', 'ssh-hostkey,http-server-header,smb-os-discovery,banner,ssl-cert']
            + port_arg + [ip]
        )

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout or ''
    except subprocess.TimeoutExpired:
        return ''
    except (FileNotFoundError, Exception):
        return ''


# ─────────────────────────────────────────────────────────────────────────────
#  OPENVAS / GVM INTEGRATION
# ─────────────────────────────────────────────────────────────────────────────

def _openvas_get_os(ip, gvm_socket=None, gvm_host='127.0.0.1', gvm_port=9390,
                    gvm_user='admin', gvm_password='admin', timeout=30):
    """
    Query a running OpenVAS / GVM daemon for best_os_txt for the given IP.
    Returns dict {os_name, os_version, os_cpe, confidence, source} or None.

    Tries python-gvm library first, falls back to raw TLS XML.
    FIX: auto-detects socket path when not supplied; os.path.exists() guard
    prevents misleading 'Unix socket' method when file is absent.
    """
    # Auto-detect socket path if caller passed None or empty string
    if not gvm_socket:
        gvm_socket = _find_gvm_socket()

    # ── python-gvm library ────────────────────────────────────────────────────
    try:
        from gvm.connections import UnixSocketConnection, TLSConnection
        from gvm.protocols.gmp import Gmp
        from gvm.transforms import EtreeTransform

        # Only use socket when the file actually exists
        if gvm_socket and os.path.exists(gvm_socket):
            connection = UnixSocketConnection(path=gvm_socket, timeout=timeout)
        else:
            connection = TLSConnection(hostname=gvm_host, port=gvm_port, timeout=timeout)

        with Gmp(connection, transform=EtreeTransform()) as gmp:
            gmp.authenticate(gvm_user, gvm_password)
            tasks_xml = gmp.get_tasks(filter_string="status=Done rows=100")
            task_ids  = [t.get('id') for t in tasks_xml.findall('.//task') if t.get('id')]

            for task_id in task_ids[:20]:
                try:
                    report_xml = gmp.get_reports(
                        filter_string=f"task_id={task_id} rows=1",
                        details=True,
                        ignore_pagination=False,
                    )
                    for host_el in report_xml.findall('.//host'):
                        ip_el = host_el.find('ip')
                        if ip_el is None or (ip_el.text or '').strip() != ip:
                            continue
                        os_info = {
                            'os_name': OS_UNKNOWN, 'os_version': '',
                            'os_cpe': '', 'confidence': 0, 'source': 'OpenVAS'
                        }
                        for detail in host_el.findall('.//detail'):
                            n_el = detail.find('name')
                            v_el = detail.find('value')
                            if n_el is None or v_el is None:
                                continue
                            n = (n_el.text or '').strip()
                            v = (v_el.text or '').strip()
                            if n == 'best_os_txt' and v:
                                canonical, ver = _classify_os_string(v)
                                os_info.update({
                                    'os_name': canonical, 'os_version': ver,
                                    'confidence': 90, 'raw': v
                                })
                            elif n == 'best_os_cpe' and v:
                                os_info['os_cpe'] = v
                                if os_info['os_name'] == OS_UNKNOWN:
                                    for prefix, canonical in _CPE_OS_MAP.items():
                                        if v.lower().startswith(prefix):
                                            os_info['os_name'] = canonical
                                            break
                        if os_info['os_name'] != OS_UNKNOWN:
                            return os_info
                except Exception:
                    continue

    except ImportError:
        pass
    except Exception:
        pass

    # ── Raw TLS XML fallback ──────────────────────────────────────────────────
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        with socket.create_connection((gvm_host, gvm_port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=gvm_host) as sock:

                def _send(xml):
                    sock.sendall(xml.encode('utf-8'))

                def _recv():
                    chunks = []
                    while True:
                        chunk = sock.recv(65536)
                        if not chunk:
                            break
                        chunks.append(chunk)
                        joined = b''.join(chunks)
                        if (b'</get_reports_response>' in joined or
                                b'</authenticate_response>' in joined):
                            break
                    return b''.join(chunks).decode('utf-8', errors='replace')

                _send(
                    f'<authenticate><credentials>'
                    f'<username>{gvm_user}</username>'
                    f'<password>{gvm_password}</password>'
                    f'</credentials></authenticate>'
                )
                if 'status="200"' not in _recv():
                    return None

                _send('<get_reports filter="rows=5 first=1 sort-reverse=date" details="1"/>')
                resp = _recv()
                ip_block_re = re.compile(
                    r'<host>.*?<ip>' + re.escape(ip) + r'</ip>.*?</host>',
                    re.DOTALL
                )
                for block in ip_block_re.findall(resp):
                    txt_m = re.search(r'<n>best_os_txt</n>\s*<value>([^<]+)</value>', block)
                    cpe_m = re.search(r'<n>best_os_cpe</n>\s*<value>([^<]+)</value>', block)
                    if txt_m:
                        raw_os = txt_m.group(1).strip()
                        canonical, ver = _classify_os_string(raw_os)
                        return {
                            'os_name':    canonical,
                            'os_version': ver,
                            'os_cpe':     cpe_m.group(1).strip() if cpe_m else '',
                            'confidence': 90,
                            'source':     'OpenVAS (XML)',
                            'raw':        raw_os,
                        }
    except Exception:
        pass

    return None


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

def detect_os(ip, nmap_output='', ports_list=None, open_ports=None,
              openvas_config=None):
    """
    Detect the OS of a host using 6 layers in priority order.

    Parameters
    ----------
    ip             : str  — target IP
    nmap_output    : str  — raw nmap stdout (pass from bulk_scan_engine)
    ports_list     : list — parsed port dicts [{port, service, version}, ...]
    open_ports     : list — open port strings ['22', '80', ...]
    openvas_config : dict — {'socket', 'host', 'port', 'user', 'password'}

    Returns
    -------
    dict: os_name, os_version, os_family, os_cpe, confidence,
          source, ttl, raw, detection_chain
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
        result.update({
            'os_name':    name,
            'os_version': version,
            'os_cpe':     cpe,
            'confidence': confidence,
            'source':     source,
            'raw':        raw,
            'os_family':  _family(name),
        })

    def _family(name):
        nl = name.lower()
        if 'windows' in nl:
            return 'windows'
        if any(x in nl for x in ('ubuntu', 'debian', 'redhat', 'centos',
                                   'rocky', 'fedora', 'oracle', 'alma', 'linux')):
            return 'linux'
        if 'macos' in nl or 'darwin' in nl:
            return 'macos'
        if 'bsd' in nl:
            return 'bsd'
        return 'unknown'

    chain = result['detection_chain']

    # ── 1. OpenVAS (highest confidence, 90%) ─────────────────────────────────
    chain.append('openvas')
    ova_cfg = openvas_config or {}
    # Auto-detect socket when caller did not supply one
    resolved_socket = ova_cfg.get('socket') or _find_gvm_socket()
    ova = _openvas_get_os(
        ip,
        gvm_socket   = resolved_socket,
        gvm_host     = ova_cfg.get('host',     '127.0.0.1'),
        gvm_port     = int(ova_cfg.get('port',  9390)),
        gvm_user     = ova_cfg.get('user',     'admin'),
        gvm_password = ova_cfg.get('password', 'admin'),
    )
    if ova and ova.get('os_name', OS_UNKNOWN) != OS_UNKNOWN:
        _set(ova['os_name'], ova.get('os_version', ''), ova.get('os_cpe', ''),
             ova.get('confidence', 90), ova.get('source', 'OpenVAS'),
             ova.get('raw', ''))
        return result

    # ── 2. Nmap CPE in existing output (85%) ──────────────────────────────────
    chain.append('nmap_cpe')
    if nmap_output:
        cpe_name, cpe_ver, cpe_str = _parse_cpe_os(nmap_output)
        if cpe_name:
            _set(cpe_name, cpe_ver, cpe_str, 85, 'Nmap CPE', cpe_str)
            return result

    # ── 3. Nmap OS section in existing output (80%) ───────────────────────────
    chain.append('nmap_os_section')
    if nmap_output:
        nm_name, nm_ver, nm_raw = _parse_nmap_os_section(nmap_output)
        if nm_name:
            _set(nm_name, nm_ver, '', 80, 'Nmap OS Detection', nm_raw)
            return result

    # ── 4. Service banners from existing port data (75%) ──────────────────────
    # FIX #5: moved BEFORE dedicated nmap scan — uses already-parsed data, faster
    chain.append('service_banners')
    if ports_list:
        bn_name, bn_ver, bn_note = _os_from_service_banners(ports_list)
        if bn_name:
            _set(bn_name, bn_ver, '', 75, f'Service Banner ({bn_note})', bn_note)
            return result

    # ── 5. Dedicated nmap scan (root: -O | non-root: -sV -sC) (80-85%) ───────
    # FIX #2 & #3: non-root path now collects real banner data via -sV -sC
    chain.append('nmap_scan')
    fresh_output = _nmap_os_scan(ip, open_ports=open_ports)
    if fresh_output:
        # CPE from fresh scan
        cpe_name, cpe_ver, cpe_str = _parse_cpe_os(fresh_output)
        if cpe_name:
            label = 'Nmap -O CPE' if (_has_root() or platform.system().lower() == 'windows') else 'Nmap -sV CPE'
            _set(cpe_name, cpe_ver, cpe_str, 85, label, cpe_str)
            return result
        # OS section from fresh scan
        nm_name, nm_ver, nm_raw = _parse_nmap_os_section(fresh_output)
        if nm_name:
            label = 'Nmap -O' if (_has_root() or platform.system().lower() == 'windows') else 'Nmap -sV Banner'
            _set(nm_name, nm_ver, '', 80, label, nm_raw)
            return result
        # Banner analysis on fresh scan ports
        seen_ports = set()
        fresh_ports = []
        for line in fresh_output.splitlines():
            line = line.strip()
            if line.startswith('|'):
                continue
            m = re.match(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', line)
            if m:
                port, proto, svc, rest = m.groups()
                if port not in seen_ports:
                    seen_ports.add(port)
                    fresh_ports.append({
                        'port': port, 'protocol': proto,
                        'service': svc, 'version': rest.strip()
                    })
        if fresh_ports:
            bn_name, bn_ver, bn_note = _os_from_service_banners(fresh_ports)
            if bn_name:
                _set(bn_name, bn_ver, '', 75, f'Service Banner ({bn_note})', bn_note)
                return result

    # ── 6. TTL heuristic (last resort, 40%) ───────────────────────────────────
    chain.append('ttl')
    ttl_hint, ttl_val = _get_ttl_os_hint(ip)
    result['ttl'] = ttl_val
    if ttl_hint:
        _set(ttl_hint, '', '', 40, f'TTL heuristic (TTL={ttl_val})', f'TTL={ttl_val}')
        return result

    result['os_family'] = 'unknown'
    return result


def enrich_result_with_os(result, openvas_config=None):
    """
    Enrich a scan_single_ip() result dict in-place.
    Called from bulk_scan_engine after nmap parsing.
    result['_nmap_raw'] must be set before calling this.
    """
    ip          = result.get('ip', '')
    ports_list  = result.get('ports', [])
    open_ports  = result.get('open_ports', [])
    nmap_output = result.get('_nmap_raw', '')

    os_info = detect_os(
        ip,
        nmap_output    = nmap_output,
        ports_list     = ports_list,
        open_ports     = open_ports,
        openvas_config = openvas_config,
    )

    canonical = os_info['os_name']
    version   = os_info['os_version']
    if canonical != OS_UNKNOWN:
        result['os'] = f"{canonical} {version}".strip() if version else canonical

    result['os_detail'] = os_info
    result['os_family'] = os_info['os_family']
    return result


# ─────────────────────────────────────────────────────────────────────────────
#  OPENVAS AVAILABILITY CHECK
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
#  GVM SOCKET AUTO-DETECTION
# ─────────────────────────────────────────────────────────────────────────────

# All known GVM/OpenVAS socket paths across distros and WSL setups
_GVM_SOCKET_CANDIDATES = [
    '/run/gvmd/gvmd.sock',          # Kali / Debian / Ubuntu default
    '/var/run/gvmd/gvmd.sock',      # older distros
    '/run/gvm/gvmd.sock',           # some community builds
    '/var/run/gvm/gvmd.sock',
    '/tmp/gvm/gvmd.sock',
    '/usr/local/var/run/gvmd.sock', # macOS homebrew
]


def _find_gvm_socket():
    """
    Scan all known socket paths and return the first one that exists.
    Also honours the OPENVAS_SOCKET environment variable.
    Returns socket path string or '' if none found.
    """
    env_sock = os.environ.get('OPENVAS_SOCKET', '').strip()
    if env_sock and os.path.exists(env_sock):
        return env_sock
    for path in _GVM_SOCKET_CANDIDATES:
        if os.path.exists(path):
            return path
    return ''


def check_openvas_available(gvm_socket=None,
                             gvm_host='127.0.0.1', gvm_port=9390,
                             gvm_user='admin', gvm_password='admin',
                             timeout=10):
    """
    Test whether OpenVAS/GVM is reachable and can authenticate.
    Returns dict: {available, version, method, error}

    If gvm_socket is None (default), auto-detects the socket path.
    Tries Unix socket first. Only falls back to TCP if socket not found.
    Reports the real socket error instead of overwriting it with TCP error.
    """
    # Auto-detect socket if not supplied
    if gvm_socket is None:
        gvm_socket = _find_gvm_socket()

    info = {'available': False, 'version': '', 'method': '', 'error': ''}

    # ── Try python-gvm via socket or TLS ──────────────────────────────────────
    socket_exists = bool(gvm_socket and os.path.exists(gvm_socket))
    use_socket    = socket_exists

    try:
        from gvm.connections import UnixSocketConnection, TLSConnection
        from gvm.protocols.gmp import Gmp
        from gvm.transforms import EtreeTransform

        if use_socket:
            conn           = UnixSocketConnection(path=gvm_socket, timeout=timeout)
            info['method'] = f'Unix socket: {gvm_socket}'
        else:
            conn           = TLSConnection(hostname=gvm_host, port=gvm_port, timeout=timeout)
            info['method'] = f'TCP {gvm_host}:{gvm_port}'

        with Gmp(conn, transform=EtreeTransform()) as gmp:
            ver_xml = gmp.get_version()
            version = ver_xml.findtext('.//version') or 'unknown'
            gmp.authenticate(gvm_user, gvm_password)
            info.update({'available': True, 'version': version})
            return info

    except ImportError:
        info['error'] = 'python-gvm not installed — run: pip3 install python-gvm'
        return info   # no point trying TCP raw without python-gvm either
    except Exception as e:
        socket_err = str(e)
        info['error'] = f"Socket auth error: {socket_err}" if use_socket else str(e)
        # If the socket existed but auth failed (wrong password), don't try TCP
        if use_socket and ('authentication' in socket_err.lower()
                           or 'permission' in socket_err.lower()
                           or 'credentials' in socket_err.lower()
                           or 'failed' in socket_err.lower()):
            info['error'] = f"Wrong password for GVM admin user ({socket_err})"
            return info

    # ── Raw TCP fallback — only if no socket was found ────────────────────────
    # If a socket existed but failed, skip TCP (different host wouldn't help)
    if use_socket:
        return info   # keep the real socket error, don't hide it with TCP error

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
                info.update({
                    'available': True,
                    'version':   ver.group(1) if ver else 'unknown',
                    'method':    f'TCP (raw) {gvm_host}:{gvm_port}',
                    'error':     '',
                })
    except Exception as e:
        info['error'] = str(e)

    return info


# ─────────────────────────────────────────────────────────────────────────────
#  STANDALONE TEST
#  FIX #1 vs v1: now runs a real nmap -sV scan first so CPE/banner layers
#  receive actual data and don't always fall through to TTL.
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import sys

    target_ip = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'

    print(f"\n[*] OpenVAS OS Detector v2 — testing against {target_ip}")
    print("=" * 60)

    # ── Step 1: Check OpenVAS ─────────────────────────────────────────────────
    print("\n[1] Checking OpenVAS availability...")
    ova = check_openvas_available()
    print(f"    Available : {ova['available']}")
    print(f"    Version   : {ova['version']}")
    print(f"    Method    : {ova['method']}")
    if ova['error']:
        print(f"    Note      : {ova['error']}")

    # ── Step 2: Run nmap -sV to gather banners + CPE (no root needed) ─────────
    # FIX #1: this is what was missing in v1 — standalone test had no nmap data
    nmap_raw       = ''
    parsed_ports   = []
    open_port_list = []

    if _check_tool('nmap'):
        print(f"\n[2] Running nmap -sV scan on {target_ip} (works without root)...")
        try:
            cmd = [
                'nmap', '-T4', '-Pn', '-sV', '-sC',
                '--version-intensity', '9',
                '--script', 'ssh-hostkey,http-server-header,smb-os-discovery,banner',
                '--top-ports', '1000',
                target_ip
            ]
            proc     = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            nmap_raw = proc.stdout or ''

            if nmap_raw:
                print(f"    nmap completed ({len(nmap_raw)} bytes of output)")
                # Parse ports from output for banner analysis
                seen = set()
                for line in nmap_raw.splitlines():
                    line = line.strip()
                    if line.startswith('|'):
                        continue
                    m = re.match(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', line)
                    if m:
                        port, proto, svc, rest = m.groups()
                        if port not in seen:
                            seen.add(port)
                            open_port_list.append(port)
                            parsed_ports.append({
                                'port':     port,
                                'protocol': proto,
                                'service':  svc,
                                'version':  rest.strip(),
                            })
                print(f"    Open ports : {', '.join(open_port_list) or 'none found'}")
                if parsed_ports:
                    print("    Services   :")
                    for p in parsed_ports[:8]:
                        print(f"      {p['port']:>5}/{p['protocol']}  {p['service']:<15}  {p['version'][:60]}")
            else:
                print("    nmap returned no output (host may be down or blocking)")

        except subprocess.TimeoutExpired:
            print("    nmap timed out (180s)")
        except Exception as e:
            print(f"    nmap error: {e}")
    else:
        print("\n[2] nmap not found — only TTL fallback will run")

    # ── Step 3: Detect OS with all collected data ─────────────────────────────
    print(f"\n[3] Running OS detection for {target_ip}...")
    os_info = detect_os(
        target_ip,
        nmap_output    = nmap_raw,
        ports_list     = parsed_ports,
        open_ports     = open_port_list,
        openvas_config = None,   # set to dict with socket/host/port/user/password to use OpenVAS
    )

    print(f"\n    ┌─ Result ─────────────────────────────────────")
    print(f"    │  OS Name    : {os_info['os_name']}")
    print(f"    │  OS Version : {os_info['os_version'] or '(not detected)'}")
    print(f"    │  OS Family  : {os_info['os_family']}")
    print(f"    │  Confidence : {os_info['confidence']}%")
    print(f"    │  Source     : {os_info['source']}")
    print(f"    │  TTL        : {os_info['ttl']}")
    print(f"    │  Chain      : {' → '.join(os_info['detection_chain'])}")
    print(f"    └──────────────────────────────────────────────")
    print(f"\n    Full JSON:\n{json.dumps(os_info, indent=4)}")