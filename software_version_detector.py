"""
Software Version Detector for Bulk IP Scanning
===============================================
Detects installed software, versions, and checks for outdated/vulnerable versions.
Integrates with bulk_scan_engine.py via detect_software_on_ip() and
enrich_scan_result_with_software().

Flow:
  1. parse_software_from_nmap()  – extracts software+versions from nmap banner output
  2. detect_software_via_scripts() – runs nmap scripts for deeper version detection
  3. check_version_status()       – compares detected version against known latest/EOL data
  4. get_software_remediation()   – returns accurate, actionable remediation per software
  5. enrich_scan_result_with_software() – top-level enrichment function called from scan_single_ip()
"""

import re
import subprocess
import shutil
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# KNOWN SOFTWARE VERSION DATABASE
# Format:
#   'key': {
#       'display_name': str,
#       'latest_stable': str,          # latest known stable release
#       'eol_versions': [...],          # version prefixes that are End-of-Life
#       'critical_versions': [...],     # versions with known critical CVEs
#       'min_safe': str,                # minimum version considered safe
#       'cve_examples': [...],          # representative CVEs for old versions
#       'upgrade_url': str,
#       'category': str,                # web_server|database|ssh|ftp|mail|runtime|cms|other
#   }
# ─────────────────────────────────────────────────────────────────────────────
SOFTWARE_VERSION_DB = {
    # ── Web Servers ─────────────────────────────────────────────────────────
    'apache': {
        'display_name': 'Apache HTTP Server',
        'latest_stable': '2.4.62',
        'min_safe': '2.4.54',
        'eol_versions': ['1.3', '2.0', '2.2'],
        'critical_versions': ['2.4.49', '2.4.50'],   # CVE-2021-41773, CVE-2021-42013
        'cve_examples': ['CVE-2021-41773', 'CVE-2021-42013', 'CVE-2022-31813', 'CVE-2023-25690'],
        'upgrade_url': 'https://httpd.apache.org/download.cgi',
        'category': 'web_server',
    },
    'nginx': {
        'display_name': 'Nginx',
        'latest_stable': '1.26.2',
        'min_safe': '1.24.0',
        'eol_versions': ['0.', '1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6',
                         '1.7', '1.8', '1.9', '1.10', '1.11', '1.12', '1.13',
                         '1.14', '1.15', '1.16', '1.17', '1.18', '1.19', '1.20'],
        'critical_versions': ['1.18.0', '1.16.1'],
        'cve_examples': ['CVE-2021-23017', 'CVE-2022-41741', 'CVE-2022-41742'],
        'upgrade_url': 'https://nginx.org/en/download.html',
        'category': 'web_server',
    },
    'iis': {
        'display_name': 'Microsoft IIS',
        'latest_stable': '10.0',
        'min_safe': '10.0',
        'eol_versions': ['6.0', '7.0', '7.5', '8.0', '8.5'],
        'critical_versions': ['6.0'],
        'cve_examples': ['CVE-2017-7269', 'CVE-2022-21907'],
        'upgrade_url': 'https://docs.microsoft.com/en-us/iis/get-started/whats-new-in-iis-10',
        'category': 'web_server',
    },
    'lighttpd': {
        'display_name': 'Lighttpd',
        'latest_stable': '1.4.76',
        'min_safe': '1.4.67',
        'eol_versions': ['1.3'],
        'critical_versions': [],
        'cve_examples': ['CVE-2022-41556'],
        'upgrade_url': 'https://www.lighttpd.net/download/',
        'category': 'web_server',
    },

    # ── Databases ────────────────────────────────────────────────────────────
    'mysql': {
        'display_name': 'MySQL',
        'latest_stable': '8.4.0',
        'min_safe': '8.0.32',
        'eol_versions': ['5.1', '5.5', '5.6'],
        'critical_versions': ['5.7.0', '5.7.1', '5.7.2', '5.7.3', '5.7.4',
                              '5.7.5', '5.7.6', '5.7.7', '5.7.8', '5.7.9',
                              '5.7.10', '5.7.11', '5.7.12', '5.7.13', '5.7.14',
                              '5.7.15', '5.7.16', '5.7.17', '5.7.18', '5.7.19',
                              '5.7.20', '5.7.21', '5.7.22', '5.7.23', '5.7.24',
                              '5.7.25', '5.7.26', '5.7.27', '5.7.28', '5.7.29',
                              '5.7.30'],
        'cve_examples': ['CVE-2020-14765', 'CVE-2021-2180', 'CVE-2023-21980'],
        'upgrade_url': 'https://dev.mysql.com/downloads/mysql/',
        'category': 'database',
    },
    'mariadb': {
        'display_name': 'MariaDB',
        'latest_stable': '11.4.3',
        'min_safe': '10.11.0',
        'eol_versions': ['5.5', '10.0', '10.1', '10.2', '10.3', '10.4', '10.5', '10.6'],
        'critical_versions': [],
        'cve_examples': ['CVE-2022-32091', 'CVE-2023-38836'],
        'upgrade_url': 'https://mariadb.org/download/',
        'category': 'database',
    },
    'postgresql': {
        'display_name': 'PostgreSQL',
        'latest_stable': '17.0',
        'min_safe': '15.0',
        'eol_versions': ['9.4', '9.5', '9.6', '10', '11', '12'],
        'critical_versions': [],
        'cve_examples': ['CVE-2023-2454', 'CVE-2023-39417'],
        'upgrade_url': 'https://www.postgresql.org/download/',
        'category': 'database',
    },
    'mssql': {
        'display_name': 'Microsoft SQL Server',
        'latest_stable': '2022',
        'min_safe': '2019',
        'eol_versions': ['2000', '2005', '2008', '2012', '2014'],
        'critical_versions': ['2008', '2012'],
        'cve_examples': ['CVE-2020-0618', 'CVE-2022-37969'],
        'upgrade_url': 'https://www.microsoft.com/en-us/sql-server/sql-server-downloads',
        'category': 'database',
    },
    'mongodb': {
        'display_name': 'MongoDB',
        'latest_stable': '7.0.14',
        'min_safe': '6.0.0',
        'eol_versions': ['2.6', '3.0', '3.2', '3.4', '3.6', '4.0', '4.2'],
        'critical_versions': [],
        'cve_examples': ['CVE-2019-2389', 'CVE-2021-20330'],
        'upgrade_url': 'https://www.mongodb.com/try/download/community',
        'category': 'database',
    },
    'redis': {
        'display_name': 'Redis',
        'latest_stable': '7.4.0',
        'min_safe': '7.0.0',
        'eol_versions': ['2.', '3.', '4.', '5.'],
        'critical_versions': ['6.0.0', '6.0.1', '6.0.2', '6.0.3', '6.0.4',
                              '6.0.5', '6.0.6', '6.0.7', '6.0.8', '6.0.9'],
        'cve_examples': ['CVE-2022-0543', 'CVE-2023-28425', 'CVE-2023-41056'],
        'upgrade_url': 'https://redis.io/download',
        'category': 'database',
    },

    # ── SSH / Remote Access ──────────────────────────────────────────────────
    'openssh': {
        'display_name': 'OpenSSH',
        'latest_stable': '9.8p1',
        'min_safe': '8.9p1',
        'eol_versions': ['3.', '4.', '5.', '6.', '7.'],
        'critical_versions': ['9.5p1', '9.6p1'],   # CVE-2024-6387 regreSSHion
        'cve_examples': ['CVE-2024-6387', 'CVE-2023-38408', 'CVE-2016-20012'],
        'upgrade_url': 'https://www.openssh.com/releasenotes.html',
        'category': 'ssh',
    },
    'dropbear': {
        'display_name': 'Dropbear SSH',
        'latest_stable': '2022.83',
        'min_safe': '2020.81',
        'eol_versions': [],
        'critical_versions': [],
        'cve_examples': ['CVE-2018-15599'],
        'upgrade_url': 'https://matt.ucc.asn.au/dropbear/dropbear.html',
        'category': 'ssh',
    },

    # ── FTP ──────────────────────────────────────────────────────────────────
    'vsftpd': {
        'display_name': 'vsftpd',
        'latest_stable': '3.0.5',
        'min_safe': '3.0.3',
        'eol_versions': ['2.0', '2.1', '2.2'],
        'critical_versions': ['2.3.4'],   # deliberate backdoor CVE-2011-2523 — opens root shell on port 6200
        'cve_examples': ['CVE-2011-2523'],
        'upgrade_url': 'https://security.appspot.com/vsftpd.html',
        'category': 'ftp',
    },
    'proftpd': {
        'display_name': 'ProFTPD',
        'latest_stable': '1.3.8b',
        'min_safe': '1.3.8',
        'eol_versions': ['1.2', '1.3.0', '1.3.1', '1.3.2', '1.3.3', '1.3.4', '1.3.5'],
        'critical_versions': ['1.3.5'],
        'cve_examples': ['CVE-2019-12815', 'CVE-2021-46854'],
        'upgrade_url': 'http://www.proftpd.org/docs/RELEASE_NOTES',
        'category': 'ftp',
    },

    # ── Mail Servers ─────────────────────────────────────────────────────────
    'postfix': {
        'display_name': 'Postfix',
        'latest_stable': '3.9.0',
        'min_safe': '3.7.0',
        'eol_versions': ['2.3', '2.4', '2.5', '2.6'],
        'critical_versions': [],
        'cve_examples': ['CVE-2023-51764'],
        'upgrade_url': 'http://www.postfix.org/download.html',
        'category': 'mail',
    },
    'exim': {
        'display_name': 'Exim',
        'latest_stable': '4.98',
        'min_safe': '4.96',
        'eol_versions': ['3.', '4.0', '4.1', '4.2', '4.3', '4.4', '4.5', '4.6',
                         '4.7', '4.8', '4.9'],
        'critical_versions': ['4.87', '4.88', '4.89', '4.90', '4.91'],
        'cve_examples': ['CVE-2019-10149', 'CVE-2020-28017', 'CVE-2023-42219'],
        'upgrade_url': 'https://www.exim.org/mirrors.html',
        'category': 'mail',
    },
    'sendmail': {
        'display_name': 'Sendmail',
        'latest_stable': '8.18.1',
        'min_safe': '8.17.0',
        'eol_versions': ['8.8', '8.9', '8.10', '8.11', '8.12', '8.13', '8.14'],
        'critical_versions': [],
        'cve_examples': ['CVE-2020-7247', 'CVE-2023-51765'],
        'upgrade_url': 'https://www.sendmail.org',
        'category': 'mail',
    },
    'dovecot': {
        'display_name': 'Dovecot IMAP/POP3',
        'latest_stable': '2.3.21',
        'min_safe': '2.3.16',
        'eol_versions': ['1.', '2.0', '2.1', '2.2'],
        'critical_versions': [],
        'cve_examples': ['CVE-2022-30550', 'CVE-2023-29652'],
        'upgrade_url': 'https://www.dovecot.org',
        'category': 'mail',
    },

    # ── Runtimes / Languages ─────────────────────────────────────────────────
    'php': {
        'display_name': 'PHP',
        'latest_stable': '8.3.11',
        'min_safe': '8.1.0',
        'eol_versions': ['4.', '5.', '7.0', '7.1', '7.2', '7.3', '7.4', '8.0'],
        'critical_versions': ['8.1.0', '8.1.1'],
        'cve_examples': ['CVE-2022-31628', 'CVE-2023-3823', 'CVE-2024-4577'],
        'upgrade_url': 'https://www.php.net/downloads.php',
        'category': 'runtime',
    },
    'node': {
        'display_name': 'Node.js',
        'latest_stable': '22.9.0',
        'min_safe': '20.0.0',
        'eol_versions': ['0.', '4.', '6.', '8.', '9.', '10.', '11.', '12.',
                         '13.', '14.', '15.', '16.', '17.', '18.'],
        'critical_versions': [],
        'cve_examples': ['CVE-2023-30581', 'CVE-2024-27983'],
        'upgrade_url': 'https://nodejs.org/en/download/',
        'category': 'runtime',
    },
    'python': {
        'display_name': 'Python',
        'latest_stable': '3.12.5',
        'min_safe': '3.10.0',
        'eol_versions': ['2.', '3.0', '3.1', '3.2', '3.3', '3.4', '3.5', '3.6', '3.7', '3.8'],
        'critical_versions': [],
        'cve_examples': ['CVE-2022-45061', 'CVE-2023-24329'],
        'upgrade_url': 'https://www.python.org/downloads/',
        'category': 'runtime',
    },
    'java': {
        'display_name': 'Java / JRE',
        'latest_stable': '21',
        'min_safe': '17',
        'eol_versions': ['1.', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16'],
        'critical_versions': [],
        'cve_examples': ['CVE-2022-21449', 'CVE-2022-21476'],
        'upgrade_url': 'https://adoptium.net/temurin/releases/',
        'category': 'runtime',
    },

    # ── SMB / Samba ──────────────────────────────────────────────────────────
    'samba': {
        'display_name': 'Samba',
        'latest_stable': '4.21.0',
        'min_safe': '4.19.0',
        'eol_versions': ['3.', '4.0', '4.1', '4.2', '4.3', '4.4', '4.5',
                         '4.6', '4.7', '4.8', '4.9', '4.10', '4.11', '4.12'],
        'critical_versions': ['4.5.0', '4.5.1', '4.5.2', '4.5.3'],
        'cve_examples': ['CVE-2017-7494', 'CVE-2021-44142', 'CVE-2022-38023'],
        'upgrade_url': 'https://www.samba.org/samba/download/',
        'category': 'file_sharing',
    },

    # ── VPN / Proxy ──────────────────────────────────────────────────────────
    'openssh_sftp': {
        'display_name': 'OpenSSH SFTP',
        'latest_stable': '9.8p1',
        'min_safe': '8.9p1',
        'eol_versions': ['3.', '4.', '5.', '6.', '7.'],
        'critical_versions': [],
        'cve_examples': ['CVE-2024-6387'],
        'upgrade_url': 'https://www.openssh.com/releasenotes.html',
        'category': 'ssh',
    },
    'squid': {
        'display_name': 'Squid Proxy',
        'latest_stable': '6.10',
        'min_safe': '6.0',
        'eol_versions': ['2.', '3.', '4.', '5.'],
        'critical_versions': [],
        'cve_examples': ['CVE-2023-46846', 'CVE-2023-46847', 'CVE-2024-25617'],
        'upgrade_url': 'http://www.squid-cache.org/Versions/',
        'category': 'proxy',
    },

    # ── Monitoring / Admin ───────────────────────────────────────────────────
    'tomcat': {
        'display_name': 'Apache Tomcat',
        'latest_stable': '11.0.0',
        'min_safe': '10.1.0',
        'eol_versions': ['4.', '5.', '6.', '7.', '8.0', '8.5.0', '8.5.1', '8.5.2',
                         '8.5.3', '8.5.4', '8.5.5', '8.5.6', '8.5.7', '8.5.8',
                         '8.5.9', '8.5.10', '9.0.0', '9.0.1', '9.0.2'],
        'critical_versions': ['9.0.0', '10.0.0', '10.0.1'],
        'cve_examples': ['CVE-2020-1938', 'CVE-2022-34305', 'CVE-2023-46589'],
        'upgrade_url': 'https://tomcat.apache.org/download-11.cgi',
        'category': 'web_server',
    },
    'jenkins': {
        'display_name': 'Jenkins',
        'latest_stable': '2.474',
        'min_safe': '2.426',
        'eol_versions': [],
        'critical_versions': [],
        'cve_examples': ['CVE-2024-23897', 'CVE-2023-27898'],
        'upgrade_url': 'https://www.jenkins.io/download/',
        'category': 'cicd',
    },
    'elasticsearch': {
        'display_name': 'Elasticsearch',
        'latest_stable': '8.15.0',
        'min_safe': '8.0.0',
        'eol_versions': ['1.', '2.', '5.', '6.', '7.'],
        'critical_versions': [],
        'cve_examples': ['CVE-2021-22145', 'CVE-2023-31419'],
        'upgrade_url': 'https://www.elastic.co/downloads/elasticsearch',
        'category': 'database',
    },
    'rabbitmq': {
        'display_name': 'RabbitMQ',
        'latest_stable': '3.13.7',
        'min_safe': '3.12.0',
        'eol_versions': ['3.6', '3.7', '3.8', '3.9', '3.10'],
        'critical_versions': [],
        'cve_examples': ['CVE-2023-46118'],
        'upgrade_url': 'https://www.rabbitmq.com/download.html',
        'category': 'message_broker',
    },
    'memcached': {
        'display_name': 'Memcached',
        'latest_stable': '1.6.29',
        'min_safe': '1.6.12',
        'eol_versions': ['1.4', '1.5'],
        'critical_versions': ['1.5.6'],
        'cve_examples': ['CVE-2018-1000115', 'CVE-2022-48571'],
        'upgrade_url': 'https://memcached.org/downloads',
        'category': 'cache',
    },
    'rdp': {
        'display_name': 'Windows Remote Desktop (RDP)',
        'latest_stable': 'Current',
        'min_safe': 'Patched',
        'eol_versions': [],
        'critical_versions': [],
        'cve_examples': ['CVE-2019-0708', 'CVE-2020-0609', 'CVE-2022-21990'],
        'upgrade_url': 'https://msrc.microsoft.com/update-guide/',
        'category': 'remote_access',
    },
    'telnet': {
        'display_name': 'Telnet',
        'latest_stable': 'DEPRECATED',
        'min_safe': 'NEVER_SAFE',
        'eol_versions': ['ALL'],
        'critical_versions': ['ALL'],
        'cve_examples': ['CVE-2001-0554', 'CVE-2011-4862'],
        'upgrade_url': 'https://www.openssh.com/',
        'category': 'remote_access',
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# REMEDIATION DATABASE
# ─────────────────────────────────────────────────────────────────────────────
REMEDIATION_DB = {
    'apache': {
        'outdated': {
            'title': 'Update Apache HTTP Server to Latest Stable Version',
            'severity': 'High',
            'description': (
                'Running an outdated Apache version exposes the server to known exploits '
                'including path traversal (CVE-2021-41773), request smuggling '
                '(CVE-2023-25690), and privilege escalation vulnerabilities.'
            ),
            'steps': [
                'Back up Apache configuration: sudo cp -r /etc/apache2 /etc/apache2.bak',
                'Update via package manager: sudo apt update && sudo apt upgrade apache2',
                'Or compile from source using the latest tarball from https://httpd.apache.org/',
                'Verify new version: apache2 -v',
                'Review and apply security headers (see Missing Headers remediation)',
                'Test configuration before restart: sudo apache2ctl configtest',
                'Restart service: sudo systemctl restart apache2',
                'Verify TLS configuration: openssl s_client -connect <host>:443',
            ],
            'commands': [
                'sudo apt update && sudo apt upgrade apache2',
                'apache2 -v',
                'sudo apache2ctl configtest && sudo systemctl restart apache2',
            ],
            'references': [
                'https://httpd.apache.org/security/vulnerabilities_24.html',
                'https://httpd.apache.org/download.cgi',
            ],
        },
        'eol': {
            'title': 'Apache Version is End-of-Life — Immediate Upgrade Required',
            'severity': 'Critical',
            'description': (
                'The detected Apache version has reached End-of-Life and no longer '
                'receives security patches. This is a critical risk. Migrate immediately.'
            ),
            'steps': [
                'Immediately plan migration to Apache 2.4.x (latest stable)',
                'Export current virtual host and module configs',
                'Install Apache 2.4.x on a test server, migrate config, validate',
                'Schedule production cutover with minimal downtime',
                'Do NOT expose this server to the internet until upgraded',
            ],
            'commands': [
                'sudo apt remove apache2 && sudo apt install apache2',
                'sudo systemctl enable apache2 && sudo systemctl start apache2',
            ],
            'references': ['https://httpd.apache.org/download.cgi'],
        },
    },
    'nginx': {
        'outdated': {
            'title': 'Update Nginx to Latest Stable Version',
            'severity': 'High',
            'description': (
                'Outdated Nginx is vulnerable to memory corruption (CVE-2022-41741/42), '
                'resolver vulnerabilities (CVE-2021-23017), and HTTP/2 DoS attacks.'
            ),
            'steps': [
                'Backup nginx config: sudo cp -r /etc/nginx /etc/nginx.bak',
                'Update via package manager: sudo apt update && sudo apt upgrade nginx',
                'Or add official Nginx repo for latest: https://nginx.org/en/linux_packages.html',
                'Verify version: nginx -v',
                'Test config: sudo nginx -t',
                'Reload: sudo systemctl reload nginx',
                'Disable TLS 1.0/1.1 in /etc/nginx/nginx.conf',
            ],
            'commands': [
                'sudo apt update && sudo apt upgrade nginx',
                'nginx -v',
                'sudo nginx -t && sudo systemctl reload nginx',
            ],
            'references': [
                'https://nginx.org/en/CHANGES',
                'https://nginx.org/en/security_advisories.html',
            ],
        },
        'eol': {
            'title': 'Nginx Version is End-of-Life — Immediate Upgrade Required',
            'severity': 'Critical',
            'description': 'Nginx mainline and legacy stable branches below 1.24 are no longer patched.',
            'steps': [
                'Add official Nginx stable repo and upgrade to 1.26.x',
                'Review config compatibility (particularly SSL directives)',
                'Test with nginx -t before reload',
            ],
            'commands': [
                'curl -fsSL https://nginx.org/keys/nginx_signing.key | sudo apt-key add -',
                'sudo apt update && sudo apt install nginx',
                'nginx -v && sudo nginx -t && sudo systemctl reload nginx',
            ],
            'references': ['https://nginx.org/en/download.html'],
        },
    },
    'openssh': {
        'outdated': {
            'title': 'Update OpenSSH to Patch regreSSHion and Related CVEs',
            'severity': 'Critical',
            'description': (
                'CVE-2024-6387 (regreSSHion) allows unauthenticated remote code execution '
                'as root on glibc-based Linux systems running OpenSSH 8.5p1–9.7p1. '
                'OpenSSH versions below 8.9p1 also have multiple other critical vulnerabilities.'
            ),
            'steps': [
                'Immediately check your version: ssh -V',
                'Update via package manager: sudo apt update && sudo apt upgrade openssh-server',
                'If package manager has no fix yet, set LoginGraceTime 0 in /etc/ssh/sshd_config (mitigates CVE-2024-6387)',
                'Disable root login: PermitRootLogin no in sshd_config',
                'Use key-based auth only: PasswordAuthentication no',
                'Limit SSH to specific IPs with firewall rules',
                'Restart SSH: sudo systemctl restart sshd',
                'Verify: ssh -V',
            ],
            'commands': [
                'sudo apt update && sudo apt upgrade openssh-server',
                'ssh -V',
                'echo "PermitRootLogin no" | sudo tee -a /etc/ssh/sshd_config',
                'echo "PasswordAuthentication no" | sudo tee -a /etc/ssh/sshd_config',
                'sudo systemctl restart sshd',
            ],
            'references': [
                'https://www.openssh.com/security.html',
                'https://nvd.nist.gov/vuln/detail/CVE-2024-6387',
            ],
        },
        'eol': {
            'title': 'OpenSSH Version is Critically Outdated — Upgrade Immediately',
            'severity': 'Critical',
            'description': 'Very old OpenSSH versions have dozens of known RCE and privilege escalation CVEs.',
            'steps': [
                'Upgrade OpenSSH via package manager immediately',
                'Disable remote SSH access until patched if possible',
                'Consider replacing with a hardened SSH gateway',
            ],
            'commands': [
                'sudo apt update && sudo apt install --only-upgrade openssh-server',
                'sudo systemctl restart sshd',
            ],
            'references': ['https://www.openssh.com/releasenotes.html'],
        },
    },
    'mysql': {
        'outdated': {
            'title': 'Update MySQL to Patch Authentication and Privilege Escalation CVEs',
            'severity': 'High',
            'description': (
                'MySQL 5.7 and older 8.0 builds contain multiple vulnerabilities including '
                'unauthenticated access to sensitive tables, privilege escalation, '
                'and denial-of-service via crafted SQL.'
            ),
            'steps': [
                'Backup all databases first: mysqldump --all-databases > backup.sql',
                'Update MySQL: sudo apt update && sudo apt upgrade mysql-server',
                'Or use official MySQL repo: https://dev.mysql.com/downloads/repo/apt/',
                'Run mysql_upgrade after updating',
                'Verify: mysql --version',
                'Bind MySQL to localhost only: bind-address = 127.0.0.1 in my.cnf',
                'Remove anonymous users: DELETE FROM mysql.user WHERE User=\'\'',
                'Disable remote root login',
            ],
            'commands': [
                'mysqldump --all-databases -u root -p > full_backup.sql',
                'sudo apt update && sudo apt upgrade mysql-server',
                'sudo mysql_upgrade -u root -p',
                'mysql --version',
            ],
            'references': [
                'https://dev.mysql.com/doc/relnotes/mysql/8.0/en/',
                'https://www.mysql.com/support/eol-notice.html',
            ],
        },
        'eol': {
            'title': 'MySQL Version is End-of-Life — Critical Risk',
            'severity': 'Critical',
            'description': 'MySQL 5.5 and 5.6 are end-of-life with no further security patches.',
            'steps': [
                'Immediately plan upgrade to MySQL 8.0+ or migrate to MariaDB 10.11+',
                'Export data, upgrade, run mysql_upgrade, validate application compatibility',
                'Isolate this server from public network until upgraded',
            ],
            'commands': [
                'mysqldump --all-databases -u root -p > backup.sql',
                'sudo apt remove mysql-server && sudo apt install mysql-server-8.0',
            ],
            'references': ['https://dev.mysql.com/downloads/mysql/'],
        },
    },
    'php': {
        'outdated': {
            'title': 'Update PHP to Patch RCE and Information Disclosure CVEs',
            'severity': 'Critical',
            'description': (
                'PHP 7.x and early 8.0/8.1 versions contain critical vulnerabilities: '
                'CVE-2024-4577 (argument injection on Windows/CGI), '
                'CVE-2023-3823 (XML external entity), and '
                'CVE-2022-31628 (file disclosure via phar). '
                'PHP 7.x and below have NO security support.'
            ),
            'steps': [
                'Identify current PHP version: php -v',
                'Add PHP repo: sudo add-apt-repository ppa:ondrej/php',
                'Install PHP 8.3: sudo apt install php8.3 php8.3-fpm php8.3-{cli,common,curl,xml,mbstring,gd,mysqlnd}',
                'Update php.ini: disable allow_url_fopen, expose_php = Off, display_errors = Off',
                'Test application against new PHP version in staging first',
                'Switch web server to use new PHP-FPM socket',
                'Verify: php -v',
            ],
            'commands': [
                'php -v',
                'sudo add-apt-repository ppa:ondrej/php && sudo apt update',
                'sudo apt install php8.3 php8.3-fpm',
                'php -v',
            ],
            'references': [
                'https://www.php.net/supported-versions.php',
                'https://nvd.nist.gov/vuln/detail/CVE-2024-4577',
            ],
        },
        'eol': {
            'title': 'PHP Version is End-of-Life — No Security Patches Available',
            'severity': 'Critical',
            'description': 'PHP 5.x and 7.x are fully end-of-life. No patches are released for new CVEs.',
            'steps': [
                'Migrate application to PHP 8.2+ immediately',
                'Use https://php-legacy-migration.com or Rector for automated code refactoring',
                'Test thoroughly in staging before production deployment',
            ],
            'commands': [
                'sudo add-apt-repository ppa:ondrej/php && sudo apt install php8.3',
            ],
            'references': ['https://www.php.net/eol.php'],
        },
    },
    'vsftpd': {
        'outdated': {
            'title': 'Update vsftpd — Backdoor in 2.3.4 and Known CVEs',
            'severity': 'Critical',
            'description': (
                'vsftpd 2.3.4 contains a deliberate backdoor (CVE-2011-2523) that opens a '
                'root shell on port 6200 when a smiley-face username is used. '
                'Other versions have denial-of-service vulnerabilities.'
            ),
            'steps': [
                'Check version: vsftpd --version',
                'Update immediately: sudo apt update && sudo apt upgrade vsftpd',
                'Consider replacing FTP with SFTP (OpenSSH) or FTPS',
                'Restrict vsftpd to local users only: local_enable=YES, anonymous_enable=NO',
                'Force SSL: ssl_enable=YES, force_local_data_ssl=YES',
                'Chroot users: chroot_local_user=YES',
                'Firewall: only allow FTP from trusted IPs',
            ],
            'commands': [
                'sudo apt update && sudo apt upgrade vsftpd',
                'sudo systemctl restart vsftpd',
                'netstat -tlnp | grep vsftpd',
            ],
            'references': [
                'https://security.appspot.com/vsftpd.html',
                'https://nvd.nist.gov/vuln/detail/CVE-2011-2523',
            ],
        },
        'eol': {
            'title': 'vsftpd Version is Outdated — Replace with SFTP',
            'severity': 'High',
            'description': 'Old vsftpd versions are unpatched. Migrate to SFTP for secure file transfer.',
            'steps': [
                'Install OpenSSH SFTP subsystem (usually included with openssh-server)',
                'Configure SFTP-only users with chroot in /etc/ssh/sshd_config',
                'Disable vsftpd: sudo systemctl disable vsftpd',
            ],
            'commands': [
                'sudo systemctl stop vsftpd && sudo systemctl disable vsftpd',
                'sudo systemctl restart sshd',
            ],
            'references': ['https://wiki.archlinux.org/title/SFTP_chroot'],
        },
    },
    'telnet': {
        'outdated': {
            'title': 'Telnet is Active — Disable Immediately and Replace with SSH',
            'severity': 'Critical',
            'description': (
                'Telnet transmits all data including credentials in plaintext. '
                'Anyone on the network path can intercept passwords and session data. '
                'There is NO version of Telnet that is safe to use over a network.'
            ),
            'steps': [
                'Stop Telnet service immediately: sudo systemctl stop telnet',
                'Disable it: sudo systemctl disable telnet',
                'Or via inetd: remove telnet line from /etc/inetd.conf, restart inetd',
                'Install and configure OpenSSH as replacement',
                'Block port 23 at firewall: sudo ufw deny 23',
                'Verify Telnet is closed: nmap -p23 <host>',
            ],
            'commands': [
                'sudo systemctl stop telnet.socket && sudo systemctl disable telnet.socket',
                'sudo ufw deny 23/tcp',
                'sudo apt install openssh-server && sudo systemctl enable sshd',
            ],
            'references': [
                'https://www.ietf.org/rfc/rfc0854.txt',
                'https://www.openssh.com/',
            ],
        },
        'eol': {
            'title': 'Telnet is Active — Disable Immediately and Replace with SSH',
            'severity': 'Critical',
            'description': 'Telnet is fundamentally insecure. See outdated remediation.',
            'steps': ['See "outdated" remediation above — all Telnet versions are unsafe.'],
            'commands': ['sudo systemctl stop telnet && sudo systemctl disable telnet'],
            'references': ['https://www.openssh.com/'],
        },
    },
    'rdp': {
        'outdated': {
            'title': 'Apply Latest Windows Security Updates to Patch RDP CVEs',
            'severity': 'Critical',
            'description': (
                'RDP has a history of critical CVEs: CVE-2019-0708 (BlueKeep, RCE without auth), '
                'CVE-2020-0609/0610 (Windows RD Gateway RCE), CVE-2022-21990. '
                'Exposed RDP is one of the top ransomware entry vectors.'
            ),
            'steps': [
                'Apply all Windows security updates immediately (Windows Update)',
                'Enable Network Level Authentication (NLA): gpedit.msc > Computer Config > Admin Templates > Windows Components > Remote Desktop Services',
                'Block RDP from internet — only allow from VPN/trusted IPs',
                'Use non-standard port (security through obscurity, not sufficient alone)',
                'Enable RDP firewall rule only for specific source IPs',
                'Deploy an RD Gateway for controlled external access',
                'Enable account lockout: after 5 failed attempts',
                'Use strong passwords / MFA for all RDP-accessible accounts',
                'Monitor RDP login events (Event ID 4625, 4624)',
            ],
            'commands': [
                'netsh advfirewall firewall add rule name="Block RDP Public" protocol=TCP dir=in localport=3389 action=block',
                'reg add "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-TCP" /v SecurityLayer /t REG_DWORD /d 2 /f',
            ],
            'references': [
                'https://msrc.microsoft.com/update-guide/',
                'https://nvd.nist.gov/vuln/detail/CVE-2019-0708',
            ],
        },
        'eol': {
            'title': 'Apply Windows Updates Immediately — RDP Has Active Exploits',
            'severity': 'Critical',
            'description': 'Unpatched RDP is actively exploited. See outdated remediation.',
            'steps': ['Apply all Windows patches, restrict RDP access, enable NLA.'],
            'commands': ['wuauclt /detectnow /updatenow'],
            'references': ['https://msrc.microsoft.com/update-guide/'],
        },
    },
    'redis': {
        'outdated': {
            'title': 'Update Redis and Restrict Network Access',
            'severity': 'High',
            'description': (
                'Redis running without authentication on a public interface is a critical risk. '
                'CVE-2022-0543 allows Lua sandbox escape for RCE. '
                'Older Redis versions also lack ACL system (added in 6.0).'
            ),
            'steps': [
                'Update Redis: sudo apt update && sudo apt upgrade redis-server',
                'Bind to localhost only: bind 127.0.0.1 in redis.conf',
                'Enable authentication: requirepass <strong-password> in redis.conf',
                'Enable protected-mode: protected-mode yes',
                'Disable dangerous commands: rename-command FLUSHALL ""',
                'Use Redis ACLs (6.0+) for fine-grained access control',
                'Restart: sudo systemctl restart redis',
            ],
            'commands': [
                'sudo apt update && sudo apt upgrade redis-server',
                'echo "bind 127.0.0.1" | sudo tee -a /etc/redis/redis.conf',
                'sudo systemctl restart redis',
                'redis-cli ping',
            ],
            'references': [
                'https://redis.io/docs/manual/security/',
                'https://nvd.nist.gov/vuln/detail/CVE-2022-0543',
            ],
        },
        'eol': {
            'title': 'Redis Version is End-of-Life — Upgrade Required',
            'severity': 'High',
            'description': 'Redis 5.x and below receive no security patches.',
            'steps': ['Upgrade to Redis 7.x, review breaking changes in migration guide.'],
            'commands': ['sudo apt install redis-server', 'redis-server --version'],
            'references': ['https://redis.io/download'],
        },
    },
    'samba': {
        'outdated': {
            'title': 'Update Samba to Patch EternalBlue-Class and RCE Vulnerabilities',
            'severity': 'Critical',
            'description': (
                'CVE-2017-7494 (SambaCry) allows unauthenticated RCE if a writable share exists. '
                'CVE-2021-44142 is an out-of-bounds heap write via VFS. '
                'Samba vulnerabilities are actively used by ransomware and worms.'
            ),
            'steps': [
                'Update Samba immediately: sudo apt update && sudo apt upgrade samba',
                'Restrict shares to required users only in smb.conf',
                'Disable SMBv1: min protocol = SMB2 in [global] section of smb.conf',
                'Do not expose Samba (ports 139/445) to the internet',
                'Use firewall to restrict SMB to trusted subnets only',
                'Enable Samba audit logging',
                'Restart: sudo systemctl restart smbd nmbd',
            ],
            'commands': [
                'sudo apt update && sudo apt upgrade samba',
                'echo "min protocol = SMB2" | sudo tee -a /etc/samba/smb.conf',
                'sudo testparm && sudo systemctl restart smbd',
                'smbstatus --version',
            ],
            'references': [
                'https://www.samba.org/samba/security/',
                'https://nvd.nist.gov/vuln/detail/CVE-2017-7494',
            ],
        },
        'eol': {
            'title': 'Samba Version is End-of-Life — Immediate Upgrade Required',
            'severity': 'Critical',
            'description': 'Samba 3.x and 4.0-4.12 are end-of-life with no patches.',
            'steps': ['Upgrade to Samba 4.19+ following the official migration guide.'],
            'commands': ['sudo apt install samba', 'smbd --version'],
            'references': ['https://www.samba.org/samba/download/'],
        },
    },
    'exim': {
        'outdated': {
            'title': 'Update Exim to Patch Remote Code Execution CVEs',
            'severity': 'Critical',
            'description': (
                'CVE-2019-10149 (The Return of the WIZard) allows remote command execution. '
                'Multiple heap overflow and privilege escalation CVEs exist in older Exim builds.'
            ),
            'steps': [
                'Update Exim immediately: sudo apt update && sudo apt upgrade exim4',
                'Or compile from https://www.exim.org/mirrors.html',
                'Verify version: exim --version',
                'Review SMTP AUTH configuration',
                'Restrict relay permissions in /etc/exim4/exim4.conf',
                'Enable rate limiting to prevent abuse',
                'Test config: sudo exim4 -bV',
            ],
            'commands': [
                'sudo apt update && sudo apt upgrade exim4',
                'exim --version',
                'sudo systemctl restart exim4',
            ],
            'references': [
                'https://www.exim.org/static/doc/security/',
                'https://nvd.nist.gov/vuln/detail/CVE-2019-10149',
            ],
        },
        'eol': {
            'title': 'Exim Version is End-of-Life — Upgrade Immediately',
            'severity': 'Critical',
            'description': 'Exim 4.91 and below have multiple unpatched critical CVEs.',
            'steps': ['Upgrade to Exim 4.97+ or migrate to Postfix.'],
            'commands': ['sudo apt install exim4', 'exim --version'],
            'references': ['https://www.exim.org/mirrors.html'],
        },
    },
    'mongodb': {
        'outdated': {
            'title': 'Update MongoDB and Enable Authentication',
            'severity': 'High',
            'description': (
                'Many MongoDB instances run without authentication (default in older builds). '
                'CVE-2021-20330 and others allow data disclosure and DoS. '
                'Unauthenticated MongoDB on a public IP is trivially exploitable.'
            ),
            'steps': [
                'Update MongoDB: follow https://www.mongodb.com/docs/manual/tutorial/upgrade-revision/',
                'Enable access control: security.authorization: enabled in mongod.conf',
                'Create admin user with strong password',
                'Bind to localhost: net.bindIp: 127.0.0.1',
                'If remote access needed, use TLS and allowlisted IPs',
                'Restart: sudo systemctl restart mongod',
            ],
            'commands': [
                'sudo apt update && sudo apt upgrade mongodb-org',
                'mongo --version',
                'sudo systemctl restart mongod',
            ],
            'references': [
                'https://www.mongodb.com/docs/manual/security/',
                'https://www.mongodb.com/docs/manual/administration/upgrade/',
            ],
        },
        'eol': {
            'title': 'MongoDB Version is End-of-Life',
            'severity': 'High',
            'description': 'MongoDB 4.2 and below are EOL. Upgrade to 7.0 LTS.',
            'steps': ['Follow the MongoDB upgrade path guide for step-by-step major version upgrades.'],
            'commands': ['mongod --version'],
            'references': ['https://www.mongodb.com/support-policy/legacy'],
        },
    },
    'tomcat': {
        'outdated': {
            'title': 'Update Apache Tomcat to Patch AJP Ghostcat and HTTP/2 CVEs',
            'severity': 'High',
            'description': (
                'CVE-2020-1938 (Ghostcat) allows file read/include via AJP connector. '
                'CVE-2022-34305 is a partial request smuggling issue. '
                'CVE-2023-46589 allows request smuggling via malformed HTTP headers.'
            ),
            'steps': [
                'Backup Tomcat webapps and conf directories',
                'Download latest Tomcat from https://tomcat.apache.org/',
                'Replace binaries, preserve conf/ and webapps/',
                'Disable AJP connector if not used: comment out in server.xml',
                'Set requiredSecret for AJP if it must remain: <Connector ... requiredSecret="secret" />',
                'Remove default manager/host-manager apps in production',
                'Change default admin credentials',
                'Run Tomcat as non-root dedicated user',
            ],
            'commands': [
                'sudo systemctl stop tomcat',
                '# Download latest from https://tomcat.apache.org/',
                'sudo systemctl start tomcat',
                'curl -s http://localhost:8080/ | grep -i tomcat',
            ],
            'references': [
                'https://tomcat.apache.org/security-10.html',
                'https://nvd.nist.gov/vuln/detail/CVE-2020-1938',
            ],
        },
        'eol': {
            'title': 'Apache Tomcat Version is End-of-Life',
            'severity': 'Critical',
            'description': 'Tomcat 7.x, 8.0.x, and 8.5.x are EOL.',
            'steps': ['Upgrade to Tomcat 10.1.x or 11.x. Review Java EE to Jakarta EE namespace changes.'],
            'commands': ['sudo apt install tomcat10', 'catalina.sh version'],
            'references': ['https://tomcat.apache.org/whichversion.html'],
        },
    },
    'default': {
        'outdated': {
            'title': 'Update Detected Software to Latest Stable Version',
            'severity': 'Medium',
            'description': (
                'Running outdated software increases exposure to known CVEs. '
                'Apply vendor patches and follow security advisories.'
            ),
            'steps': [
                'Identify the exact installed version',
                'Check vendor security advisories for CVEs affecting your version',
                'Apply vendor-provided patches or update via package manager',
                'Test in staging environment before production deployment',
                'Enable automatic security updates for OS packages',
                'Subscribe to vendor security mailing lists',
            ],
            'commands': [
                'sudo apt update && sudo apt upgrade',
                'sudo apt list --upgradable',
            ],
            'references': [
                'https://nvd.nist.gov/',
                'https://www.cvedetails.com/',
            ],
        },
        'eol': {
            'title': 'Software is End-of-Life — Upgrade or Replace Immediately',
            'severity': 'Critical',
            'description': 'EOL software receives no security updates. Replace or upgrade immediately.',
            'steps': [
                'Identify the supported replacement or newer version',
                'Plan migration with minimal service disruption',
                'Isolate this system from untrusted networks until upgraded',
            ],
            'commands': ['sudo apt update && sudo apt upgrade'],
            'references': ['https://endoflife.date/'],
        },
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# VERSION COMPARISON HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _parse_version(version_str):
    """Parse a version string to a tuple of integers for comparison."""
    if not version_str:
        return (0,)
    # Extract leading numeric version (e.g. "2.4.41 ((Ubuntu))" → "2.4.41")
    m = re.match(r'[\s\w]*?(\d+[\d.]*)', str(version_str))
    if not m:
        return (0,)
    parts = m.group(1).split('.')
    result = []
    for p in parts[:4]:
        p_clean = re.sub(r'[^\d].*', '', p)
        try:
            result.append(int(p_clean))
        except ValueError:
            break
    return tuple(result) if result else (0,)


def _version_lt(v1_str, v2_str):
    """Return True if version v1 < v2."""
    return _parse_version(v1_str) < _parse_version(v2_str)


def _starts_with_any(version_str, prefixes):
    """Return True if version_str starts with any of the given prefixes."""
    v = str(version_str).strip()
    for prefix in prefixes:
        if v.startswith(str(prefix)):
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# CORE DETECTION FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def identify_software_from_banner(service_name, version_banner):
    """
    Map a service name / banner string to a SOFTWARE_VERSION_DB key.
    Returns (db_key, detected_version_string) or (None, None).
    """
    service_lower = str(service_name).lower()
    banner_lower = str(version_banner).lower()
    combined = service_lower + ' ' + banner_lower

    # Order matters — check more specific before generic
    mappings = [
        (['openssh', 'openSSH'],                                'openssh'),
        (['dropbear'],                                          'dropbear'),
        (['apache tomcat', 'tomcat'],                           'tomcat'),
        (['apache', 'httpd', 'apache2'],                        'apache'),
        (['nginx'],                                             'nginx'),
        (['iis', 'microsoft-iis', 'microsoft iis'],             'iis'),
        (['lighttpd'],                                          'lighttpd'),
        (['mysql'],                                             'mysql'),
        (['mariadb'],                                           'mariadb'),
        (['postgresql', 'postgres'],                            'postgresql'),
        (['microsoft sql', 'mssql', 'ms-sql', 'sqlserver'],     'mssql'),
        (['mongodb', 'mongo'],                                  'mongodb'),
        (['redis'],                                             'redis'),
        (['memcached'],                                         'memcached'),
        (['vsftpd'],                                            'vsftpd'),
        (['proftpd'],                                           'proftpd'),
        (['postfix', 'esmtp postfix'],                          'postfix'),
        (['exim', 'exim smtpd'],                                'exim'),
        (['sendmail'],                                          'sendmail'),
        (['dovecot'],                                           'dovecot'),
        (['php'],                                               'php'),
        (['node', 'nodejs', 'node.js'],                         'node'),
        (['python'],                                            'python'),
        (['java', 'jre', 'jdk'],                                'java'),
        (['samba', 'smbd', 'nmbd'],                             'samba'),
        (['squid'],                                             'squid'),
        (['elasticsearch'],                                     'elasticsearch'),
        (['rabbitmq'],                                          'rabbitmq'),
        (['jenkins'],                                           'jenkins'),
        (['telnet', 'telnetd'],                                 'telnet'),
        (['rdp', 'ms-wbt-server', 'msrdp', 'remote desktop'],  'rdp'),
    ]

    for keywords, db_key in mappings:
        for kw in keywords:
            if kw.lower() in combined:
                # Extract version number from banner
                version = _extract_version_from_banner(version_banner, service_name)
                return db_key, version

    return None, None


def _extract_version_from_banner(banner, service_name=''):
    """
    Extract the version string from an nmap banner like:
      'OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)'
      'Apache httpd 2.4.41 ((Ubuntu))'
      'MySQL 5.7.30-0ubuntu0.18.04.1'
    Returns the version string or 'Unknown'.
    """
    combined = f"{service_name} {banner}"

    # Patterns ordered from most specific to least
    patterns = [
        # Apache httpd 2.4.41
        r'(?:httpd|apache)[/ ](\d+\.\d+[\.\d]*)',
        # OpenSSH 8.2p1
        r'openssh[/ ](\d+\.\d+[p\d]*)',
        # nginx/1.18.0
        r'nginx[/ ](\d+\.\d+[\.\d]*)',
        # MySQL 5.7.30
        r'(?:mysql|mariadb)[/ ](\d+\.\d+[\.\d]*)',
        # PostgreSQL 13.4
        r'postgresql[/ ](\d+[\.\d]*)',
        # PHP/7.4.3
        r'php[/ ](\d+\.\d+[\.\d]*)',
        # vsftpd 3.0.3
        r'vsftpd (\d+\.\d+[\.\d]*)',
        # Exim 4.94.2
        r'exim[/ ](\d+\.\d+[\.\d]*)',
        # Postfix
        r'postfix[/ ](\d+\.\d+[\.\d]*)',
        # Dovecot
        r'dovecot[/ ](\d+\.\d+[\.\d]*)',
        # Redis
        r'redis[/ ](\d+\.\d+[\.\d]*)',
        # Generic version X.Y.Z
        r'(?:^|[\s/])(\d+\.\d+[\.\d]*)',
    ]

    for pat in patterns:
        m = re.search(pat, combined, re.IGNORECASE)
        if m:
            return m.group(1)

    return 'Unknown'


def check_version_status(db_key, detected_version):
    """
    Check whether detected_version is:
      - 'eol'      : End-of-Life
      - 'critical' : Has known critical CVEs for this exact version
      - 'outdated' : Older than min_safe but not EOL
      - 'current'  : Up to date
      - 'unknown'  : Version string could not be parsed
    Returns (status, info_dict)
    """
    info = SOFTWARE_VERSION_DB.get(db_key)
    if not info:
        return 'unknown', {}

    # Special cases: always unsafe regardless of version string
    if db_key == 'telnet':
        return 'critical', info

    if not detected_version or detected_version == 'Unknown':
        return 'unknown', info

    # Check EOL
    if _starts_with_any(detected_version, info['eol_versions']):
        return 'eol', info

    # Check critical versions (exact prefix match)
    if _starts_with_any(detected_version, info['critical_versions']):
        return 'critical', info

    # Check if outdated (< min_safe)
    min_safe = info.get('min_safe', '')
    if min_safe and min_safe not in ('Current', 'Patched', 'NEVER_SAFE'):
        if _version_lt(detected_version, min_safe):
            return 'outdated', info

    return 'current', info


def get_software_remediation(db_key, status):
    """
    Return the remediation dict for a given software key and status.
    Merges software-specific remediation with generic CVE info from the DB.
    """
    sw_info = SOFTWARE_VERSION_DB.get(db_key, {})
    remediation_key = 'eol' if status in ('eol', 'critical') else 'outdated'

    # Look up software-specific remediation, fallback to default
    sw_remediation = REMEDIATION_DB.get(db_key, REMEDIATION_DB['default'])
    rem = sw_remediation.get(remediation_key, REMEDIATION_DB['default'][remediation_key]).copy()

    # Enrich with CVEs from the version DB
    cves = sw_info.get('cve_examples', [])
    if cves:
        rem['known_cves'] = cves

    rem['upgrade_url'] = sw_info.get('upgrade_url', '')
    rem['latest_stable'] = sw_info.get('latest_stable', 'Unknown')
    rem['category'] = sw_info.get('category', 'other')

    return rem


# ─────────────────────────────────────────────────────────────────────────────
# NMAP-SCRIPT BASED DEEPER VERSION DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def run_nmap_version_scripts(ip, open_ports):
    """
    Run targeted nmap version-detection scripts on discovered open ports.
    Returns raw nmap output string.
    Only called when nmap is available and we have open ports.
    """
    if not shutil.which('nmap') or not open_ports:
        return ''

    port_list = ','.join(str(p) for p in open_ports[:50])  # limit to 50 ports
    args = [
        'nmap', '-T4', '-Pn', '-sV',
        '--version-intensity', '7',
        '--script', 'banner,http-server-header,ssh2-enum-algos,ftp-anon,smtp-commands',
        '-p', port_list,
        ip
    ]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
        return proc.stdout or ''
    except Exception:
        return ''


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENRICHMENT FUNCTION
# ─────────────────────────────────────────────────────────────────────────────

def parse_software_from_ports(ports):
    """
    Given a list of port dicts (from parse_nmap_output), extract all
    detected software with version info.

    Each port dict has: port, protocol, service, version, state

    Returns list of software_finding dicts.
    """
    findings = []
    seen_keys = set()

    for port_info in ports:
        service = port_info.get('service', '')
        version_banner = port_info.get('version', '')
        port_num = port_info.get('port', '')

        db_key, detected_version = identify_software_from_banner(service, version_banner)
        if not db_key:
            continue

        # Deduplicate (same software detected on multiple ports is OK but log once)
        dedup_key = f"{db_key}:{detected_version}"
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        sw_info = SOFTWARE_VERSION_DB.get(db_key, {})
        status, _ = check_version_status(db_key, detected_version)
        remediation = None

        if status in ('eol', 'critical', 'outdated'):
            remediation = get_software_remediation(db_key, status)

        finding = {
            'software_key': db_key,
            'display_name': sw_info.get('display_name', db_key),
            'category': sw_info.get('category', 'other'),
            'detected_version': detected_version,
            'latest_stable': sw_info.get('latest_stable', 'Unknown'),
            'status': status,           # 'current'|'outdated'|'eol'|'critical'|'unknown'
            'port': port_num,
            'service': service,
            'raw_banner': version_banner,
            'known_cves': sw_info.get('cve_examples', []),
            'upgrade_url': sw_info.get('upgrade_url', ''),
            'remediation': remediation,
        }

        findings.append(finding)

    return findings


def software_findings_to_vulnerabilities(software_findings, ip):
    """
    Convert software_findings list into vulnerability dicts compatible with
    the existing bulk_scan_engine vulnerability format.
    """
    vulns = []
    for sw in software_findings:
        status = sw.get('status')
        if status not in ('eol', 'critical', 'outdated'):
            continue

        rem = sw.get('remediation') or {}
        severity_map = {
            'eol': 'Critical',
            'critical': 'Critical',
            'outdated': 'High',
        }
        severity = rem.get('severity') or severity_map.get(status, 'Medium')

        cves = sw.get('known_cves', [])
        cve_str = ', '.join(cves[:3]) if cves else None

        # Build description
        latest = sw.get('latest_stable', 'Unknown')
        detected = sw.get('detected_version', 'Unknown')
        if status == 'eol':
            description = (
                f"{sw['display_name']} v{detected} is End-of-Life and receives "
                f"no security patches. Upgrade to v{latest}."
            )
        elif status == 'critical':
            description = (
                f"{sw['display_name']} v{detected} has known critical CVEs "
                f"({', '.join(cves[:2])}). Upgrade to v{latest} immediately."
            )
        else:
            description = (
                f"{sw['display_name']} v{detected} is outdated (latest: v{latest}). "
                f"Known CVEs: {', '.join(cves[:2]) if cves else 'see advisories'}."
            )

        # Build remediation text from structured data
        rem_steps = rem.get('steps', [])
        rem_commands = rem.get('commands', [])
        remediation_text = rem.get('description', '')
        if rem_steps:
            remediation_text += '\n\nSteps:\n' + '\n'.join(f'  {i+1}. {s}' for i, s in enumerate(rem_steps))
        if rem_commands:
            remediation_text += '\n\nCommands:\n' + '\n'.join(f'  $ {c}' for c in rem_commands)
        if sw.get('upgrade_url'):
            remediation_text += f"\n\nUpgrade: {sw['upgrade_url']}"

        vuln = {
            'name': f"Outdated Software: {sw['display_name']} v{detected}",
            'description': description,
            'severity': severity,
            'source': 'SoftwareVersionCheck',
            'cve': cve_str,
            'port': sw.get('port'),
            'remediation': remediation_text,
            'software_key': sw.get('software_key'),
            'detected_version': detected,
            'latest_stable': latest,
            'status': status,
            'upgrade_url': sw.get('upgrade_url', ''),
            'known_cves': cves,
        }
        vulns.append(vuln)

    return vulns


def enrich_scan_result_with_software(scan_result):
    """
    Top-level function: takes a scan_result dict from scan_single_ip()
    and adds 'software_inventory' (all detected software) and enriches
    'vulnerabilities' with outdated/EOL software findings.

    Modifies scan_result in-place and returns it.

    Usage in bulk_scan_engine.scan_single_ip():
        from software_version_detector import enrich_scan_result_with_software
        result = enrich_scan_result_with_software(result)
    """
    ports = scan_result.get('ports', [])
    ip = scan_result.get('ip', '')

    if not ports:
        scan_result['software_inventory'] = []
        return scan_result

    software_findings = parse_software_from_ports(ports)
    scan_result['software_inventory'] = software_findings

    # Convert outdated/EOL findings into vulnerability entries
    sw_vulns = software_findings_to_vulnerabilities(software_findings, ip)
    if sw_vulns:
        existing = scan_result.get('vulnerabilities', [])
        scan_result['vulnerabilities'] = existing + sw_vulns

    # Update severity if new vulns are more critical
    if sw_vulns:
        has_critical = any(v['severity'] == 'Critical' for v in sw_vulns)
        has_high = any(v['severity'] == 'High' for v in sw_vulns)
        current_sev = scan_result.get('severity', 'none')
        sev_rank = {'none': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        if has_critical and sev_rank.get(current_sev, 0) < 4:
            scan_result['severity'] = 'critical'
            scan_result['risk'] = 'High'
        elif has_high and sev_rank.get(current_sev, 0) < 3:
            scan_result['severity'] = 'high'
            scan_result['risk'] = 'High'

    return scan_result