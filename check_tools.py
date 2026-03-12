"""
Verify all scan tools are available before running the app.
Run from WSL: python3 check_tools.py
"""
import shutil
import subprocess
import sys

TOOLS = [
    ('nmap', True, 'Ports, services, OS, vuln scripts'),
    ('nikto', False, 'Web vulnerability scanning'),
    ('masscan', False, 'Fast port discovery'),
    ('nuclei', False, 'Fast vuln scanning'),
]

def main():
    print("=" * 50)
    print("Scan Tools Verification")
    print("=" * 50)
    all_ok = True
    for name, required, purpose in TOOLS:
        path = shutil.which(name)
        ok = path is not None
        status = "✓" if ok else "✗"
        req = " (REQUIRED)" if required else ""
        print(f"  {status} {name}{req}: {path or 'NOT FOUND'}")
        if required and not ok:
            all_ok = False
    print()
    print("NVD API: Always available (uses cache)")
    print("=" * 50)

    if not all_ok:
        print("\n⚠️  Nmap is required. Install: sudo apt install nmap")
        sys.exit(1)

    # Quick nmap test
    print("\nQuick Nmap test on 127.0.0.1...")
    try:
        r = subprocess.run(['nmap', '-sn', '127.0.0.1'], capture_output=True, text=True, timeout=10)
        if 'Host is up' in (r.stdout or '') or r.returncode == 0:
            print("  ✓ Nmap works!")
        else:
            print("  ⚠️  Nmap ran but check output")
    except Exception as e:
        print(f"  ✗ Nmap test failed: {e}")
        sys.exit(1)

    print("\n✅ All tools OK. Run: python3 app.py")
    return 0

if __name__ == '__main__':
    sys.exit(main())
