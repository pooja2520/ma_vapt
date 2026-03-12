#!/bin/bash
# Run the VAPT app from WSL so it can use Nmap, Nikto, Masscan, Nuclei
# Usage: ./run_from_wsl.sh

echo "=== VAPT Scanner - Running from WSL ==="
echo ""

# MySQL on Windows: WSL localhost != Windows. Use Windows host IP.
if [ -f /etc/resolv.conf ]; then
  WIN_HOST=$(grep nameserver /etc/resolv.conf | awk '{print $2}' | head -1)
  if [ -n "$WIN_HOST" ]; then
    export MYSQL_HOST="$WIN_HOST"
    echo "MySQL: using Windows host $WIN_HOST (from /etc/resolv.conf)"
  fi
fi
echo ""

# Activate venv if present
[ -d venv ] && source venv/bin/activate

# Check tools
echo "Checking scan tools..."
for tool in nmap nikto masscan nuclei; do
  if command -v $tool &>/dev/null; then
    echo "  ✓ $tool: $(which $tool)"
  else
    echo "  ✗ $tool: NOT FOUND"
  fi
done
echo ""

# Quick nmap test
echo "Quick Nmap test (127.0.0.1)..."
nmap -sn 127.0.0.1 2>/dev/null | head -5
echo ""

# Run the app
echo "Starting Flask app on http://0.0.0.0:5005"
echo "Open http://localhost:5005 in your Windows browser"
echo ""
python3 app.py
