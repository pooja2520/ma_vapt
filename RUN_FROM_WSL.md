# Run VAPT Scanner from WSL (with Nmap, Nikto, etc.)

Since you installed the scan tools inside WSL, the app must run **from WSL** to use them.

## Step 1: Open WSL

In PowerShell or Windows Terminal:
```powershell
wsl
```

## Step 2: Go to project folder

Windows path `C:\Users\sarth\Videos\mavapt\ma_vapt` in WSL is:
```bash
cd /mnt/c/Users/sarth/Videos/mavapt/ma_vapt
```

## Step 3: Verify tools

```bash
python3 check_tools.py
```

You should see ✓ for nmap (and others if installed).

## Step 4: Install Python deps (if needed)

```bash
pip3 install -r requirements.txt
```

## Step 5: Run the app

**MySQL is on Windows** – WSL's `localhost` is not Windows. Set the Windows host IP first:

```bash
export MYSQL_HOST=$(grep nameserver /etc/resolv.conf | awk '{print $2}')
source venv/bin/activate
python3 app.py
```

Or use the helper script (does this automatically):

```bash
./run_from_wsl.sh
```

## Step 6: Open in browser

Open **http://localhost:5005** in your Windows browser.

---

## MySQL (if app uses database)

If MySQL is on Windows, it should work. If MySQL is in WSL:
```bash
sudo service mysql start
```

Update `.env` if needed:
- `MYSQL_HOST=localhost` (default)

---

## Don't close WSL

Keep the WSL terminal open while using the app. Closing it stops the server.
