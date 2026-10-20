#!/usr/bin/env bash
# Web Monitor installer - Linux & Windows (Git Bash / MSYS2)
set -u
cd "$(dirname "$0")"

B=$'\033[1;34m'; R=$'\033[1;31m'; G=$'\033[1;32m'; Y=$'\033[1;33m'; N=$'\033[0m'
say()  { echo -e "${B}==>${N} $*"; }
ok()   { echo -e "${G}OK${N}  $*"; }
warn() { echo -e "${Y}!!${N}  $*"; }
die()  { echo -e "${R}ERROR:${N} $*"; exit 1; }

# ---------------------------------------------------------------- detect OS
case "$(uname -s)" in
  Linux*)               OS=linux ;;
  MINGW*|MSYS*|CYGWIN*) OS=windows ;;
  *) die "Unsupported OS: $(uname -s) (Linux and Windows only)" ;;
esac
say "Detected OS: $OS"

# ------------------------------------------------------------ find Python
PY=""
find_python() {
  for c in python3 python py; do
    if command -v "$c" >/dev/null 2>&1 &&
       "$c" -c 'import sys; sys.exit(0 if sys.version_info>=(3,8) else 1)' 2>/dev/null; then
      PY="$c"; return 0
    fi
  done
  return 1
}

linux_hint() {
  if   command -v apt-get >/dev/null; then echo "sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip"
  elif command -v dnf     >/dev/null; then echo "sudo dnf install -y python3 python3-pip"
  elif command -v yum     >/dev/null; then echo "sudo yum install -y python3 python3-pip"
  elif command -v pacman  >/dev/null; then echo "sudo pacman -S --needed python python-pip"
  elif command -v zypper  >/dev/null; then echo "sudo zypper install -y python3 python3-pip"
  else echo "Install Python 3.8+ (with venv and pip) using your package manager"; fi
}

if ! find_python; then
  if [ "$OS" = windows ]; then
    say "Python 3.8+ not found. Installing with winget..."
    if command -v winget >/dev/null 2>&1; then
      winget install -e --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements \
        || die "winget failed. Install Python manually from https://www.python.org/downloads/ (tick 'Add to PATH')."
      echo
      ok "Python installed. Close this terminal, open a NEW Git Bash and run ./install.sh again."
      exit 0
    else
      die "winget not available. Install Python from https://www.python.org/downloads/ (tick 'Add to PATH') and re-run."
    fi
  else
    warn "Python 3.8+ is missing. Please install it yourself, then re-run ./install.sh:"
    echo "    $(linux_hint)"
    exit 1
  fi
fi
ok "Python: $($PY --version 2>&1)"

if [ "$OS" = linux ] && ! "$PY" -c 'import venv, ensurepip' 2>/dev/null; then
  warn "Python venv/pip module is missing. Please install it, then re-run ./install.sh:"
  echo "    $(linux_hint)"
  exit 1
fi

# ------------------------------------------------------------------- venv
say "Creating virtual environment..."
"$PY" -m venv venv || die "Could not create venv."
if [ "$OS" = windows ]; then VPY="$PWD/venv/Scripts/python.exe"; else VPY="$PWD/venv/bin/python"; fi

say "Installing dependencies (flask, waitress)..."
"$VPY" -m pip install --upgrade pip -q
if ! "$VPY" -m pip install -r requirements.txt -q; then
  if [ "$OS" = linux ]; then
    die "pip install failed (network/proxy?). Please run manually: ./venv/bin/pip install -r requirements.txt"
  else
    die "pip install failed. Check your internet connection and re-run."
  fi
fi
ok "Dependencies installed."

# ---------------------------------------------------------------- prompts
echo
read -rp "Panel FQDN (e.g. monitor.example.com) [empty = IP only]: " FQDN
read -rp "Panel port [8080]: " PORT; PORT="${PORT:-8080}"
case "$PORT" in ''|*[!0-9]*) die "Port must be a number." ;; esac
read -rp "Admin username [admin]: " AUSER; AUSER="${AUSER:-admin}"
while true; do
  read -rsp "Admin password (min 8 chars): " APASS; echo
  read -rsp "Repeat password: " APASS2; echo
  [ "$APASS" = "$APASS2" ] && [ "${#APASS}" -ge 8 ] && break
  warn "Passwords do not match or are shorter than 8 characters."
done

FQDN="$FQDN" PORT="$PORT" "$VPY" - <<'PYEOF'
import json, os, secrets
p = "config.json"
c = json.load(open(p)) if os.path.exists(p) else {}
c.update(fqdn=os.environ["FQDN"], port=int(os.environ["PORT"]))
c.setdefault("secret_key", secrets.token_hex(32))
json.dump(c, open(p, "w"), indent=2)
PYEOF

APP_ADMIN_USER="$AUSER" APP_ADMIN_PASS="$APASS" "$VPY" app.py --init-admin || die "Could not create admin user."

# ------------------------------------------------------------- run / service
IP="$("$VPY" -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
try:
    s.connect(('10.255.255.255',1));print(s.getsockname()[0])
except Exception:
    print('127.0.0.1')")"

if [ "$OS" = linux ]; then
  if [ "$(id -u)" = 0 ] && command -v systemctl >/dev/null 2>&1; then
    read -rp "Install as a systemd service (auto-start on boot)? [Y/n]: " A
    if [[ ! "${A:-Y}" =~ ^[Nn] ]]; then
      cat > /etc/systemd/system/webmonitor.service <<EOF
[Unit]
Description=Web Monitor
After=network.target

[Service]
WorkingDirectory=$PWD
ExecStart=$VPY $PWD/app.py
Restart=always
User=$(stat -c %U "$PWD")

[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload && systemctl enable --now webmonitor && ok "Service 'webmonitor' started."
    fi
  else
    warn "Not root / no systemd: run manually with:  $VPY app.py"
    warn "(To auto-start on boot, re-run install.sh with sudo.)"
  fi
  echo "If a firewall is active, open the port, e.g.:  sudo ufw allow $PORT/tcp"
else
  printf '@echo off\r\ncd /d "%%~dp0"\r\n"venv\\Scripts\\python.exe" app.py\r\n' > start.bat
  ok "Created start.bat (double-click to start)."
  read -rp "Register auto-start at boot (needs Administrator)? [y/N]: " A
  if [[ "${A:-N}" =~ ^[Yy] ]]; then
    WP="$(cygpath -w "$PWD" 2>/dev/null || pwd -W)"
    MSYS_NO_PATHCONV=1 schtasks /Create /TN WebMonitor /TR "\"$WP\\start.bat\"" /SC ONSTART /RU SYSTEM /F \
      && ok "Scheduled task 'WebMonitor' created." \
      || warn "Failed - run Git Bash as Administrator and retry."
  fi
  echo "Windows Firewall: allow inbound TCP $PORT (Admin PowerShell):"
  echo "  New-NetFirewallRule -DisplayName WebMonitor -Direction Inbound -Protocol TCP -LocalPort $PORT -Action Allow"
  read -rp "Start the panel now? [Y/n]: " A
  [[ "${A:-Y}" =~ ^[Nn] ]] || { cmd.exe /c start "" start.bat >/dev/null 2>&1; }
fi

echo
ok "Installation finished."
[ -n "$FQDN" ] && echo "   Panel:  http://$FQDN:$PORT"
echo "   Panel:  http://$IP:$PORT"
echo "   (Make sure DNS of $FQDN points to this server.)" | { [ -n "$FQDN" ] && cat || true; }
