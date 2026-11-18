#!/usr/bin/env bash
# Install / update vuln-watch on this host. Idempotent. Run: sudo ./install.sh
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root (sudo ./install.sh)"; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"
DST=/opt/vuln-watch

command -v dpkg-repack >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dpkg-repack
python3 -c 'import apt' || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-apt

mkdir -p "$DST" /etc/vuln-watch /var/lib/vuln-watch /var/backups/vuln-watch
chmod 700 /etc/vuln-watch /var/lib/vuln-watch /var/backups/vuln-watch
rsync -a --delete --exclude .git --exclude __pycache__ "$SRC/bin" "$SRC/vuln_watch" "$DST/"
chown -R root:root "$DST"; chmod -R go-w "$DST"

if [ ! -f /etc/vuln-watch/config.json ]; then
  install -m600 "$SRC/config.example.json" /etc/vuln-watch/config.json
  echo ">> edit /etc/vuln-watch/config.json and create /etc/vuln-watch/telegram.env"
fi

install -m644 "$SRC"/systemd/vuln-watch-*.service "$SRC"/systemd/vuln-watch-*.timer /etc/systemd/system/
mkdir -p /etc/systemd/system/apt-daily-upgrade.service.d
install -m644 "$SRC/systemd/apt-daily-upgrade-vuln-watch.conf" /etc/systemd/system/apt-daily-upgrade.service.d/vuln-watch.conf
systemctl daemon-reload
systemctl enable --now vuln-watch-scan.timer vuln-watch-patch.timer vuln-watch-digest.timer
systemctl enable vuln-watch-postboot.service
systemctl list-timers 'vuln-watch-*' --no-pager
