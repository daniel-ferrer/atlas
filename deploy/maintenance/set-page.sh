#!/usr/bin/env bash
# Select the embedded page served by the maintenance black-hole unit.
set -Eeuo pipefail

usage() {
  echo "Usage: $0 <coming-soon|maintenance>" >&2
}

if [[ $# -ne 1 || ( $1 != "coming-soon" && $1 != "maintenance" ) ]]; then
  usage
  exit 2
fi

page=$1
drop_in=/etc/systemd/system/maintenance.service.d/page.conf
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

printf '[Service]\nEnvironment=MAINT_PAGE=%s\n' "$page" > "$tmp"
sudo install -D -m 0644 "$tmp" "$drop_in"
sudo systemctl daemon-reload
sudo systemctl restart maintenance

echo "Maintenance page set to $page."
