#!/usr/bin/env bash
# Toggle fail-safe maintenance routing for one app origin.
# Overrides: CLOUDFLARED_CONFIG, CLOUDFLARED_UNIT, MAINT_UNIT,
# MAINT_SERVICE, MAINT_APP_CONTAINER, MAINT_APP_SERVICE, MAINT_STATE,
# MAINT_HEALTH_TIMEOUT. The app service must publish only on loopback.
set -Eeuo pipefail

usage() {
  echo "Usage: $0 <on|off> <app-hostname> <tunnel-name>" >&2
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then usage; exit 0; fi
if [[ $# -ne 3 || ( $1 != "on" && $1 != "off" ) ]]; then usage; exit 2; fi

mode=$1
app_hostname=$2
tunnel_name=$3
cloudflared_config=${CLOUDFLARED_CONFIG:-"${HOME}/.cloudflared/config.yml"}
cloudflared_unit=${CLOUDFLARED_UNIT:-cloudflared}
maint_unit=${MAINT_UNIT:-maintenance}
maint_service=${MAINT_SERVICE:-http://localhost:8081}
state_file=${MAINT_STATE:-"${HOME}/.cloudflared/.maintenance-state"}
health_timeout=${MAINT_HEALTH_TIMEOUT:-120}
app_container=${MAINT_APP_CONTAINER:-}
app_service=${MAINT_APP_SERVICE:-}
on_in_progress=false

config_value() {
  local key=$1
  awk -v key="$key" '
    /^[[:space:]]*#/ { next }
    {
      line=$0; sub(/^[[:space:]-]*/, "", line)
      if (index(line, key ":") == 1) {
        sub("^" key ":[[:space:]]*", "", line); gsub(/^[\047\"]|[\047\"]$/, "", line); print line; exit
      }
    }' "$cloudflared_config"
}

service_for_host() {
  local wanted=$1
  awk -v wanted="$wanted" '
    function value(line, key) { sub(/^[[:space:]-]*/, "", line); sub("^" key ":[[:space:]]*", "", line); gsub(/^[\047\"]|[\047\"]$/, "", line); return line }
    /^[[:space:]-]*hostname:[[:space:]]*/ { matched=(value($0, "hostname") == wanted); next }
    matched && /^[[:space:]]*service:[[:space:]]*/ { print value($0, "service"); exit }
  ' "$cloudflared_config"
}

rewrite_service() {
  local from=$1 to=$2 tmp
  tmp=$(mktemp "${cloudflared_config}.tmp.XXXXXX")
  awk -v from="$from" -v to="$to" '
    function trimmed(line) { sub(/^[[:space:]]*/, "", line); sub(/^service:[[:space:]]*/, "", line); gsub(/^[\047\"]|[\047\"]$/, "", line); return line }
    /^[[:space:]]*service:[[:space:]]*/ {
      original=$0
      if (trimmed($0) == from) { match(original, /^[[:space:]]*/); print substr(original, 1, RLENGTH) "service: " to; next }
    }
    { print }
  ' "$cloudflared_config" > "$tmp"
  chmod --reference="$cloudflared_config" "$tmp"
  if ! cloudflared tunnel --config "$tmp" ingress validate >/dev/null; then rm -f "$tmp"; return 1; fi
  cp -p "$cloudflared_config" "${cloudflared_config}.bak"
  mv "$tmp" "$cloudflared_config"
}

reload_cloudflared() {
  if sudo systemctl is-active --quiet "$cloudflared_unit"; then
    sudo systemctl kill -s HUP "$cloudflared_unit"
  else
    sudo systemctl start "$cloudflared_unit"
  fi

  local deadline=$((SECONDS + 15))
  while (( SECONDS < deadline )); do
    sudo systemctl is-active --quiet "$cloudflared_unit" && return 0
    sleep 1
  done
  return 1
}

discover_container() {
  local service=$1 port candidates
  [[ $service =~ :([0-9]+)(/|$) ]] || return 1
  port=${BASH_REMATCH[1]}
  candidates=$(docker ps -a --filter "publish=$port" --format '{{.Names}}')
  [[ $(printf '%s\n' "$candidates" | sed '/^$/d' | wc -l) -eq 1 ]] || return 1
  printf '%s\n' "$candidates"
}

stop_app_best_effort() {
  [[ -n $app_container ]] && docker stop "$app_container" >/dev/null 2>&1 || true
}

fail_safe() {
  local status=$?
  if [[ $status -ne 0 && $on_in_progress == true ]]; then
    stop_app_best_effort
    echo "Maintenance enable failed; the app was stopped where identifiable. Check maintenance routing before retrying." >&2
  fi
  exit "$status"
}
trap fail_safe EXIT

[[ -r $cloudflared_config ]] || { echo "cloudflared config is not readable" >&2; exit 1; }
[[ $(config_value tunnel) == "$tunnel_name" ]] || { echo "tunnel name does not match this config" >&2; exit 1; }

if [[ $mode == on ]]; then
  on_in_progress=true
  current_service=$(service_for_host "$app_hostname")
  [[ -n $current_service ]] || { echo "hostname has no ingress rule" >&2; exit 1; }

  if [[ $current_service == "$maint_service" ]]; then
    [[ -r $state_file ]] && app_service=$(<"$state_file")
  else
    app_service=$current_service
  fi
  if [[ -z $app_container && -n $app_service ]]; then app_container=$(discover_container "$app_service" || true); fi

  sudo systemctl start "$maint_unit"
  [[ $(curl --silent --output /dev/null --write-out '%{http_code}' "$maint_service") == 503 ]] || { echo "maintenance server did not return 503" >&2; exit 1; }

  if [[ $current_service != "$maint_service" ]]; then
    mkdir -p "$(dirname "$state_file")"
    (umask 077; printf '%s\n' "$app_service" > "$state_file")
    rewrite_service "$app_service" "$maint_service"
    if grep -Fq -- "$app_service" "$cloudflared_config"; then echo "real app origin remains in ingress" >&2; exit 1; fi
    reload_cloudflared
  fi

  [[ -n $app_container ]] || { echo "app container could not be identified; stop it manually" >&2; exit 1; }
  docker stop "$app_container" >/dev/null
  [[ $(docker inspect -f '{{.State.Status}}' "$app_container") == exited ]]
  [[ $(service_for_host "$app_hostname") == "$maint_service" ]]
  on_in_progress=false
  echo "Maintenance is on for $app_hostname; ingress is black-holed and the app container is stopped."
  exit 0
fi

current_service=$(service_for_host "$app_hostname")
if [[ $current_service != "$maint_service" ]]; then
  echo "Maintenance is already off for $app_hostname."
  exit 0
fi
if [[ -z $app_service && -r $state_file ]]; then app_service=$(<"$state_file"); fi
[[ -n $app_service ]] || { echo "no saved app service; set MAINT_APP_SERVICE" >&2; exit 1; }
if [[ -z $app_container ]]; then app_container=$(discover_container "$app_service" || true); fi
[[ -n $app_container ]] || { echo "app container could not be identified; set MAINT_APP_CONTAINER" >&2; exit 1; }

docker start "$app_container" >/dev/null
deadline=$((SECONDS + health_timeout))
while (( SECONDS < deadline )); do
  health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$app_container")
  if [[ $health == healthy ]]; then break; fi
  if [[ $health == none && $app_service =~ :([0-9]+)(/|$) ]] && curl --silent --fail --output /dev/null "http://127.0.0.1:${BASH_REMATCH[1]}"; then break; fi
  sleep 2
done
if [[ $health != healthy ]]; then
  if [[ $health != none || ! $app_service =~ :([0-9]+)(/|$) ]] || ! curl --silent --fail --output /dev/null "http://127.0.0.1:${BASH_REMATCH[1]}"; then
    echo "app did not become healthy; maintenance routing remains active" >&2
    exit 1
  fi
fi

rewrite_service "$maint_service" "$app_service"
reload_cloudflared
rm -f "$state_file"
echo "Maintenance is off for $app_hostname; the healthy app is routed normally."
