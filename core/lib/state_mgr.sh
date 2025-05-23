# Manajemen state
#!/usr/bin/env bash
declare -r STATE_FILE="/var/lib/atomic/state.json"

system_state_load() {
  if [[ -f "$STATE_FILE" ]]; then
    jq -r '.' "$STATE_FILE"
  else
    echo '{}'
  fi
}

system_state_save() {
  local state=$(cat <<EOF
{
  "timestamp": "$(date +%s)",
  "version": "${VERSION}",
  "services": $(service_state_report)
}
EOF
  )
  echo "$state" > "$STATE_FILE"
}

service_state_report() {
  systemctl list-units --type=service --no-pager \
    | awk '{print $1,$3,$4}' \
    | jq -R -s -c 'split("\n") | map(select(. != "")) | map(split(" ")) | map({service: .[0], status: .[1], preset: .[2]})'
}