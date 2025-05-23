# Entry point utama
#!/usr/bin/env bash
set -eo pipefail

# Load core libraries
source core/lib/color.sh
source core/lib/audit.sh
source core/lib/state_mgr.sh

declare -r VERSION="4.2.0"
declare -r LOCK_FILE="/tmp/atomic-deploy.lock"

# Main execution flow
main() {
  trap "emergency_cleanup" ERR SIGINT SIGTERM
  
  check_dependencies
  acquire_lock
  parse_args "$@"
  load_configs
  execute_modules
  finalize
}

acquire_lock() {
  if [ -f "$LOCK_FILE" ]; then
    log_error "Another deployment is in progress"
    exit 1
  fi
  touch "$LOCK_FILE"
  audit_sys "Lock acquired"
}

execute_modules() {
  local modules=(
    "00_system/bootstrap.sh"
    "00_system/kernel.sh"
    "10_web/nginx.sh"
    "10_web/certbot.sh"
    "20_container/docker.sh"
    "20_container/compose.sh"
    "30_app/deploy.sh"
    "40_security/firewall.sh"
    "40_security/hardening.sh"
  )

  for module in "${modules[@]}"; do
    if [[ -f "core/modules/${module}" ]]; then
      log_info "Executing module: ${module}"
      bash "core/modules/${module}" || handle_module_error "${module}"
      audit_sys "Module ${module} completed"
    fi
  done
}

finalize() {
  run_hooks "post-deploy"
  rm -f "$LOCK_FILE"
  audit_sys "Deployment completed"
  system_state_save
}

main "$@"