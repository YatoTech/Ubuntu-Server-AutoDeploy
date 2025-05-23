# Sistem rollback
#!/usr/bin/env bash
# core/modules/30_app/rollback.sh

rollback_system() {
  local version=${1:-$(jq -r '.last_stable' ${STATE_FILE})}
  
  log_warn "Initiating rollback to version ${version}"
  
  case $version in
    v3.*) rollback_v3 ;;
    v4.*) rollback_v4 ;;
    *)    log_error "Unsupported version"; return 1 ;;
  esac
  
  audit_sys "Rollback completed to ${version}"
}

rollback_v4() {
  # Implementasi rollback spesifik versi
  docker-compose -f ${ARTIFACTS_DIR}/v4/docker-compose.yaml down
  cp -r ${BACKUP_DIR}/v4/nginx /etc/nginx
}