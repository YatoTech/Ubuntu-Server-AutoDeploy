# Reverse proxy
#!/usr/bin/env bash
source ../../lib/audit.sh

configure_nginx() {
  log_header "Configuring HyperScale Web Proxy"
  
  # Dynamic template rendering dengan envsubst
  envsubst < ${CONFIG_DIR}/templates/nginx/atomic.conf > /etc/nginx/sites-available/atomic
  
  # Zero-downtime deployment
  if nginx -t; then
    systemctl reload nginx
    audit_sys "Nginx reloaded successfully"
  else
    log_error "Nginx config test failed"
    return 1
  fi
}

# Load-balancer configuration
setup_load_balancer() {
  local upstreams=($(get_cluster_nodes))
  
  cat > ${CONFIG_DIR}/upstreams.conf <<EOF
upstream atomic_cluster {
  least_conn;
  ${upstreams[@]/#/server }
}
EOF
}

configure_nginx