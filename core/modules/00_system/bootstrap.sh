# Inisialisasi dasar
#!/usr/bin/env bash
source ../../lib/color.sh

init_system() {
  log_header "Initializing Atomic System"
  
  # Parallel package installation
  (apt-get update && apt-get full-upgrade -y) &
  (install_base_packages) &
  (setup_environment) &
  wait
  
  verify_system
}

install_base_packages() {
  declare -a packages=(
    "jq" "git" "curl" "wget"
    "build-essential" "python3-pip"
    "unzip" "htop" "nload"
  )
  
  apt-get install -y "${packages[@]}"
}

setup_environment() {
  # Setup global environment
  cat > /etc/profile.d/atomic.sh <<EOF
export ATOMIC_DEPLOY_MODE="cluster"
export DEPLOY_DIR="/opt/atomic"
export CONFIG_DIR="/etc/atomic"
EOF
}

init_system