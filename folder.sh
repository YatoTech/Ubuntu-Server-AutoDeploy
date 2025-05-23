#!/bin/bash

# folder.sh - Membuat struktur direktori dan file untuk atomic deploy

# Buat file marker
touch .maintenance

# Buat struktur folder
mkdir -p core/lib
mkdir -p core/modules/00_system
mkdir -p core/modules/10_web
mkdir -p core/modules/20_container
mkdir -p core/modules/30_app
mkdir -p core/modules/40_security
mkdir -p configs/services
mkdir -p hooks/pre-install
mkdir -p hooks/post-deploy
mkdir -p artifacts

# Buat file utama dengan isi komentar sesuai fungsinya
declare -A FILES=(
  ["core/orchestrator.sh"]="# Entry point utama"
  ["core/lib/color.sh"]="# Manajemen warna terminal"
  ["core/lib/audit.sh"]="# Pencatatan perubahan sistem"
  ["core/lib/state_mgr.sh"]="# Manajemen state"
  ["core/modules/00_system/bootstrap.sh"]="# Inisialisasi dasar"
  ["core/modules/00_system/kernel.sh"]="# Optimasi kernel"
  ["core/modules/10_web/nginx.sh"]="# Reverse proxy"
  ["core/modules/10_web/certbot.sh"]="# Manajemen SSL"
  ["core/modules/20_container/docker.sh"]="# Runtime Docker"
  ["core/modules/20_container/compose.sh"]="# Docker Compose"
  ["core/modules/30_app/deploy.sh"]="# Logic deployment"
  ["core/modules/30_app/rollback.sh"]="# Sistem rollback"
  ["core/modules/40_security/firewall.sh"]="# Konfigurasi UFW"
  ["core/modules/40_security/hardening.sh"]="# Security hardening"
  ["configs/system.conf"]="# Konfigurasi sistem"
)

# Buat file dan isi komentar di dalamnya
for path in "${!FILES[@]}"; do
  echo "${FILES[$path]}" > "$path"
done

echo "Struktur direktori dan file berhasil dibuat."
