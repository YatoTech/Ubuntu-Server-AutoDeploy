#!/bin/bash

# Professional Auto-Deploy Server Setup Script
# Author: Yatogami
# Version: 2.0
# Description: Complete server deployment with nuclear-grade error handling

# --------------------------
# Configuration
# --------------------------
CURRENT_IP=$(hostname -I | awk '{print $1}')
DEFAULT_DOMAIN="yatogami.net"
ADMIN_USER="yato"
ADMIN_PASS="yatogamii"
DOCKER_NODE_IMAGE="node:18-alpine"
WEB_PORT=3000
NGINX_PORT=80
NGINX_SSL_PORT=443
LOG_FILE="/var/log/auto-deploy-$(date +%Y%m%d%H%M%S).log"
MAX_RETRIES=3
RETRY_DELAY=5
BACKUP_DIR="/var/backups/auto-deploy-$(date +%Y%m%d%H%M%S)"
TEMP_DIR=$(mktemp -d)

# --------------------------
# Initialization
# --------------------------
# ANSI Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging Setup
exec > >(tee -a "$LOG_FILE") 2>&1

# --------------------------
# Core Functions
# --------------------------

log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO") echo -e "${GREEN}[${timestamp}] INFO: ${message}${NC}" ;;
        "WARN") echo -e "${YELLOW}[${timestamp}] WARN: ${message}${NC}" ;;
        "ERROR") echo -e "${RED}[${timestamp}] ERROR: ${message}${NC}" ;;
        "DEBUG") echo -e "${BLUE}[${timestamp}] DEBUG: ${message}${NC}" ;;
        *) echo -e "[${timestamp}] ${message}" ;;
    esac
}

create_backup() {
    local target=$1
    log "INFO" "Creating backup of ${target}"
    mkdir -p "${BACKUP_DIR}"
    cp -r "${target}" "${BACKUP_DIR}/" || {
        log "WARN" "Failed to backup ${target}"
        return 1
    }
}

retry_command() {
    local cmd=$1
    local description=$2
    local max_retries=$MAX_RETRIES
    local retry_delay=$RETRY_DELAY
    local exit_code=0

    for ((i=1; i<=max_retries; i++)); do
        log "INFO" "Attempt ${i}/${max_retries}: ${description}"
        eval "$cmd"
        exit_code=$?
        
        if [ $exit_code -eq 0 ]; then
            log "INFO" "${description} succeeded"
            return 0
        fi
        
        if [ $i -lt $max_retries ]; then
            log "WARN" "${description} failed, retrying in ${retry_delay}s..."
            sleep $retry_delay
            retry_delay=$((retry_delay * 2)) # Exponential backoff
        fi
    done

    log "ERROR" "${description} failed after ${max_retries} attempts"
    return $exit_code
}

verify_dependency() {
    local dep=$1
    if ! command -v "$dep" &> /dev/null; then
        log "ERROR" "Missing dependency: ${dep}"
        return 1
    fi
    return 0
}

# --------------------------
# Setup Functions
# --------------------------

system_update() {
    log "INFO" "Starting system update..."
    
    retry_command "apt-get update" "Update package lists" || {
        log "WARN" "Continuing with potentially stale package lists"
    }
    
    retry_command "apt-get upgrade -y" "Upgrade packages" || {
        log "WARN" "System upgrade partially completed"
    }
    
    retry_command "apt-get dist-upgrade -y" "Distribution upgrade" || {
        log "WARN" "Distribution upgrade partially completed"
    }
    
    retry_command "apt-get autoremove -y" "Remove unused packages" || {
        log "WARN" "Could not clean all unused packages"
    }
    
    log "INFO" "System update completed"
}

install_essentials() {
    log "INFO" "Installing essential packages..."
    
    local packages=(
        curl wget git htop nano ufw fail2ban unattended-upgrades
        nginx docker.io docker-compose jq net-tools openssl
        python3-certbot-nginx apt-transport-https ca-certificates
        software-properties-common gnupg-agent
    )
    
    for pkg in "${packages[@]}"; do
        if dpkg -l | grep -q "^ii  ${pkg} "; then
            log "INFO" "Package ${pkg} already installed"
            continue
        fi
        
        retry_command "apt-get install -y ${pkg}" "Install ${pkg}" || {
            log "WARN" "Failed to install ${pkg}, trying with --fix-broken..."
            apt-get install -y --fix-broken "${pkg}" || {
                log "WARN" "Could not install ${pkg}, skipping..."
                continue
            }
        }
    done
    
    # Docker service management
    retry_command "systemctl enable docker" "Enable Docker service" || {
        log "WARN" "Could not enable Docker service"
    }
    
    retry_command "systemctl start docker" "Start Docker service" || {
        log "WARN" "Could not start Docker service"
    }
    
    log "INFO" "Essential packages installation completed"
}

setup_webapp() {
    log "INFO" "Setting up web application..."
    
    # Create directory structure
    mkdir -p webapp/{public/{css,js,uploads},views} || {
        log "ERROR" "Failed to create webapp directories"
        return 1
    }
    
    # package.json
    cat > webapp/package.json <<EOL
{
  "name": "auto-deploy-web",
  "version": "1.0.0",
  "description": "Auto Deploy Web Interface",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "body-parser": "^1.20.2",
    "dockerode": "^3.3.4",
    "dotenv": "^16.3.1",
    "ejs": "^3.1.9",
    "fs-extra": "^11.2.0",
    "multer": "^1.4.5-lts.1"
  }
}
EOL

    # server.js with enhanced error handling
    cat > webapp/server.js <<EOL
const express = require('express');
const bodyParser = require('body-parser');
const Docker = require('dockerode');
const path = require('path');
const fs = require('fs-extra');
const multer = require('multer');
require('dotenv').config();

// Initialize app
const app = express();
const docker = new Docker();

// Configure file uploads
const upload = multer({
    dest: path.join(__dirname, 'public/uploads'),
    limits: { fileSize: 100 * 1024 * 1024 } // 100MB limit
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Authentication middleware
const authenticate = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).set('WWW-Authenticate', 'Basic').send();
        }

        const [user, pass] = Buffer.from(authHeader.split(' ')[1], 'base64')
            .toString()
            .split(':');

        if (user !== process.env.ADMIN_USER || pass !== process.env.ADMIN_PASS) {
            return res.status(403).send('Forbidden');
        }

        next();
    } catch (err) {
        console.error('Authentication error:', err);
        res.status(500).send('Authentication failed');
    }
};

// Routes
app.get('/', authenticate, (req, res) => {
    res.render('index', { 
        domain: process.env.DOMAIN,
        ip: process.env.CURRENT_IP
    });
});

app.post('/deploy', authenticate, upload.single('website'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const targetPath = path.join(__dirname, 'public/deployments', req.file.originalname);
        await fs.move(req.file.path, targetPath);
        
        // Add your deployment logic here
        res.json({ 
            status: 'success',
            message: 'Deployment started',
            file: req.file.originalname
        });
    } catch (err) {
        console.error('Deployment error:', err);
        res.status(500).json({ 
            error: 'Deployment failed',
            details: err.message
        });
    }
});

// Docker API endpoints
app.get('/api/containers', authenticate, async (req, res) => {
    try {
        const containers = await docker.listContainers({ all: true });
        res.json(containers);
    } catch (err) {
        console.error('Container list error:', err);
        res.status(500).json({ error: 'Failed to list containers' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Application error:', err);
    res.status(500).send('Internal Server Error');
});

// Start server
const PORT = process.env.WEB_PORT || 3000;
app.listen(PORT, () => {
    console.log(\`Server running on port \${PORT}\`);
    console.log(\`Access at: http://localhost:\${PORT}\`);
});
EOL

    # Frontend views
    cat > webapp/views/index.ejs <<EOL
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Auto-Deploy - <%= domain %></title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>Auto-Deploy Web Interface</h1>
            <p>Server: <%= ip %></p>
        </header>
        
        <section class="deploy-section">
            <h2>Website Deployment</h2>
            <form id="deployForm" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="website">Select file to deploy:</label>
                    <input type="file" id="website" name="website" required>
                </div>
                <button type="submit">Deploy</button>
                <div id="deployStatus"></div>
            </form>
        </section>
        
        <section class="docker-section">
            <h2>Container Management</h2>
            <div class="container-controls">
                <button id="refreshContainers">Refresh</button>
            </div>
            <div id="containersList">
                <p>Loading containers...</p>
            </div>
        </section>
    </div>
    
    <script src="/js/app.js"></script>
</body>
</html>
EOL

    # CSS styling
    cat > webapp/public/css/style.css <<EOL
:root {
    --primary-color: #4285f4;
    --secondary-color: #34a853;
    --error-color: #ea4335;
    --warning-color: #fbbc05;
    --text-color: #333;
    --light-gray: #f5f5f5;
    --border-radius: 4px;
}

* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: var(--text-color);
    background-color: var(--light-gray);
    padding: 20px;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    background: white;
    padding: 30px;
    border-radius: var(--border-radius);
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

header {
    margin-bottom: 30px;
    padding-bottom: 15px;
    border-bottom: 1px solid #eee;
}

h1, h2 {
    color: var(--primary-color);
    margin-bottom: 15px;
}

.form-group {
    margin-bottom: 15px;
}

label {
    display: block;
    margin-bottom: 5px;
    font-weight: 600;
}

input[type="file"] {
    display: block;
    width: 100%;
    padding: 10px;
    border: 1px solid #ddd;
    border-radius: var(--border-radius);
    margin-bottom: 10px;
}

button {
    background-color: var(--primary-color);
    color: white;
    border: none;
    padding: 10px 20px;
    border-radius: var(--border-radius);
    cursor: pointer;
    font-size: 16px;
    transition: background-color 0.3s;
}

button:hover {
    background-color: #3367d6;
}

#containersList {
    margin-top: 20px;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}

th, td {
    padding: 12px 15px;
    text-align: left;
    border-bottom: 1px solid #ddd;
}

th {
    background-color: var(--light-gray);
    font-weight: 600;
}

tr:hover {
    background-color: rgba(66, 133, 244, 0.05);
}

.status-running {
    color: var(--secondary-color);
}

.status-stopped {
    color: var(--error-color);
}

#deployStatus {
    margin-top: 15px;
    padding: 10px;
    border-radius: var(--border-radius);
}

.success-message {
    background-color: rgba(52, 168, 83, 0.1);
    color: var(--secondary-color);
    border: 1px solid var(--secondary-color);
}

.error-message {
    background-color: rgba(234, 67, 53, 0.1);
    color: var(--error-color);
    border: 1px solid var(--error-color);
}
EOL

    # JavaScript with enhanced error handling
    cat > webapp/public/js/app.js <<EOL
document.addEventListener('DOMContentLoaded', () => {
    // DOM elements
    const deployForm = document.getElementById('deployForm');
    const deployStatus = document.getElementById('deployStatus');
    const containersList = document.getElementById('containersList');
    const refreshBtn = document.getElementById('refreshContainers');
    
    // Load containers on page load
    loadContainers();
    
    // Setup form submission
    deployForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = new FormData(deployForm);
        deployStatus.textContent = 'Uploading...';
        deployStatus.className = '';
        
        try {
            const response = await fetch('/deploy', {
                method: 'POST',
                body: formData,
                headers: {
                    'Authorization': 'Basic ' + btoa('${ADMIN_USER}:${ADMIN_PASS}')
                }
            });
            
            const result = await response.json();
            
            if (response.ok) {
                deployStatus.textContent = 'Success: ' + result.message;
                deployStatus.className = 'success-message';
            } else {
                throw new Error(result.error || 'Deployment failed');
            }
        } catch (error) {
            console.error('Deployment error:', error);
            deployStatus.textContent = 'Error: ' + error.message;
            deployStatus.className = 'error-message';
        }
    });
    
    // Setup refresh button
    refreshBtn.addEventListener('click', loadContainers);
    
    // Container management functions
    async function loadContainers() {
        containersList.innerHTML = '<p>Loading containers...</p>';
        
        try {
            const response = await fetch('/api/containers', {
                headers: {
                    'Authorization': 'Basic ' + btoa('${ADMIN_USER}:${ADMIN_PASS}')
                }
            });
            
            const containers = await response.json();
            
            if (!response.ok) {
                throw new Error(containers.error || 'Failed to load containers');
            }
            
            if (containers.length === 0) {
                containersList.innerHTML = '<p>No containers running</p>';
                return;
            }
            
            containersList.innerHTML = \`
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Name</th>
                            <th>Image</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        \${containers.map(container => \`
                            <tr>
                                <td>\${container.Id.substring(0, 12)}</td>
                                <td>\${container.Names[0].replace('/', '')}</td>
                                <td>\${container.Image}</td>
                                <td class="status-\${container.State.toLowerCase()}">\${container.State}</td>
                                <td>
                                    \${container.State === 'running' 
                                        ? '<button onclick="stopContainer(\`\${container.Id}\`)">Stop</button>'
                                        : '<button onclick="startContainer(\`\${container.Id}\`)">Start</button>'
                                    }
                                </td>
                            </tr>
                        \`).join('')}
                    </tbody>
                </table>
            \`;
        } catch (error) {
            console.error('Error loading containers:', error);
            containersList.innerHTML = \`
                <div class="error-message">
                    Error loading containers: \${error.message}
                </div>
            \`;
        }
    }
});

// Global container control functions
async function startContainer(containerId) {
    try {
        const response = await fetch(\`/api/containers/\${containerId}/start\`, {
            method: 'POST',
            headers: {
                'Authorization': 'Basic ' + btoa('${ADMIN_USER}:${ADMIN_PASS}')
            }
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to start container');
        }
        
        // Reload the container list
        document.getElementById('refreshContainers').click();
    } catch (error) {
        console.error('Error starting container:', error);
        alert('Error starting container: ' + error.message);
    }
}

async function stopContainer(containerId) {
    try {
        const response = await fetch(\`/api/containers/\${containerId}/stop\`, {
            method: 'POST',
            headers: {
                'Authorization': 'Basic ' + btoa('${ADMIN_USER}:${ADMIN_PASS}')
            }
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to stop container');
        }
        
        // Reload the container list
        document.getElementById('refreshContainers').click();
    } catch (error) {
        console.error('Error stopping container:', error);
        alert('Error stopping container: ' + error.message);
    }
}
EOL

    log "INFO" "Web application setup completed"
}

setup_docker() {
    log "INFO" "Configuring Docker..."
    
    create_backup "/etc/docker/daemon.json" || {
        log "WARN" "Could not backup Docker config"
    }
    
    # Dockerfile
    cat > Dockerfile <<EOL
FROM ${DOCKER_NODE_IMAGE}
WORKDIR /app
COPY webapp/package*.json ./
RUN npm install --production --no-optional
COPY webapp .
EXPOSE ${WEB_PORT}
HEALTHCHECK --interval=30s --timeout=3s \\
    CMD curl -f http://localhost:${WEB_PORT}/ || exit 1
CMD ["node", "server.js"]
EOL

    # docker-compose.yml with resource limits
    cat > docker-compose.yml <<EOL
version: '3.8'
services:
  webapp:
    build: .
    container_name: auto-deploy-web
    restart: unless-stopped
    ports:
      - "${WEB_PORT}:${WEB_PORT}"
    environment:
      - ADMIN_USER=\${ADMIN_USER}
      - ADMIN_PASS=\${ADMIN_PASS}
      - DOMAIN=\${DOMAIN}
      - WEB_PORT=\${WEB_PORT}
      - CURRENT_IP=\${CURRENT_IP}
    volumes:
      - ./webapp:/app
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      - deploy-network
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          memory: 256M

networks:
  deploy-network:
    driver: bridge
EOL

    # Control script with enhanced functionality
    cat > docker.sh <<EOL
#!/bin/bash
ACTION=\$1
ENV_FILE=".env"

# Load environment variables
if [ -f "\$ENV_FILE" ]; then
    export \$(grep -v '^#' \$ENV_FILE | xargs)
fi

case \$ACTION in
    start)
        docker-compose up -d --build
        ;;
    stop)
        docker-compose down
        ;;
    restart)
        docker-compose restart
        ;;
    status)
        echo "=== Docker Containers ==="
        docker-compose ps
        echo "=== System Resources ==="
        docker stats --no-stream
        ;;
    logs)
        docker-compose logs -f --tail=100
        ;;
    update)
        git pull origin master
        docker-compose build --no-cache
        docker-compose up -d
        ;;
    backup)
        BACKUP_DIR="backups/\$(date +%Y%m%d%H%M%S)"
        mkdir -p "\$BACKUP_DIR"
        docker-compose exec webapp tar czf /tmp/backup.tar.gz /app
        docker cp \$(docker-compose ps -q webapp):/tmp/backup.tar.gz "\$BACKUP_DIR/backup.tar.gz"
        echo "Backup created in \$BACKUP_DIR/backup.tar.gz"
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart|status|logs|update|backup}"
        exit 1
        ;;
esac
EOL

    chmod +x docker.sh
    log "INFO" "Docker configuration completed"
}

setup_nginx() {
    log "INFO" "Configuring Nginx reverse proxy..."
    
    create_backup "/etc/nginx" || {
        log "WARN" "Could not backup Nginx config"
    }
    
    # Create Nginx config with multiple optimizations
    cat > /etc/nginx/sites-available/${DEFAULT_DOMAIN} <<EOL
# HTTP to HTTPS redirect
server {
    listen ${NGINX_PORT};
    listen [::]:${NGINX_PORT};
    server_name ${DEFAULT_DOMAIN} www.${DEFAULT_DOMAIN};
    return 301 https://\$host\$request_uri;
}

# Main HTTPS server
server {
    listen ${NGINX_SSL_PORT} ssl http2;
    listen [::]:${NGINX_SSL_PORT} ssl http2;
    server_name ${DEFAULT_DOMAIN} www.${DEFAULT_DOMAIN};

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/${DEFAULT_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DEFAULT_DOMAIN}/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/${DEFAULT_DOMAIN}/chain.pem;
    
    # SSL Optimization
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;" always;
    
    # Proxy configuration
    location / {
        proxy_pass http://localhost:${WEB_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Static file caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)\$ {
        expires 30d;
        add_header Cache-Control "public, no-transform";
        try_files \$uri \$uri/ =404;
    }
    
    # Disable access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    # Error pages
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root /usr/share/nginx/html;
    }
}
EOL

    # Enable site
    ln -sf "/etc/nginx/sites-available/${DEFAULT_DOMAIN}" "/etc/nginx/sites-enabled/" || {
        log "ERROR" "Failed to enable Nginx site"
        return 1
    }
    
    # Test configuration
    if ! nginx -t; then
        log "ERROR" "Nginx configuration test failed"
        return 1
    fi
    
    # Restart Nginx
    systemctl restart nginx || {
        log "ERROR" "Failed to restart Nginx"
        return 1
    }
    
    log "INFO" "Nginx configuration completed"
}

setup_ssl() {
    log "INFO" "Setting up SSL certificates..."
    
    # Check if domain resolves to server IP
    local domain_check=""
    read -p "Does ${DEFAULT_DOMAIN} point to ${CURRENT_IP}? (y/n): " domain_check
    
    if [ "$domain_check" != "y" ]; then
        log "WARN" "SSL setup skipped - domain not configured"
        return 0
    fi
    
    # Stop Nginx temporarily for certbot
    systemctl stop nginx || {
        log "WARN" "Could not stop Nginx, attempting SSL setup anyway"
    }
    
    # Obtain certificate
    if certbot certonly --standalone \
        -d "${DEFAULT_DOMAIN}" \
        -d "www.${DEFAULT_DOMAIN}" \
        --non-interactive \
        --agree-tos \
        --email "admin@${DEFAULT_DOMAIN}" \
        --preferred-challenges http; then
        
        log "INFO" "SSL certificate obtained successfully"
    else
        log "ERROR" "Failed to obtain SSL certificate"
        return 1
    fi
    
    # Restart Nginx
    systemctl start nginx || {
        log "ERROR" "Failed to restart Nginx after SSL setup"
        return 1
    }
    
    # Setup auto-renewal
    (crontab -l 2>/dev/null; echo "0 3 * * * /usr/bin/certbot renew --quiet --post-hook 'systemctl reload nginx'") | crontab - || {
        log "WARN" "Could not setup SSL auto-renewal"
    }
    
    log "INFO" "SSL setup completed"
}

setup_firewall() {
    log "INFO" "Configuring firewall..."
    
    # Enable UFW if not already enabled
    if ! ufw status | grep -q "Status: active"; then
        ufw --force enable || {
            log "ERROR" "Failed to enable UFW"
            return 1
        }
    fi
    
    # Configure rules
    ufw allow OpenSSH || {
        log "WARN" "Could not allow OpenSSH through firewall"
    }
    
    ufw allow 'Nginx Full' || {
        log "WARN" "Could not allow Nginx through firewall"
    }
    
    log "INFO" "Firewall configuration completed"
}

system_optimization() {
    log "INFO" "Optimizing system settings..."
    
    # Kernel tuning
    cat >> /etc/sysctl.conf <<EOL
# File watchers for Node.js
fs.inotify.max_user_watches=524288

# Network performance
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=65535
net.ipv4.tcp_tw_reuse=1
net.ipv4.ip_local_port_range=1024 65535

# Memory management
vm.swappiness=10
vm.overcommit_memory=1
EOL
    
    # Apply settings
    sysctl -p || {
        log "WARN" "Could not apply all kernel optimizations"
    }
    
    # Configure automatic updates
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOL
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOL
    
    # Security hardening
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    
    systemctl restart sshd || {
        log "WARN" "Could not restart SSH service"
    }
    
    log "INFO" "System optimization completed"
}

# --------------------------
# Main Execution
# --------------------------

main() {
    log "INFO" "Starting Auto-Deploy Server Setup"
    log "INFO" "Log file: ${LOG_FILE}"
    log "INFO" "Backup directory: ${BACKUP_DIR}"
    
    # Create backup directory
    mkdir -p "${BACKUP_DIR}" || {
        log "WARN" "Could not create backup directory"
    }
    
    # Setup steps with error handling
    local setup_steps=(
        system_update
        install_essentials
        setup_webapp
        setup_docker
        setup_nginx
        setup_ssl
        setup_firewall
        system_optimization
    )
    
    for step in "${setup_steps[@]}"; do
        if ! $step; then
            log "WARN" "Step ${step} encountered errors - continuing with setup"
        fi
    done
    
    # Final status
    log "INFO" "Setup completed with status:"
    echo "----------------------------------------"
    echo " Web Application URL: http://${CURRENT_IP}:${WEB_PORT}"
    echo " Admin Credentials: ${ADMIN_USER}/${ADMIN_PASS}"
    echo " Control Script: ./docker.sh {start|stop|restart|status|logs}"
    echo "----------------------------------------"
    
    # Start services
    ./docker.sh start
}

# Start main execution
main
