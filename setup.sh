#!/bin/bash

# Ultimate Auto-Deploy Server Setup with Nuclear-Grade Error Handling
# Author: Yatogami
# Version: 3.0
# Description: Enterprise-grade deployment system with self-healing capabilities

# --------------------------
# Global Configuration
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
MAX_RETRIES=5
RETRY_DELAY=10
BACKUP_DIR="/var/backups/auto-deploy-$(date +%Y%m%d%H%M%S)"
TEMP_DIR=$(mktemp -d)
DEPENDENCIES=(
    curl wget git htop nano ufw fail2ban unattended-upgrades
    nginx docker.io docker-compose jq net-tools openssl
    python3-certbot-nginx apt-transport-https ca-certificates
    software-properties-common gnupg-agent
)

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
        "CRITICAL") echo -e "${MAGENTA}[${timestamp}] CRITICAL: ${message}${NC}" ;;
        *) echo -e "[${timestamp}] ${message}" ;;
    esac
}

create_backup() {
    local target=$1
    log "INFO" "Creating backup of ${target}"
    mkdir -p "${BACKUP_DIR}"
    
    if [ -d "$target" ] || [ -f "$target" ]; then
        cp -r "${target}" "${BACKUP_DIR}/" || {
            log "WARN" "Failed to backup ${target}"
            return 1
        }
    else
        log "DEBUG" "Backup target ${target} does not exist"
        return 2
    fi
}

retry_command() {
    local cmd=$1
    local description=$2
    local max_retries=${3:-$MAX_RETRIES}
    local retry_delay=${4:-$RETRY_DELAY}
    local exit_code=0
    local attempt=1

    while [ $attempt -le $max_retries ]; do
        log "INFO" "Attempt ${attempt}/${max_retries}: ${description}"
        
        # Execute command with error capture
        eval "$cmd" 2>&1
        exit_code=$?
        
        if [ $exit_code -eq 0 ]; then
            log "INFO" "${description} succeeded"
            return 0
        fi
        
        if [ $attempt -lt $max_retries ]; then
            log "WARN" "${description} failed (Code: ${exit_code}), retrying in ${retry_delay}s..."
            sleep $retry_delay
            retry_delay=$((retry_delay * 2)) # Exponential backoff
        fi
        
        attempt=$((attempt + 1))
    done

    log "ERROR" "${description} failed after ${max_retries} attempts"
    return $exit_code
}

verify_dependency() {
    local dep=$1
    if ! command -v "$dep" &> /dev/null; then
        log "WARN" "Missing dependency: ${dep}"
        return 1
    fi
    return 0
}

emergency_cleanup() {
    log "CRITICAL" "Initiating emergency cleanup..."
    
    # Stop all containers
    docker ps -aq | xargs -r docker stop || log "WARN" "Failed to stop containers"
    
    # Restore Nginx config if backup exists
    if [ -d "${BACKUP_DIR}/nginx" ]; then
        log "INFO" "Restoring Nginx configuration"
        rm -rf /etc/nginx/*
        cp -r "${BACKUP_DIR}/nginx"/* /etc/nginx/ || log "WARN" "Failed to restore Nginx config"
    fi
    
    # Restart services
    systemctl restart nginx || log "WARN" "Failed to restart Nginx"
    systemctl restart docker || log "WARN" "Failed to restart Docker"
    
    log "CRITICAL" "Emergency cleanup completed"
    exit 1
}

# --------------------------
# Setup Functions with Enhanced Error Handling
# --------------------------

system_update() {
    log "INFO" "Starting system update..."
    
    local update_cmds=(
        "apt-get update"
        "apt-get upgrade -y"
        "apt-get dist-upgrade -y"
        "apt-get autoremove -y"
    )
    
    for cmd in "${update_cmds[@]}"; do
        retry_command "$cmd" "System update step: $cmd" 3 5 || {
            log "WARN" "System update partially completed"
            return 1
        }
    done
    
    log "INFO" "System update completed"
    return 0
}

install_essentials() {
    log "INFO" "Installing essential packages..."
    
    # First attempt with all packages
    if ! retry_command "apt-get install -y ${DEPENDENCIES[*]}" "Install all packages"; then
        log "WARN" "Bulk installation failed, trying individual packages..."
        
        # Install packages one by one
        for pkg in "${DEPENDENCIES[@]}"; do
            if dpkg -l | grep -q "^ii  ${pkg} "; then
                log "DEBUG" "Package ${pkg} already installed"
                continue
            fi
            
            if ! retry_command "apt-get install -y ${pkg}" "Install ${pkg}" 2 5; then
                log "WARN" "Failed to install ${pkg}, trying with --fix-broken..."
                apt-get install -y --fix-broken "${pkg}" || {
                    log "ERROR" "Critical failure installing ${pkg}"
                    emergency_cleanup
                }
            fi
        done
    fi
    
    # Docker service management with multiple fallbacks
    if ! systemctl is-active --quiet docker; then
        log "INFO" "Configuring Docker service..."
        
        if ! retry_command "systemctl enable docker" "Enable Docker service"; then
            log "WARN" "Standard enable failed, trying alternative method..."
            systemctl unmask docker
            systemctl enable docker || {
                log "ERROR" "Cannot enable Docker service"
                emergency_cleanup
            }
        fi
        
        if ! retry_command "systemctl start docker" "Start Docker service"; then
            log "WARN" "Standard start failed, trying alternative method..."
            systemctl daemon-reload
            systemctl restart docker || {
                log "ERROR" "Cannot start Docker service"
                emergency_cleanup
            }
        fi
    fi
    
    log "INFO" "Essential packages installation completed"
    return 0
}

setup_webapp() {
    log "INFO" "Setting up web application..."
    
    # Create directory structure with validation
    local dirs=(
        "webapp"
        "webapp/public"
        "webapp/public/css"
        "webapp/public/js"
        "webapp/public/uploads"
        "webapp/views"
    )
    
    for dir in "${dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir" || {
                log "ERROR" "Failed to create directory: ${dir}"
                emergency_cleanup
            }
        fi
    done
    
    # Generate package.json with validation
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

    [ -s "webapp/package.json" ] || {
        log "ERROR" "Failed to create package.json"
        emergency_cleanup
    }

    # Generate server.js with enhanced error handling
    cat > webapp/server.js <<EOL
const express = require('express');
const bodyParser = require('body-parser');
const Docker = require('dockerode');
const path = require('path');
const fs = require('fs-extra');
const multer = require('multer');
require('dotenv').config();

// Initialize app with enhanced error handling
const app = express();
const docker = new Docker({
    socketPath: '/var/run/docker.sock',
    timeout: 3000
});

// Configure file uploads with limits
const upload = multer({
    dest: path.join(__dirname, 'public/uploads'),
    limits: {
        fileSize: 100 * 1024 * 1024, // 100MB
        files: 1
    }
});

// Middleware with error handling
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Enhanced authentication middleware
const authenticate = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            res.set('WWW-Authenticate', 'Basic realm="Authorization Required"');
            return res.status(401).json({ error: 'Authentication required' });
        }

        const credentials = Buffer.from(authHeader.split(' ')[1], 'base64')
            .toString()
            .split(':');

        if (credentials.length !== 2 || 
            credentials[0] !== process.env.ADMIN_USER || 
            credentials[1] !== process.env.ADMIN_PASS) {
            return res.status(403).json({ error: 'Invalid credentials' });
        }

        next();
    } catch (err) {
        console.error('Authentication error:', err);
        res.status(500).json({ error: 'Authentication processing failed' });
    }
};

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'healthy',
        timestamp: new Date().toISOString()
    });
});

// Main application routes
app.get('/', authenticate, (req, res) => {
    try {
        res.render('index', { 
            domain: process.env.DOMAIN,
            ip: process.env.CURRENT_IP,
            version: '1.0.0'
        });
    } catch (err) {
        console.error('Render error:', err);
        res.status(500).send('Internal Server Error');
    }
});

// File upload endpoint with validation
app.post('/deploy', authenticate, upload.single('website'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // Validate file extension
        const allowedExtensions = ['.zip', '.tar', '.gz'];
        const fileExt = path.extname(req.file.originalname).toLowerCase();
        
        if (!allowedExtensions.includes(fileExt)) {
            await fs.remove(req.file.path);
            return res.status(400).json({ error: 'Invalid file type' });
        }

        const targetDir = path.join(__dirname, 'public/deployments');
        await fs.ensureDir(targetDir);
        
        const targetPath = path.join(targetDir, req.file.originalname);
        await fs.move(req.file.path, targetPath);
        
        res.json({ 
            status: 'success',
            message: 'Deployment started',
            file: req.file.originalname,
            size: req.file.size
        });
    } catch (err) {
        console.error('Deployment error:', err);
        
        // Cleanup failed upload
        if (req.file && req.file.path) {
            await fs.remove(req.file.path).catch(e => console.error('Cleanup error:', e));
        }
        
        res.status(500).json({ 
            error: 'Deployment failed',
            details: err.message
        });
    }
});

// Docker API endpoints with timeout
app.get('/api/containers', authenticate, async (req, res) => {
    try {
        const containers = await Promise.race([
            docker.listContainers({ all: true }),
            new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Timeout')), 5000))
        ]);
        res.json(containers);
    } catch (err) {
        console.error('Container list error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Application error:', err.stack);
    res.status(500).json({ error: 'Internal Server Error' });
});

// Start server with port validation
const PORT = parseInt(process.env.WEB_PORT) || 3000;
if (isNaN(PORT) {
    console.error('Invalid port number');
    process.exit(1);
}

app.listen(PORT, () => {
    console.log(\`Server running on port \${PORT}\`);
    console.log(\`Access at: http://localhost:\${PORT}\`);
}).on('error', (err) => {
    console.error('Server startup error:', err);
    process.exit(1);
});
EOL

    [ -s "webapp/server.js" ] || {
        log "ERROR" "Failed to create server.js"
        emergency_cleanup
    }

    # Generate frontend files
    generate_frontend_files
    
    log "INFO" "Web application setup completed"
    return 0
}

generate_frontend_files() {
    # Generate index.ejs
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
        <header class="header">
            <h1>Auto-Deploy Web Interface</h1>
            <div class="server-info">
                <span class="info-label">Server:</span>
                <span class="info-value"><%= ip %></span>
                <span class="info-label">Version:</span>
                <span class="info-value"><%= version %></span>
            </div>
        </header>
        
        <section class="deploy-section">
            <h2>Website Deployment</h2>
            <form id="deployForm" class="deploy-form" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="website">Select deployment package:</label>
                    <input type="file" id="website" name="website" accept=".zip,.tar,.gz" required>
                    <div class="file-info" id="fileInfo"></div>
                </div>
                <button type="submit" class="btn btn-primary" id="deployButton">
                    <span class="btn-text">Deploy</span>
                    <span class="spinner hidden" id="spinner"></span>
                </button>
                <div class="status-message" id="deployStatus"></div>
            </form>
        </section>
        
        <section class="docker-section">
            <div class="section-header">
                <h2>Container Management</h2>
                <button class="btn btn-secondary" id="refreshContainers">
                    <i class="refresh-icon">↻</i> Refresh
                </button>
            </div>
            <div class="container-list" id="containersList">
                <div class="loading-state">
                    <div class="spinner"></div>
                    <p>Loading containers...</p>
                </div>
            </div>
        </section>
    </div>
    
    <script src="/js/app.js"></script>
</body>
</html>
EOL

    # Generate CSS
    cat > webapp/public/css/style.css <<EOL
:root {
    --primary-color: #4285f4;
    --secondary-color: #34a853;
    --error-color: #ea4335;
    --warning-color: #fbbc05;
    --text-color: #333;
    --light-gray: #f5f5f5;
    --dark-gray: #333;
    --border-radius: 4px;
    --box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
    --transition: all 0.3s ease;
}

* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

body {
    background-color: #f9f9f9;
    color: var(--text-color);
    line-height: 1.6;
    padding: 20px;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    background: white;
    padding: 30px;
    border-radius: var(--border-radius);
    box-shadow: var(--box-shadow);
}

.header {
    margin-bottom: 30px;
    padding-bottom: 15px;
    border-bottom: 1px solid #eee;
}

.server-info {
    display: flex;
    gap: 20px;
    margin-top: 10px;
    font-size: 0.9rem;
    color: #666;
}

.info-label {
    font-weight: 600;
}

.info-value {
    font-family: monospace;
}

.deploy-form {
    margin-top: 20px;
}

.form-group {
    margin-bottom: 20px;
}

label {
    display: block;
    margin-bottom: 8px;
    font-weight: 600;
}

input[type="file"] {
    display: none;
}

.file-info {
    margin-top: 10px;
    padding: 10px;
    border: 1px dashed #ddd;
    border-radius: var(--border-radius);
    background-color: var(--light-gray);
}

.btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 10px 20px;
    border: none;
    border-radius: var(--border-radius);
    font-size: 16px;
    font-weight: 500;
    cursor: pointer;
    transition: var(--transition);
}

.btn-primary {
    background-color: var(--primary-color);
    color: white;
}

.btn-primary:hover {
    background-color: #3367d6;
}

.btn-secondary {
    background-color: var(--light-gray);
    color: var(--text-color);
}

.btn-secondary:hover {
    background-color: #e0e0e0;
}

.spinner {
    display: inline-block;
    width: 16px;
    height: 16px;
    border: 3px solid rgba(255, 255, 255, 0.3);
    border-radius: 50%;
    border-top-color: white;
    animation: spin 1s ease-in-out infinite;
    margin-left: 10px;
}

@keyframes spin {
    to { transform: rotate(360deg); }
}

.hidden {
    display: none;
}

.status-message {
    margin-top: 15px;
    padding: 12px;
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

.section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 15px;
}

.container-list {
    margin-top: 20px;
}

.loading-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 30px;
}

.loading-state .spinner {
    width: 40px;
    height: 40px;
    border-width: 4px;
    margin-bottom: 15px;
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

.action-btn {
    padding: 5px 10px;
    font-size: 14px;
    margin-right: 5px;
}

.refresh-icon {
    margin-right: 5px;
}

@media (max-width: 768px) {
    .container {
        padding: 15px;
    }
    
    .server-info {
        flex-direction: column;
        gap: 5px;
    }
    
    th, td {
        padding: 8px 10px;
    }
}
EOL

    # Generate JavaScript
    cat > webapp/public/js/app.js <<EOL
document.addEventListener('DOMContentLoaded', () => {
    // DOM elements
    const deployForm = document.getElementById('deployForm');
    const fileInput = document.getElementById('website');
    const fileInfo = document.getElementById('fileInfo');
    const deployButton = document.getElementById('deployButton');
    const btnText = document.querySelector('.btn-text');
    const spinner = document.getElementById('spinner');
    const deployStatus = document.getElementById('deployStatus');
    const containersList = document.getElementById('containersList');
    const refreshBtn = document.getElementById('refreshContainers');
    
    // File input handler
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            const file = e.target.files[0];
            fileInfo.innerHTML = \`
                <strong>Selected file:</strong> \${file.name}<br>
                <strong>Size:</strong> \${formatFileSize(file.size)}
            \`;
        } else {
            fileInfo.innerHTML = 'No file selected';
        }
    });
    
    // Form submission handler
    deployForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = new FormData(deployForm);
        if (!formData.get('website')) {
            showStatus('Please select a file first', 'error');
            return;
        }
        
        // UI updates
        btnText.textContent = 'Deploying...';
        spinner.classList.remove('hidden');
        deployButton.disabled = true;
        showStatus('Uploading file...', 'info');
        
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
                showStatus(\`Success: \${result.message}\`, 'success');
                fileInput.value = '';
                fileInfo.innerHTML = '';
            } else {
                throw new Error(result.error || 'Deployment failed');
            }
        } catch (error) {
            console.error('Deployment error:', error);
            showStatus(\`Error: \${error.message}\`, 'error');
        } finally {
            btnText.textContent = 'Deploy';
            spinner.classList.add('hidden');
            deployButton.disabled = false;
        }
    });
    
    // Load containers on page load
    loadContainers();
    
    // Refresh button handler
    refreshBtn.addEventListener('click', loadContainers);
    
    // Helper functions
    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    function showStatus(message, type) {
        deployStatus.textContent = message;
        deployStatus.className = 'status-message';
        
        switch (type) {
            case 'success':
                deployStatus.classList.add('success-message');
                break;
            case 'error':
                deployStatus.classList.add('error-message');
                break;
            default:
                deployStatus.style.color = 'inherit';
        }
    }
    
    async function loadContainers() {
        containersList.innerHTML = \`
            <div class="loading-state">
                <div class="spinner"></div>
                <p>Loading containers...</p>
            </div>
        \`;
        
        try {
            const response = await fetch('/api/containers', {
                headers: {
                    'Authorization': 'Basic ' + btoa('${ADMIN_USER}:${ADMIN_PASS}')
                }
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to load containers');
            }
            
            const containers = await response.json();
            
            if (containers.length === 0) {
                containersList.innerHTML = '<p>No containers running</p>';
                return;
            }
            
            containersList.innerHTML = \`
                <div class="table-responsive">
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
                                    <td class="status-\${container.State.toLowerCase()}">
                                        \${container.State}
                                    </td>
                                    <td>
                                        \${container.State === 'running' 
                                            ? '<button class="action-btn" onclick="stopContainer(\`\${container.Id}\`)">Stop</button>'
                                            : '<button class="action-btn" onclick="startContainer(\`\${container.Id}\`)">Start</button>'
                                        }
                                    </td>
                                </tr>
                            \`).join('')}
                        </tbody>
                    </table>
                </div>
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
}

setup_docker() {
    log "INFO" "Configuring Docker environment..."
    
    create_backup "/etc/docker" || {
        log "WARN" "Could not backup Docker configuration"
    }
    
    # Generate Dockerfile with health checks
    cat > Dockerfile <<EOL
FROM ${DOCKER_NODE_IMAGE}
WORKDIR /app

# Install curl for health checks
RUN apk add --no-cache curl

COPY webapp/package*.json ./
RUN npm install --production --no-optional --quiet

COPY webapp .

# Health check with timeout
HEALTHCHECK --interval=30s --timeout=3s \\
    CMD curl -f http://localhost:${WEB_PORT}/health || exit 1

EXPOSE ${WEB_PORT}
USER node
CMD ["node", "server.js"]
EOL

    [ -s "Dockerfile" ] || {
        log "ERROR" "Failed to create Dockerfile"
        emergency_cleanup
    }

    # Generate docker-compose.yml with resource limits
    cat > docker-compose.yml <<EOL
version: '3.8'

services:
  webapp:
    build:
      context: .
      dockerfile: Dockerfile
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
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:${WEB_PORT}/health"]
      interval: 30s
      timeout: 5s
      retries: 3

networks:
  deploy-network:
    driver: bridge
    name: auto-deploy-network
EOL

    [ -s "docker-compose.yml" ] || {
        log "ERROR" "Failed to create docker-compose.yml"
        emergency_cleanup
    }

    # Generate control script with backup functionality
    cat > docker.sh <<EOL
#!/bin/bash

ACTION=\$1
ENV_FILE=".env"

# Load environment variables
if [ -f "\$ENV_FILE" ]; then
    export \$(grep -v '^#' \$ENV_FILE | xargs)
fi

# Docker compose command with buildx if available
DOCKER_COMPOSE_CMD="docker-compose"
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker-compose"
elif docker compose version &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker compose"
else
    echo "Error: No docker-compose command found"
    exit 1
fi

case \$ACTION in
    start)
        \$DOCKER_COMPOSE_CMD up -d --build
        ;;
    stop)
        \$DOCKER_COMPOSE_CMD down
        ;;
    restart)
        \$DOCKER_COMPOSE_CMD restart
        ;;
    status)
        echo "=== Docker Containers ==="
        \$DOCKER_COMPOSE_CMD ps
        echo "=== System Resources ==="
        docker stats --no-stream
        echo "=== Health Status ==="
        \$DOCKER_COMPOSE_CMD ps | awk 'NR>1 {print \$1}' | xargs -I {} docker inspect --format '{{.Name}} - {{.State.Health.Status}}' {}
        ;;
    logs)
        \$DOCKER_COMPOSE_CMD logs -f --tail=100
        ;;
    update)
        git pull origin master
        \$DOCKER_COMPOSE_CMD build --no-cache
        \$DOCKER_COMPOSE_CMD up -d
        ;;
    backup)
        TIMESTAMP=\$(date +%Y%m%d%H%M%S)
        BACKUP_DIR="backups/\$TIMESTAMP"
        mkdir -p "\$BACKUP_DIR"
        
        # Backup application data
        \$DOCKER_COMPOSE_CMD exec -T webapp tar czf /tmp/app_backup.tar.gz /app
        docker cp \$(\$DOCKER_COMPOSE_CMD ps -q webapp):/tmp/app_backup.tar.gz "\$BACKUP_DIR/app_backup.tar.gz"
        
        # Backup database if exists
        if \$DOCKER_COMPOSE_CMD ps -q db &> /dev/null; then
            \$DOCKER_COMPOSE_CMD exec -T db sh -c 'mysqldump -u\$MYSQL_USER -p\$MYSQL_PASSWORD \$MYSQL_DATABASE' > "\$BACKUP_DIR/db_backup.sql"
        fi
        
        # Backup configuration
        tar czf "\$BACKUP_DIR/config_backup.tar.gz" .env docker-compose.yml
        
        echo "Backup created in \$BACKUP_DIR"
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart|status|logs|update|backup}"
        exit 1
        ;;
esac
EOL

    chmod +x docker.sh || {
        log "ERROR" "Failed to make docker.sh executable"
        emergency_cleanup
    }

    log "INFO" "Docker configuration completed"
    return 0
}

setup_nginx() {
    log "INFO" "Configuring Nginx reverse proxy..."
    
    create_backup "/etc/nginx" || {
        log "ERROR" "Failed to backup Nginx configuration"
        emergency_cleanup
    }
    
    # Generate Nginx configuration with multiple optimizations
    cat > /etc/nginx/sites-available/${DEFAULT_DOMAIN} <<EOL
# HTTP to HTTPS redirect
server {
    listen ${NGINX_PORT} default_server;
    listen [::]:${NGINX_PORT} default_server;
    server_name _;
    return 301 https://\$host\$request_uri;
}

# Main HTTPS server
server {
    listen ${NGINX_SSL_PORT} ssl http2;
    listen [::]:${NGINX_SSL_PORT} ssl http2;
    server_name ${DEFAULT_DOMAIN} www.${DEFAULT_DOMAIN};

    # SSL Configuration - Will be managed by Certbot
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
    ssl_dhparam /etc/nginx/dhparam.pem;
    
    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    
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
    location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg)\$ {
        expires 30d;
        add_header Cache-Control "public, no-transform";
        try_files \$uri \$uri/ =404;
    }
    
    # Disable access to hidden files
    location ~ /\\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    # Error pages
    error_page 400 401 402 403 404 405 /40x.html;
    error_page 500 502 503 504 /50x.html;
    
    location = /40x.html {
        root /usr/share/nginx/html;
        internal;
    }
    
    location = /50x.html {
        root /usr/share/nginx/html;
        internal;
    }
    
    # Logging
    access_log /var/log/nginx/${DEFAULT_DOMAIN}_access.log;
    error_log /var/log/nginx/${DEFAULT_DOMAIN}_error.log;
}
EOL

    # Enable site
    ln -sf "/etc/nginx/sites-available/${DEFAULT_DOMAIN}" "/etc/nginx/sites-enabled/" || {
        log "ERROR" "Failed to enable Nginx site"
        emergency_cleanup
    }
    
    # Remove default config if exists
    [ -f "/etc/nginx/sites-enabled/default" ] && rm -f "/etc/nginx/sites-enabled/default"
    
    # Generate DH parameters (background process)
    if [ ! -f "/etc/nginx/dhparam.pem" ]; then
        log "INFO" "Generating DH parameters (this may take several minutes)..."
        openssl dhparam -out /etc/nginx/dhparam.pem 2048 &> /dev/null &
    fi
    
    # Test configuration
    if ! nginx -t; then
        log "ERROR" "Nginx configuration test failed"
        emergency_cleanup
    fi
    
    # Restart Nginx
    systemctl restart nginx || {
        log "ERROR" "Failed to restart Nginx"
        emergency_cleanup
    }
    
    log "INFO" "Nginx configuration completed"
    return 0
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
    
    # Obtain certificate with multiple fallbacks
    local certbot_cmd="certbot certonly --standalone \
        -d ${DEFAULT_DOMAIN} \
        -d www.${DEFAULT_DOMAIN} \
        --non-interactive \
        --agree-tos \
        --email admin@${DEFAULT_DOMAIN} \
        --preferred-challenges http \
        --keep-until-expiring"
    
    if ! retry_command "$certbot_cmd" "Obtain SSL certificate" 3 10; then
        log "WARN" "Standard certbot failed, trying alternative methods..."
        
        # Try with DNS challenge if HTTP fails
        if certbot certonly --manual \
            -d ${DEFAULT_DOMAIN} \
            -d www.${DEFAULT_DOMAIN} \
            --non-interactive \
            --agree-tos \
            --email admin@${DEFAULT_DOMAIN} \
            --preferred-challenges dns \
            --manual-public-ip-logging-ok; then
            
            log "INFO" "SSL certificate obtained via DNS challenge"
        else
            log "ERROR" "All SSL certificate acquisition methods failed"
            systemctl start nginx || true
            return 1
        fi
    fi
    
    # Restart Nginx
    systemctl start nginx || {
        log "ERROR" "Failed to restart Nginx after SSL setup"
        return 1
    }
    
    # Setup auto-renewal with pre and post hooks
    (crontab -l 2>/dev/null; echo "0 3 * * * /usr/bin/certbot renew --quiet --pre-hook 'systemctl stop nginx' --post-hook 'systemctl start nginx'") | crontab - || {
        log "WARN" "Could not setup SSL auto-renewal"
    }
    
    log "INFO" "SSL setup completed"
    return 0
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
    return 0
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
    return 0
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
            log "WARN" "Step ${step} encountered errors - attempting to continue"
        fi
    done
    
    # Final status
    echo -e "\n${GREEN}=== Setup Completed ===${NC}"
    echo -e "Web Application URL: ${BLUE}http://${CURRENT_IP}:${WEB_PORT}${NC}"
    echo -e "Admin Credentials: ${YELLOW}${ADMIN_USER}/${ADMIN_PASS}${NC}"
    echo -e "Control Script: ${CYAN}./docker.sh {start|stop|restart|status|logs|update|backup}${NC}"
    echo -e "Log File: ${MAGENTA}${LOG_FILE}${NC}"
    echo -e "Backup Directory: ${MAGENTA}${BACKUP_DIR}${NC}"
    echo -e "\nNext Steps:"
    echo -e "1. Configure DNS for ${DEFAULT_DOMAIN} to point to ${CURRENT_IP}"
    echo -e "2. Run ${CYAN}./docker.sh start${NC} to launch the application"
    echo -e "3. Monitor logs with ${CYAN}./docker.sh logs${NC}"
    
    # Start services
    ./docker.sh start
}

# Start main execution with error trapping
trap emergency_cleanup SIGINT SIGTERM ERR
main
