#!/bin/bash

# Ultimate Ubuntu Server Auto-Deploy Setup
# Author: Yatogami
# Description: Complete server setup for web deployment (without network configuration)

# --------------------------
# Configuration
# --------------------------
CURRENT_IP=$(hostname -I | awk '{print $1}')  # Gets current server IP
DEFAULT_DOMAIN="yatogami.net"                # Default domain name
ADMIN_USER="yato"                            # Admin username for web interface
ADMIN_PASS="yatogamii"                       # Admin password
DOCKER_NODE_IMAGE="node:18-alpine"           # Docker image for Node.js
WEB_PORT=3000                                # Port for web application
NGINX_PORT=80                                # Nginx HTTP port
NGINX_SSL_PORT=443                           # Nginx HTTPS port
LOG_FILE="/var/log/auto-deploy-setup.log"    # Log file location

# --------------------------
# Initialization
# --------------------------
# Colors for console output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function that writes to both console and log file
log() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a $LOG_FILE
}

# Error handling function that logs and exits
error_exit() {
    log "${RED}ERROR: $1${NC}"
    exit 1
}

# Verify script is run as root
if [ "$(id -u)" -ne 0 ]; then
    error_exit "This script must be run as root"
fi

# --------------------------
# Main Setup Functions
# --------------------------

# System update and upgrade
system_update() {
    log "${YELLOW}Starting system update...${NC}"
    apt-get update || error_exit "Failed to update package lists"
    apt-get upgrade -y || error_exit "Failed to upgrade packages"
    apt-get dist-upgrade -y || error_exit "Failed to dist-upgrade"
    apt-get autoremove -y || error_exit "Failed to autoremove packages"
    log "${GREEN}System update completed${NC}"
}

# Install all required packages
install_essentials() {
    log "${YELLOW}Installing essential packages...${NC}"
    
    # List of packages to install
    local packages=(
        curl wget git htop nano ufw fail2ban unattended-upgrades
        nginx docker.io docker-compose jq net-tools openssl certbot
    )
    
    apt-get install -y "${packages[@]}" || error_exit "Failed to install essential packages"
    
    # Start and enable Docker
    systemctl enable docker || error_exit "Failed to enable Docker"
    systemctl start docker || error_exit "Failed to start Docker"
    
    log "${GREEN}Essential packages installed${NC}"
}

# Create environment configuration file
setup_env() {
    log "${YELLOW}Setting up environment configuration...${NC}"
    
    cat > .env <<EOL
# Auto-Deploy Web Server Configuration
ADMIN_USER=$ADMIN_USER
ADMIN_PASS=$ADMIN_PASS
DOMAIN=$DEFAULT_DOMAIN
WEB_PORT=$WEB_PORT
NGINX_PORT=$NGINX_PORT
NGINX_SSL_PORT=$NGINX_SSL_PORT
DOCKER_NODE_IMAGE=$DOCKER_NODE_IMAGE
CURRENT_IP=$CURRENT_IP
EOL
    
    log "${GREEN}Environment configuration created${NC}"
}

# Docker setup with Node.js container
setup_docker() {
    log "${YELLOW}Setting up Docker configuration...${NC}"
    
    # Dockerfile for Node.js application
    cat > Dockerfile <<EOL
FROM $DOCKER_NODE_IMAGE
WORKDIR /app
COPY webapp/package*.json ./
RUN npm install
COPY webapp .
EXPOSE $WEB_PORT
CMD ["node", "server.js"]
EOL
    
    # Docker Compose configuration
    cat > docker-compose.yml <<EOL
version: '3.8'
services:
  webapp:
    build: .
    container_name: auto-deploy-web
    restart: always
    ports:
      - "$WEB_PORT:$WEB_PORT"
    environment:
      - ADMIN_USER=\${ADMIN_USER}
      - ADMIN_PASS=\${ADMIN_PASS}
    volumes:
      - ./webapp:/app
      - /var/run/docker.sock:/var/run/docker.sock
EOL
    
    # Docker control script
    cat > docker.sh <<EOL
#!/bin/bash
ACTION=\$1
case \$ACTION in
    start) docker-compose up -d --build ;;
    stop) docker-compose down ;;
    restart) docker-compose restart ;;
    status) docker-compose ps ;;
    logs) docker-compose logs -f ;;
    *) echo "Usage: \$0 {start|stop|restart|status|logs}"; exit 1 ;;
esac
EOL
    
    chmod +x docker.sh
    log "${GREEN}Docker configuration created${NC}"
}

# Complete web application setup
setup_webapp() {
    log "${YELLOW}Setting up web application...${NC}"
    
    # Create directory structure
    mkdir -p webapp/{public/{css,js},views}
    
    # package.json for Node.js dependencies
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
    
    # Main server application
    cat > webapp/server.js <<EOL
const express = require('express');
const bodyParser = require('body-parser');
const Docker = require('dockerode');
const path = require('path');
const fs = require('fs-extra');
const multer = require('multer');
require('dotenv').config();

const app = express();
const docker = new Docker();
const upload = multer({ dest: 'uploads/' });

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Basic authentication
const auth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).send('Authorization Required');
    
    const credentials = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
    if (credentials[0] !== process.env.ADMIN_USER || credentials[1] !== process.env.ADMIN_PASS) {
        return res.status(403).send('Forbidden');
    }
    next();
};

// Routes
app.get('/', auth, (req, res) => res.render('index', { domain: process.env.DOMAIN }));

app.post('/deploy', auth, upload.single('website'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).send('No file uploaded');
        await fs.move(req.file.path, path.join(__dirname, 'public/deployments', req.file.originalname));
        res.send('Deployment started successfully!');
    } catch (err) {
        console.error(err);
        res.status(500).send('Deployment failed');
    }
});

// Docker management API
app.get('/containers', auth, async (req, res) => {
    try {
        res.json(await docker.listContainers({ all: true }));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/containers/:id/start', auth, async (req, res) => {
    try {
        await docker.getContainer(req.params.id).start();
        res.json({ status: 'started' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/containers/:id/stop', auth, async (req, res) => {
    try {
        await docker.getContainer(req.params.id).stop();
        res.json({ status: 'stopped' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(process.env.WEB_PORT || 3000, () => {
    console.log(\`Server running on port \${process.env.WEB_PORT || 3000}\`);
});
EOL
    
    # Frontend views and assets
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
        <h1>Auto-Deploy Web Interface</h1>
        <div class="deploy-section">
            <h2>Deploy Website</h2>
            <form action="/deploy" method="post" enctype="multipart/form-data">
                <input type="file" name="website" required>
                <button type="submit">Deploy</button>
            </form>
        </div>
        <div class="docker-section">
            <h2>Docker Containers</h2>
            <div id="containers-list">Loading containers...</div>
        </div>
    </div>
    <script src="/js/app.js"></script>
</body>
</html>
EOL

    # Basic CSS styling
    cat > webapp/public/css/style.css <<EOL
body {
    font-family: Arial, sans-serif;
    margin: 0;
    padding: 20px;
    background-color: #f5f5f5;
}
.container {
    max-width: 800px;
    margin: 0 auto;
    background: white;
    padding: 20px;
    border-radius: 5px;
    box-shadow: 0 0 10px rgba(0,0,0,0.1);
}
.deploy-section, .docker-section {
    margin: 20px 0;
    padding: 15px;
    border: 1px solid #ddd;
    border-radius: 5px;
}
button {
    background: #007bff;
    color: white;
    border: none;
    padding: 8px 15px;
    border-radius: 4px;
    cursor: pointer;
}
button:hover {
    background: #0056b3;
}
EOL

    # Client-side JavaScript
    cat > webapp/public/js/app.js <<EOL
document.addEventListener('DOMContentLoaded', () => {
    fetch('/containers')
        .then(res => res.json())
        .then(containers => {
            const containerList = document.getElementById('containers-list');
            if (containers.length === 0) {
                containerList.innerHTML = '<p>No containers running</p>';
                return;
            }
            
            containerList.innerHTML = \`
                <table>
                    <thead>
                        <tr>
                            <th>ID</th><th>Name</th><th>Image</th><th>Status</th><th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        \${containers.map(c => \`
                            <tr>
                                <td>\${c.Id.substring(0,12)}</td>
                                <td>\${c.Names[0].replace('/','')}</td>
                                <td>\${c.Image}</td>
                                <td>\${c.State}</td>
                                <td>
                                    \${c.State === 'running' ? 
                                        '<button onclick="stopContainer(\''+c.Id+'\')">Stop</button>' : 
                                        '<button onclick="startContainer(\''+c.Id+'\')">Start</button>'}
                                </td>
                            </tr>
                        \`).join('')}
                    </tbody>
                </table>\`;
        })
        .catch(err => {
            console.error('Error:', err);
            document.getElementById('containers-list').innerHTML = '<p>Error loading containers</p>';
        });
});

function startContainer(id) {
    fetch(\`/containers/\${id}/start\`, { method: 'POST' })
        .then(() => location.reload())
        .catch(console.error);
}

function stopContainer(id) {
    fetch(\`/containers/\${id}/stop\`, { method: 'POST' })
        .then(() => location.reload())
        .catch(console.error);
}
EOL
    
    log "${GREEN}Web application setup completed${NC}"
}

# Nginx reverse proxy configuration
setup_nginx() {
    log "${YELLOW}Setting up Nginx reverse proxy...${NC}"
    
    mkdir -p /etc/nginx/ssl
    
    # Nginx configuration for the domain
    cat > /etc/nginx/sites-available/$DEFAULT_DOMAIN <<EOL
server {
    listen $NGINX_PORT;
    listen [::]:$NGINX_PORT;
    server_name $DEFAULT_DOMAIN www.$DEFAULT_DOMAIN;
    
    location / {
        proxy_pass http://localhost:$WEB_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOL
    
    # Enable the site
    ln -s /etc/nginx/sites-available/$DEFAULT_DOMAIN /etc/nginx/sites-enabled/
    
    # Test and restart Nginx
    nginx -t || error_exit "Nginx configuration test failed"
    systemctl restart nginx || error_exit "Failed to restart Nginx"
    
    log "${GREEN}Nginx reverse proxy configured for $DEFAULT_DOMAIN${NC}"
}

# SSL certificate setup with Let's Encrypt
setup_ssl() {
    log "${YELLOW}Setting up SSL with Let's Encrypt...${NC}"
    
    # Verify domain points to this server
    log "${BLUE}NOTE: Domain $DEFAULT_DOMAIN must point to $CURRENT_IP${NC}"
    read -p "Does your domain point to this IP? (y/n): " DOMAIN_CHECK
    
    if [ "$DOMAIN_CHECK" != "y" ]; then
        log "${YELLOW}Skipping SSL setup. Run later with: certbot --nginx -d $DEFAULT_DOMAIN -d www.$DEFAULT_DOMAIN${NC}"
        return
    fi
    
    # Obtain and install certificate
    certbot --nginx -d $DEFAULT_DOMAIN -d www.$DEFAULT_DOMAIN \
        --non-interactive --agree-tos --email admin@$DEFAULT_DOMAIN \
        || error_exit "SSL setup failed"
    
    # Set up automatic renewal
    (crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet") | crontab -
    
    log "${GREEN}SSL setup completed for $DEFAULT_DOMAIN${NC}"
}

# Server control script
setup_server_control() {
    log "${YELLOW}Setting up server control script...${NC}"
    
    cat > server.sh <<EOL
#!/bin/bash
ACTION=\$1
case \$ACTION in
    start)
        ./docker.sh start
        systemctl start nginx
        ;;
    stop)
        ./docker.sh stop
        systemctl stop nginx
        ;;
    restart)
        ./docker.sh restart
        systemctl restart nginx
        ;;
    status)
        echo "=== Docker Containers ==="
        ./docker.sh status
        echo "=== Nginx Status ==="
        systemctl status nginx --no-pager
        ;;
    logs)
        ./docker.sh logs
        ;;
    update)
        git pull origin master
        ./docker.sh stop
        ./docker.sh start
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart|status|logs|update}"
        exit 1
        ;;
esac
EOL
    
    chmod +x server.sh
    log "${GREEN}Server control script created${NC}"
}

# System optimization and security
system_optimization() {
    log "${YELLOW}Applying system optimizations...${NC}"
    
    # Increase file watcher limit for Node.js
    echo "fs.inotify.max_user_watches=524288" >> /etc/sysctl.conf
    sysctl -p
    
    # Optimize swap usage
    echo "vm.swappiness=10" >> /etc/sysctl.conf
    sysctl -p
    
    # Security hardening
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl restart sshd
    
    # Configure automatic updates
    echo 'Unattended-Upgrade::Automatic-Reboot "true";' >> /etc/apt/apt.conf.d/50unattended-upgrades
    echo 'Unattended-Upgrade::Automatic-Reboot-Time "02:00";' >> /etc/apt/apt.conf.d/50unattended-upgrades
    
    # Configure firewall
    ufw allow OpenSSH
    ufw allow 'Nginx Full'
    ufw --force enable
    
    log "${GREEN}System optimizations applied${NC}"
}

# --------------------------
# Main Execution
# --------------------------
main() {
    log "${BLUE}Starting Auto-Deploy Server Setup${NC}"
    
    # Step 1: System preparation
    system_update
    install_essentials
    
    # Step 2: Application setup
    setup_env
    setup_docker
    setup_webapp
    
    # Step 3: Web server configuration
    setup_nginx
    setup_ssl
    
    # Step 4: Management and optimization
    setup_server_control
    system_optimization
    
    # Completion message
    log "${GREEN}Setup completed successfully!${NC}"
    log "${BLUE}Next steps:${NC}"
    log "1. Start services: ./server.sh start"
    log "2. Access web interface: http://$DEFAULT_DOMAIN"
    log "3. Use credentials: $ADMIN_USER / $ADMIN_PASS"
    log "4. Check logs at: $LOG_FILE"
    
    # Start services automatically
    ./server.sh start
}

# Start the main process
main
