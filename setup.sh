#!/bin/bash

# Advanced Ubuntu Server Auto-Deploy Setup
# Author: Yatogami
# Description: Transforms fresh Ubuntu server into auto-deploy web server

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
LOG_FILE="/var/log/auto-deploy-setup.log"

# --------------------------
# Initialization
# --------------------------
# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a $LOG_FILE
}

# Error handling function
error_exit() {
    log "${RED}ERROR: $1${NC}"
    exit 1
}

# Check root
if [ "$(id -u)" -ne 0 ]; then
    error_exit "This script must be run as root"
fi

# --------------------------
# Main Setup Functions
# --------------------------

# Initial system update
system_update() {
    log "${YELLOW}Starting system update...${NC}"
    apt-get update || error_exit "Failed to update package lists"
    apt-get upgrade -y || error_exit "Failed to upgrade packages"
    apt-get dist-upgrade -y || error_exit "Failed to dist-upgrade"
    apt-get autoremove -y || error_exit "Failed to autoremove packages"
    log "${GREEN}System update completed${NC}"
}

# Install essential packages
install_essentials() {
    log "${YELLOW}Installing essential packages...${NC}"
    apt-get install -y \
        curl \
        wget \
        git \
        htop \
        nano \
        ufw \
        fail2ban \
        unattended-upgrades \
        nginx \
        docker.io \
        docker-compose \
        jq \
        net-tools \
        openssl \
        certbot || error_exit "Failed to install essential packages"
    
    # Start and enable Docker
    systemctl enable docker || error_exit "Failed to enable Docker"
    systemctl start docker || error_exit "Failed to start Docker"
    
    log "${GREEN}Essential packages installed${NC}"
}

# Configure static IP
configure_static_ip() {
    log "${YELLOW}Configuring static IP...${NC}"
    
    # Get current network interface
    INTERFACE=$(ip route | grep default | awk '{print $5}')
    if [ -z "$INTERFACE" ]; then
        error_exit "Could not determine network interface"
    fi
    
    # Get current network config
    NETMASK=$(ifconfig $INTERFACE | grep netmask | awk '{print $4}')
    GATEWAY=$(ip route | grep default | awk '{print $3}')
    DNS_SERVERS="8.8.8.8 8.8.4.4"
    
    # Backup current netplan config
    cp /etc/netplan/*.yaml /etc/netplan/00-installer-config.yaml.bak
    
    # Create new netplan config
    cat > /etc/netplan/00-installer-config.yaml <<EOL
network:
  version: 2
  renderer: networkd
  ethernets:
    $INTERFACE:
      dhcp4: no
      addresses: [$CURRENT_IP/24]
      gateway4: $GATEWAY
      nameservers:
        addresses: [$DNS_SERVERS]
EOL
    
    # Apply new config
    netplan apply || error_exit "Failed to apply netplan configuration"
    
    log "${GREEN}Static IP configured: $CURRENT_IP${NC}"
}

# Setup environment file
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

# Setup Docker configuration
setup_docker() {
    log "${YELLOW}Setting up Docker configuration...${NC}"
    
    # Create Dockerfile
    cat > Dockerfile <<EOL
FROM $DOCKER_NODE_IMAGE
WORKDIR /app
COPY webapp/package*.json ./
RUN npm install
COPY webapp .
EXPOSE $WEB_PORT
CMD ["node", "server.js"]
EOL
    
    # Create docker-compose.yml
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
    
    # Create docker.sh control script
    cat > docker.sh <<EOL
#!/bin/bash

# Docker control script
ACTION=\$1

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
        docker-compose ps
        ;;
    logs)
        docker-compose logs -f
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
EOL
    
    chmod +x docker.sh
    log "${GREEN}Docker configuration created${NC}"
}

# Setup Node.js web application
setup_webapp() {
    log "${YELLOW}Setting up web application...${NC}"
    
    mkdir -p webapp/public/{css,js}
    
    # Create package.json
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
    
    # Create server.js
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

// Basic auth middleware
const auth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        res.set('WWW-Authenticate', 'Basic realm="Authorization Required"');
        return res.status(401).send('Authorization Required');
    }
    
    const credentials = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
    if (credentials[0] !== process.env.ADMIN_USER || credentials[1] !== process.env.ADMIN_PASS) {
        return res.status(403).send('Forbidden');
    }
    
    next();
};

// Routes
app.get('/', auth, (req, res) => {
    res.render('index', { domain: process.env.DOMAIN });
});

app.post('/deploy', auth, upload.single('website'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).send('No file uploaded');
        }

        const tempPath = req.file.path;
        const targetPath = path.join(__dirname, 'public/deployments', req.file.originalname);
        
        await fs.move(tempPath, targetPath);
        
        // Here you would add your actual deployment logic
        // For example, unzipping and moving files to the correct location
        
        res.send('Deployment started successfully!');
    } catch (err) {
        console.error(err);
        res.status(500).send('Deployment failed');
    }
});

// Docker management endpoints
app.get('/containers', auth, async (req, res) => {
    try {
        const containers = await docker.listContainers({ all: true });
        res.json(containers);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/containers/:id/start', auth, async (req, res) => {
    try {
        const container = docker.getContainer(req.params.id);
        await container.start();
        res.json({ status: 'started' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/containers/:id/stop', auth, async (req, res) => {
    try {
        const container = docker.getContainer(req.params.id);
        await container.stop();
        res.json({ status: 'stopped' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.WEB_PORT || 3000;
app.listen(PORT, () => {
    console.log(\`Auto-deploy web interface running on port \${PORT}\`);
});
EOL
    
    # Create basic HTML view
    mkdir -p webapp/views
    cat > webapp/views/index.ejs <<EOL
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Auto-Deploy Interface - <%= domain %></title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <div class="container">
        <h1>Auto-Deploy Web Interface</h1>
        <p>Welcome to your auto-deployment dashboard for <%= domain %></p>
        
        <div class="deploy-section">
            <h2>Deploy New Website</h2>
            <form action="/deploy" method="post" enctype="multipart/form-data">
                <input type="file" name="website" required>
                <button type="submit">Deploy</button>
            </form>
        </div>
        
        <div class="docker-section">
            <h2>Docker Containers</h2>
            <div id="containers-list">
                Loading containers...
            </div>
        </div>
    </div>
    
    <script src="/js/app.js"></script>
</body>
</html>
EOL
    
    # Create basic CSS
    cat > webapp/public/css/style.css <<EOL
body {
    font-family: Arial, sans-serif;
    line-height: 1.6;
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
    
    # Create basic JavaScript
    cat > webapp/public/js/app.js <<EOL
document.addEventListener('DOMContentLoaded', function() {
    fetch('/containers')
        .then(response => response.json())
        .then(containers => {
            const containerList = document.getElementById('containers-list');
            containerList.innerHTML = '';
            
            if (containers.length === 0) {
                containerList.innerHTML = '<p>No containers running</p>';
                return;
            }
            
            const table = document.createElement('table');
            table.innerHTML = `
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
                    ${containers.map(container => `
                        <tr>
                            <td>${container.Id.substring(0, 12)}</td>
                            <td>${container.Names[0].replace('/', '')}</td>
                            <td>${container.Image}</td>
                            <td>${container.State}</td>
                            <td>
                                ${container.State === 'running' ? 
                                    `<button onclick="stopContainer('${container.Id}')">Stop</button>` : 
                                    `<button onclick="startContainer('${container.Id}')">Start</button>`}
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            `;
            
            containerList.appendChild(table);
        })
        .catch(error => {
            console.error('Error fetching containers:', error);
            document.getElementById('containers-list').innerHTML = 
                '<p>Error loading containers</p>';
        });
});

function startContainer(containerId) {
    fetch(\`/containers/\${containerId}/start\`, { method: 'POST' })
        .then(response => location.reload())
        .catch(error => console.error('Error starting container:', error));
}

function stopContainer(containerId) {
    fetch(\`/containers/\${containerId}/stop\`, { method: 'POST' })
        .then(response => location.reload())
        .catch(error => console.error('Error stopping container:', error));
}
EOL
    
    log "${GREEN}Web application setup completed${NC}"
}

# Setup Nginx reverse proxy
setup_nginx() {
    log "${YELLOW}Setting up Nginx reverse proxy...${NC}"
    
    mkdir -p /etc/nginx/ssl
    
    # Create Nginx config
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
    
    # Enable site
    ln -s /etc/nginx/sites-available/$DEFAULT_DOMAIN /etc/nginx/sites-enabled/
    
    # Test and reload Nginx
    nginx -t || error_exit "Nginx configuration test failed"
    systemctl restart nginx || error_exit "Failed to restart Nginx"
    
    log "${GREEN}Nginx reverse proxy configured for $DEFAULT_DOMAIN${NC}"
}

# Setup SSL with Let's Encrypt
setup_ssl() {
    log "${YELLOW}Setting up SSL with Let's Encrypt...${NC}"
    
    # Check if domain resolves to this IP
    log "${BLUE}NOTE: For SSL to work, your domain $DEFAULT_DOMAIN must point to this server's IP ($CURRENT_IP)${NC}"
    read -p "Does your domain point to this IP? (y/n): " DOMAIN_CHECK
    
    if [ "$DOMAIN_CHECK" != "y" ]; then
        log "${YELLOW}Skipping SSL setup. You can run this later with: certbot --nginx -d $DEFAULT_DOMAIN -d www.$DEFAULT_DOMAIN${NC}"
        return
    fi
    
    certbot --nginx -d $DEFAULT_DOMAIN -d www.$DEFAULT_DOMAIN --non-interactive --agree-tos --email admin@$DEFAULT_DOMAIN || error_exit "SSL setup failed"
    
    # Set up auto-renewal
    (crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet") | crontab -
    
    log "${GREEN}SSL setup completed for $DEFAULT_DOMAIN${NC}"
}

# Setup server control script
setup_server_control() {
    log "${YELLOW}Setting up server control script...${NC}"
    
    cat > server.sh <<EOL
#!/bin/bash

# Server control script
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

# Final system optimization
system_optimization() {
    log "${YELLOW}Applying system optimizations...${NC}"
    
    # Increase file watcher limit (useful for Node.js)
    echo "fs.inotify.max_user_watches=524288" >> /etc/sysctl.conf
    sysctl -p
    
    # Optimize swap usage
    echo "vm.swappiness=10" >> /etc/sysctl.conf
    sysctl -p
    
    # Basic security hardening
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl restart sshd
    
    # Configure unattended-upgrades
    echo 'Unattended-Upgrade::Automatic-Reboot "true";' >> /etc/apt/apt.conf.d/50unattended-upgrades
    echo 'Unattended-Upgrade::Automatic-Reboot-Time "02:00";' >> /etc/apt/apt.conf.d/50unattended-upgrades
    
    log "${GREEN}System optimizations applied${NC}"
}

# --------------------------
# Main Execution
# --------------------------
main() {
    log "${BLUE}Starting Auto-Deploy Server Setup${NC}"
    
    # Step 1: System update
    system_update
    
    # Step 2: Install essentials
    install_essentials
    
    # Step 3: Configure static IP
    configure_static_ip
    
    # Step 4: Setup environment
    setup_env
    
    # Step 5: Setup Docker
    setup_docker
    
    # Step 6: Setup web application
    setup_webapp
    
    # Step 7: Setup Nginx
    setup_nginx
    
    # Step 8: Setup SSL (interactive)
    setup_ssl
    
    # Step 9: Setup server control
    setup_server_control
    
    # Step 10: System optimization
    system_optimization
    
    # Final instructions
    log "${GREEN}Setup completed successfully!${NC}"
    log "${BLUE}Next steps:${NC}"
    log "1. Upload your website files to the webapp/public folder"
    log "2. Start the server with: ./server.sh start"
    log "3. Access your auto-deploy interface at: http://$DEFAULT_DOMAIN"
    log "4. Use username '$ADMIN_USER' and password '$ADMIN_PASS' to login"
    
    # Start services
    ./server.sh start
}

# Execute main function
main
