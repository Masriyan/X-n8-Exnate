#!/bin/bash

# ============================================
# X-n8 (Exnate) Quick Setup Script
# ============================================
# This script helps you quickly deploy X-n8
# Run with: chmod +x setup.sh && ./setup.sh
# ============================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print banner
echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                                                           ║"
echo "║              X-n8 (EXNATE) QUICK SETUP                   ║"
echo "║           Agentic SOC Automation Platform                ║"
echo "║                                                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check prerequisites
echo -e "\n${YELLOW}[1/8] Checking prerequisites...${NC}"

check_command() {
    if command -v $1 &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} $1 is installed"
        return 0
    else
        echo -e "  ${RED}✗${NC} $1 is NOT installed"
        return 1
    fi
}

MISSING=0
check_command docker || MISSING=1
check_command docker-compose || { check_command "docker compose" || MISSING=1; }
check_command curl || MISSING=1
check_command git || MISSING=1

if [ $MISSING -eq 1 ]; then
    echo -e "\n${RED}Please install missing prerequisites and try again.${NC}"
    exit 1
fi

# Create environment file if not exists
echo -e "\n${YELLOW}[2/8] Setting up environment configuration...${NC}"

if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        cp .env.example .env
        echo -e "  ${GREEN}✓${NC} Created .env from template"
        
        # Generate encryption key
        ENCRYPTION_KEY=$(openssl rand -hex 16 2>/dev/null || cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 32 | head -n 1)
        sed -i "s/your-32-character-encryption-key-here/$ENCRYPTION_KEY/g" .env 2>/dev/null || true
        echo -e "  ${GREEN}✓${NC} Generated encryption key"
        
        # Generate random passwords
        POSTGRES_PASS=$(openssl rand -base64 16 2>/dev/null || cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
        N8N_PASS=$(openssl rand -base64 12 2>/dev/null || cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)
        sed -i "s/YourSecureDBPassword123!/$POSTGRES_PASS/g" .env 2>/dev/null || true
        sed -i "s/YourSecurePassword123!/$N8N_PASS/g" .env 2>/dev/null || true
        echo -e "  ${GREEN}✓${NC} Generated secure passwords"
        
        echo -e "\n  ${YELLOW}⚠ IMPORTANT: Edit .env to add your API keys:${NC}"
        echo -e "    - XSOAR_URL and XSOAR_API_KEY"
        echo -e "    - OPENAI_API_KEY (or Azure OpenAI)"
        echo -e "    - SLACK_BOT_TOKEN (optional)"
    else
        echo -e "  ${RED}✗${NC} .env.example not found"
        exit 1
    fi
else
    echo -e "  ${GREEN}✓${NC} .env already exists"
fi

# Create required directories
echo -e "\n${YELLOW}[3/8] Creating required directories...${NC}"

mkdir -p nginx/ssl
mkdir -p monitoring/grafana/datasources
mkdir -p monitoring/grafana/dashboards
echo -e "  ${GREEN}✓${NC} Directories created"

# Create Nginx config if not exists
if [ ! -f nginx/nginx.conf ]; then
    cat > nginx/nginx.conf << 'NGINX_EOF'
events {
    worker_connections 1024;
}

http {
    upstream n8n {
        server n8n:5678;
    }

    server {
        listen 80;
        server_name _;
        
        location / {
            proxy_pass http://n8n;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_cache_bypass $http_upgrade;
            proxy_read_timeout 300s;
            proxy_connect_timeout 75s;
        }
    }
}
NGINX_EOF
    echo -e "  ${GREEN}✓${NC} Nginx configuration created"
fi

# Create Grafana datasource config
if [ ! -f monitoring/grafana/datasources/prometheus.yml ]; then
    cat > monitoring/grafana/datasources/prometheus.yml << 'GRAFANA_EOF'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
GRAFANA_EOF
    echo -e "  ${GREEN}✓${NC} Grafana datasource configured"
fi

# Start Docker services
echo -e "\n${YELLOW}[4/8] Starting Docker services...${NC}"
echo -e "  This may take a few minutes for first-time download..."

docker-compose up -d 2>&1 | while read line; do
    echo "  $line"
done

echo -e "  ${GREEN}✓${NC} Docker services started"

# Wait for n8n to be ready
echo -e "\n${YELLOW}[5/8] Waiting for n8n to be ready...${NC}"

MAX_RETRIES=30
RETRY=0
while [ $RETRY -lt $MAX_RETRIES ]; do
    if curl -s http://localhost:5678/healthz > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} n8n is ready!"
        break
    fi
    RETRY=$((RETRY + 1))
    echo -e "  Waiting... ($RETRY/$MAX_RETRIES)"
    sleep 5
done

if [ $RETRY -eq $MAX_RETRIES ]; then
    echo -e "  ${RED}✗${NC} n8n did not start in time. Check logs: docker-compose logs n8n"
    exit 1
fi

# Check all services
echo -e "\n${YELLOW}[6/8] Verifying all services...${NC}"

check_service() {
    if docker-compose ps | grep "$1" | grep -q "Up"; then
        echo -e "  ${GREEN}✓${NC} $1 is running"
        return 0
    else
        echo -e "  ${RED}✗${NC} $1 is NOT running"
        return 1
    fi
}

check_service "xn8-n8n"
check_service "xn8-postgres"
check_service "xn8-redis"

# Import workflows
echo -e "\n${YELLOW}[7/8] Importing X-n8 workflows...${NC}"

import_workflow() {
    if [ -f "$1" ]; then
        docker exec -it xn8-n8n n8n import:workflow --input="/home/node/workflows/$2" 2>/dev/null && \
            echo -e "  ${GREEN}✓${NC} Imported: $2" || \
            echo -e "  ${YELLOW}⚠${NC} Could not import: $2 (may need manual import)"
    fi
}

# Note: Workflows need to be mounted in the container
# For now, provide instructions
echo -e "  ${YELLOW}⚠${NC} Workflows need to be imported manually:"
echo -e "    1. Open n8n UI at http://localhost:5678"
echo -e "    2. Go to Workflows → Import from File"
echo -e "    3. Import files from n8n-workflows/core/"
echo -e "    4. Import files from n8n-workflows/categories/"

# Print summary
echo -e "\n${YELLOW}[8/8] Setup Complete!${NC}"
echo -e "\n${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}                   X-n8 IS READY!                           ${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"

echo -e "\n${BLUE}Access URLs:${NC}"
echo -e "  • n8n:        http://localhost:5678"
echo -e "  • Grafana:    http://localhost:3000 (admin/admin)"
echo -e "  • Prometheus: http://localhost:9090"

echo -e "\n${BLUE}Default Credentials:${NC}"
echo -e "  • n8n User:     admin"
echo -e "  • n8n Password: (check .env for N8N_BASIC_AUTH_PASSWORD)"

echo -e "\n${BLUE}Next Steps:${NC}"
echo -e "  1. Edit .env and add your API keys"
echo -e "  2. Import workflows from n8n-workflows/"
echo -e "  3. Configure credentials in n8n"
echo -e "  4. Set up SIEM forwarding"
echo -e "  5. Read docs/IMPLEMENTATION-GUIDE.md"

echo -e "\n${BLUE}Useful Commands:${NC}"
echo -e "  • View logs:     docker-compose logs -f"
echo -e "  • Stop services: docker-compose down"
echo -e "  • Restart:       docker-compose restart"

echo -e "\n${GREEN}Thank you for using X-n8 (Exnate)! 🛡️${NC}\n"
