# n8n Setup Guide

> **X-n8 (Exnate)** - Complete n8n Configuration Guide

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation Methods](#installation-methods)
3. [Initial Configuration](#initial-configuration)
4. [Importing Workflows](#importing-workflows)
5. [Credential Setup](#credential-setup)
6. [Environment Variables](#environment-variables)
7. [Webhook Configuration](#webhook-configuration)
8. [Performance Tuning](#performance-tuning)
9. [High Availability](#high-availability)
10. [Troubleshooting](#troubleshooting)

---

## 1. Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Storage | 20 GB | 50+ GB SSD |
| Network | 100 Mbps | 1 Gbps |

### Software Requirements

- **Node.js** 18.x or higher
- **npm** 8.x or higher
- **Docker** 20.x+ (for container deployment)
- **Redis** 6.x+ (for deduplication)
- **PostgreSQL** 13+ (for production)

---

## 2. Installation Methods

### Method A: Docker (Recommended)

```bash
# Create docker-compose.yml
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  n8n:
    image: n8nio/n8n:latest
    restart: always
    ports:
      - "5678:5678"
    environment:
      - N8N_BASIC_AUTH_ACTIVE=true
      - N8N_BASIC_AUTH_USER=admin
      - N8N_BASIC_AUTH_PASSWORD=changeme
      - N8N_HOST=your-n8n-domain.com
      - N8N_PORT=5678
      - N8N_PROTOCOL=https
      - N8N_ENCRYPTION_KEY=your-encryption-key
      - WEBHOOK_URL=https://your-n8n-domain.com/
      - DB_TYPE=postgresdb
      - DB_POSTGRESDB_HOST=postgres
      - DB_POSTGRESDB_PORT=5432
      - DB_POSTGRESDB_DATABASE=n8n
      - DB_POSTGRESDB_USER=n8n
      - DB_POSTGRESDB_PASSWORD=n8npassword
      - EXECUTIONS_DATA_PRUNE=true
      - EXECUTIONS_DATA_MAX_AGE=168
    volumes:
      - n8n_data:/home/node/.n8n
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:15
    restart: always
    environment:
      - POSTGRES_USER=n8n
      - POSTGRES_PASSWORD=n8npassword
      - POSTGRES_DB=n8n
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    restart: always
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  n8n_data:
  postgres_data:
  redis_data:
EOF

# Start services
docker-compose up -d
```

### Method B: npm Global Install

```bash
# Install n8n globally
npm install -g n8n

# Start n8n
n8n start

# Or with PM2 for production
npm install -g pm2
pm2 start n8n
pm2 save
pm2 startup
```

### Method C: Kubernetes (Enterprise)

```yaml
# n8n-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: n8n
spec:
  replicas: 2
  selector:
    matchLabels:
      app: n8n
  template:
    metadata:
      labels:
        app: n8n
    spec:
      containers:
      - name: n8n
        image: n8nio/n8n:latest
        ports:
        - containerPort: 5678
        env:
        - name: N8N_ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: n8n-secrets
              key: encryption-key
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
```

---

## 3. Initial Configuration

### Access n8n

1. Navigate to `http://localhost:5678` (or your domain)
2. Create admin account
3. Complete initial setup wizard

### Recommended Settings

Navigate to **Settings** → **General**:

```json
{
  "timezone": "UTC",
  "saveExecutionProgress": true,
  "saveManualExecutions": true,
  "saveDataOnError": "all",
  "saveDataOnSuccess": "all",
  "workflowCallerPolicyDefaultOption": "any"
}
```

---

## 4. Importing Workflows

### Import Core Workflows

```bash
# Clone X-n8 repository
git clone https://github.com/Masriyan/X-n8-Exnate.git
cd X-n8-Exnate

# Import core workflows via CLI
n8n import:workflow --input=n8n-workflows/core/alert-ingestion.json
n8n import:workflow --input=n8n-workflows/core/ai-analysis.json
n8n import:workflow --input=n8n-workflows/core/deduplication.json

# Import all category playbooks
find n8n-workflows/categories -name "*.json" -exec n8n import:workflow --input={} \;
```

### Import via UI

1. Go to **Workflows** → **Import from File**
2. Select JSON workflow file
3. Click **Import**
4. Repeat for each playbook

### Verify Imports

After importing, verify:
- [ ] All nodes are connected
- [ ] No credential errors
- [ ] Webhooks are unique

---

## 5. Credential Setup

### Required Credentials

Create these credentials in **Settings** → **Credentials**:

#### OpenAI / Azure OpenAI

```json
{
  "name": "OpenAI - X-n8",
  "type": "openAiApi",
  "data": {
    "apiKey": "sk-your-api-key"
  }
}
```

#### Redis

```json
{
  "name": "Redis - X-n8",
  "type": "redis",
  "data": {
    "host": "localhost",
    "port": 6379,
    "password": ""
  }
}
```

#### XSOAR HTTP Header Auth

```json
{
  "name": "XSOAR API",
  "type": "httpHeaderAuth",
  "data": {
    "name": "Authorization",
    "value": "your-xsoar-api-key"
  }
}
```

#### Slack

```json
{
  "name": "Slack Bot - X-n8",
  "type": "slackApi",
  "data": {
    "accessToken": "xoxb-your-bot-token"
  }
}
```

---

## 6. Environment Variables

### Core Variables

```bash
# n8n Configuration
N8N_HOST=n8n.yourcompany.com
N8N_PORT=5678
N8N_PROTOCOL=https
N8N_ENCRYPTION_KEY=your-32-char-encryption-key

# X-n8 Integrations
XSOAR_URL=https://xsoar.yourcompany.com
XSOAR_API_KEY=your-xsoar-api-key

# Redis
REDIS_URL=redis://localhost:6379

# AI
OPENAI_API_KEY=sk-your-key
# OR
AZURE_OPENAI_URL=https://your-instance.openai.azure.com
AZURE_OPENAI_KEY=your-azure-key
AZURE_OPENAI_DEPLOYMENT=gpt-4

# Notifications
SLACK_BOT_TOKEN=xoxb-your-token
SLACK_CHANNEL=#soc-alerts

# EDR (SentinelOne)
SENTINELONE_URL=https://usea1.sentinelone.net
SENTINELONE_API_KEY=your-s1-key

# Firewall (Palo Alto)
PALO_ALTO_URL=https://firewall.yourcompany.com
PALO_ALTO_API_KEY=your-pan-key
```

---

## 7. Webhook Configuration

### Enable Webhooks

1. Go to workflow settings
2. Enable **Active** toggle
3. Note the webhook URL: `https://n8n.yourcompany.com/webhook/xn8-ingest`

### Webhook Security

```javascript
// Add authentication check in webhook node
const authHeader = $input.first().headers.authorization;
const validKey = $env.WEBHOOK_SECRET;

if (authHeader !== `Bearer ${validKey}`) {
  throw new Error('Unauthorized');
}
```

### Configure Firewall

Allow inbound traffic to n8n:

```bash
# UFW example
sudo ufw allow 5678/tcp

# iptables example
iptables -A INPUT -p tcp --dport 5678 -j ACCEPT
```

---

## 8. Performance Tuning

### Execution Scaling

```bash
# Set worker count (docker-compose)
environment:
  - EXECUTIONS_MODE=queue
  - EXECUTIONS_PROCESS=own
  - N8N_WORKERS=4
```

### Memory Optimization

```bash
# Increase Node.js memory
NODE_OPTIONS=--max-old-space-size=4096

# Prune old executions
N8N_EXECUTIONS_DATA_PRUNE=true
N8N_EXECUTIONS_DATA_MAX_AGE=48  # hours
```

### Redis Optimization

```redis
# redis.conf
maxmemory 2gb
maxmemory-policy allkeys-lru
```

---

## 9. High Availability

### Multi-Instance Setup

```yaml
# docker-compose.yml with scaling
services:
  n8n:
    image: n8nio/n8n
    deploy:
      replicas: 3
    environment:
      - EXECUTIONS_MODE=queue
      - QUEUE_BULL_REDIS_HOST=redis
```

### Load Balancer

```nginx
# nginx.conf
upstream n8n {
    least_conn;
    server n8n-1:5678;
    server n8n-2:5678;
    server n8n-3:5678;
}

server {
    listen 443 ssl;
    server_name n8n.yourcompany.com;
    
    location / {
        proxy_pass http://n8n;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
    }
}
```

---

## 10. Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Webhook not reachable | Check firewall, verify active status |
| Credential errors | Recreate credential, verify API key |
| High memory usage | Enable execution pruning, increase memory |
| Slow workflows | Add worker processes, optimize code nodes |

### Debug Mode

```bash
# Enable debug logging
N8N_LOG_LEVEL=debug n8n start

# View logs
docker-compose logs -f n8n
```

### Health Check

```bash
# Check n8n status
curl http://localhost:5678/healthz

# Expected response
{"status":"ok"}
```

---

## 📞 Support

- **Documentation**: [https://docs.n8n.io](https://docs.n8n.io)
- **X-n8 Issues**: [GitHub Issues](https://github.com/Masriyan/X-n8-Exnate/issues)
- **n8n Community**: [community.n8n.io](https://community.n8n.io)

---

<p align="center">
  <a href="https://github.com/Masriyan/X-n8-Exnate">← Back to Repository</a>
</p>
