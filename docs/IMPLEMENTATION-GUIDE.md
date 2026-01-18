# X-n8 Implementation Guide

> **Complete Step-by-Step Guide to Deploy X-n8 (Exnate) Agentic SOC Platform**

<p align="center">
  <img src="../assets/banner.png" alt="X-n8 Banner" width="100%">
</p>

---

## 📋 Table of Contents

1. [Prerequisites & Planning](#phase-1-prerequisites--planning)
2. [Infrastructure Setup](#phase-2-infrastructure-setup)
3. [n8n Deployment](#phase-3-n8n-deployment)
4. [Import X-n8 Workflows](#phase-4-import-x-n8-workflows)
5. [Configure AI Integration](#phase-5-configure-ai-integration)
6. [XSOAR Integration](#phase-6-xsoar-integration)
7. [SIEM Integration](#phase-7-siem-integration)
8. [Monitoring Setup](#phase-8-monitoring-setup)
9. [Testing & Validation](#phase-9-testing--validation)
10. [Go-Live Checklist](#phase-10-go-live-checklist)

---

## Phase 1: Prerequisites & Planning

### 1.1 System Requirements

| Component | Minimum | Recommended | Production |
|-----------|---------|-------------|------------|
| **CPU** | 4 cores | 8 cores | 16+ cores |
| **RAM** | 8 GB | 16 GB | 32+ GB |
| **Storage** | 50 GB SSD | 100 GB SSD | 500+ GB SSD |
| **Network** | 100 Mbps | 1 Gbps | 10 Gbps |

### 1.2 Software Requirements

```bash
# Check requirements
docker --version     # Required: 20.10+
docker-compose --version  # Required: 2.0+
git --version        # Required: 2.30+
curl --version       # Required for testing
```

### 1.3 Network Requirements

| Service | Port | Direction | Description |
|---------|------|-----------|-------------|
| n8n | 5678 | Inbound | Webhook receiver |
| n8n | 443 | Inbound | HTTPS (via Nginx) |
| XSOAR | 443 | Outbound | Incident creation |
| Redis | 6379 | Internal | Deduplication |
| PostgreSQL | 5432 | Internal | Database |
| OpenAI | 443 | Outbound | AI API |

### 1.4 Accounts & API Keys Needed

Before starting, gather these credentials:

- [ ] **OpenAI API Key** (or Azure OpenAI)
- [ ] **XSOAR API Key** (from Settings → API Keys)
- [ ] **Slack Bot Token** (optional, for notifications)
- [ ] **EDR API Keys** (SentinelOne, CrowdStrike, etc.)
- [ ] **SIEM Webhook Configuration** access

### 1.5 Clone the Repository

```bash
# Clone X-n8 repository
git clone https://github.com/Masriyan/X-n8-Exnate.git
cd X-n8-Exnate

# Verify structure
ls -la
# You should see:
# - docker-compose.yml
# - n8n-workflows/
# - xsoar-content/
# - docs/
# - schemas/
```

---

## Phase 2: Infrastructure Setup

### 2.1 Create Environment File

```bash
# Copy example environment file
cp .env.example .env

# Edit with your values
nano .env
```

### 2.2 Configure .env File

Edit each section carefully:

```bash
# ============================================
# REQUIRED: n8n Configuration
# ============================================
N8N_HOST=n8n.yourcompany.com          # Your domain (or localhost for testing)
N8N_PROTOCOL=https                     # Use 'http' for local testing
N8N_BASIC_AUTH_USER=admin              # Change this!
N8N_BASIC_AUTH_PASSWORD=YourSecurePassword123!  # Change this!
N8N_ENCRYPTION_KEY=$(openssl rand -hex 16)      # Generate: openssl rand -hex 16

# ============================================
# REQUIRED: Database
# ============================================
POSTGRES_USER=n8n
POSTGRES_PASSWORD=YourSecureDBPassword123!      # Change this!

# ============================================
# REQUIRED: XSOAR Integration
# ============================================
XSOAR_URL=https://xsoar.yourcompany.com
XSOAR_API_KEY=your-xsoar-api-key-here

# ============================================
# REQUIRED: AI Configuration (Choose One)
# ============================================
# Option A: OpenAI
OPENAI_API_KEY=sk-your-openai-api-key

# Option B: Azure OpenAI (uncomment if using)
# AZURE_OPENAI_URL=https://your-instance.openai.azure.com
# AZURE_OPENAI_KEY=your-azure-key
# AZURE_OPENAI_DEPLOYMENT=gpt-4

# ============================================
# OPTIONAL: Notifications
# ============================================
SLACK_BOT_TOKEN=xoxb-your-slack-token
SLACK_CHANNEL=#soc-alerts

# ============================================
# OPTIONAL: EDR Integration
# ============================================
SENTINELONE_URL=https://usea1.sentinelone.net
SENTINELONE_API_KEY=your-api-key

# ============================================
# OPTIONAL: Threat Intel
# ============================================
VIRUSTOTAL_API_KEY=your-vt-api-key
```

### 2.3 Create Required Directories

```bash
# Create Nginx configuration directory
mkdir -p nginx/ssl

# Create basic Nginx config
cat > nginx/nginx.conf << 'EOF'
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
EOF
```

### 2.4 Create Grafana Data Source Config

```bash
mkdir -p monitoring/grafana/datasources

cat > monitoring/grafana/datasources/prometheus.yml << 'EOF'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
EOF
```

---

## Phase 3: n8n Deployment

### 3.1 Start the Docker Stack

```bash
# Start all services in background
docker-compose up -d

# Verify all containers are running
docker-compose ps

# Expected output:
# NAME              STATUS    PORTS
# xn8-n8n          Up       0.0.0.0:5678->5678/tcp
# xn8-postgres     Up       5432/tcp
# xn8-redis        Up       6379/tcp
# xn8-nginx        Up       0.0.0.0:80->80/tcp
# xn8-prometheus   Up       0.0.0.0:9090->9090/tcp
# xn8-grafana      Up       0.0.0.0:3000->3000/tcp
```

### 3.2 Verify Services

```bash
# Check n8n is responding
curl http://localhost:5678/healthz
# Expected: {"status":"ok"}

# Check Redis
docker exec xn8-redis redis-cli ping
# Expected: PONG

# Check PostgreSQL
docker exec xn8-postgres pg_isready -U n8n
# Expected: accepting connections

# Check logs for errors
docker-compose logs -f n8n
```

### 3.3 Access n8n UI

1. Open browser: `http://localhost:5678` (or your domain)
2. Login with credentials from `.env`:
   - Username: `admin` (or your N8N_BASIC_AUTH_USER)
   - Password: Your N8N_BASIC_AUTH_PASSWORD
3. Complete the initial setup wizard

---

## Phase 4: Import X-n8 Workflows

### 4.1 Import Core Workflows (Required)

```bash
# Import via n8n CLI inside container
docker exec -it xn8-n8n sh -c "
  n8n import:workflow --input=/home/node/workflows/core/alert-ingestion.json
  n8n import:workflow --input=/home/node/workflows/core/ai-analysis.json
  n8n import:workflow --input=/home/node/workflows/core/deduplication.json
"
```

**Or import via UI:**

1. Go to **Workflows** → **Import from File**
2. Select `n8n-workflows/core/alert-ingestion.json`
3. Click **Import**
4. Repeat for `ai-analysis.json` and `deduplication.json`

### 4.2 Import Category Playbooks

```bash
# Import all category playbooks
docker exec -it xn8-n8n sh -c "
  for f in /home/node/workflows/categories/**/*.json; do
    echo 'Importing:' \$f
    n8n import:workflow --input=\"\$f\"
  done
"
```

### 4.3 Verify Imports

1. Go to **Workflows** page
2. You should see:
   - X-n8 Alert Ingestion Master Workflow
   - X-n8 AI Analysis Workflow
   - X-n8 Deduplication & Clustering Workflow
   - Plus 14 category playbooks

---

## Phase 5: Configure AI Integration

### 5.1 Create OpenAI Credential

1. Go to **Settings** → **Credentials** → **Add Credential**
2. Select **OpenAI API**
3. Configure:
   ```
   Name: OpenAI - X-n8
   API Key: sk-your-openai-api-key
   ```
4. Click **Save**

### 5.2 Create Redis Credential

1. Go to **Settings** → **Credentials** → **Add Credential**
2. Select **Redis**
3. Configure:
   ```
   Name: Redis - X-n8
   Host: redis
   Port: 6379
   Password: (leave empty if no password)
   ```
4. Click **Save**

### 5.3 Link Credentials to Workflows

1. Open **X-n8 AI Analysis Workflow**
2. Click on **AI Triage** node
3. Select **OpenAI - X-n8** credential
4. Click **Save**

5. Open **X-n8 Deduplication & Clustering Workflow**
6. Click on **Check Redis** node
7. Select **Redis - X-n8** credential
8. Click **Save**

### 5.4 Test AI Integration

1. Open **X-n8 AI Analysis Workflow**
2. Click **Execute Workflow**
3. Enter test data:
   ```json
   {
     "alert_id": "TEST-001",
     "event_type": "suspicious_login",
     "severity": "high",
     "entities": {
       "user": "test.user@company.com",
       "src_ip": "185.123.45.67",
       "host": "WORKSTATION-42"
     }
   }
   ```
4. Verify AI response is generated

---

## Phase 6: XSOAR Integration

### 6.1 Configure XSOAR API Credential in n8n

1. Go to **Settings** → **Credentials** → **Add Credential**
2. Select **Header Auth**
3. Configure:
   ```
   Name: XSOAR API
   Name: Authorization
   Value: your-xsoar-api-key
   ```
4. Click **Save**

### 6.2 Update Workflow with XSOAR URL

1. Open **X-n8 AI Analysis Workflow**
2. Click on **Create XSOAR Incident** node
3. Update URL to: `https://your-xsoar.company.com/incident`
4. Select **XSOAR API** credential
5. Click **Save**

### 6.3 Install X-n8 Integration in XSOAR

1. Copy integration files to XSOAR server:
   ```bash
   # On XSOAR server or via XSOAR CLI
   cp xsoar-content/Integrations/XN8Bridge/* /path/to/xsoar/content/
   ```

2. In XSOAR UI:
   - Go to **Settings** → **Integrations** → **Instances**
   - Search for **X-n8 Bridge**
   - Click **Add Instance**
   - Configure:
     ```
     Name: X-n8 Bridge
     Server URL: https://n8n.yourcompany.com
     Webhook Secret: (optional)
     ```
   - Click **Test** to verify
   - Click **Save**

### 6.4 Import XSOAR Playbooks

1. In XSOAR UI:
   - Go to **Playbooks**
   - Click **Import**
   - Select `xsoar-content/Playbooks/XN8_Master_Response.json`
   - Click **Import**

### 6.5 Create X-n8 Incident Type

1. Go to **Settings** → **Objects Setup** → **Incidents** → **Incident Types**
2. Click **New Incident Type**
3. Configure:
   - Name: `X-n8 Alert`
   - Default Playbook: `X-n8 Master Response`
   - Color: `#6366f1`
4. Click **Save**

---

## Phase 7: SIEM Integration

### 7.1 Get Webhook URL

1. In n8n, open **X-n8 Alert Ingestion Master Workflow**
2. Click on **Alert Webhook** node
3. Note the webhook URL:
   ```
   https://n8n.yourcompany.com/webhook/xn8-ingest
   ```

### 7.2 Configure SIEM (Choose Your Platform)

#### Option A: Splunk

1. Go to **Settings** → **Alert Actions**
2. Create new Webhook action:
   ```
   URL: https://n8n.yourcompany.com/webhook/xn8-ingest
   Method: POST
   Content-Type: application/json
   ```
3. Add to your alert searches

#### Option B: Microsoft Sentinel

1. Create Logic App with trigger: **When alert is created**
2. Add HTTP action:
   ```
   Method: POST
   URI: https://n8n.yourcompany.com/webhook/xn8-ingest
   Headers: Content-Type: application/json
   Body: @{triggerBody()}
   ```

#### Option C: Elastic SIEM

1. Go to **Stack Management** → **Watcher**
2. Create new Watch with Webhook action:
   ```json
   {
     "actions": {
       "xn8_webhook": {
         "webhook": {
           "method": "POST",
           "url": "https://n8n.yourcompany.com/webhook/xn8-ingest"
         }
       }
     }
   }
   ```

#### Option D: Wazuh

1. Edit `/var/ossec/etc/ossec.conf`:
   ```xml
   <integration>
     <name>custom-xn8</name>
     <hook_url>https://n8n.yourcompany.com/webhook/xn8-ingest</hook_url>
     <level>10</level>
     <alert_format>json</alert_format>
   </integration>
   ```
2. Restart Wazuh manager

### 7.3 Activate Webhook

1. In n8n, open **X-n8 Alert Ingestion Master Workflow**
2. Toggle **Active** to ON
3. Workflow is now receiving alerts!

---

## Phase 8: Monitoring Setup

### 8.1 Access Grafana

1. Open browser: `http://localhost:3000`
2. Login:
   - Username: `admin`
   - Password: `admin` (or your GRAFANA_PASSWORD)
3. Change password when prompted

### 8.2 Import X-n8 Dashboard

1. Go to **Dashboards** → **Import**
2. Click **Upload JSON file**
3. Select `monitoring/grafana/dashboards/xn8-soc-dashboard.json`
4. Click **Import**

### 8.3 Configure Alerting

1. Go to **Alerting** → **Notification Channels**
2. Add Slack channel:
   ```
   Name: SOC Alerts
   Type: Slack
   Webhook URL: https://hooks.slack.com/services/...
   ```
3. Link to alert rules

### 8.4 Verify Prometheus

1. Open `http://localhost:9090`
2. Check targets: Status → Targets
3. Verify all targets are UP

---

## Phase 9: Testing & Validation

### 9.1 Send Test Alert

```bash
# Send test alert to X-n8
curl -X POST https://n8n.yourcompany.com/webhook/xn8-ingest \
  -H "Content-Type: application/json" \
  -d '{
    "source": "test",
    "alert_id": "TEST-'$(date +%s)'",
    "severity": "high",
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "event_type": "suspicious_login",
    "entities": {
      "src_ip": "185.123.45.67",
      "user": "test.user@company.com",
      "host": "WORKSTATION-42"
    },
    "description": "Test alert for X-n8 validation"
  }'
```

### 9.2 Verify Alert Processing

1. **Check n8n Executions**:
   - Go to n8n → Executions
   - Find the test execution
   - Verify all nodes succeeded

2. **Check Slack Notification** (if configured):
   - Look for message in #soc-alerts

3. **Check XSOAR Incident** (if high severity):
   - Go to XSOAR → Incidents
   - Look for "X-n8: suspicious_login - WORKSTATION-42"

### 9.3 Validate AI Scoring

Review the AI analysis in the execution:
```json
{
  "severity_score": 75,
  "severity_label": "high",
  "confidence": 0.85,
  "is_true_positive": true,
  "summary": "Login from unusual IP...",
  "recommended_actions": [...]
}
```

### 9.4 Test Deduplication

```bash
# Send same alert 3 times
for i in 1 2 3; do
  curl -X POST https://n8n.yourcompany.com/webhook/xn8-ingest \
    -H "Content-Type: application/json" \
    -d '{
      "source": "test",
      "alert_id": "DEDUP-TEST",
      "severity": "medium",
      "entities": { "src_ip": "192.168.1.100" }
    }'
  sleep 1
done
```

Verify:
- Only 1 incident created (not 3)
- Alert count shows 3

### 9.5 End-to-End Test Matrix

| Test Case | Expected Result | Status |
|-----------|-----------------|--------|
| Low severity alert | Auto-closed, no incident | ☐ |
| Medium severity alert | Slack notification | ☐ |
| High severity alert | XSOAR incident created | ☐ |
| Duplicate alerts | Deduplicated & counted | ☐ |
| Invalid payload | Graceful error handling | ☐ |
| AI enrichment | Summary & MITRE mapping | ☐ |
| Correlation | Related alerts grouped | ☐ |

---

## Phase 10: Go-Live Checklist

### Pre-Production Checklist

#### Security
- [ ] Changed all default passwords
- [ ] Enabled HTTPS with valid certificate
- [ ] Configured firewall rules
- [ ] Enabled audit logging
- [ ] Secured API keys in vault

#### High Availability
- [ ] Configured n8n workers (>1 replica)
- [ ] Database backups scheduled
- [ ] Redis persistence enabled
- [ ] Load balancer configured (if needed)

#### Monitoring
- [ ] Grafana dashboard imported
- [ ] Prometheus alerts configured
- [ ] Slack alerting enabled
- [ ] Log aggregation setup

#### Documentation
- [ ] Runbooks available to SOC team
- [ ] Training completed for analysts
- [ ] Escalation paths documented
- [ ] On-call schedule defined

#### Testing
- [ ] All test cases passed
- [ ] Performance tested under load
- [ ] Failover tested
- [ ] Rollback procedure documented

### Go-Live Steps

1. **Notify Team**
   ```
   Subject: X-n8 Go-Live - [DATE]
   
   X-n8 SOC automation platform will be activated at [TIME].
   Expected behavior:
   - Alerts from SIEM will route through X-n8
   - AI triage will score alerts automatically
   - High severity alerts create XSOAR incidents
   
   Contact SOC Manager for issues.
   ```

2. **Enable Production SIEM Forwarding**
   - Activate alert forwarding in SIEM
   - Start with subset of rules (phased rollout)

3. **Monitor First Hour**
   - Watch Grafana dashboard
   - Check for errors in n8n executions
   - Verify XSOAR incidents are creating correctly

4. **Gradual Rollout** (Recommended)
   - Day 1: Enable 10% of alert rules
   - Day 2-3: Increase to 50%
   - Week 2: Full 100%

### Post-Go-Live

- [ ] Daily review of false positive rates
- [ ] Weekly tuning of correlation rules
- [ ] Monthly review of detection coverage
- [ ] Quarterly training refresh

---

## 🎉 Congratulations!

You have successfully deployed X-n8 (Exnate) Agentic SOC Platform!

### Quick Links

| Resource | URL |
|----------|-----|
| n8n Dashboard | http://localhost:5678 |
| Grafana | http://localhost:3000 |
| Prometheus | http://localhost:9090 |
| Documentation | [docs/](../docs/) |
| Playbook Index | [PLAYBOOK-INDEX.md](PLAYBOOK-INDEX.md) |
| Use Case Index | [USE-CASE-INDEX.md](USE-CASE-INDEX.md) |

### Getting Help

- **Issues**: [GitHub Issues](https://github.com/Masriyan/X-n8-Exnate/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Masriyan/X-n8-Exnate/discussions)
- **Documentation**: [docs/](../docs/)

---

<p align="center">
  <strong>Built with ❤️ for the Security Community</strong>
</p>

<p align="center">
  <a href="https://github.com/Masriyan/X-n8-Exnate">⭐ Star us on GitHub</a>
</p>
