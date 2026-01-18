# SIEM Connectors Guide

> **X-n8 (Exnate)** - Multi-SIEM Integration Configuration

---

## 📋 Supported SIEMs

| SIEM | Connection Type | Status |
|------|-----------------|--------|
| Splunk | HEC / REST API | ✅ Supported |
| Microsoft Sentinel | Logic Apps / Event Hub | ✅ Supported |
| IBM QRadar | HTTPS / REST API | ✅ Supported |
| Wazuh | Webhook / API | ✅ Supported |
| Elastic SIEM | Webhook / Elasticsearch | ✅ Supported |
| CrowdStrike Falcon | Webhook / Streaming API | ✅ Supported |

---

## 🔧 Splunk Configuration

### Option 1: HTTP Event Collector (HEC) Webhook

#### Step 1: Create Alert Action

In Splunk, create an alert with webhook action:

1. Navigate to **Settings** → **Searches, Reports, and Alerts**
2. Create new alert or edit existing
3. Add Action: **Webhook**
4. URL: `https://n8n.company.com/webhook/xn8-ingest`

#### Step 2: Configure Payload

```json
{
  "source": "splunk",
  "alert_id": "$result.sid$",
  "search_name": "$name$",
  "severity": "$result.severity$",
  "timestamp": "$result.time$",
  "event_type": "$result.event_type$",
  "entities": {
    "src_ip": "$result.src_ip$",
    "dst_ip": "$result.dst_ip$",
    "user": "$result.user$",
    "host": "$result.host$"
  },
  "raw_event": "$result._raw$"
}
```

### Option 2: Splunk REST API Polling

Create n8n workflow with Schedule trigger:

```javascript
// Splunk API polling node
const splunkUrl = $env.SPLUNK_URL;
const searchQuery = 'search index=security severity>=high | head 100';

const response = await $http.post(`${splunkUrl}/services/search/jobs`, {
  headers: { 
    'Authorization': `Splunk ${$env.SPLUNK_TOKEN}`,
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: `search=${encodeURIComponent(searchQuery)}&output_mode=json`
});

return response.json.results;
```

---

## ☁️ Microsoft Sentinel Configuration

### Option 1: Logic Apps Integration

#### Step 1: Create Logic App

1. In Azure Portal, create new **Logic App**
2. Trigger: **When a new alert is created**
3. Action: **HTTP Webhook**

#### Step 2: Configure HTTP Action

| Field | Value |
|-------|-------|
| Method | POST |
| URI | https://n8n.company.com/webhook/xn8-ingest |
| Headers | Content-Type: application/json |
| Body | (see below) |

```json
{
  "source": "sentinel",
  "alert_id": "@{triggerBody()?['SystemAlertId']}",
  "severity": "@{triggerBody()?['Severity']}",
  "timestamp": "@{triggerBody()?['TimeGenerated']}",
  "event_type": "@{triggerBody()?['AlertType']}",
  "entities": "@{triggerBody()?['Entities']}",
  "description": "@{triggerBody()?['Description']}",
  "tactics": "@{triggerBody()?['Tactics']}",
  "TenantId": "@{triggerBody()?['TenantId']}"
}
```

### Option 2: Azure Event Hub Streaming

```javascript
// n8n Event Hub consumer node configuration
const eventHubConfig = {
  connectionString: $env.AZURE_EVENTHUB_CONNECTION,
  eventHubName: 'sentinel-alerts',
  consumerGroup: 'x-n8-consumer'
};
```

---

## 📊 IBM QRadar Configuration

### Configure QRadar Webhook Rule

1. Navigate to **Offenses** → **Rules**
2. Create new **Event Rule**
3. Add action: **Dispatch Remote Command (HTTP)**

### Configure HTTP Dispatch

| Field | Value |
|-------|-------|
| URL | https://n8n.company.com/webhook/xn8-ingest |
| Method | POST |
| Headers | Content-Type: application/json |

### Payload Template

```json
{
  "source": "qradar",
  "alert_id": "${RULE_ID}-${START_TIME}",
  "offense_id": "${OFFENSE_ID}",
  "severity": "${MAGNITUDE}",
  "timestamp": "${START_TIME}",
  "event_type": "${RULE_NAME}",
  "entities": {
    "src_ip": "${SOURCE_IP}",
    "dst_ip": "${DESTINATION_IP}",
    "user": "${USERNAME}"
  },
  "category": "${CATEGORY}",
  "device_count": "${DEVICE_COUNT}"
}
```

---

## 🛡️ Wazuh Configuration

### Step 1: Configure Wazuh Integration

Edit `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
  <integration>
    <name>custom-xn8</name>
    <hook_url>https://n8n.company.com/webhook/xn8-ingest</hook_url>
    <level>10</level>
    <rule_id>100001,100002,100003</rule_id>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```

### Step 2: Create Integration Script

Create `/var/ossec/integrations/custom-xn8`:

```python
#!/usr/bin/env python3

import json
import sys
import requests

def main():
    alert_file = sys.argv[1]
    webhook_url = sys.argv[3]
    
    with open(alert_file) as f:
        alert = json.load(f)
    
    payload = {
        "source": "wazuh",
        "alert_id": alert.get("id"),
        "severity": "high" if alert.get("rule", {}).get("level", 0) >= 10 else "medium",
        "timestamp": alert.get("timestamp"),
        "event_type": alert.get("rule", {}).get("description"),
        "entities": {
            "src_ip": alert.get("data", {}).get("srcip"),
            "user": alert.get("data", {}).get("srcuser"),
            "host": alert.get("agent", {}).get("name")
        },
        "raw_event": alert
    }
    
    requests.post(webhook_url, json=payload)

if __name__ == "__main__":
    main()
```

### Step 3: Set Permissions

```bash
chmod 750 /var/ossec/integrations/custom-xn8
chown root:wazuh /var/ossec/integrations/custom-xn8
systemctl restart wazuh-manager
```

---

## 🔍 Elastic SIEM Configuration

### Option 1: Watcher Webhook

Create Elasticsearch Watcher:

```json
{
  "trigger": {
    "schedule": {
      "interval": "1m"
    }
  },
  "input": {
    "search": {
      "request": {
        "indices": ["logs-*"],
        "body": {
          "query": {
            "bool": {
              "must": [
                { "range": { "@timestamp": { "gte": "now-1m" } } },
                { "term": { "event.kind": "alert" } }
              ]
            }
          }
        }
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total.value": { "gt": 0 }
    }
  },
  "actions": {
    "xn8_webhook": {
      "webhook": {
        "method": "POST",
        "url": "https://n8n.company.com/webhook/xn8-ingest",
        "headers": {
          "Content-Type": "application/json"
        },
        "body": "{{#toJson}}ctx.payload{{/toJson}}"
      }
    }
  }
}
```

### Option 2: Kibana Alerting

1. Navigate to **Stack Management** → **Alerting**
2. Create rule with Elasticsearch query condition
3. Add action: **Webhook**
4. Configure URL and payload

---

## 🦅 CrowdStrike Falcon Configuration

### Streaming API Integration

Create n8n workflow with HTTP Request node:

```javascript
// CrowdStrike Streaming API consumer
const csUrl = 'https://api.crowdstrike.com/sensors/entities/datafeed/v2';

const response = await $http.get(csUrl, {
  headers: {
    'Authorization': `Bearer ${$env.CS_TOKEN}`,
    'Accept': 'application/json'
  }
});

// Transform to X-n8 format
return response.data.resources.map(event => ({
  source: 'crowdstrike',
  alert_id: event.metadata.eventId,
  severity: event.event.Severity,
  timestamp: event.metadata.eventCreationTime,
  event_type: event.metadata.eventType,
  entities: {
    host: event.event.ComputerName,
    user: event.event.UserName,
    file_hash: event.event.SHA256HashData
  }
}));
```

---

## 📐 Universal Alert Schema

All SIEM connectors should normalize to this format:

```json
{
  "alert_id": "unique-id",
  "timestamp": "2024-01-18T15:30:00Z",
  "source": "siem-name",
  "severity": "critical|high|medium|low|informational",
  "event_type": "brute_force|malware|phishing|...",
  "entities": {
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.1",
    "user": "john.doe",
    "host": "WORKSTATION-42",
    "domain": "evil.com",
    "file_hash": "abc123...",
    "url": "https://malicious.com/path"
  },
  "mitre_attack": {
    "tactic": "Credential Access",
    "technique": "Brute Force",
    "technique_id": "T1110"
  },
  "raw_event": { ... }
}
```

---

## 🧪 Testing Connectors

### Test Payload

```bash
curl -X POST https://n8n.company.com/webhook/xn8-ingest \
  -H "Content-Type: application/json" \
  -d '{
    "source": "test",
    "alert_id": "TEST-001",
    "severity": "high",
    "timestamp": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "event_type": "test_alert",
    "entities": {
      "src_ip": "192.168.1.100",
      "user": "test.user"
    }
  }'
```

### Expected Response

```json
{
  "status": "accepted",
  "alert_id": "TEST-001",
  "correlation_id": "corr-xyz789"
}
```

---

<p align="center">
  <a href="https://github.com/Masriyan/X-n8-Exnate">← Back to Repository</a>
</p>
