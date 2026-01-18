# XSOAR Integration Guide

> **X-n8 (Exnate)** - Palo Alto Cortex XSOAR Configuration

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Creating the Integration](#creating-the-integration)
4. [Configuring Incident Types](#configuring-incident-types)
5. [Playbook Configuration](#playbook-configuration)
6. [Webhook Configuration](#webhook-configuration)
7. [Testing the Integration](#testing-the-integration)
8. [Advanced Configuration](#advanced-configuration)

---

## 1. Overview

X-n8 integrates with XSOAR for:
- **Incident Creation**: High-severity alerts create XSOAR incidents
- **Case Management**: Full incident lifecycle management
- **Automated Response**: XSOAR playbooks for remediation
- **DBOT Scoring**: Indicator reputation management
- **Audit Trail**: Compliance and reporting

### Integration Architecture

```
┌─────────────┐      REST API       ┌─────────────┐
│    n8n      │ ─────────────────── │    XSOAR    │
│  (X-n8)     │                     │             │
│             │ ◄───────────────── │             │
│ Create      │      Webhook        │  Playbooks  │
│ Incident    │                     │  Execute    │
└─────────────┘                     └─────────────┘
```

---

## 2. Prerequisites

### XSOAR Requirements

- **XSOAR 6.0+** (Cortex XSOAR)
- **API Key** with incident creation permissions
- **Network Access** from n8n to XSOAR

### Generate API Key

1. Navigate to **Settings** → **Integrations** → **API Keys**
2. Click **Get Your Key**
3. Copy the generated API key
4. Store securely

---

## 3. Creating the Integration

### Step 1: Create X-n8 Integration Instance

Navigate to **Settings** → **Integrations** → **Instances**

Click **Add Instance** and configure:

| Field | Value |
|-------|-------|
| Name | X-n8 Bridge |
| Server URL | https://your-n8n-instance.com |
| API Key | (n8n webhook auth if configured) |

### Step 2: Verify Connectivity

```bash
# Test from XSOAR CLI
!xn8-test-connection
```

---

## 4. Configuring Incident Types

### Create X-n8 Incident Type

Navigate to **Settings** → **Objects Setup** → **Incidents** → **Incident Types**

Create new type: **X-n8 Alert**

```json
{
  "name": "X-n8 Alert",
  "color": "#6366f1",
  "defaultPlaybook": "X-n8 Master Response",
  "layout": "X-n8 Layout",
  "fields": [
    "xn8correlationid",
    "xn8aisummary",
    "xn8severityscore",
    "xn8confidence",
    "xn8mitremapping"
  ]
}
```

### Create Custom Fields

| Field Name | Type | Description |
|------------|------|-------------|
| xn8correlationid | Short Text | X-n8 correlation ID |
| xn8aisummary | Long Text | AI-generated summary |
| xn8severityscore | Number | AI severity (0-100) |
| xn8confidence | Number | AI confidence (0-1) |
| xn8mitremapping | Multi-Select | MITRE techniques |
| xn8originalalerts | JSON | Original alert data |
| xn8recommendedactions | List | AI recommended actions |

---

## 5. Playbook Configuration

### Master Response Playbook

Create playbook: **X-n8 Master Response**

```yaml
name: X-n8 Master Response
description: Master playbook for X-n8 incidents
starttaskid: "0"
tasks:
  "0":
    id: "0"
    taskid: start
    type: start
    
  "1":
    id: "1"
    taskid: extract-indicators
    type: regular
    task:
      brand: Builtin
      script: ExtractIndicatorsFromTextFile
      
  "2":
    id: "2"
    taskid: enrich-indicators
    type: playbook
    task:
      playbookId: Entity Enrichment - Generic v3
      
  "3":
    id: "3"
    taskid: route-by-category
    type: condition
    conditions:
      - condition:
          - left:
              value:
                simple: ${incident.type}
            operator: containsGeneral
            right:
              value:
                simple: EDR
        label: EDR
      - condition:
          - left:
              value:
                simple: ${incident.type}
            operator: containsGeneral
            right:
              value:
                simple: IAM
        label: IAM
      # Additional conditions...
      
  "4":
    id: "4"
    taskid: edr-response
    type: playbook
    task:
      playbookId: X-n8 EDR Response
      
  "5":
    id: "5"
    taskid: iam-response
    type: playbook
    task:
      playbookId: X-n8 IAM Response
```

### Category-Specific Playbooks

Create these sub-playbooks:

| Playbook | Description |
|----------|-------------|
| X-n8 EDR Response | Handle endpoint threats |
| X-n8 IAM Response | Handle identity threats |
| X-n8 Email Response | Handle email threats |
| X-n8 Cloud Response | Handle cloud alerts |
| X-n8 Network Response | Handle network threats |

---

## 6. Webhook Configuration

### Create Outgoing Webhook

For feedback from XSOAR to n8n:

Navigate to **Settings** → **Integrations** → **Servers & Services**

Add **Generic Webhook**:

| Field | Value |
|-------|-------|
| Name | X-n8 Feedback |
| URL | https://n8n.company.com/webhook/xsoar-feedback |
| Method | POST |
| Headers | Content-Type: application/json |

### Trigger Webhook on Close

Create automation script:

```python
# xn8_send_feedback.py
import requests

FEEDBACK_URL = demisto.params().get('feedback_url')

def send_feedback():
    incident = demisto.incident()
    
    payload = {
        "incident_id": incident.get('id'),
        "correlation_id": incident.get('CustomFields', {}).get('xn8correlationid'),
        "status": incident.get('status'),
        "closing_notes": incident.get('closeNotes'),
        "actions_taken": demisto.gets(demisto.context(), 'ActionsTaken'),
        "dbot_scores": demisto.gets(demisto.context(), 'DBotScore')
    }
    
    response = requests.post(FEEDBACK_URL, json=payload)
    return f"Feedback sent: {response.status_code}"

demisto.results(send_feedback())
```

---

## 7. Testing the Integration

### Create Test Incident

From XSOAR War Room:

```bash
!createIncident \
  name="X-n8 Test Incident" \
  type="X-n8 Alert" \
  severity=3 \
  xn8correlationid="test-123" \
  xn8aisummary="Test alert for integration validation"
```

### Verify in n8n

Check that test incident appears in n8n logs.

### Send Test from n8n

```bash
curl -X POST https://xsoar.company.com/incident \
  -H "Authorization: YOUR-API-KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "X-n8: Test Integration",
    "type": "X-n8 Alert",
    "severity": 2,
    "CustomFields": {
      "xn8correlationid": "test-456",
      "xn8aisummary": "Integration test from n8n"
    }
  }'
```

---

## 8. Advanced Configuration

### Custom Incident Layout

Create layout: **X-n8 Layout**

```json
{
  "sections": [
    {
      "name": "AI Analysis",
      "fields": [
        "xn8aisummary",
        "xn8severityscore",
        "xn8confidence",
        "xn8recommendedactions"
      ]
    },
    {
      "name": "MITRE ATT&CK",
      "fields": [
        "xn8mitremapping"
      ]
    },
    {
      "name": "Original Alerts",
      "fields": [
        "xn8originalalerts"
      ]
    }
  ]
}
```

### Indicator Auto-Extract

Configure in **Settings** → **Objects Setup** → **Indicator Extraction**:

| Content Type | Pattern |
|--------------|---------|
| IP | Extract from xn8originalalerts |
| Hash | Extract from xn8originalalerts |
| Domain | Extract from xn8originalalerts |
| URL | Extract from xn8originalalerts |

### SLA Configuration

Set SLAs for X-n8 incidents:

| Severity | Response SLA | Resolution SLA |
|----------|--------------|----------------|
| Critical | 15 minutes | 4 hours |
| High | 1 hour | 8 hours |
| Medium | 4 hours | 24 hours |
| Low | 24 hours | 72 hours |

---

## 📞 Support

- **XSOAR Docs**: [docs.paloaltonetworks.com](https://docs.paloaltonetworks.com/cortex/cortex-xsoar)
- **X-n8 Issues**: [GitHub Issues](https://github.com/Masriyan/X-n8-Exnate/issues)

---

<p align="center">
  <a href="https://github.com/Masriyan/X-n8-Exnate">← Back to Repository</a>
</p>
