# X-n8 Architecture Documentation

## System Architecture Overview

X-n8 implements a hybrid security automation architecture that leverages n8n for agile, AI-driven alert processing and XSOAR for enterprise-grade incident management and remediation.

---

## Architectural Layers

### Layer 1: SIEM Integration Layer

**Purpose**: Ingest alerts from multiple SIEM platforms

**Supported Sources**:
- Splunk (via HEC webhook, REST API)
- Microsoft Sentinel (via Logic Apps, Event Hub)
- IBM QRadar (via API, syslog)
- Wazuh (via API, webhook)
- Elastic SIEM (via webhook, Elasticsearch API)

**Integration Patterns**:
```
┌─────────────────────────────────────────────────┐
│             SIEM INTEGRATION LAYER              │
├─────────────────────────────────────────────────┤
│  Webhook Receivers    │  Polling Connectors     │
│  - HTTP POST          │  - REST API polling     │
│  - Splunk HEC         │  - Elasticsearch query  │
│  - Azure Event Grid   │  - QRadar API           │
└─────────────────────────────────────────────────┘
```

### Layer 2: n8n Agentic Intelligence Layer

**Purpose**: AI-powered alert analysis, deduplication, and decision routing

**Components**:

1. **Alert Normalization Engine**
   - Transforms vendor-specific formats to unified schema
   - Extracts entities (IPs, users, hosts, hashes)
   - Maps to MITRE ATT&CK techniques

2. **Deduplication & Clustering**
   - Content-hash based deduplication
   - Time-window aggregation (configurable)
   - Entity-based incident grouping

3. **AI Agent Analysis**
   - LLM-powered severity scoring
   - Context-aware threat assessment
   - Natural language incident summaries
   - Recommended action generation

4. **Decision Router**
   - Auto-close for known false positives
   - Human escalation for medium confidence
   - XSOAR handoff for confirmed threats

### Layer 3: XSOAR Orchestration Layer

**Purpose**: Enterprise incident management and automated remediation

**Capabilities**:
- Full incident lifecycle management
- DBOT indicator reputation scoring
- Integration with 700+ security tools
- Automated playbook execution
- Compliance and audit logging

---

## Data Flow Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          DATA FLOW                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  SIEM Alert                                                          │
│      │                                                               │
│      ▼                                                               │
│  ┌─────────────────┐                                                │
│  │  n8n Webhook    │ ← Receives raw alert                          │
│  └────────┬────────┘                                                │
│           │                                                          │
│           ▼                                                          │
│  ┌─────────────────┐                                                │
│  │  Normalize      │ ← Transform to unified schema                  │
│  └────────┬────────┘                                                │
│           │                                                          │
│           ▼                                                          │
│  ┌─────────────────┐     ┌──────────────┐                          │
│  │  Deduplicate    │────▶│ Redis Cache  │                          │
│  └────────┬────────┘     └──────────────┘                          │
│           │                                                          │
│           ▼                                                          │
│  ┌─────────────────┐     ┌──────────────┐                          │
│  │  AI Analysis    │────▶│  LLM API     │                          │
│  └────────┬────────┘     └──────────────┘                          │
│           │                                                          │
│      ┌────┴────┬────────┐                                           │
│      ▼         ▼        ▼                                           │
│  ┌───────┐ ┌───────┐ ┌───────────┐                                 │
│  │ Close │ │Notify │ │  XSOAR    │                                 │
│  │ (FP)  │ │Analyst│ │  Escalate │                                 │
│  └───────┘ └───────┘ └─────┬─────┘                                 │
│                            │                                         │
│                            ▼                                         │
│                    ┌───────────────┐                                │
│                    │ Create Case   │                                │
│                    └───────┬───────┘                                │
│                            │                                         │
│                            ▼                                         │
│                    ┌───────────────┐                                │
│                    │ Run Playbook  │                                │
│                    └───────┬───────┘                                │
│                            │                                         │
│                            ▼                                         │
│                    ┌───────────────┐                                │
│                    │ Remediate     │                                │
│                    └───────────────┘                                │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## AI Agent Architecture

### Master Triage Agent

The core AI agent responsible for initial alert assessment.

**Input**: Normalized alert with entity extraction
**Output**: Severity score, confidence, recommendations

**Capabilities**:
- Multi-factor severity scoring (0-100)
- True positive vs false positive classification
- MITRE ATT&CK technique identification
- Natural language incident summarization
- Recommended response actions

### Category-Specific Agents

Specialized agents for each security domain:

| Agent | Specialization |
|-------|---------------|
| API Security Agent | OAuth, JWT, BOLA analysis |
| Cloud Security Agent | AWS/Azure/GCP configurations |
| DLP Agent | Data exfiltration patterns |
| EDR Agent | Endpoint threat analysis |
| Email Agent | Phishing, BEC detection |
| IAM Agent | Identity threat assessment |

---

## Integration Points

### n8n to XSOAR

**Protocol**: REST API
**Authentication**: API Key
**Payload**: JSON (incident-output.json schema)

```javascript
// n8n HTTP Request Node
{
  method: 'POST',
  url: 'https://xsoar.company.com/incident',
  headers: {
    'Authorization': 'API_KEY',
    'Content-Type': 'application/json'
  },
  body: incidentPayload
}
```

### XSOAR to n8n (Feedback Loop)

**Purpose**: Closed-loop learning and tuning
**Protocol**: Webhook callback
**Payload**: JSON (response-feedback.json schema)

---

## Deployment Architecture

### Recommended Setup

```
┌─────────────────────────────────────────────────────────────────┐
│                      DEPLOYMENT TOPOLOGY                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   n8n        │  │   Redis      │  │  PostgreSQL  │          │
│  │   (Docker)   │  │   (Cache)    │  │  (State)     │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│         │                 │                 │                    │
│         └─────────────────┼─────────────────┘                   │
│                           │                                      │
│                    ┌──────┴──────┐                              │
│                    │   Network   │                              │
│                    └──────┬──────┘                              │
│                           │                                      │
│  ┌────────────────────────┴────────────────────────┐           │
│  │                    XSOAR                         │           │
│  │  (On-prem or Cortex XSOAR Cloud)                │           │
│  └──────────────────────────────────────────────────┘           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Resource Requirements

| Component | CPU | RAM | Storage |
|-----------|-----|-----|---------|
| n8n | 2 cores | 4 GB | 20 GB |
| Redis | 1 core | 2 GB | 10 GB |
| PostgreSQL | 2 cores | 4 GB | 50 GB |

---

## Security Considerations

1. **API Authentication**: All integrations use API keys or OAuth
2. **Data Encryption**: TLS 1.3 for all communications
3. **Secret Management**: Use HashiCorp Vault or similar
4. **Access Control**: RBAC for n8n workflows
5. **Audit Logging**: All actions logged for compliance
