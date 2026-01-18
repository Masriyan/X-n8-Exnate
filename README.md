<p align="center">
  <img src="assets/banner.png" alt="X-n8 (Exnate) Banner" width="100%">
</p>

<h1 align="center">🛡️ X-n8 (Exnate)</h1>
<h3 align="center">The Nexus for Agentic SOC Automation</h3>

<p align="center">
  <strong>450 Security Use Cases • 200 Playbooks • AI-Powered Triage • Enterprise-Grade Response</strong>
</p>

<p align="center">
  <a href="https://github.com/Masriyan/X-n8-Exnate/releases"><img src="https://img.shields.io/github/v/release/Masriyan/X-n8-Exnate?style=for-the-badge&color=blue" alt="Release"></a>
  <a href="https://github.com/Masriyan/X-n8-Exnate/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Masriyan/X-n8-Exnate?style=for-the-badge&color=green" alt="License"></a>
  <a href="https://github.com/Masriyan/X-n8-Exnate/stargazers"><img src="https://img.shields.io/github/stars/Masriyan/X-n8-Exnate?style=for-the-badge&color=yellow" alt="Stars"></a>
  <a href="https://github.com/Masriyan/X-n8-Exnate/network/members"><img src="https://img.shields.io/github/forks/Masriyan/X-n8-Exnate?style=for-the-badge&color=orange" alt="Forks"></a>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#-use-cases">Use Cases</a> •
  <a href="#-playbooks">Playbooks</a> •
  <a href="#-documentation">Documentation</a> •
  <a href="#-contributing">Contributing</a>
</p>

---

## 🎯 What is X-n8?

**X-n8 (Exnate)** is a revolutionary hybrid security automation framework that combines the agility of **n8n** with the enterprise power of **Palo Alto Cortex XSOAR**. It provides SOC teams with AI-powered alert triage, automated incident response, and comprehensive threat detection across 20 security domains.

### 🌟 Key Features

| Feature | Description |
|---------|-------------|
| 🤖 **AI-Powered Triage** | LLM-based severity scoring with 0-100 confidence ratings |
| 🔄 **450 Use Cases** | Comprehensive coverage across 20 security categories |
| 📋 **200 Playbooks** | Ready-to-deploy n8n workflows with XSOAR integration |
| 🎯 **MITRE ATT&CK Mapping** | Every use case aligned to ATT&CK techniques |
| 🔗 **Multi-SIEM Support** | Splunk, Sentinel, QRadar, Wazuh, Elastic SIEM |
| ⚡ **Auto-Remediation** | Intelligent automated response actions |
| 📊 **Deduplication** | Redis-based alert clustering and correlation |
| 🔐 **Enterprise-Grade** | XSOAR integration for compliance & audit |

---

## 🏗️ Architecture

### High-Level System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           X-n8 (EXNATE) ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐ │
│  │  SPLUNK   │  │ SENTINEL  │  │  QRADAR   │  │   WAZUH   │  │  ELASTIC  │ │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘ │
│        │              │              │              │              │        │
│        └──────────────┴──────────────┴──────────────┴──────────────┘        │
│                                      │                                       │
│                                      ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                    n8n AGENTIC INTELLIGENCE LAYER                        ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    ││
│  │  │  WEBHOOK    │  │ NORMALIZER  │  │   REDIS     │  │ AI TRIAGE   │    ││
│  │  │  RECEIVER   │─▶│   ENGINE    │─▶│   DEDUP     │─▶│   AGENT     │    ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └──────┬──────┘    ││
│  └───────────────────────────────────────────────────────────────│─────────┘│
│                                                                  │          │
│        ┌─────────────────────────────────────────────────────────┘          │
│        │                                                                     │
│        ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                    DECISION ROUTER                                       ││
│  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐                ││
│  │  │   AUTO-CLOSE  │  │ HUMAN REVIEW  │  │    XSOAR      │                ││
│  │  │  Score < 30   │  │ Score 30-70   │  │  Score > 70   │                ││
│  │  └───────────────┘  └───────────────┘  └───────┬───────┘                ││
│  └─────────────────────────────────────────────────────│────────────────────┘│
│                                                        │                     │
│                                                        ▼                     │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                 XSOAR RESPONSE & ORCHESTRATION LAYER                     ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    ││
│  │  │    CASE     │  │   DBOT      │  │  PLAYBOOK   │  │ REMEDIATION │    ││
│  │  │ MANAGEMENT  │  │  SCORING    │  │  EXECUTION  │  │   ACTIONS   │    ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘    ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow Diagram

```mermaid
flowchart TD
    subgraph SIEM["📊 SIEM Sources"]
        A1[Splunk]
        A2[Sentinel]
        A3[QRadar]
        A4[Wazuh]
        A5[Elastic]
    end

    subgraph N8N["⚡ n8n Agentic Layer"]
        B1[Webhook Receiver]
        B2[Alert Normalizer]
        B3[Redis Deduplication]
        B4[AI Triage Agent]
        B5{Decision Router}
    end

    subgraph ACTIONS["🎯 Actions"]
        C1[Auto-Close FP]
        C2[Slack Notification]
        C3[XSOAR Incident]
    end

    subgraph XSOAR["🛡️ XSOAR Layer"]
        D1[Case Management]
        D2[Playbook Execution]
        D3[Remediation]
        D4[Audit Logging]
    end

    A1 & A2 & A3 & A4 & A5 --> B1
    B1 --> B2 --> B3 --> B4 --> B5
    B5 -->|Score < 30| C1
    B5 -->|Score 30-70| C2
    B5 -->|Score > 70| C3
    C3 --> D1 --> D2 --> D3 --> D4
```

### AI Agent Decision Flow

```mermaid
flowchart LR
    A[Raw Alert] --> B[Normalize]
    B --> C[Extract Entities]
    C --> D[Enrich Context]
    D --> E[AI Analysis]
    
    E --> F{Severity Score}
    
    F -->|0-29| G[Informational]
    F -->|30-49| H[Low]
    F -->|50-69| I[Medium]
    F -->|70-89| J[High]
    F -->|90-100| K[Critical]
    
    G --> L[Log Only]
    H --> M[Notify Slack]
    I --> N[Create Ticket]
    J --> O[XSOAR Incident]
    K --> P[Emergency Response]
    
    style K fill:#ff4444
    style J fill:#ff8800
    style I fill:#ffcc00
    style H fill:#88cc00
    style G fill:#44aa44
```

---

## 🚀 Quick Start

### Prerequisites

- **n8n** v1.0+ (self-hosted or cloud)
- **Redis** 6.0+ (for deduplication)
- **XSOAR** 6.0+ (Cortex XSOAR)
- **Node.js** 18+ (for local development)

### Installation

```bash
# Clone the repository
git clone https://github.com/Masriyan/X-n8-Exnate.git
cd X-n8-Exnate

# Import core workflows to n8n
n8n import:workflow --input=n8n-workflows/core/alert-ingestion.json
n8n import:workflow --input=n8n-workflows/core/ai-analysis.json
n8n import:workflow --input=n8n-workflows/core/deduplication.json

# Import category playbooks
for f in n8n-workflows/categories/**/*.json; do
  n8n import:workflow --input="$f"
done
```

### Configuration

1. **Set Environment Variables**

```bash
# Create .env file
cat > .env << EOF
# XSOAR Configuration
XSOAR_URL=https://xsoar.yourcompany.com
XSOAR_API_KEY=your-api-key

# Redis Configuration
REDIS_URL=redis://localhost:6379

# AI Configuration
OPENAI_API_KEY=your-openai-key
# OR
AZURE_OPENAI_URL=https://your-instance.openai.azure.com
AZURE_OPENAI_KEY=your-azure-key

# Notification
SLACK_BOT_TOKEN=xoxb-your-slack-token
SLACK_CHANNEL=#soc-alerts

# EDR Integration
SENTINELONE_URL=https://usea1.sentinelone.net
SENTINELONE_API_KEY=your-s1-key

# Firewall Integration
PALO_ALTO_URL=https://firewall.yourcompany.com
PALO_ALTO_API_KEY=your-pan-key
EOF
```

2. **Configure n8n Credentials**

Navigate to n8n → Settings → Credentials and add:
- OpenAI API credential
- Redis credential
- HTTP Header Auth for XSOAR
- Slack Bot credential

3. **Activate Webhooks**

Enable the Alert Ingestion workflow and note the webhook URL:
```
https://your-n8n-instance.com/webhook/xn8-ingest
```

4. **Configure SIEM Forwarding**

Point your SIEM alerts to the n8n webhook endpoint.

---

## 📚 Use Cases

### Category Overview

| # | Category | Use Cases | Description |
|---|----------|-----------|-------------|
| 1 | [API Security](docs/use-cases/01-api-security.md) | 20 | Shadow APIs, BOLA, JWT, OAuth abuse |
| 2 | [Cloud Security](docs/use-cases/02-cloud-security.md) | 25 | AWS, Azure, GCP misconfigurations |
| 3 | [DLP](docs/use-cases/03-dlp.md) | 20 | Data exfiltration detection |
| 4 | [EDR](docs/use-cases/04-edr.md) | 25 | Endpoint threats, ransomware |
| 5 | [Email Security](docs/use-cases/05-email-security.md) | 20 | Phishing, BEC, malware |
| 6 | [IAM](docs/use-cases/06-iam.md) | 20 | Identity threats, MFA abuse |
| 7 | [Firewall](docs/use-cases/07-firewall.md) | 20 | Network security, IP blocking |
| 8 | [Impossible Travel](docs/use-cases/08-impossible-travel.md) | 15 | Geographic anomalies |
| 9 | [Insider Threat](docs/use-cases/09-insider-threat.md) | 20 | User behavior analytics |
| 10 | [SaaS Security](docs/use-cases/10-saas-security.md) | 20 | O365, Salesforce, Slack |
| 11 | [WAF](docs/use-cases/11-waf.md) | 20 | Web attacks, SQLi, XSS |
| 12 | [Threat Intel](docs/use-cases/12-threat-intel.md) | 25 | IOC enrichment & correlation |
| 13 | [Network Security](docs/use-cases/13-network-security.md) | 25 | MITM, spoofing, tunneling |
| 14 | [Vulnerability Mgmt](docs/use-cases/14-vulnerability-management.md) | 25 | CVE response, patching |
| 15 | [Compliance](docs/use-cases/15-compliance-audit.md) | 25 | PCI-DSS, HIPAA, GDPR |
| 16 | [Mobile Security](docs/use-cases/16-mobile-security.md) | 25 | MDM, mobile threats |
| 17 | [OT/ICS Security](docs/use-cases/17-ot-ics-security.md) | 25 | SCADA, PLC protection |
| 18 | [DevSecOps](docs/use-cases/18-devsecops.md) | 25 | CI/CD security, supply chain |
| 19 | [Physical Security](docs/use-cases/19-physical-security.md) | 20 | Badge access, CCTV |
| 20 | [Fraud Detection](docs/use-cases/20-fraud-detection.md) | 30 | Account takeover, transaction fraud |

### Severity Distribution

```
Critical  ████████████████████  99 use cases (22%)
High      ██████████████████████████████████████  178 use cases (40%)
Medium    ██████████████████████████████  133 use cases (30%)
Low       ████████  40 use cases (8%)
```

---

## 📋 Playbooks

### Playbook Index

> **[📖 Full Playbook Index](docs/PLAYBOOK-INDEX.md)** - Complete reference for all 200 playbooks

### Core Workflows

| Playbook | Description | File |
|----------|-------------|------|
| Alert Ingestion | Main webhook with normalization | [alert-ingestion.json](n8n-workflows/core/alert-ingestion.json) |
| AI Analysis | LLM-powered triage | [ai-analysis.json](n8n-workflows/core/ai-analysis.json) |
| Deduplication | Redis clustering engine | [deduplication.json](n8n-workflows/core/deduplication.json) |

### Featured Category Playbooks

| Category | Playbook | Use Case | Description |
|----------|----------|----------|-------------|
| API | Shadow API Detection | UC-001 | Detect undocumented endpoints |
| API | BOLA Detection | UC-002 | Object-level authorization bypass |
| Cloud | S3 Public Access | UC-022 | Auto-remediate public buckets |
| EDR | Auto Isolation | UC-066 | Critical threat host isolation |
| EDR | Ransomware Response | UC-071 | Multi-stage ransomware containment |
| Email | BEC Detection | UC-092 | CEO fraud prevention |
| IAM | MFA Fatigue | UC-112 | Push notification attack detection |
| Firewall | Auto IP Block | UC-131 | Threat intel-driven blocking |
| WAF | SQL Injection | UC-206 | Auto-block SQLi attackers |

### Playbook Architecture

```
n8n-workflows/
├── core/                          # Core engine workflows
│   ├── alert-ingestion.json       # Main entry point
│   ├── ai-analysis.json           # AI triage logic
│   └── deduplication.json         # Redis dedup engine
│
└── categories/                    # Category-specific playbooks
    ├── api-security/
    │   ├── shadow-api-detection.json
    │   ├── bola-detection.json
    │   └── ...
    ├── cloud-security/
    │   ├── s3-public-access.json
    │   └── ...
    ├── edr/
    │   ├── auto-host-isolation.json
    │   ├── ransomware-response.json
    │   └── ...
    └── ...
```

---

## 📖 Documentation

### Core Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design & data flows |
| [Use Case Index](docs/USE-CASE-INDEX.md) | All 450 use cases |
| [Playbook Index](docs/PLAYBOOK-INDEX.md) | All 200 playbooks |
| [AI Agent Prompts](agent-prompts/triage-agent.md) | LLM configuration |

### Integration Guides

| Guide | Description |
|-------|-------------|
| [n8n Setup](docs/integration/n8n-setup.md) | n8n configuration |
| [XSOAR Setup](docs/integration/xsoar-setup.md) | XSOAR integration |
| [SIEM Connectors](docs/integration/siem-connectors.md) | SIEM forwarding |

### JSON Schemas

| Schema | Description |
|--------|-------------|
| [Alert Input](schemas/alert-input.json) | SIEM → n8n format |
| [Incident Output](schemas/incident-output.json) | n8n → XSOAR format |
| [Response Feedback](schemas/response-feedback.json) | XSOAR → n8n feedback |

---

## 🔧 Usage Examples

### Example 1: Ingesting a Splunk Alert

```bash
curl -X POST https://your-n8n.com/webhook/xn8-ingest \
  -H "Content-Type: application/json" \
  -d '{
    "source": "splunk",
    "alert_id": "ALERT-12345",
    "severity": "high",
    "event_type": "brute_force",
    "timestamp": "2024-01-18T15:30:00Z",
    "entities": {
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.0.50",
      "user": "john.doe",
      "host": "WORKSTATION-42"
    }
  }'
```

### Example 2: AI Triage Response

The AI agent will return a structured analysis:

```json
{
  "severity_score": 75,
  "severity_label": "high",
  "confidence": 0.85,
  "is_true_positive": true,
  "summary": "Multiple failed login attempts from internal IP targeting privileged account.",
  "mitre_tactics": ["Credential Access"],
  "mitre_techniques": ["T1110.001: Password Guessing"],
  "recommended_actions": [
    "Verify with user john.doe",
    "Check for additional failed logins",
    "Consider temporary account lock"
  ],
  "escalate_to_xsoar": true
}
```

### Example 3: XSOAR Incident Creation

When escalated, X-n8 creates an XSOAR incident:

```json
{
  "name": "X-n8: Brute Force - WORKSTATION-42",
  "severity": 3,
  "type": "IAM Security",
  "labels": [
    {"type": "Source IP", "value": "192.168.1.100"},
    {"type": "User", "value": "john.doe"},
    {"type": "MITRE", "value": "T1110.001"}
  ],
  "xn8_metadata": {
    "correlation_id": "corr-abc123",
    "ai_summary": "Multiple failed login attempts...",
    "ai_severity_score": 75,
    "ai_confidence": 0.85
  }
}
```

---

## 🗺️ Roadmap

### Version 1.0 (Current)
- [x] 450 Use Cases documented
- [x] 200 Playbooks designed
- [x] Core workflows implemented
- [x] AI Agent prompts configured
- [x] JSON schemas defined

### Version 1.1 (Planned)
- [ ] All 200 playbooks fully implemented as JSON
- [ ] XSOAR Content Pack release
- [ ] Docker Compose deployment
- [ ] Terraform IaC templates

### Version 2.0 (Future)
- [ ] Web-based dashboard
- [ ] ML-based false positive learning
- [ ] Multi-tenant support
- [ ] SOAR-agnostic adapter layer

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### How to Contribute

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Contribution Areas

- 📝 New use case documentation
- 🔧 n8n playbook implementations
- 🧪 Testing and validation
- 📖 Documentation improvements
- 🌐 Translations

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **n8n** - The workflow automation platform
- **Palo Alto Networks** - Cortex XSOAR
- **MITRE** - ATT&CK Framework
- **NIST** - Incident Response Guidelines

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Masriyan/X-n8-Exnate/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Masriyan/X-n8-Exnate/discussions)
- **Security**: [Security Policy](SECURITY.md)

---

<p align="center">
  <strong>Built with ❤️ by the X-n8 Team</strong>
</p>

<p align="center">
  <a href="https://github.com/Masriyan/X-n8-Exnate">⭐ Star us on GitHub</a>
</p>
