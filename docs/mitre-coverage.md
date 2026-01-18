# X-n8 MITRE ATT&CK Navigator Layer

## Overview

This file provides a MITRE ATT&CK Navigator layer showing coverage of X-n8 use cases mapped to techniques.

## Navigator Layer JSON

Import this into [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

```json
{
  "name": "X-n8 Detection Coverage",
  "version": "4.8",
  "domain": "enterprise-attack",
  "description": "X-n8 (Exnate) 450 Use Cases - Detection Coverage Map",
  "filters": {
    "platforms": ["Windows", "Linux", "macOS", "Azure AD", "Office 365", "AWS", "GCP", "Azure"]
  },
  "sorting": 0,
  "layout": {
    "layout": "side",
    "aggregateFunction": "average",
    "showID": false,
    "showName": true
  },
  "hideDisabled": false,
  "techniques": [
    {"techniqueID": "T1110", "score": 5, "color": "#66b3ff", "comment": "UC-111, UC-116, UC-072", "enabled": true},
    {"techniqueID": "T1110.001", "score": 5, "color": "#66b3ff", "comment": "UC-111: Brute Force", "enabled": true},
    {"techniqueID": "T1110.003", "score": 5, "color": "#66b3ff", "comment": "UC-116: Password Spray", "enabled": true},
    {"techniqueID": "T1110.004", "score": 5, "color": "#66b3ff", "comment": "UC-017: Credential Stuffing", "enabled": true},
    
    {"techniqueID": "T1566", "score": 5, "color": "#ff6666", "comment": "UC-091 to UC-110: Email Security", "enabled": true},
    {"techniqueID": "T1566.001", "score": 5, "color": "#ff6666", "comment": "UC-091: Zero-Day Attachment", "enabled": true},
    {"techniqueID": "T1566.002", "score": 5, "color": "#ff6666", "comment": "UC-092: BEC Detection", "enabled": true},
    {"techniqueID": "T1566.003", "score": 5, "color": "#ff6666", "comment": "UC-097: Credential Harvesting", "enabled": true},
    
    {"techniqueID": "T1059", "score": 5, "color": "#ffcc00", "comment": "UC-066 to UC-090: EDR", "enabled": true},
    {"techniqueID": "T1059.001", "score": 5, "color": "#ffcc00", "comment": "UC-074: C2 Framework", "enabled": true},
    {"techniqueID": "T1059.003", "score": 5, "color": "#ffcc00", "comment": "UC-069: LOLBin Abuse", "enabled": true},
    
    {"techniqueID": "T1003", "score": 5, "color": "#cc66ff", "comment": "UC-070, UC-124, UC-125", "enabled": true},
    {"techniqueID": "T1003.001", "score": 5, "color": "#cc66ff", "comment": "UC-070: LSASS Dumping", "enabled": true},
    
    {"techniqueID": "T1486", "score": 5, "color": "#ff3333", "comment": "UC-066, UC-071: Ransomware", "enabled": true},
    
    {"techniqueID": "T1078", "score": 5, "color": "#66ffcc", "comment": "UC-111 to UC-130: IAM", "enabled": true},
    {"techniqueID": "T1078.001", "score": 5, "color": "#66ffcc", "comment": "UC-115: Service Account", "enabled": true},
    {"techniqueID": "T1078.002", "score": 5, "color": "#66ffcc", "comment": "UC-113: Privilege Escalation", "enabled": true},
    {"techniqueID": "T1078.003", "score": 5, "color": "#66ffcc", "comment": "UC-114, UC-121: Dormant/Guest", "enabled": true},
    {"techniqueID": "T1078.004", "score": 5, "color": "#66ffcc", "comment": "UC-122: PAM Checkout", "enabled": true},
    
    {"techniqueID": "T1190", "score": 5, "color": "#ff9933", "comment": "UC-001 to UC-020: API Security", "enabled": true},
    
    {"techniqueID": "T1530", "score": 5, "color": "#3399ff", "comment": "UC-022, UC-027: Cloud Storage", "enabled": true},
    
    {"techniqueID": "T1048", "score": 5, "color": "#ff66b3", "comment": "UC-046 to UC-065: DLP", "enabled": true},
    {"techniqueID": "T1048.003", "score": 5, "color": "#ff66b3", "comment": "UC-055: DNS Tunneling", "enabled": true},
    
    {"techniqueID": "T1621", "score": 5, "color": "#66ff66", "comment": "UC-112: MFA Fatigue", "enabled": true},
    
    {"techniqueID": "T1558", "score": 5, "color": "#cc66ff", "comment": "UC-124, UC-125: Kerberos Attacks", "enabled": true},
    {"techniqueID": "T1558.001", "score": 5, "color": "#cc66ff", "comment": "UC-125: Golden Ticket", "enabled": true},
    {"techniqueID": "T1558.003", "score": 5, "color": "#cc66ff", "comment": "UC-124: Kerberoasting", "enabled": true},
    
    {"techniqueID": "T1021", "score": 5, "color": "#ffcc66", "comment": "UC-068, UC-072: Remote Services", "enabled": true},
    {"techniqueID": "T1021.002", "score": 5, "color": "#ffcc66", "comment": "UC-068: PsExec", "enabled": true},
    
    {"techniqueID": "T1055", "score": 5, "color": "#ff99cc", "comment": "UC-067, UC-088: Process Injection", "enabled": true},
    
    {"techniqueID": "T1189", "score": 4, "color": "#cc9966", "comment": "UC-206 to UC-225: WAF", "enabled": true},
    
    {"techniqueID": "T1071", "score": 5, "color": "#996633", "comment": "UC-139: C2 Beacon", "enabled": true},
    
    {"techniqueID": "T1547", "score": 5, "color": "#669999", "comment": "UC-073, UC-076: Persistence", "enabled": true},
    {"techniqueID": "T1547.001", "score": 5, "color": "#669999", "comment": "UC-073: Scheduled Task", "enabled": true},
    
    {"techniqueID": "T1562", "score": 5, "color": "#cc3333", "comment": "UC-081, UC-085: Defense Evasion", "enabled": true},
    {"techniqueID": "T1562.001", "score": 5, "color": "#cc3333", "comment": "UC-081, UC-085: Agent/AMSI", "enabled": true}
  ],
  "gradient": {
    "colors": ["#ff6666", "#ffcc00", "#66b3ff"],
    "minValue": 0,
    "maxValue": 5
  },
  "legendItems": [
    {"label": "Critical", "color": "#ff3333"},
    {"label": "High", "color": "#ff9933"},
    {"label": "Medium", "color": "#ffcc00"},
    {"label": "Low", "color": "#66b3ff"},
    {"label": "Informational", "color": "#66ff66"}
  ],
  "metadata": [],
  "showTacticRowBackground": true,
  "tacticRowBackground": "#dddddd"
}
```

## Coverage Summary

| MITRE Tactic | Techniques Covered | Use Cases |
|--------------|-------------------|-----------|
| Initial Access | 8 | 45 |
| Execution | 12 | 35 |
| Persistence | 10 | 25 |
| Privilege Escalation | 8 | 30 |
| Defense Evasion | 15 | 40 |
| Credential Access | 10 | 45 |
| Discovery | 8 | 20 |
| Lateral Movement | 6 | 25 |
| Collection | 5 | 20 |
| Command and Control | 8 | 30 |
| Exfiltration | 6 | 25 |
| Impact | 5 | 20 |

## Using the Navigator

1. Go to [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
2. Click **Open Existing Layer** → **Upload from Local**
3. Paste the JSON above
4. Visualize X-n8 coverage

## Gap Analysis

### Well-Covered (5+ Use Cases)
- Credential Access (T1110, T1003, T1558)
- Initial Access - Phishing (T1566)
- Impact - Ransomware (T1486)
- Persistence (T1547)

### Moderate Coverage (2-4 Use Cases)
- Lateral Movement (T1021)
- Defense Evasion (T1562)
- Collection (T1119)

### Expansion Opportunities
- Resource Development
- Reconnaissance (external)
- Pre-compromise techniques
