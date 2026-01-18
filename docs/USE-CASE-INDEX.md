# X-n8 Complete Use Case Index (1-450)

<p align="center">
  <img src="../assets/banner.png" alt="X-n8 Banner" width="100%">
</p>

> **The Nexus for Agentic SOC Automation** - All 450 Use Cases at a Glance

<p align="center">
  <a href="https://github.com/Masriyan/X-n8-Exnate">🏠 Repository</a> •
  <a href="PLAYBOOK-INDEX.md">📋 Playbooks</a> •
  <a href="architecture.md">🏗️ Architecture</a>
</p>

---

## Index by Category

### 1. API Security (UC-001 to UC-020)
[📄 Full Documentation](use-cases/01-api-security.md)

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-001 | Shadow API Discovery & Alert | Medium | T1190 |
| UC-002 | BOLA (Broken Object Level Auth) Detection | High | T1078.004 |
| UC-003 | JWT Token Tampering Detection | Critical | T1539 |
| UC-004 | API Rate Limit Bypass Detection | High | T1499.003 |
| UC-005 | Sensitive Data Exposure in API Response | High | T1530 |
| UC-006 | GraphQL Introspection Attack | Medium | T1595.002 |
| UC-007 | External API Key Leakage Detection | Critical | T1552.001 |
| UC-008 | Mass Assignment Vulnerability Exploitation | High | T1190 |
| UC-009 | API Authentication Bypass Attempt | Critical | T1556 |
| UC-010 | Broken Function Level Authorization (BFLA) | High | T1078 |
| UC-011 | API Endpoint Enumeration Detection | Medium | T1595.002 |
| UC-012 | OAuth Token Hijacking Detection | Critical | T1550.001 |
| UC-013 | API Response Manipulation (MITM) | Critical | T1557 |
| UC-014 | Server-Side Request Forgery (SSRF) via API | Critical | T1190 |
| UC-015 | Old API Version Exploitation | Medium | T1190 |
| UC-016 | WebSocket Injection Attack | High | T1190 |
| UC-017 | API Credential Stuffing Detection | High | T1110.004 |
| UC-018 | Business Logic Abuse Detection | High | T1190 |
| UC-019 | Debug Endpoint Exposure Detection | High | T1190 |
| UC-020 | API Denial of Service Detection | Critical | T1499 |

---

### 2. Cloud Security (UC-021 to UC-045)
[📄 Full Documentation](use-cases/02-cloud-security.md)

| ID | Use Case | Severity | Cloud |
|----|----------|----------|-------|
| UC-021 | IAM User Without MFA Detection | High | AWS |
| UC-022 | S3 Public Access Detection | Critical | AWS |
| UC-023 | IMDS Exploitation Detection | Critical | AWS |
| UC-024 | Azure Role Assignment Escalation | Critical | Azure |
| UC-025 | GCP Service Account Key Creation | High | GCP |
| UC-026 | Suspicious Cross-Account Access | High | AWS |
| UC-027 | Azure Blob Anonymous Access | Critical | Azure |
| UC-028 | GCP Firewall Rule Modification | High | GCP |
| UC-029 | AWS Root Account Activity | Critical | AWS |
| UC-030 | Untagged Resource Detection | Low | Multi |
| UC-031 | K8s RBAC Escalation Detection | High | K8s |
| UC-032 | CloudTrail Logging Disabled | Critical | AWS |
| UC-033 | Key Vault Anomalous Access | High | Azure |
| UC-034 | BigQuery Large Export Detection | High | GCP |
| UC-035 | Cross-Cloud Lateral Movement | Critical | Multi |
| UC-036 | Security Group 0.0.0.0/0 Rule | High | AWS |
| UC-037 | Azure Logging Disabled | Critical | Azure |
| UC-038 | Public Registry Image Pull | Medium | Containers |
| UC-039 | Lambda Permission Escalation | High | AWS |
| UC-040 | GCP Org-Level IAM Change | Critical | GCP |
| UC-041 | Secrets in Function Environment | High | Serverless |
| UC-042 | Managed Identity Token Theft | Critical | Azure |
| UC-043 | Mass Resource Deletion | Critical | Multi |
| UC-044 | Terraform State Public Access | Critical | IaC |
| UC-045 | Unusual Cloud Spending | Medium | Multi |

---

### 3. DLP - Data Loss Prevention (UC-046 to UC-065)
[📄 Full Documentation](use-cases/03-dlp.md)

| ID | Use Case | Severity | Channel |
|----|----------|----------|---------|
| UC-046 | USB Storage Device Alert | Medium | Physical |
| UC-047 | USB Data Exfiltration Detection | High | Physical |
| UC-048 | Personal Cloud Upload Detection | High | Cloud |
| UC-049 | Source Code Repository Leak | Critical | Repository |
| UC-050 | Mass File Download Alert | High | Network |
| UC-051 | Email Sensitive Data Detection | High | Email |
| UC-052 | Suspicious Print Job Detection | Medium | Physical |
| UC-053 | Screen Capture Software Alert | Medium | Endpoint |
| UC-054 | Steganography Upload Detection | High | Files |
| UC-055 | DNS Tunneling Detection | Critical | DNS |
| UC-056 | Password-Protected Archive Detection | Medium | Files |
| UC-057 | Clipboard Sensitive Data Detection | Medium | Endpoint |
| UC-058 | Unauthorized FTP Transfer Detection | High | Network |
| UC-059 | Large Database Export Alert | High | Database |
| UC-060 | Wireless File Transfer Detection | Medium | Physical |
| UC-061 | Collaboration Tool External Sharing | High | SaaS |
| UC-062 | Cloud Sync Excessive Upload | High | Cloud |
| UC-063 | API Bulk Data Export Detection | High | API |
| UC-064 | Unauthorized SaaS Usage | Medium | SaaS |
| UC-065 | File Rename DLP Evasion | High | Endpoint |

---

### 4. EDR - Endpoint Detection & Response (UC-066 to UC-090)
[📄 Full Documentation](use-cases/04-edr.md)

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-066 | Auto-Isolate Critical Threat | Critical | T1486 |
| UC-067 | Forensic Memory Capture | High | T1055 |
| UC-068 | PsExec Lateral Movement Alert | High | T1021.002 |
| UC-069 | LOLBin Abuse Detection | Medium | T1218 |
| UC-070 | LSASS Credential Dumping | Critical | T1003.001 |
| UC-071 | Ransomware Behavior Pattern | Critical | T1486 |
| UC-072 | RDP Brute Force Detection | High | T1110.001 |
| UC-073 | Malicious Scheduled Task | High | T1053.005 |
| UC-074 | C2 Framework Detection | Critical | T1059.001 |
| UC-075 | Malicious USB HID Detection | High | T1091 |
| UC-076 | WMI Persistence Detection | High | T1546.003 |
| UC-077 | DLL Side-Loading Alert | High | T1574.002 |
| UC-078 | Suspicious Kernel Driver Load | Critical | T1068 |
| UC-079 | Boot Sector Modification | Critical | T1542.001 |
| UC-080 | Process Relationship Anomaly | Medium | T1059 |
| UC-081 | Security Agent Tampering | Critical | T1562.001 |
| UC-082 | Known Malware Hash Detection | High | T1204 |
| UC-083 | Malicious Script Detection | High | T1059 |
| UC-084 | Network Share Enumeration | Medium | T1135 |
| UC-085 | AMSI Bypass Attempt | High | T1562.001 |
| UC-086 | Alert Storm Correlation | Critical | Multiple |
| UC-087 | Browser Password Theft | High | T1555.003 |
| UC-088 | Remote Thread Injection | High | T1055.003 |
| UC-089 | System Discovery Activity | Low | T1082 |
| UC-090 | Security Configuration Modification | Medium | T1562.002 |

---

### 5. Email Security (UC-091 to UC-110)
[📄 Full Documentation](use-cases/05-email-security.md)

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-091 | Zero-Day Attachment Analysis | Critical | T1566.001 |
| UC-092 | BEC Detection - CEO Fraud | Critical | T1566.002 |
| UC-093 | Automated Mailbox Sweep | High | T1114.002 |
| UC-094 | Phishing Link Click Tracking | High | T1566.002 |
| UC-095 | Spoofed Domain Detection | High | T1566.002 |
| UC-096 | Mass Phishing Campaign Detection | Critical | T1566 |
| UC-097 | Credential Harvesting Page Detection | Critical | T1566.003 |
| UC-098 | Internal Phishing Detection | High | T1534 |
| UC-099 | Email Forwarding Rule Creation | Medium | T1114.003 |
| UC-100 | Malicious Macro Detection | High | T1566.001 |
| UC-101 | VIP Impersonation Alert | Critical | T1566.002 |
| UC-102 | Suspicious Attachment Type Alert | Medium | T1566.001 |
| UC-103 | Vendor Email Compromise Detection | High | T1566.002 |
| UC-104 | QR Code Phishing (Quishing) | High | T1566.002 |
| UC-105 | Thread Hijacking Detection | High | T1566 |
| UC-106 | OAuth Phishing Detection | Critical | T1566.002 |
| UC-107 | Email DLP Violation | High | T1048.003 |
| UC-108 | Suspicious Reply-To Address | Medium | T1566.002 |
| UC-109 | Password Protected Attachment Alert | Medium | T1566.001 |
| UC-110 | Auto-Reply Loop Detection | Low | T1114 |

---

### 6. IAM - Identity & Access Management (UC-111 to UC-130)
[📄 Full Documentation](use-cases/06-iam.md)

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-111 | Brute Force Detection | High | T1110.001 |
| UC-112 | MFA Fatigue Attack Detection | Critical | T1621 |
| UC-113 | Privilege Escalation Alert | Critical | T1078.002 |
| UC-114 | Dormant Account Activation | High | T1078.003 |
| UC-115 | Service Account Abuse Detection | High | T1078.001 |
| UC-116 | Password Spray Detection | High | T1110.003 |
| UC-117 | Admin Account Lockout Alert | Critical | T1531 |
| UC-118 | SSO Session Anomaly Detection | High | T1550.001 |
| UC-119 | Group Membership Change Alert | Medium | T1098.001 |
| UC-120 | API Key/Token Anomaly | High | T1552 |
| UC-121 | Guest Account Abuse Detection | Medium | T1078.003 |
| UC-122 | PAM Checkout Anomaly | High | T1078.004 |
| UC-123 | Certificate-Based Auth Abuse | High | T1552.004 |
| UC-124 | Kerberoasting Detection | Critical | T1558.003 |
| UC-125 | Golden Ticket Detection | Critical | T1558.001 |
| UC-126 | MFA Enrollment Anomaly | Medium | T1556.006 |
| UC-127 | Recovery Email/Phone Change | High | T1098.005 |
| UC-128 | Failed Auth Threshold Alert | Medium | T1110 |
| UC-129 | Account Takeover Indicators | Critical | T1078 |
| UC-130 | Delegated Permission Abuse | High | T1098 |

---

### 7. Firewall (UC-131 to UC-150)
[📄 Full Documentation](use-cases/07-firewall.md)

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-131 | Auto-Block Malicious IP | High | T1071 |
| UC-132 | Reputation-Based Blocking | Medium | T1071 |
| UC-133 | Rule Change Audit Alert | Medium | T1562.004 |
| UC-134 | Traffic Anomaly Detection | High | T1071 |
| UC-135 | Port Scan Detection | Medium | T1046 |
| UC-136 | Geo-Blocking Violation | Medium | T1090.003 |
| UC-137 | Expired Rule Cleanup | Low | T1562.004 |
| UC-138 | Shadow IT Detection | Medium | T1071 |
| UC-139 | C2 Beacon Detection | Critical | T1071 |
| UC-140 | DNS Tunneling via FW Detection | Critical | T1071.004 |
| UC-141 | Outbound Tor Detection | High | T1090.003 |
| UC-142 | Protocol Anomaly Detection | High | T1071 |
| UC-143 | Excessive Denied Traffic Alert | Medium | T1046 |
| UC-144 | Internal Segmentation Breach | Critical | T1021 |
| UC-145 | VPN Tunnel Anomaly | High | T1133 |
| UC-146 | Cryptomining Traffic Detection | Medium | T1496 |
| UC-147 | Data Exfil via Allowed Ports | High | T1048 |
| UC-148 | Firewall Failover Alert | Critical | T1562.004 |
| UC-149 | Rule Overlap Detection | Low | T1562.004 |
| UC-150 | High-Risk Port Exposure | High | T1133 |

---

### 8. Impossible Travel (UC-151 to UC-165)
[📄 Full Documentation](use-cases/08-impossible-travel.md)

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-151 | Basic Impossible Travel Detection | High | T1078 |
| UC-152 | VPN vs Geolocation Verification | Medium | T1090.003 |
| UC-153 | SaaS Login Correlation | High | T1078.004 |
| UC-154 | Corporate VPN True Location | Medium | T1078 |
| UC-155 | Mobile Device Location Mismatch | High | T1078 |
| UC-156 | Time Zone Anomaly Detection | Medium | T1078 |
| UC-157 | Multi-Country Access Pattern | Critical | T1078 |
| UC-158 | Night Owl Detection | Low | T1078 |
| UC-159 | ISP Change Correlation | Medium | T1078 |
| UC-160 | Known VPN Provider Detection | Low | T1090.003 |
| UC-161 | Residential vs Datacenter IP | Medium | T1078 |
| UC-162 | Auth Velocity Anomaly | High | T1078 |
| UC-163 | Same Device New Location | High | T1078 |
| UC-164 | Historical Travel Pattern Analysis | Medium | T1078 |
| UC-165 | Concurrent Session Detection | Critical | T1078 |

---

### 9. Insider Threat (UC-166 to UC-185)
[📄 Full Documentation](use-cases/09-insider-threat.md)

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-166 | UBA Baseline Deviation | Medium | T1078 |
| UC-167 | After-Hours Sensitive Access | Medium | T1078 |
| UC-168 | Sensitive File Access Anomaly | High | T1213 |
| UC-169 | Mass File Download Detection | High | T1213 |
| UC-170 | Resignation Risk Correlation | High | T1567 |
| UC-171 | Privileged Access Abuse | Critical | T1078.002 |
| UC-172 | Data Hoarding Behavior | Medium | T1213 |
| UC-173 | Print Volume Anomaly | Medium | T1052 |
| UC-174 | Email Forward to Personal | High | T1114.003 |
| UC-175 | Competitor Communication Detection | High | T1213 |
| UC-176 | Access Pattern Deviation | Medium | T1078 |
| UC-177 | Badge Access Anomaly | Low | T1078 |
| UC-178 | Shared Credential Usage | High | T1078.001 |
| UC-179 | VPN Split Tunnel Abuse | Medium | T1090 |
| UC-180 | Pre-Termination Behavior | High | T1567 |
| UC-181 | Intellectual Property Access | High | T1213 |
| UC-182 | External Collaboration Spike | Medium | T1567.002 |
| UC-183 | Unusual Application Usage | Low | T1078 |
| UC-184 | Peer Comparison Anomaly | Medium | T1078 |
| UC-185 | Manager Notification Trigger | High | T1078 |

---

### 10. SaaS Security (UC-186 to UC-205)
[📄 Full Documentation](use-cases/10-saas-security.md)

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-186 | Suspicious OAuth App Grant | Critical | T1550.001 |
| UC-187 | Admin Settings Change Alert | High | T1098 |
| UC-188 | External Sharing Enabled | High | T1213.002 |
| UC-189 | New Admin Account Created | High | T1098 |
| UC-190 | Mailbox Delegation Added | Medium | T1098 |
| UC-191 | Risky OAuth Permission Scope | Critical | T1550.001 |
| UC-192 | SaaS Account Takeover Detection | Critical | T1078.004 |
| UC-193 | API Connector Abuse | High | T1550.001 |
| UC-194 | Shadow IT SaaS Discovery | Medium | T1213 |
| UC-195 | Conditional Access Bypass | High | T1078.004 |
| UC-196 | Teams External Channel Alert | Medium | T1213.002 |
| UC-197 | Salesforce Data Export Detection | High | T1213 |
| UC-198 | Slack Webhook Creation Alert | Medium | T1550.001 |
| UC-199 | Power Automate Risky Flow | High | T1098 |
| UC-200 | Guest User Over-Permission | Medium | T1078.003 |
| UC-201 | Third-Party App Access Review | Medium | T1550.001 |
| UC-202 | Azure AD Sign-In Anomaly | High | T1078.004 |
| UC-203 | SharePoint Anonymous Link Alert | High | T1213.002 |
| UC-204 | Zoom Recording External Share | Medium | T1213 |
| UC-205 | SSO Configuration Change | Critical | T1556 |

---

### 11. WAF - Web Application Firewall (UC-206 to UC-225)
[📄 Full Documentation](use-cases/11-waf.md)

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-206 | SQL Injection Mitigation | Critical | T1190 |
| UC-207 | XSS Attack Detection | High | T1059.007 |
| UC-208 | Advanced Bot Detection | Medium | T1190 |
| UC-209 | Path Traversal Attack Detection | High | T1190 |
| UC-210 | Command Injection Detection | Critical | T1059 |
| UC-211 | Rate Limit Breach Alert | Medium | T1190 |
| UC-212 | XML/XXE Injection Detection | Critical | T1190 |
| UC-213 | SSRF Detection via WAF Logs | Critical | T1190 |
| UC-214 | API Abuse Pattern Detection | High | T1190 |
| UC-215 | Credential Stuffing Detection | High | T1110.004 |
| UC-216 | Scanner Detection | Low | T1046 |
| UC-217 | Malicious File Upload Detection | High | T1190 |
| UC-218 | Session Hijacking Detection | Critical | T1550.001 |
| UC-219 | Log4j Attack Pattern Detection | Critical | T1190 |
| UC-220 | Deserialization Attack Detection | Critical | T1190 |
| UC-221 | HTTP Request Smuggling | High | T1190 |
| UC-222 | Web Shell Detection | Critical | T1505.003 |
| UC-223 | Brute Force Login Detection | High | T1110.001 |
| UC-224 | Geo-Fencing Violation | Medium | T1090.003 |
| UC-225 | Zero-Day Pattern Analysis | Critical | T1190 |

---

### 12. Threat Intelligence (UC-226 to UC-250)
[📄 Full Documentation](use-cases/12-threat-intel.md)

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-226 | VirusTotal Hash Enrichment | Variable | T1588 |
| UC-227 | AlienVault OTX Lookup | Variable | T1588 |
| UC-228 | MISP IOC Correlation | High | T1588 |
| UC-229 | IP Reputation Check | Variable | T1595 |
| UC-230 | Domain Age Analysis | Medium | T1594 |
| UC-231 | WHOIS History Lookup | Low | T1594 |
| UC-232 | Passive DNS Enrichment | Medium | T1594 |
| UC-233 | Certificate Transparency Monitoring | Low | T1594 |
| UC-234 | Threat Actor Attribution | High | T1588 |
| UC-235 | Campaign Correlation | High | T1588 |
| UC-236 | IOC Aging & Expiry Management | Low | T1588 |
| UC-237 | Custom Feed Integration | Variable | T1588 |
| UC-238 | Shodan Asset Lookup | Medium | T1595 |
| UC-239 | Dark Web Mention Alert | High | T1594 |
| UC-240 | Brand Impersonation Detection | High | T1594 |
| UC-241 | Typosquatting Detection | Medium | T1594 |
| UC-242 | APT IOC Matching | Critical | T1588 |
| UC-243 | Sandbox Detonation Analysis | High | T1588 |
| UC-244 | YARA Rule Matching | High | T1588 |
| UC-245 | STIX/TAXII Consumption | Variable | T1588 |
| UC-246 | Threat Report Parsing | Low | T1588 |
| UC-247 | IOC Deduplication | Low | T1588 |
| UC-248 | Confidence Scoring | Variable | T1588 |
| UC-249 | Historical IOC Retrohunt | High | T1588 |
| UC-250 | TI Platform Sync | Low | T1588 |

---

## Statistics

| Category | Use Cases | Critical | High | Medium | Low |
|----------|-----------|----------|------|--------|-----|
| API Security | 20 | 7 | 10 | 3 | 0 |
| Cloud Security | 25 | 11 | 10 | 3 | 1 |
| DLP | 20 | 2 | 10 | 7 | 1 |
| EDR | 25 | 8 | 12 | 4 | 1 |
| Email Security | 20 | 5 | 9 | 5 | 1 |
| IAM | 20 | 5 | 9 | 5 | 1 |
| Firewall | 20 | 4 | 7 | 7 | 2 |
| Impossible Travel | 15 | 2 | 5 | 6 | 2 |
| Insider Threat | 20 | 1 | 8 | 9 | 2 |
| SaaS Security | 20 | 4 | 9 | 6 | 1 |
| WAF | 20 | 8 | 7 | 4 | 1 |
| Threat Intel | 25 | 1 | 8 | 6 | 5 |
| **TOTAL** | **250** | **58** | **104** | **65** | **18** |
