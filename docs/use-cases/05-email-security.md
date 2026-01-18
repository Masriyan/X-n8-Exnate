# Email Security Use Cases (91-110)

> **X-n8 Playbook Collection** - Protecting Against Email-Based Threats

---

## Overview

Email Security use cases focus on detecting phishing, BEC, malicious attachments, and automated response to email threats.

### MITRE ATT&CK Mapping
- **T1566** - Phishing
- **T1534** - Internal Spearphishing
- **T1114** - Email Collection

---

## Use Cases Summary

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-091 | Zero-Day Attachment Analysis | Critical | T1566.001 |
| UC-092 | BEC Detection - CEO Fraud | Critical | T1566.002 |
| UC-093 | Automated Mailbox Sweep | High | T1114.002 |
| UC-094 | Phishing Link Click Tracking | High | T1566.002 |
| UC-095 | Spoofed Domain Detection | High | T1566.002 |
| UC-096 | Mass Phishing Campaign | Critical | T1566 |
| UC-097 | Credential Harvesting Page | Critical | T1566.003 |
| UC-098 | Internal Phishing Detection | High | T1534 |
| UC-099 | Email Forwarding Rule Creation | Medium | T1114.003 |
| UC-100 | Malicious Macro Detection | High | T1566.001 |
| UC-101 | VIP Impersonation Alert | Critical | T1566.002 |
| UC-102 | Suspicious Attachment Type | Medium | T1566.001 |
| UC-103 | Vendor Email Compromise | High | T1566.002 |
| UC-104 | QR Code Phishing (Quishing) | High | T1566.002 |
| UC-105 | Thread Hijacking Detection | High | T1566 |
| UC-106 | OAuth Phishing Detection | Critical | T1566.002 |
| UC-107 | Email DLP Violation | High | T1048.003 |
| UC-108 | Suspicious Reply-To Address | Medium | T1566.002 |
| UC-109 | Password Protected Attachment | Medium | T1566.001 |
| UC-110 | Auto-Reply Loop Detection | Low | T1114 |

---

## Sample Use Case Details

### UC-091: Zero-Day Attachment Analysis

**Trigger**: Email with attachment not matching known signatures

**n8n Logic**:
```javascript
const email = $input.first().json;
if (email.attachments?.length > 0) {
  const unknownAttachments = email.attachments.filter(a => !a.signatureMatch);
  if (unknownAttachments.length > 0) {
    return { action: "sandbox_analysis", attachments: unknownAttachments, severity: "high" };
  }
}
```

**XSOAR Actions**: Submit to sandbox, quarantine if malicious, block sender

### UC-092: BEC Detection - CEO Fraud

**Trigger**: Email appearing from executive requesting urgent financial action

**n8n Logic**:
```javascript
const email = $input.first().json;
const executives = await getExecutiveList();
const urgentPatterns = /urgent|wire|transfer|immediately|confidential/i;
if (email.fromDisplayName && executives.some(e => email.fromDisplayName.includes(e)) && 
    !email.fromAddress.endsWith('@company.com') && urgentPatterns.test(email.body)) {
  return { alert_type: "bec_ceo_fraud", severity: "critical" };
}
```

**XSOAR Actions**: Quarantine email, alert recipient and security, block sender

### UC-093: Automated Mailbox Sweep

**Trigger**: Request to search and remove malicious emails across organization

**n8n Logic**:
```javascript
const ioc = $input.first().json;
// Search all mailboxes for matching criteria
const searchCriteria = {
  sender: ioc.maliciousSender,
  subject: ioc.subjectPattern,
  attachment_hash: ioc.attachmentHash
};
return { action: "mailbox_sweep", criteria: searchCriteria, action: "quarantine" };
```

**XSOAR Actions**: Execute search via Graph API/EWS, quarantine matches, report

### UC-106: OAuth Phishing Detection

**Trigger**: Email containing OAuth consent URL for suspicious app

**n8n Logic**:
```javascript
const email = $input.first().json;
const oauthPatterns = [/login\.microsoftonline\.com.*client_id=/i, /accounts\.google\.com.*client_id=/i];
if (oauthPatterns.some(p => p.test(email.body))) {
  const clientId = extractClientId(email.body);
  const isApproved = await checkApprovedOAuthApps(clientId);
  if (!isApproved) return { alert_type: "oauth_phishing", severity: "critical" };
}
```

**XSOAR Actions**: Block email, alert user, revoke if consented, block app
