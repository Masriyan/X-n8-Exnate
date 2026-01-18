# IAM Use Cases (111-130)

> **X-n8n Playbook Collection** - Identity & Access Management Security

---

## Overview

IAM use cases focus on detecting identity threats including brute force, MFA bypass, privilege escalation, and suspicious account activity.

### MITRE ATT&CK Mapping
- **T1110** - Brute Force
- **T1078** - Valid Accounts
- **T1098** - Account Manipulation

---

## Use Cases Summary

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-111 | Brute Force Detection | High | T1110.001 |
| UC-112 | MFA Fatigue Attack | Critical | T1621 |
| UC-113 | Privilege Escalation Alert | Critical | T1078.002 |
| UC-114 | Dormant Account Activation | High | T1078.003 |
| UC-115 | Service Account Abuse | High | T1078.001 |
| UC-116 | Password Spray Detection | High | T1110.003 |
| UC-117 | Admin Account Lockout | Critical | T1531 |
| UC-118 | SSO Session Anomaly | High | T1550.001 |
| UC-119 | Group Membership Change | Medium | T1098.001 |
| UC-120 | API Key/Token Anomaly | High | T1552 |
| UC-121 | Guest Account Abuse | Medium | T1078.003 |
| UC-122 | PAM Checkout Anomaly | High | T1078.004 |
| UC-123 | Certificate-Based Auth Abuse | High | T1552.004 |
| UC-124 | Kerberoasting Detection | Critical | T1558.003 |
| UC-125 | Golden Ticket Detection | Critical | T1558.001 |
| UC-126 | MFA Enrollment Anomaly | Medium | T1556.006 |
| UC-127 | Recovery Email/Phone Change | High | T1098.005 |
| UC-128 | Failed Auth Threshold | Medium | T1110 |
| UC-129 | Account Takeover Indicators | Critical | T1078 |
| UC-130 | Delegated Permission Abuse | High | T1098 |

---

## Sample Use Case Details

### UC-112: MFA Fatigue Attack

**Trigger**: Multiple MFA push notifications rejected followed by acceptance

**n8n Logic**:
```javascript
const events = $input.all();
const mfaPushes = events.filter(e => e.json.eventType === 'mfa_push');
const rejected = mfaPushes.filter(e => e.json.result === 'rejected').length;
const accepted = mfaPushes.filter(e => e.json.result === 'accepted').length;
if (rejected >= 5 && accepted === 1) {
  return { alert_type: "mfa_fatigue", user: events[0].json.user, severity: "critical" };
}
```

**XSOAR Actions**: Disable user account, invalidate sessions, contact user

### UC-113: Privilege Escalation Alert

**Trigger**: User added to privileged group unexpectedly

**n8n Logic**:
```javascript
const event = $input.first().json;
const privilegedGroups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins'];
if (event.eventType === 'group_add' && privilegedGroups.includes(event.groupName)) {
  const isApproved = await checkChangeRequest(event.user, event.modifiedBy);
  if (!isApproved) return { alert_type: "privilege_escalation", severity: "critical" };
}
```

**XSOAR Actions**: Revert change, create incident, investigate modifier

### UC-124: Kerberoasting Detection

**Trigger**: Excessive Kerberos TGS requests for service accounts

**n8n Logic**:
```javascript
const events = $input.all();
const tgsRequests = events.filter(e => e.json.eventId === 4769);
const byUser = {};
tgsRequests.forEach(e => {
  byUser[e.json.user] = (byUser[e.json.user] || 0) + 1;
});
const suspicious = Object.entries(byUser).filter(([_, count]) => count > 10);
if (suspicious.length > 0) {
  return { alert_type: "kerberoasting", users: suspicious, severity: "critical" };
}
```

**XSOAR Actions**: Disable accounts, rotate service passwords, investigate
