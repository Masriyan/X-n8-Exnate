# SaaS Security Use Cases (186-205)

> **X-n8n Playbook Collection** - Securing O365, Salesforce, Slack & Cloud Apps

---

## Overview

SaaS Security use cases focus on detecting OAuth app risks, admin configuration changes, shadow IT, and data leaks across cloud applications.

### MITRE ATT&CK Mapping
- **T1550.001** - Application Access Token
- **T1098** - Account Manipulation
- **T1213** - Data from Information Repositories

---

## Use Cases Summary

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-186 | Suspicious OAuth App Grant | Critical | T1550.001 |
| UC-187 | Admin Settings Change | High | T1098 |
| UC-188 | External Sharing Enabled | High | T1213.002 |
| UC-189 | New Admin Account Created | High | T1098 |
| UC-190 | Mailbox Delegation Added | Medium | T1098 |
| UC-191 | Risky OAuth Permission Scope | Critical | T1550.001 |
| UC-192 | SaaS Account Takeover | Critical | T1078.004 |
| UC-193 | API Connector Abuse | High | T1550.001 |
| UC-194 | Shadow IT SaaS Discovery | Medium | T1213 |
| UC-195 | Conditional Access Bypass | High | T1078.004 |
| UC-196 | Teams External Channel | Medium | T1213.002 |
| UC-197 | Salesforce Data Export | High | T1213 |
| UC-198 | Slack Webhook Creation | Medium | T1550.001 |
| UC-199 | Power Automate Risky Flow | High | T1098 |
| UC-200 | Guest User Over-Permission | Medium | T1078.003 |
| UC-201 | Third-Party App Access Review | Medium | T1550.001 |
| UC-202 | Azure AD Sign-In Anomaly | High | T1078.004 |
| UC-203 | SharePoint Anonymous Link | High | T1213.002 |
| UC-204 | Zoom Recording External Share | Medium | T1213 |
| UC-205 | SSO Configuration Change | Critical | T1556 |

---

## Sample Use Case Details

### UC-186: Suspicious OAuth App Grant

**Trigger**: User consents to high-privilege OAuth application

**n8n Logic**:
```javascript
const consent = $input.first().json;
const riskyPermissions = ['Mail.Read', 'Mail.Send', 'Directory.Read.All', 'Files.ReadWrite.All'];
const hasRiskyPerm = consent.permissions.some(p => riskyPermissions.includes(p));
const isUnknownApp = !await isApprovedApp(consent.appId);
if (hasRiskyPerm && isUnknownApp) {
  return { alert_type: "risky_oauth_consent", user: consent.user, app: consent.appName, 
           permissions: consent.permissions, severity: "critical" };
}
```

**XSOAR Actions**: Revoke consent, block app, notify user and admin

### UC-192: SaaS Account Takeover

**Trigger**: Multiple indicators of account compromise in SaaS

**n8n Logic**:
```javascript
const indicators = $input.all();
const accountTakeoverSigns = {
  passwordChange: indicators.some(i => i.json.action === 'password_change'),
  mfaChange: indicators.some(i => i.json.action === 'mfa_method_changed'),
  forwardRule: indicators.some(i => i.json.action === 'email_forward_created'),
  newLocation: indicators.some(i => i.json.newLocation === true)
};
if (Object.values(accountTakeoverSigns).filter(Boolean).length >= 2) {
  return { alert_type: "account_takeover", user: indicators[0].json.user, 
           indicators: accountTakeoverSigns, severity: "critical" };
}
```

**XSOAR Actions**: Disable account, terminate sessions, reset credentials, investigate
