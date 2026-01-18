# Insider Threat Use Cases (166-185)

> **X-n8n Playbook Collection** - User Behavior Analytics & Insider Risk

---

## Overview

Insider Threat use cases focus on detecting malicious or negligent behavior by authorized users through behavioral analytics and anomaly detection.

### MITRE ATT&CK Mapping
- **T1567** - Exfiltration Over Web Service
- **T1213** - Data from Information Repositories
- **T1530** - Data from Cloud Storage

---

## Use Cases Summary

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-166 | UBA Baseline Deviation | Medium | T1078 |
| UC-167 | After-Hours Access | Medium | T1078 |
| UC-168 | Sensitive File Access Anomaly | High | T1213 |
| UC-169 | Mass File Download | High | T1213 |
| UC-170 | Resignation Risk Correlation | High | T1567 |
| UC-171 | Privileged Access Abuse | Critical | T1078.002 |
| UC-172 | Data Hoarding Behavior | Medium | T1213 |
| UC-173 | Print Volume Anomaly | Medium | T1052 |
| UC-174 | Email Forward to Personal | High | T1114.003 |
| UC-175 | Competitor Communication | High | T1213 |
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

## Sample Use Case Details

### UC-167: Sensitive File Access After Hours

**Trigger**: Access to classified files outside business hours

**n8n Logic**:
```javascript
const event = $input.first().json;
const hour = new Date(event.timestamp).getHours();
const isAfterHours = hour < 6 || hour > 22;
const sensitiveLabels = ['confidential', 'secret', 'restricted'];
if (isAfterHours && sensitiveLabels.some(l => event.fileLabel?.includes(l))) {
  return { alert_type: "after_hours_sensitive", user: event.user, file: event.fileName, severity: "medium" };
}
```

**XSOAR Actions**: Log access, notify manager, create incident if pattern

### UC-169: Mass File Download Detection

**Trigger**: User downloading significantly more files than baseline

**n8n Logic**:
```javascript
const activity = $input.first().json;
const userBaseline = await getUserDownloadBaseline(activity.user);
if (activity.downloadCount > userBaseline * 5) {
  return { alert_type: "mass_download", user: activity.user, count: activity.downloadCount, 
           baseline: userBaseline, severity: "high" };
}
```

**XSOAR Actions**: Create insider threat incident, notify CISO, review content

### UC-170: Resignation Risk Correlation

**Trigger**: HR resignation flag combined with data access anomaly

**n8n Logic**:
```javascript
const dlpAlert = $input.first().json;
const hrFlags = await getHRRiskFlags(dlpAlert.user);
if (hrFlags.includes('resignation_pending') || hrFlags.includes('pip')) {
  return { ...dlpAlert, severity: "critical", hr_context: hrFlags, 
           alert_type: "flight_risk_data_access" };
}
```

**XSOAR Actions**: Escalate to HR, restrict data access, monitor closely
