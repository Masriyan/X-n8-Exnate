# Physical Security Use Cases (401-420)

> **X-n8 Playbook Collection** - Cyber-Physical Security Integration

---

## Overview

Physical Security use cases focus on integrating physical access control with cyber security monitoring.

---

## Use Cases Summary

| ID | Use Case | Severity | Type |
|----|----------|----------|------|
| UC-401 | Badge Tailgating Detection | Medium | Access |
| UC-402 | After-Hours Building Access | Medium | Access |
| UC-403 | Server Room Unauthorized Entry | Critical | Access |
| UC-404 | Badge + Login Correlation | High | Correlation |
| UC-405 | Impossible Badge + VPN | High | Correlation |
| UC-406 | Terminated Employee Badge | Critical | Access |
| UC-407 | Visitor Access Anomaly | Medium | Access |
| UC-408 | Data Center Door Held | High | Physical |
| UC-409 | CCTV Tampering Detection | High | Physical |
| UC-410 | Environmental Alert (HVAC) | Medium | Environmental |
| UC-411 | Fire Suppression Activation | Critical | Safety |
| UC-412 | UPS/Power Anomaly | Medium | Infrastructure |
| UC-413 | Badge Cloning Detection | Critical | Access |
| UC-414 | Multi-Location Access Anomaly | High | Correlation |
| UC-415 | Contractor Access Expiry | Medium | Access |
| UC-416 | Executive Protection Alert | High | VIP |
| UC-417 | Restricted Area Breach | Critical | Access |
| UC-418 | Mass Badge Creation | Medium | Admin |
| UC-419 | Access Level Change Audit | Low | Admin |
| UC-420 | Physical + Cyber Incident Link | Critical | Correlation |

---

## Sample Use Case Details

### UC-404: Badge + Login Correlation

**Trigger**: User logs into system without corresponding badge access

**n8n Logic**:
```javascript
const login = $input.first().json;
const recentBadge = await getRecentBadgeAccess(login.user, '30m');

if (!recentBadge && !login.isRemote) {
  return {
    alert_type: "badge_login_mismatch",
    user: login.user,
    login_location: login.workstation,
    last_badge: recentBadge?.location || 'none',
    severity: "high"
  };
}
```

**XSOAR Actions**: Verify user identity, check for credential sharing, alert physical security
