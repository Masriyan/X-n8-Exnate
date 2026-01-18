# Impossible Travel Use Cases (151-165)

> **X-n8n Playbook Collection** - Detecting Geographic Authentication Anomalies

---

## Overview

Impossible Travel use cases detect authentication from geographically distant locations within impossible timeframes, distinguishing VPN usage from actual compromise.

### MITRE ATT&CK Mapping
- **T1078** - Valid Accounts
- **T1090.003** - Multi-hop Proxy

---

## Use Cases Summary

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-151 | Basic Impossible Travel | High | T1078 |
| UC-152 | VPN vs Geolocation Verify | Medium | T1090.003 |
| UC-153 | SaaS Login Correlation | High | T1078.004 |
| UC-154 | Corporate VPN True Location | Medium | T1078 |
| UC-155 | Mobile Device Location Mismatch | High | T1078 |
| UC-156 | Time Zone Anomaly | Medium | T1078 |
| UC-157 | Multi-Country Access Pattern | Critical | T1078 |
| UC-158 | Night Owl Detection | Low | T1078 |
| UC-159 | ISP Change Correlation | Medium | T1078 |
| UC-160 | Known VPN Provider Detection | Low | T1090.003 |
| UC-161 | Residential vs Datacenter IP | Medium | T1078 |
| UC-162 | Auth Velocity Anomaly | High | T1078 |
| UC-163 | Same Device New Location | High | T1078 |
| UC-164 | Historical Travel Pattern | Medium | T1078 |
| UC-165 | Concurrent Session Detection | Critical | T1078 |

---

## Sample Use Case Details

### UC-151: Basic Impossible Travel Detection

**Trigger**: Login from locations impossible to travel between in elapsed time

**n8n Logic**:
```javascript
const login = $input.first().json;
const previousLogin = await getLastLogin(login.user);
if (previousLogin) {
  const distance = calculateDistance(previousLogin.location, login.location);
  const timeElapsed = (login.timestamp - previousLogin.timestamp) / 3600000; // hours
  const maxPossibleSpeed = 1000; // km/h (supersonic flight)
  if (distance / timeElapsed > maxPossibleSpeed) {
    return { alert_type: "impossible_travel", user: login.user, distance, timeElapsed, severity: "high" };
  }
}
```

**XSOAR Actions**: Require MFA re-auth, create incident, notify user

### UC-152: VPN vs Geolocation Verification

**Trigger**: Impossible travel alert with one endpoint matching known VPN

**n8n Logic**:
```javascript
const alert = $input.first().json;
const vpnProviders = await getKnownVPNProviders();
const isVPN = vpnProviders.some(v => v.ranges.includes(alert.newIP));
if (isVPN) {
  // Reduce severity for known VPN usage
  return { ...alert, severity: "low", vpn_detected: true };
}
return { ...alert, severity: "high", vpn_detected: false };
```

**XSOAR Actions**: Auto-close if approved VPN, escalate if unknown

### UC-165: Concurrent Session Detection

**Trigger**: Same user authenticated from multiple distant locations simultaneously

**n8n Logic**:
```javascript
const activeSessions = $input.all();
const sessionsByUser = {};
activeSessions.forEach(s => {
  if (!sessionsByUser[s.json.user]) sessionsByUser[s.json.user] = [];
  sessionsByUser[s.json.user].push(s.json);
});
Object.entries(sessionsByUser).forEach(([user, sessions]) => {
  if (sessions.length > 1) {
    const locations = sessions.map(s => s.location);
    if (areGeographicallyDistant(locations)) {
      return { alert_type: "concurrent_impossible", user, locations, severity: "critical" };
    }
  }
});
```

**XSOAR Actions**: Terminate all sessions, lock account, investigate
