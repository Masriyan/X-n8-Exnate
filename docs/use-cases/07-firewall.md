# Firewall Use Cases (131-150)

> **X-n8n Playbook Collection** - Network Perimeter Security Automation

---

## Overview

Firewall use cases focus on automated IP blocking, rule auditing, traffic anomaly detection, and perimeter security operations.

### MITRE ATT&CK Mapping
- **T1071** - Application Layer Protocol
- **T1046** - Network Service Scanning
- **T1090** - Proxy

---

## Use Cases Summary

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-131 | Auto-Block Malicious IP | High | T1071 |
| UC-132 | Reputation-Based Blocking | Medium | T1071 |
| UC-133 | Rule Change Audit | Medium | T1562.004 |
| UC-134 | Traffic Anomaly Detection | High | T1071 |
| UC-135 | Port Scan Detection | Medium | T1046 |
| UC-136 | Geo-Blocking Violation | Medium | T1090.003 |
| UC-137 | Expired Rule Cleanup | Low | T1562.004 |
| UC-138 | Shadow IT Detection | Medium | T1071 |
| UC-139 | C2 Beacon Detection | Critical | T1071 |
| UC-140 | DNS Tunneling via FW | Critical | T1071.004 |
| UC-141 | Outbound Tor Detection | High | T1090.003 |
| UC-142 | Protocol Anomaly | High | T1071 |
| UC-143 | Excessive Denied Traffic | Medium | T1046 |
| UC-144 | Internal Segmentation Breach | Critical | T1021 |
| UC-145 | VPN Tunnel Anomaly | High | T1133 |
| UC-146 | Cryptomining Traffic | Medium | T1496 |
| UC-147 | Data Exfil via Allowed Ports | High | T1048 |
| UC-148 | Firewall Failover Alert | Critical | T1562.004 |
| UC-149 | Rule Overlap Detection | Low | T1562.004 |
| UC-150 | High-Risk Port Exposure | High | T1133 |

---

## Sample Use Case Details

### UC-131: Auto-Block Malicious IP

**Trigger**: Threat intel match or attack detection for external IP

**n8n Logic**:
```javascript
const alert = $input.first().json;
const isExternal = !alert.sourceIP.startsWith('10.') && !alert.sourceIP.startsWith('192.168.');
if (isExternal && alert.threatScore > 80) {
  return { action: "block_ip", ip: alert.sourceIP, firewall: "perimeter", duration: "24h" };
}
```

**XSOAR Actions**: Add to blocklist, update firewall rules, log action

### UC-139: C2 Beacon Detection

**Trigger**: Periodic outbound connections matching beaconing patterns

**n8n Logic**:
```javascript
const flows = $input.all();
const byDest = {};
flows.forEach(f => {
  const key = f.json.destIP;
  if (!byDest[key]) byDest[key] = [];
  byDest[key].push(f.json.timestamp);
});
// Check for regular intervals indicating beaconing
Object.entries(byDest).forEach(([ip, times]) => {
  if (times.length > 10 && hasRegularInterval(times)) {
    return { alert_type: "c2_beacon", dest_ip: ip, severity: "critical" };
  }
});
```

**XSOAR Actions**: Block destination, isolate source host, investigate
