# Network Security Use Cases (251-275)

> **X-n8 Playbook Collection** - Advanced Network Threat Detection

---

## Overview

Network Security use cases focus on detecting network-based threats including MITM attacks, network reconnaissance, protocol abuse, and traffic analysis.

### MITRE ATT&CK Mapping
- **T1040** - Network Sniffing
- **T1557** - Adversary-in-the-Middle
- **T1046** - Network Service Discovery

---

## Use Cases Summary

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-251 | ARP Spoofing Detection | High | T1557.002 |
| UC-252 | DNS Spoofing Alert | High | T1557.003 |
| UC-253 | DHCP Starvation Attack | Medium | T1557 |
| UC-254 | Rogue DHCP Server Detection | High | T1557 |
| UC-255 | VLAN Hopping Detection | Critical | T1599 |
| UC-256 | MAC Flooding Attack | Medium | T1557 |
| UC-257 | STP Manipulation Detection | Critical | T1557 |
| UC-258 | Network Tap Detection | High | T1040 |
| UC-259 | Promiscuous Mode Alert | Medium | T1040 |
| UC-260 | Unauthorized SPAN Port | Critical | T1040 |
| UC-261 | BGP Hijacking Detection | Critical | T1557 |
| UC-262 | Route Table Manipulation | High | T1557 |
| UC-263 | ICMP Tunnel Detection | High | T1095 |
| UC-264 | GRE Tunnel Abuse | Medium | T1572 |
| UC-265 | SSL Stripping Detection | Critical | T1557.002 |
| UC-266 | Certificate Pinning Bypass | High | T1557 |
| UC-267 | Network Segmentation Violation | Critical | T1599 |
| UC-268 | Unauthorized Subnet Access | High | T1021 |
| UC-269 | Broadcast Storm Detection | Medium | T1499 |
| UC-270 | Multicast Abuse | Low | T1095 |
| UC-271 | IPv6 Tunnel Detection | Medium | T1572 |
| UC-272 | NDP Spoofing (IPv6) | High | T1557 |
| UC-273 | Wireless Deauth Attack | High | T1557 |
| UC-274 | Evil Twin AP Detection | Critical | T1557 |
| UC-275 | Bluetooth Exploitation | Medium | T1011 |

---

## Sample Use Case Details

### UC-251: ARP Spoofing Detection

**Trigger**: Multiple MAC addresses claiming same IP or rapid ARP table changes

**n8n Logic**:
```javascript
const arpEvents = $input.all();
const ipToMac = {};
const conflicts = [];

arpEvents.forEach(e => {
  const ip = e.json.ip;
  const mac = e.json.mac;
  if (ipToMac[ip] && ipToMac[ip] !== mac) {
    conflicts.push({ ip, oldMac: ipToMac[ip], newMac: mac });
  }
  ipToMac[ip] = mac;
});

if (conflicts.length > 0) {
  return { alert_type: "arp_spoofing", conflicts, severity: "high" };
}
```

**XSOAR Actions**: Alert network team, isolate suspicious ports, update switch ACLs

### UC-274: Evil Twin AP Detection

**Trigger**: Wireless IDS detection of rogue access point with corporate SSID

**n8n Logic**:
```javascript
const widsAlert = $input.first().json;
const legitimateAPs = await getLegitimateAPList();

if (!legitimateAPs.some(ap => ap.bssid === widsAlert.bssid) && 
    widsAlert.ssid === 'CorporateWiFi') {
  return { 
    alert_type: "evil_twin_ap", 
    rogue_bssid: widsAlert.bssid,
    location: widsAlert.location,
    severity: "critical" 
  };
}
```

**XSOAR Actions**: Locate and disable rogue AP, alert physical security, notify users
