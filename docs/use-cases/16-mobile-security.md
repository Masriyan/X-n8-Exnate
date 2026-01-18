# Mobile Security Use Cases (326-350)

> **X-n8 Playbook Collection** - Mobile Device & App Security

---

## Overview

Mobile Security use cases focus on MDM/EMM security, mobile app threats, and BYOD policy enforcement.

### MITRE ATT&CK Mobile Mapping
- **T1407** - Download New Code at Runtime
- **T1406** - Obfuscated Files or Information
- **T1418** - Application Discovery

---

## Use Cases Summary

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-326 | Jailbreak/Root Detection | High | T1398 |
| UC-327 | MDM Profile Removal | High | T1398 |
| UC-328 | Unauthorized App Install | Medium | T1407 |
| UC-329 | Malicious App Detection | Critical | T1407 |
| UC-330 | App Permission Abuse | Medium | T1418 |
| UC-331 | Mobile Phishing (Smishing) | High | T1566 |
| UC-332 | SIM Swap Detection | Critical | T1451 |
| UC-333 | Device Compliance Failure | Medium | T1398 |
| UC-334 | Lost/Stolen Device Alert | High | T1398 |
| UC-335 | Remote Wipe Trigger | Critical | T1398 |
| UC-336 | USB Debugging Enabled | Medium | T1398 |
| UC-337 | Unknown Sources Enabled | Medium | T1407 |
| UC-338 | Mobile VPN Bypass | Medium | T1090 |
| UC-339 | Screen Overlay Attack | High | T1411 |
| UC-340 | Clipboard Data Theft | Medium | T1414 |
| UC-341 | Mobile Banking Trojan | Critical | T1407 |
| UC-342 | Keylogger Detection | Critical | T1417 |
| UC-343 | Camera/Mic Abuse | High | T1429 |
| UC-344 | Location Spoofing | Medium | T1430 |
| UC-345 | Bluetooth Attack Vector | Medium | T1011 |
| UC-346 | NFC Exploit Detection | Medium | T1411 |
| UC-347 | App Sideloading Alert | Medium | T1407 |
| UC-348 | Outdated OS Version | Medium | T1398 |
| UC-349 | Certificate Pinning Bypass | High | T1557 |
| UC-350 | Mobile Malware C2 | Critical | T1071 |

---

## Sample Use Case Details

### UC-326: Jailbreak/Root Detection

**Trigger**: MDM detects jailbroken iOS or rooted Android device

**n8n Logic**:
```javascript
const mdmEvent = $input.first().json;
if (mdmEvent.jailbroken === true || mdmEvent.rooted === true) {
  return {
    alert_type: "device_compromised",
    device_id: mdmEvent.deviceId,
    user: mdmEvent.assignedUser,
    platform: mdmEvent.platform,
    severity: "high"
  };
}
```

**XSOAR Actions**: Revoke corporate access, remote wipe if policy allows, notify user

### UC-332: SIM Swap Detection

**Trigger**: Mobile carrier API indicates SIM change without user verification

**n8n Logic**:
```javascript
const simEvent = $input.first().json;
const userVerified = await checkSIMChangeRequest(simEvent.phoneNumber);

if (!userVerified) {
  return {
    alert_type: "sim_swap_attack",
    phone: simEvent.phoneNumber,
    user: simEvent.associatedUser,
    new_sim: simEvent.newSimId,
    severity: "critical"
  };
}
```

**XSOAR Actions**: Lock affected accounts, disable SMS MFA, notify user via alternate channel
