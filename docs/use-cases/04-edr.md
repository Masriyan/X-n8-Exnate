# EDR Use Cases (66-90)

> **X-n8 Playbook Collection** - Endpoint Detection & Response Automation

---

## Overview

EDR use cases focus on endpoint security operations including automated isolation, forensic collection, lateral movement detection, and advanced threat response.

### MITRE ATT&CK Mapping
- **T1059** - Command and Scripting Interpreter
- **T1055** - Process Injection
- **T1021** - Remote Services
- **T1570** - Lateral Tool Transfer

---

## Use Cases Summary

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-066 | Auto-Isolate Critical Threat | Critical | T1486 |
| UC-067 | Forensic Memory Capture | High | T1055 |
| UC-068 | PsExec Lateral Movement | High | T1021.002 |
| UC-069 | LOLBin Abuse Detection | Medium | T1218 |
| UC-070 | LSASS Credential Dumping | Critical | T1003.001 |
| UC-071 | Ransomware Behavior Pattern | Critical | T1486 |
| UC-072 | RDP Brute Force Detection | High | T1110.001 |
| UC-073 | Malicious Scheduled Task | High | T1053.005 |
| UC-074 | C2 Framework Detection | Critical | T1059.001 |
| UC-075 | Malicious USB HID Detection | High | T1091 |
| UC-076 | WMI Persistence Detection | High | T1546.003 |
| UC-077 | DLL Side-Loading Alert | High | T1574.002 |
| UC-078 | Suspicious Kernel Driver | Critical | T1068 |
| UC-079 | Boot Sector Modification | Critical | T1542.001 |
| UC-080 | Process Relationship Anomaly | Medium | T1059 |
| UC-081 | Security Agent Tampering | Critical | T1562.001 |
| UC-082 | Known Malware Hash Match | High | T1204 |
| UC-083 | Malicious Script Execution | High | T1059 |
| UC-084 | Network Share Enumeration | Medium | T1135 |
| UC-085 | AMSI Bypass Attempt | High | T1562.001 |
| UC-086 | Alert Storm Correlation | Critical | Multiple |
| UC-087 | Browser Password Theft | High | T1555.003 |
| UC-088 | Remote Thread Injection | High | T1055.003 |
| UC-089 | System Discovery Activity | Low | T1082 |
| UC-090 | Security Config Change | Medium | T1562.002 |

---

## Sample Use Case Details

### UC-066: Auto-Isolate Critical Threat

**Trigger**: EDR critical severity alert (ransomware, wiper, rootkit)

**n8n Logic**:
```javascript
const alert = $input.first().json;
const autoIsolateCategories = ['ransomware', 'wiper', 'rootkit'];
if (alert.severity === 'critical' && autoIsolateCategories.includes(alert.threatCategory)) {
  return { action: "isolate_host", host_id: alert.hostId, severity: "critical" };
}
```

**XSOAR Actions**: Execute isolation, create incident, trigger forensics

### UC-070: LSASS Credential Dumping

**Trigger**: EDR alert for LSASS access by non-approved processes

**n8n Logic**:
```javascript
const alert = $input.first().json;
if (alert.targetProcess === 'lsass.exe' && !['csrss.exe', 'services.exe'].includes(alert.sourceProcess.toLowerCase())) {
  return { alert_type: "credential_dumping", severity: "critical" };
}
```

**XSOAR Actions**: Isolate host, rotate credentials, trigger IR playbook

### UC-074: C2 Framework Detection

**Trigger**: EDR detection of Cobalt Strike, Empire, or similar C2 signatures

**n8n Logic**:
```javascript
const c2Indicators = ['beacon', 'cobaltstrike', 'empire', 'mimikatz'];
if (c2Indicators.some(i => alert.detectionName?.toLowerCase().includes(i))) {
  return { alert_type: "c2_framework_detected", severity: "critical" };
}
```

**XSOAR Actions**: Immediate isolation, capture network state, APT response

### UC-071: Ransomware Behavior Detection

**Trigger**: Mass file modification, suspicious extensions, shadow copy deletion

**n8n Logic**:
```javascript
const indicators = {
  massFileRename: alert.fileRenameCount > 100,
  suspiciousExt: /\.(locked|encrypted|crypt)/i.test(alert.newExtension),
  shadowDelete: alert.events?.includes('vssadmin_delete')
};
if (Object.values(indicators).filter(Boolean).length >= 2) {
  return { alert_type: "ransomware_detected", severity: "critical", action: "isolate" };
}
```

**XSOAR Actions**: Immediate isolation, terminate process, verify backups
