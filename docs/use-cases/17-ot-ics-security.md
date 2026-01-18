# OT/ICS Security Use Cases (351-375)

> **X-n8 Playbook Collection** - Operational Technology & Industrial Control Systems

---

## Overview

OT/ICS Security use cases focus on protecting industrial control systems, SCADA networks, and critical infrastructure.

### MITRE ATT&CK ICS Mapping
- **T0855** - Unauthorized Command Message
- **T0831** - Manipulation of Control
- **T0821** - Modify Controller Tasking

---

## Use Cases Summary

| ID | Use Case | Severity | MITRE ICS |
|----|----------|----------|-----------|
| UC-351 | Unauthorized PLC Access | Critical | T0855 |
| UC-352 | SCADA Protocol Anomaly | High | T0855 |
| UC-353 | HMI Unauthorized Login | High | T0823 |
| UC-354 | Firmware Modification | Critical | T0839 |
| UC-355 | Setpoint Change Alert | Critical | T0831 |
| UC-356 | Safety System Override | Critical | T0816 |
| UC-357 | OT Network Intrusion | Critical | T0866 |
| UC-358 | IT/OT Bridge Violation | High | T0866 |
| UC-359 | Engineering Workstation Anomaly | High | T0871 |
| UC-360 | Modbus Unauthorized Write | Critical | T0855 |
| UC-361 | DNP3 Protocol Abuse | Critical | T0855 |
| UC-362 | OPC UA Exploitation | High | T0855 |
| UC-363 | Historian Tampering | High | T0889 |
| UC-364 | Asset Inventory Change | Medium | T0806 |
| UC-365 | Network Baseline Deviation | Medium | T0866 |
| UC-366 | USB Device on OT Network | High | T0847 |
| UC-367 | Remote Access to OT | High | T0886 |
| UC-368 | Vendor Session Monitoring | Medium | T0886 |
| UC-369 | Industrial Malware IOC | Critical | T0882 |
| UC-370 | Default Credentials Usage | High | T0812 |
| UC-371 | Process Variable Anomaly | High | T0831 |
| UC-372 | Alarm Suppression | Critical | T0878 |
| UC-373 | Recipe/Program Download | Medium | T0843 |
| UC-374 | Time Synchronization Attack | High | T0820 |
| UC-375 | Physical Access Correlation | Medium | T0829 |

---

## Sample Use Case Details

### UC-351: Unauthorized PLC Access

**Trigger**: Connection to PLC from unauthorized source

**n8n Logic**:
```javascript
const event = $input.first().json;
const authorizedSources = await getAuthorizedOTSources(event.plcId);

if (!authorizedSources.includes(event.sourceIP)) {
  return {
    alert_type: "unauthorized_plc_access",
    plc_id: event.plcId,
    source: event.sourceIP,
    protocol: event.protocol,
    severity: "critical"
  };
}
```

**XSOAR Actions**: Block source immediately, alert OT security, preserve logs, isolate PLC if safe

### UC-355: Setpoint Change Alert

**Trigger**: Critical process setpoint modified outside maintenance window

**n8n Logic**:
```javascript
const event = $input.first().json;
const maintenanceWindow = await checkMaintenanceWindow(event.deviceId);
const criticalSetpoints = ['temperature', 'pressure', 'flow', 'level'];

if (criticalSetpoints.includes(event.setpointType) && !maintenanceWindow.active) {
  return {
    alert_type: "setpoint_change",
    device: event.deviceId,
    setpoint: event.setpointType,
    old_value: event.oldValue,
    new_value: event.newValue,
    severity: "critical"
  };
}
```

**XSOAR Actions**: Alert plant operators, log change, verify authorization, consider rollback
