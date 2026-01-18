# Compliance & Audit Use Cases (301-325)

> **X-n8 Playbook Collection** - Automated Compliance Monitoring

---

## Overview

Compliance & Audit use cases focus on regulatory compliance monitoring, policy enforcement, and audit trail management.

### Frameworks Covered
- SOC 2, ISO 27001, PCI-DSS, HIPAA, GDPR, NIST CSF

---

## Use Cases Summary

| ID | Use Case | Severity | Framework |
|----|----------|----------|-----------|
| UC-301 | PCI-DSS Scope Violation | Critical | PCI-DSS |
| UC-302 | HIPAA PHI Access Anomaly | High | HIPAA |
| UC-303 | GDPR Data Subject Request | Medium | GDPR |
| UC-304 | SOC 2 Control Failure | High | SOC 2 |
| UC-305 | ISO 27001 Nonconformity | Medium | ISO 27001 |
| UC-306 | Encryption at Rest Violation | High | Multiple |
| UC-307 | TLS Version Compliance | Medium | PCI-DSS |
| UC-308 | Password Policy Violation | Medium | Multiple |
| UC-309 | Access Review Overdue | Medium | SOC 2 |
| UC-310 | Privileged Access Audit | High | Multiple |
| UC-311 | Audit Log Tampering | Critical | Multiple |
| UC-312 | Log Retention Violation | Medium | Multiple |
| UC-313 | Data Classification Alert | Medium | GDPR |
| UC-314 | Cross-Border Data Transfer | High | GDPR |
| UC-315 | Vendor Risk Assessment Due | Medium | SOC 2 |
| UC-316 | Third-Party Access Review | Medium | ISO 27001 |
| UC-317 | Background Check Expiry | Low | SOC 2 |
| UC-318 | Security Training Overdue | Low | Multiple |
| UC-319 | Policy Acknowledgment Gap | Low | Multiple |
| UC-320 | Change Management Bypass | High | ITIL |
| UC-321 | Segregation of Duties | High | SOC 2 |
| UC-322 | Regulatory Report Deadline | Medium | Multiple |
| UC-323 | Evidence Collection Alert | Medium | Audit |
| UC-324 | Control Testing Due | Medium | SOC 2 |
| UC-325 | Compliance Score Threshold | Medium | Multiple |

---

## Sample Use Case Details

### UC-301: PCI-DSS Scope Violation

**Trigger**: Cardholder data detected in non-compliant environment

**n8n Logic**:
```javascript
const event = $input.first().json;
const pciScope = await getPCIScopeAssets();

if (event.dataType === 'credit_card' && !pciScope.includes(event.assetId)) {
  return {
    alert_type: "pci_scope_violation",
    asset: event.assetId,
    data_found: event.dataType,
    location: event.location,
    severity: "critical"
  };
}
```

**XSOAR Actions**: Quarantine data, notify compliance team, document for QSA

### UC-311: Audit Log Tampering Detection

**Trigger**: Modification or deletion of security audit logs

**n8n Logic**:
```javascript
const event = $input.first().json;
const criticalLogs = ['security', 'audit', 'access', 'authentication'];

if (event.action === 'modify' || event.action === 'delete') {
  if (criticalLogs.some(l => event.logName.toLowerCase().includes(l))) {
    return {
      alert_type: "log_tampering",
      log_name: event.logName,
      actor: event.user,
      action: event.action,
      severity: "critical"
    };
  }
}
```

**XSOAR Actions**: Lock actor account, preserve evidence, alert legal/compliance
