# DevSecOps Use Cases (376-400)

> **X-n8 Playbook Collection** - Secure Software Development Lifecycle

---

## Overview

DevSecOps use cases focus on CI/CD pipeline security, code security scanning, and supply chain security.

### MITRE ATT&CK Mapping
- **T1195** - Supply Chain Compromise
- **T1059** - Command and Scripting Interpreter
- **T1072** - Software Deployment Tools

---

## Use Cases Summary

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-376 | SAST Critical Finding | High | T1059 |
| UC-377 | DAST Vulnerability Alert | High | T1190 |
| UC-378 | SCA Vulnerable Dependency | High | T1195.001 |
| UC-379 | Secret in Code Repository | Critical | T1552.001 |
| UC-380 | Container Image Vuln | High | T1525 |
| UC-381 | IaC Security Violation | Medium | T1195 |
| UC-382 | Pipeline Integrity Check | Critical | T1195.002 |
| UC-383 | Unauthorized Code Merge | High | T1195.002 |
| UC-384 | Build Artifact Tampering | Critical | T1195.002 |
| UC-385 | Dependency Confusion | Critical | T1195.001 |
| UC-386 | Typosquatted Package | Critical | T1195.001 |
| UC-387 | CI/CD Credential Exposure | Critical | T1552 |
| UC-388 | Unsigned Container Push | Medium | T1525 |
| UC-389 | Registry Policy Violation | Medium | T1525 |
| UC-390 | Code Signing Bypass | High | T1553.002 |
| UC-391 | Branch Protection Bypass | High | T1195.002 |
| UC-392 | Self-Hosted Runner Abuse | Critical | T1072 |
| UC-393 | GitHub Actions Injection | High | T1059 |
| UC-394 | Workflow Approval Bypass | High | T1195.002 |
| UC-395 | Third-Party Action Risk | Medium | T1195.001 |
| UC-396 | License Compliance Violation | Low | T1195 |
| UC-397 | Outdated Base Image | Medium | T1525 |
| UC-398 | Privileged Container | High | T1611 |
| UC-399 | K8s Security Context | Medium | T1611 |
| UC-400 | Artifact Provenance Failure | High | T1195.002 |

---

## Sample Use Case Details

### UC-379: Secret in Code Repository

**Trigger**: Secret scanning detects credential in committed code

**n8n Logic**:
```javascript
const secret = $input.first().json;
const secretTypes = ['api_key', 'password', 'private_key', 'token', 'aws_key'];

if (secretTypes.includes(secret.type)) {
  return {
    alert_type: "secret_in_code",
    repository: secret.repository,
    file: secret.filePath,
    secret_type: secret.type,
    committer: secret.author,
    severity: "critical"
  };
}
```

**XSOAR Actions**: Rotate exposed secret, remove from history, notify developer, block deployment

### UC-385: Dependency Confusion Attack

**Trigger**: Private package name registered in public registry

**n8n Logic**:
```javascript
const alert = $input.first().json;
const privatePackages = await getPrivatePackageList();

if (privatePackages.includes(alert.packageName) && alert.registry === 'public') {
  return {
    alert_type: "dependency_confusion",
    package: alert.packageName,
    public_registry: alert.registryUrl,
    severity: "critical"
  };
}
```

**XSOAR Actions**: Block package, claim namespace, alert security team, audit affected builds
