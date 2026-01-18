# Cloud Security Use Cases (21-45)

> **X-n8 Playbook Collection** - Securing AWS, Azure, and GCP Environments

---

## Overview

Cloud Security use cases focus on detecting misconfigurations, unauthorized access, and malicious activities across multi-cloud environments including AWS, Azure, and Google Cloud Platform.

### MITRE ATT&CK Mapping
- **T1078.004** - Cloud Accounts
- **T1537** - Transfer Data to Cloud Account
- **T1580** - Cloud Infrastructure Discovery
- **T1619** - Cloud Storage Object Discovery

---

## Use Cases

### UC-021: AWS IAM User Creation Without MFA

| Field | Value |
|-------|-------|
| **ID** | UC-021 |
| **Name** | IAM User Without MFA Detection |
| **Category** | Cloud Security - AWS |
| **Severity** | High |
| **MITRE ATT&CK** | T1078.004 |

**Description**: Detect creation of IAM users without MFA enforcement, which poses a security risk.

**Trigger**: CloudTrail CreateUser event without immediate MFA assignment

**n8n Logic**:
```javascript
const event = $input.first().json;
if (event.eventName === 'CreateUser') {
  const userId = event.responseElements.user.userId;
  // Check MFA status after 5 min delay
  setTimeout(async () => {
    const mfaDevices = await checkUserMFA(userId);
    if (mfaDevices.length === 0) {
      return { alert_type: "iam_user_no_mfa", userId, severity: "high" };
    }
  }, 300000);
}
```

**XSOAR Actions**:
- Create compliance incident
- Notify AWS administrator
- Enable MFA requirement policy

---

### UC-022: S3 Bucket Public Access Enabled

| Field | Value |
|-------|-------|
| **ID** | UC-022 |
| **Name** | S3 Public Access Detection |
| **Category** | Cloud Security - AWS |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1530 |

**Description**: Detect S3 buckets with public access enabled, exposing sensitive data.

**Trigger**: CloudTrail PutBucketAcl or PutBucketPolicy with public access

**n8n Logic**:
```javascript
const event = $input.first().json;
const publicIndicators = ['AllUsers', 'AuthenticatedUsers', '*'];

if (event.eventName.includes('PutBucket')) {
  const policy = JSON.stringify(event.requestParameters);
  if (publicIndicators.some(i => policy.includes(i))) {
    return {
      alert_type: "s3_public_access",
      bucket: event.requestParameters.bucketName,
      severity: "critical"
    };
  }
}
```

**XSOAR Actions**:
- Immediately revert bucket to private
- Create critical incident
- Scan bucket for sensitive data
- Notify data owners

---

### UC-023: AWS EC2 Metadata Service Exploitation

| Field | Value |
|-------|-------|
| **ID** | UC-023 |
| **Name** | IMDS Exploitation Detection |
| **Category** | Cloud Security - AWS |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1552.005 |

**Description**: Detect attempts to access EC2 Instance Metadata Service for credential theft.

**Trigger**: Network logs showing requests to 169.254.169.254

**n8n Logic**:
```javascript
const request = $input.first().json;
if (request.destination_ip === '169.254.169.254') {
  const suspiciousPath = request.path.includes('iam') || 
                         request.path.includes('security-credentials');
  return {
    alert_type: "imds_access",
    instance_id: request.source_instance,
    path: request.path,
    severity: suspiciousPath ? "critical" : "medium"
  };
}
```

**XSOAR Actions**:
- Isolate EC2 instance
- Rotate IAM role credentials
- Create critical incident
- Forensic memory capture

---

### UC-024: Azure Subscription Privilege Escalation

| Field | Value |
|-------|-------|
| **ID** | UC-024 |
| **Name** | Azure Role Assignment Escalation |
| **Category** | Cloud Security - Azure |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1078.004 |

**Description**: Detect unauthorized privilege escalation through Azure role assignments.

**Trigger**: Azure Activity Log - Microsoft.Authorization/roleAssignments/write

**n8n Logic**:
```javascript
const event = $input.first().json;
const privilegedRoles = ['Owner', 'Contributor', 'User Access Administrator'];

if (event.operationName.includes('roleAssignments/write')) {
  const assignedRole = event.properties.requestbody.properties.roleDefinitionId;
  if (privilegedRoles.some(r => assignedRole.includes(r))) {
    return {
      alert_type: "azure_privilege_escalation",
      assigned_by: event.caller,
      role: assignedRole,
      severity: "critical"
    };
  }
}
```

**XSOAR Actions**:
- Revoke role assignment
- Create critical incident
- Notify security team
- Review all recent role changes

---

### UC-025: GCP Service Account Key Export

| Field | Value |
|-------|-------|
| **ID** | UC-025 |
| **Name** | GCP Service Account Key Creation |
| **Category** | Cloud Security - GCP |
| **Severity** | High |
| **MITRE ATT&CK** | T1552.001 |

**Description**: Detect creation of service account keys which can lead to credential exposure.

**Trigger**: GCP Audit Log - CreateServiceAccountKey

**n8n Logic**:
```javascript
const event = $input.first().json;
if (event.methodName === 'google.iam.admin.v1.CreateServiceAccountKey') {
  return {
    alert_type: "gcp_sa_key_created",
    service_account: event.resourceName,
    created_by: event.authenticationInfo.principalEmail,
    severity: "high"
  };
}
```

**XSOAR Actions**:
- Create compliance incident
- Verify key necessity with owner
- Set key expiration reminder
- Update key inventory

---

### UC-026: Cross-Account AssumeRole Abuse

| Field | Value |
|-------|-------|
| **ID** | UC-026 |
| **Name** | Suspicious Cross-Account Access |
| **Category** | Cloud Security - AWS |
| **Severity** | High |
| **MITRE ATT&CK** | T1078.004 |

**Description**: Detect unusual cross-account role assumptions.

**Trigger**: CloudTrail AssumeRole from unknown accounts

**n8n Logic**:
```javascript
const event = $input.first().json;
const trustedAccounts = await getTrustedAccountList();

if (event.eventName === 'AssumeRole') {
  const sourceAccount = event.userIdentity.accountId;
  if (!trustedAccounts.includes(sourceAccount)) {
    return {
      alert_type: "untrusted_assume_role",
      source_account: sourceAccount,
      target_role: event.requestParameters.roleArn,
      severity: "high"
    };
  }
}
```

**XSOAR Actions**:
- Review trust policy
- Create incident
- Block account if malicious
- Update trusted account list

---

### UC-027: Azure Storage Container Anonymous Access

| Field | Value |
|-------|-------|
| **ID** | UC-027 |
| **Name** | Azure Blob Anonymous Access |
| **Category** | Cloud Security - Azure |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1530 |

**Description**: Detect Azure storage containers with anonymous access enabled.

**Trigger**: Storage account configuration change to public access

**n8n Logic**:
```javascript
const event = $input.first().json;
if (event.operationName === 'Microsoft.Storage/storageAccounts/blobServices/containers/write') {
  const publicAccess = event.properties.responseBody?.publicAccess;
  if (publicAccess === 'Container' || publicAccess === 'Blob') {
    return {
      alert_type: "azure_blob_public",
      container: event.resourceId,
      access_level: publicAccess,
      severity: "critical"
    };
  }
}
```

**XSOAR Actions**:
- Disable public access
- Scan container for sensitive data
- Create critical incident
- Notify data owner

---

### UC-028: GCP VPC Firewall Rule Weakening

| Field | Value |
|-------|-------|
| **ID** | UC-028 |
| **Name** | GCP Firewall Rule Modification |
| **Category** | Cloud Security - GCP |
| **Severity** | High |
| **MITRE ATT&CK** | T1562.007 |

**Description**: Detect modifications to VPC firewall rules that weaken security posture.

**Trigger**: GCP Audit Log - compute.firewalls.patch/insert with 0.0.0.0/0

**n8n Logic**:
```javascript
const event = $input.first().json;
if (event.methodName.includes('compute.firewalls')) {
  const sourceRanges = event.request?.sourceRanges || [];
  if (sourceRanges.includes('0.0.0.0/0')) {
    return {
      alert_type: "gcp_firewall_open",
      rule_name: event.resourceName,
      allowed: event.request.allowed,
      severity: "high"
    };
  }
}
```

**XSOAR Actions**:
- Revert firewall rule
- Create incident
- Notify network team
- Review change request

---

### UC-029: AWS Root Account Usage

| Field | Value |
|-------|-------|
| **ID** | UC-029 |
| **Name** | AWS Root Account Activity |
| **Category** | Cloud Security - AWS |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1078.004 |

**Description**: Detect any usage of the AWS root account which should be avoided.

**Trigger**: CloudTrail events with Root user identity

**n8n Logic**:
```javascript
const event = $input.first().json;
if (event.userIdentity.type === 'Root') {
  return {
    alert_type: "aws_root_usage",
    event: event.eventName,
    source_ip: event.sourceIPAddress,
    severity: "critical"
  };
}
```

**XSOAR Actions**:
- Create critical incident
- Notify AWS account owners
- Verify legitimate use
- Review root account MFA

---

### UC-030: Cloud Resource Tagging Violation

| Field | Value |
|-------|-------|
| **ID** | UC-030 |
| **Name** | Untagged Resource Detection |
| **Category** | Cloud Security - Multi-Cloud |
| **Severity** | Low |
| **MITRE ATT&CK** | T1580 |

**Description**: Detect cloud resources created without required compliance tags.

**Trigger**: Resource creation events without mandatory tags

**n8n Logic**:
```javascript
const event = $input.first().json;
const requiredTags = ['Owner', 'CostCenter', 'Environment', 'Project'];
const resourceTags = event.tags || {};

const missingTags = requiredTags.filter(t => !resourceTags[t]);

if (missingTags.length > 0) {
  return {
    alert_type: "missing_tags",
    resource_id: event.resourceId,
    missing: missingTags,
    severity: "low"
  };
}
```

**XSOAR Actions**:
- Create compliance ticket
- Notify resource owner
- Auto-tag if possible
- Generate compliance report

---

### UC-031: Kubernetes RBAC Privilege Escalation

| Field | Value |
|-------|-------|
| **ID** | UC-031 |
| **Name** | K8s RBAC Escalation Detection |
| **Category** | Cloud Security - Kubernetes |
| **Severity** | High |
| **MITRE ATT&CK** | T1078.004 |

**Description**: Detect privilege escalation attempts in Kubernetes through RBAC manipulation.

**Trigger**: K8s audit log showing ClusterRoleBinding creation

**n8n Logic**:
```javascript
const event = $input.first().json;
const privilegedRoles = ['cluster-admin', 'admin', 'edit'];

if (event.objectRef.resource === 'clusterrolebindings') {
  if (event.verb === 'create' || event.verb === 'update') {
    const roleRef = event.requestObject?.roleRef?.name;
    if (privilegedRoles.includes(roleRef)) {
      return {
        alert_type: "k8s_rbac_escalation",
        user: event.user.username,
        role: roleRef,
        severity: "high"
      };
    }
  }
}
```

**XSOAR Actions**:
- Review and potentially revoke binding
- Create incident
- Notify cluster admin
- Audit all RBAC changes

---

### UC-032: AWS CloudTrail Disabled

| Field | Value |
|-------|-------|
| **ID** | UC-032 |
| **Name** | CloudTrail Logging Disabled |
| **Category** | Cloud Security - AWS |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1562.008 |

**Description**: Detect attempts to disable CloudTrail logging for defense evasion.

**Trigger**: CloudTrail StopLogging or DeleteTrail events

**n8n Logic**:
```javascript
const event = $input.first().json;
const dangerousEvents = ['StopLogging', 'DeleteTrail', 'UpdateTrail'];

if (dangerousEvents.includes(event.eventName)) {
  return {
    alert_type: "cloudtrail_disabled",
    event: event.eventName,
    trail: event.requestParameters.name,
    actor: event.userIdentity.arn,
    severity: "critical"
  };
}
```

**XSOAR Actions**:
- Re-enable CloudTrail immediately
- Create critical incident
- Lock actor account
- Trigger IR playbook

---

### UC-033: Azure Key Vault Secret Access Anomaly

| Field | Value |
|-------|-------|
| **ID** | UC-033 |
| **Name** | Key Vault Anomalous Access |
| **Category** | Cloud Security - Azure |
| **Severity** | High |
| **MITRE ATT&CK** | T1552.001 |

**Description**: Detect unusual access patterns to Azure Key Vault secrets.

**Trigger**: Key Vault access from new IP or unusual volume

**n8n Logic**:
```javascript
const event = $input.first().json;
const knownSources = await getKnownKeyVaultSources(event.vaultName);

if (event.operationName === 'SecretGet') {
  if (!knownSources.includes(event.callerIpAddress)) {
    return {
      alert_type: "keyvault_anomaly",
      vault: event.vaultName,
      secret: event.properties.id,
      source_ip: event.callerIpAddress,
      severity: "high"
    };
  }
}
```

**XSOAR Actions**:
- Rotate accessed secrets
- Create incident
- Block source IP if malicious
- Review access policies

---

### UC-034: GCP BigQuery Data Exfiltration

| Field | Value |
|-------|-------|
| **ID** | UC-034 |
| **Name** | BigQuery Large Export Detection |
| **Category** | Cloud Security - GCP |
| **Severity** | High |
| **MITRE ATT&CK** | T1537 |

**Description**: Detect large data exports from BigQuery indicating potential exfiltration.

**Trigger**: BigQuery export job exceeding size threshold

**n8n Logic**:
```javascript
const event = $input.first().json;
const exportThresholdGB = 10;

if (event.methodName === 'google.cloud.bigquery.v2.JobService.InsertJob') {
  if (event.request.configuration?.extract) {
    const bytesProcessed = event.response?.statistics?.totalBytesProcessed;
    if (bytesProcessed > exportThresholdGB * 1024 * 1024 * 1024) {
      return {
        alert_type: "bigquery_large_export",
        dataset: event.resourceName,
        size_gb: bytesProcessed / (1024 * 1024 * 1024),
        user: event.authenticationInfo.principalEmail,
        severity: "high"
      };
    }
  }
}
```

**XSOAR Actions**:
- Create DLP incident
- Notify data owner
- Review export destination
- Consider blocking job

---

### UC-035: Multi-Cloud Lateral Movement

| Field | Value |
|-------|-------|
| **ID** | UC-035 |
| **Name** | Cross-Cloud Lateral Movement |
| **Category** | Cloud Security - Multi-Cloud |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1580 |

**Description**: Detect actor accessing multiple cloud providers using same compromised credentials.

**Trigger**: Same identity accessing AWS, Azure, GCP within short timeframe

**n8n Logic**:
```javascript
const events = $input.all();
const groupedByEmail = {};

events.forEach(e => {
  const email = e.json.userEmail || e.json.userIdentity?.userName;
  if (!groupedByEmail[email]) groupedByEmail[email] = new Set();
  groupedByEmail[email].add(e.json.cloudProvider);
});

const multiCloudUsers = Object.entries(groupedByEmail)
  .filter(([_, clouds]) => clouds.size >= 2)
  .map(([email, clouds]) => ({ email, clouds: [...clouds] }));

if (multiCloudUsers.length > 0) {
  return {
    alert_type: "multi_cloud_access",
    users: multiCloudUsers,
    severity: "critical"
  };
}
```

**XSOAR Actions**:
- Disable accounts across all clouds
- Create critical incident
- Trigger unified IR playbook
- Rotate all credentials

---

### UC-036: AWS Security Group Wide Open

| Field | Value |
|-------|-------|
| **ID** | UC-036 |
| **Name** | Security Group 0.0.0.0/0 Rule |
| **Category** | Cloud Security - AWS |
| **Severity** | High |
| **MITRE ATT&CK** | T1562.007 |

**Description**: Detect security groups allowing inbound traffic from 0.0.0.0/0 on sensitive ports.

**Trigger**: AuthorizeSecurityGroupIngress with 0.0.0.0/0

**n8n Logic**:
```javascript
const event = $input.first().json;
const sensitivePorts = [22, 3389, 1433, 3306, 5432, 27017];

if (event.eventName === 'AuthorizeSecurityGroupIngress') {
  const rules = event.requestParameters.ipPermissions?.items || [];
  
  for (const rule of rules) {
    const isOpenWorld = rule.ipRanges?.items?.some(r => r.cidrIp === '0.0.0.0/0');
    const isSensitivePort = sensitivePorts.includes(rule.toPort);
    
    if (isOpenWorld && isSensitivePort) {
      return {
        alert_type: "sg_wide_open",
        security_group: event.requestParameters.groupId,
        port: rule.toPort,
        severity: "high"
      };
    }
  }
}
```

**XSOAR Actions**:
- Revoke the rule
- Create incident
- Notify security team
- Scan for exposed assets

---

### UC-037: Azure Diagnostic Settings Deleted

| Field | Value |
|-------|-------|
| **ID** | UC-037 |
| **Name** | Azure Logging Disabled |
| **Category** | Cloud Security - Azure |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1562.008 |

**Description**: Detect deletion of Azure diagnostic settings for defense evasion.

**Trigger**: DELETE operation on diagnosticSettings

**n8n Logic**:
```javascript
const event = $input.first().json;

if (event.operationName === 'Microsoft.Insights/diagnosticSettings/delete') {
  return {
    alert_type: "azure_logging_disabled",
    resource: event.resourceId,
    actor: event.caller,
    severity: "critical"
  };
}
```

**XSOAR Actions**:
- Re-enable diagnostic settings
- Create critical incident
- Investigate actor
- Check for other tampering

---

### UC-038: Container Registry Public Image Pull

| Field | Value |
|-------|-------|
| **ID** | UC-038 |
| **Name** | Public Registry Image Pull |
| **Category** | Cloud Security - Containers |
| **Severity** | Medium |
| **MITRE ATT&CK** | T1525 |

**Description**: Detect container image pulls from public registries in production.

**Trigger**: Container pull from non-approved registry

**n8n Logic**:
```javascript
const event = $input.first().json;
const approvedRegistries = ['gcr.io/myorg', 'myregistry.azurecr.io'];

if (!approvedRegistries.some(r => event.imageName.startsWith(r))) {
  return {
    alert_type: "unapproved_registry",
    image: event.imageName,
    cluster: event.clusterName,
    severity: "medium"
  };
}
```

**XSOAR Actions**:
- Create compliance incident
- Scan image for vulnerabilities
- Notify DevOps team
- Add to blocklist if malicious

---

### UC-039: AWS Lambda Function Policy Override

| Field | Value |
|-------|-------|
| **ID** | UC-039 |
| **Name** | Lambda Permission Escalation |
| **Category** | Cloud Security - AWS |
| **Severity** | High |
| **MITRE ATT&CK** | T1078.004 |

**Description**: Detect modifications to Lambda function resource policies that grant excessive access.

**Trigger**: AddPermission granting access to external accounts

**n8n Logic**:
```javascript
const event = $input.first().json;
const orgAccountPrefix = '123456789';

if (event.eventName === 'AddPermission20150331v2') {
  const principal = event.requestParameters.principal;
  if (!principal.startsWith(orgAccountPrefix) && principal !== 'lambda.amazonaws.com') {
    return {
      alert_type: "lambda_external_access",
      function: event.requestParameters.functionName,
      principal: principal,
      severity: "high"
    };
  }
}
```

**XSOAR Actions**:
- Remove permission
- Create incident
- Audit Lambda configurations
- Notify function owner

---

### UC-040: GCP Project IAM Policy Binding

| Field | Value |
|-------|-------|
| **ID** | UC-040 |
| **Name** | GCP Org-Level IAM Change |
| **Category** | Cloud Security - GCP |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1078.004 |

**Description**: Detect IAM policy changes at organization or project level.

**Trigger**: SetIamPolicy at org/project level

**n8n Logic**:
```javascript
const event = $input.first().json;
const privilegedRoles = ['roles/owner', 'roles/editor', 'roles/iam.admin'];

if (event.methodName === 'SetIamPolicy') {
  const bindings = event.request?.policy?.bindings || [];
  const privilegedBindings = bindings.filter(b => 
    privilegedRoles.includes(b.role)
  );
  
  if (privilegedBindings.length > 0) {
    return {
      alert_type: "gcp_iam_escalation",
      bindings: privilegedBindings,
      actor: event.authenticationInfo.principalEmail,
      severity: "critical"
    };
  }
}
```

**XSOAR Actions**:
- Review and potentially revert
- Create critical incident
- Notify security team
- Audit recent changes

---

### UC-041: Cloud Function/Lambda Environment Variable Secrets

| Field | Value |
|-------|-------|
| **ID** | UC-041 |
| **Name** | Secrets in Function Environment |
| **Category** | Cloud Security - Serverless |
| **Severity** | High |
| **MITRE ATT&CK** | T1552.001 |

**Description**: Detect secrets stored in serverless function environment variables.

**Trigger**: Function configuration with secret-like env vars

**n8n Logic**:
```javascript
const event = $input.first().json;
const secretPatterns = [/password/i, /secret/i, /key/i, /token/i, /credential/i];

const envVars = event.configuration?.Environment?.Variables || {};
const sensitiveVars = Object.keys(envVars).filter(k =>
  secretPatterns.some(p => p.test(k))
);

if (sensitiveVars.length > 0) {
  return {
    alert_type: "secrets_in_env",
    function: event.functionName,
    variables: sensitiveVars,
    severity: "high"
  };
}
```

**XSOAR Actions**:
- Create compliance incident
- Notify developer team
- Suggest secrets manager
- Rotate exposed secrets

---

### UC-042: Azure Managed Identity Abuse

| Field | Value |
|-------|-------|
| **ID** | UC-042 |
| **Name** | Managed Identity Token Theft |
| **Category** | Cloud Security - Azure |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1552.005 |

**Description**: Detect abuse of Azure managed identity for unauthorized access.

**Trigger**: IMDS token acquisition followed by API calls from unexpected source

**n8n Logic**:
```javascript
const event = $input.first().json;

if (event.operationName.includes('OAuth2/token') && 
    event.properties.audience === 'https://management.azure.com/') {
  const vmExpectedIP = await getVMPrivateIP(event.resourceId);
  
  if (event.callerIpAddress !== vmExpectedIP) {
    return {
      alert_type: "managed_identity_abuse",
      resource: event.resourceId,
      source_ip: event.callerIpAddress,
      severity: "critical"
    };
  }
}
```

**XSOAR Actions**:
- Revoke managed identity
- Isolate source VM
- Create critical incident
- Trigger IR playbook

---

### UC-043: Cloud Resource Deletion Spree

| Field | Value |
|-------|-------|
| **ID** | UC-043 |
| **Name** | Mass Resource Deletion |
| **Category** | Cloud Security - Multi-Cloud |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1485 |

**Description**: Detect mass deletion of cloud resources indicating destructive attack.

**Trigger**: Multiple Delete* events from same actor in short timeframe

**n8n Logic**:
```javascript
const events = $input.all();
const deleteEvents = events.filter(e => 
  e.json.eventName?.startsWith('Delete') ||
  e.json.operationName?.includes('delete')
);

const byActor = {};
deleteEvents.forEach(e => {
  const actor = e.json.userIdentity?.arn || e.json.caller;
  if (!byActor[actor]) byActor[actor] = 0;
  byActor[actor]++;
});

const massDeleters = Object.entries(byActor)
  .filter(([_, count]) => count > 10);

if (massDeleters.length > 0) {
  return {
    alert_type: "mass_deletion",
    actors: massDeleters,
    severity: "critical"
  };
}
```

**XSOAR Actions**:
- Disable actor accounts immediately
- Create critical incident
- Initiate disaster recovery
- Preserve audit logs

---

### UC-044: Terraform State File Exposure

| Field | Value |
|-------|-------|
| **ID** | UC-044 |
| **Name** | Terraform State Public Access |
| **Category** | Cloud Security - IaC |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1552.001 |

**Description**: Detect public access to Terraform state files containing secrets.

**Trigger**: Public access enabled on storage containing .tfstate files

**n8n Logic**:
```javascript
const event = $input.first().json;

if (event.alertType === 'storage_public' && 
    event.objects?.some(o => o.name.includes('.tfstate'))) {
  return {
    alert_type: "tfstate_exposed",
    storage: event.storageName,
    objects: event.objects.filter(o => o.name.includes('.tfstate')),
    severity: "critical"
  };
}
```

**XSOAR Actions**:
- Block public access immediately
- Rotate all secrets in state
- Create critical incident
- Audit state file access

---

### UC-045: Cloud Cost Anomaly Detection

| Field | Value |
|-------|-------|
| **ID** | UC-045 |
| **Name** | Unusual Cloud Spending |
| **Category** | Cloud Security - FinOps |
| **Severity** | Medium |
| **MITRE ATT&CK** | T1496 |

**Description**: Detect unusual cloud spending that may indicate cryptomining or resource abuse.

**Trigger**: Spending exceeds baseline by significant margin

**n8n Logic**:
```javascript
const costData = $input.first().json;
const baseline = costData.historicalAverage;
const current = costData.currentSpending;
const threshold = 2.0; // 200% of baseline

if (current > baseline * threshold) {
  return {
    alert_type: "cost_anomaly",
    baseline: baseline,
    current: current,
    increase_percent: ((current - baseline) / baseline * 100).toFixed(2),
    severity: "medium"
  };
}
```

**XSOAR Actions**:
- Create FinOps incident
- Identify cost drivers
- Check for cryptomining
- Notify cloud team

---

## Summary Table

| ID | Use Case | Severity | Cloud | MITRE ATT&CK |
|----|----------|----------|-------|--------------|
| UC-021 | IAM User Without MFA | High | AWS | T1078.004 |
| UC-022 | S3 Public Access | Critical | AWS | T1530 |
| UC-023 | IMDS Exploitation | Critical | AWS | T1552.005 |
| UC-024 | Azure Role Escalation | Critical | Azure | T1078.004 |
| UC-025 | GCP SA Key Export | High | GCP | T1552.001 |
| UC-026 | Cross-Account AssumeRole | High | AWS | T1078.004 |
| UC-027 | Azure Blob Public | Critical | Azure | T1530 |
| UC-028 | GCP Firewall Open | High | GCP | T1562.007 |
| UC-029 | AWS Root Usage | Critical | AWS | T1078.004 |
| UC-030 | Untagged Resources | Low | Multi | T1580 |
| UC-031 | K8s RBAC Escalation | High | K8s | T1078.004 |
| UC-032 | CloudTrail Disabled | Critical | AWS | T1562.008 |
| UC-033 | Key Vault Anomaly | High | Azure | T1552.001 |
| UC-034 | BigQuery Exfiltration | High | GCP | T1537 |
| UC-035 | Multi-Cloud Lateral | Critical | Multi | T1580 |
| UC-036 | SG Wide Open | High | AWS | T1562.007 |
| UC-037 | Azure Logging Disabled | Critical | Azure | T1562.008 |
| UC-038 | Public Registry Pull | Medium | Containers | T1525 |
| UC-039 | Lambda Permission | High | AWS | T1078.004 |
| UC-040 | GCP IAM Change | Critical | GCP | T1078.004 |
| UC-041 | Secrets in Env | High | Serverless | T1552.001 |
| UC-042 | Managed Identity Abuse | Critical | Azure | T1552.005 |
| UC-043 | Mass Deletion | Critical | Multi | T1485 |
| UC-044 | Terraform State | Critical | IaC | T1552.001 |
| UC-045 | Cost Anomaly | Medium | Multi | T1496 |
