# Data Loss Prevention (DLP) Use Cases (46-65)

> **X-n8 Playbook Collection** - Preventing Data Exfiltration Across Channels

---

## Overview

DLP use cases focus on detecting and preventing unauthorized data transfers, including exfiltration via USB, cloud storage, email, and code repositories.

### MITRE ATT&CK Mapping
- **T1052** - Exfiltration Over Physical Medium
- **T1567** - Exfiltration Over Web Service
- **T1048** - Exfiltration Over Alternative Protocol
- **T1041** - Exfiltration Over C2 Channel

---

## Use Cases

### UC-046: USB Mass Storage Connection Detection

| Field | Value |
|-------|-------|
| **ID** | UC-046 |
| **Name** | USB Storage Device Alert |
| **Category** | DLP |
| **Severity** | Medium |
| **MITRE ATT&CK** | T1052.001 |

**Description**: Detect connection of USB mass storage devices to endpoints.

**Trigger**: EDR event for USB storage device connection

**n8n Logic**:
```javascript
const event = $input.first().json;
const allowedDevices = await getAllowedUSBDevices();

if (event.deviceType === 'USB_STORAGE') {
  if (!allowedDevices.includes(event.deviceId)) {
    return {
      alert_type: "unauthorized_usb",
      host: event.hostname,
      user: event.username,
      device_id: event.deviceId,
      severity: "medium"
    };
  }
}
```

**XSOAR Actions**:
- Log device connection
- Create incident if policy violation
- Notify security team
- Block device if possible

---

### UC-047: Large File Copy to USB

| Field | Value |
|-------|-------|
| **ID** | UC-047 |
| **Name** | USB Data Exfiltration Detection |
| **Category** | DLP |
| **Severity** | High |
| **MITRE ATT&CK** | T1052.001 |

**Description**: Detect large file transfers to USB devices indicating potential exfiltration.

**Trigger**: File copy to removable media exceeding threshold

**n8n Logic**:
```javascript
const event = $input.first().json;
const thresholdMB = 100;

if (event.targetDevice?.isRemovable && event.fileSizeMB > thresholdMB) {
  const sensitivePatterns = [/\.docx?$/, /\.xlsx?$/, /\.pdf$/, /\.pptx?$/];
  const isSensitive = sensitivePatterns.some(p => p.test(event.fileName));
  
  return {
    alert_type: "usb_exfiltration",
    user: event.username,
    file: event.fileName,
    size_mb: event.fileSizeMB,
    severity: isSensitive ? "high" : "medium"
  };
}
```

**XSOAR Actions**:
- Create DLP incident
- Notify user's manager
- Block USB if policy allows
- Capture forensic evidence

---

### UC-048: Personal Cloud Storage Upload

| Field | Value |
|-------|-------|
| **ID** | UC-048 |
| **Name** | Personal Cloud Upload Detection |
| **Category** | DLP |
| **Severity** | High |
| **MITRE ATT&CK** | T1567.002 |

**Description**: Detect uploads to personal cloud storage services (Dropbox, Google Drive personal, etc.).

**Trigger**: Network traffic to personal cloud storage domains

**n8n Logic**:
```javascript
const event = $input.first().json;
const personalCloudDomains = [
  'dropbox.com', 'drive.google.com', 'onedrive.live.com',
  'box.com', 'icloud.com', 'mega.nz', 'mediafire.com'
];

const isPersonalCloud = personalCloudDomains.some(d => 
  event.destination.includes(d)
);

if (isPersonalCloud && event.bytesUploaded > 10 * 1024 * 1024) {
  return {
    alert_type: "personal_cloud_upload",
    user: event.username,
    destination: event.destination,
    bytes: event.bytesUploaded,
    severity: "high"
  };
}
```

**XSOAR Actions**:
- Block connection if possible
- Create DLP incident
- Review uploaded content
- Notify compliance team

---

### UC-049: GitHub/GitLab Source Code Leak

| Field | Value |
|-------|-------|
| **ID** | UC-049 |
| **Name** | Source Code Repository Leak |
| **Category** | DLP |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1567 |

**Description**: Detect company source code pushed to public repositories.

**Trigger**: Secret scanning or repo monitoring alert

**n8n Logic**:
```javascript
const event = $input.first().json;

if (event.alertType === 'public_repo_exposure') {
  const containsSecrets = event.findings?.some(f => 
    f.type.includes('secret') || f.type.includes('credential')
  );
  
  return {
    alert_type: "source_code_leak",
    repository: event.repoUrl,
    user: event.uploader,
    contains_secrets: containsSecrets,
    severity: "critical"
  };
}
```

**AI Agent Prompt**:
```
Analyze this source code exposure alert:
- Repository: {{repository}}
- Uploader: {{user}}
- File patterns: {{file_patterns}}
- Contains secrets: {{contains_secrets}}

Assess:
1. Is this an employee's personal project or company code?
2. What sensitive data might be exposed?
3. Recommended remediation steps
4. Should legal/HR be involved?
```

**XSOAR Actions**:
- Request repository takedown
- Rotate any exposed secrets
- Create critical incident
- Notify legal/compliance

---

### UC-050: Bulk File Download Detection

| Field | Value |
|-------|-------|
| **ID** | UC-050 |
| **Name** | Mass File Download Alert |
| **Category** | DLP |
| **Severity** | High |
| **MITRE ATT&CK** | T1567 |

**Description**: Detect users downloading unusually large amounts of data.

**Trigger**: Download volume exceeds baseline by significant margin

**n8n Logic**:
```javascript
const event = $input.first().json;
const userBaseline = await getUserDownloadBaseline(event.user);
const threshold = userBaseline * 5; // 5x normal

if (event.downloadSizeMB > threshold) {
  return {
    alert_type: "bulk_download",
    user: event.user,
    size_mb: event.downloadSizeMB,
    baseline_mb: userBaseline,
    file_count: event.fileCount,
    severity: "high"
  };
}
```

**XSOAR Actions**:
- Create DLP incident
- Review downloaded files
- Check user access history
- Interview user if suspicious

---

### UC-051: Email DLP - Sensitive Data in Attachment

| Field | Value |
|-------|-------|
| **ID** | UC-051 |
| **Name** | Email Sensitive Data Detection |
| **Category** | DLP |
| **Severity** | High |
| **MITRE ATT&CK** | T1048.003 |

**Description**: Detect sensitive data (PII, credentials, financial) in email attachments.

**Trigger**: Email gateway DLP scan detection

**n8n Logic**:
```javascript
const event = $input.first().json;

if (event.dlpMatch) {
  const externalRecipients = event.recipients.filter(r => !r.endsWith('@company.com'));
  
  return {
    alert_type: "email_dlp_violation",
    sender: event.sender,
    external_recipients: externalRecipients,
    data_types: event.dlpMatch.dataTypes,
    file_name: event.attachmentName,
    severity: externalRecipients.length > 0 ? "high" : "medium"
  };
}
```

**XSOAR Actions**:
- Quarantine email
- Create DLP incident
- Notify sender and manager
- Log for compliance

---

### UC-052: Printer Data Exfiltration

| Field | Value |
|-------|-------|
| **ID** | UC-052 |
| **Name** | Suspicious Print Job Detection |
| **Category** | DLP |
| **Severity** | Medium |
| **MITRE ATT&CK** | T1052 |

**Description**: Detect printing of sensitive documents outside business hours or in bulk.

**Trigger**: Print job with sensitive content flags

**n8n Logic**:
```javascript
const event = $input.first().json;
const hour = new Date(event.timestamp).getHours();
const isAfterHours = hour < 7 || hour > 20;

if (event.pageCount > 50 || (isAfterHours && event.containsSensitive)) {
  return {
    alert_type: "suspicious_print",
    user: event.username,
    document: event.documentName,
    pages: event.pageCount,
    after_hours: isAfterHours,
    severity: "medium"
  };
}
```

**XSOAR Actions**:
- Log print job details
- Create incident if policy violation
- Notify manager for after-hours prints
- Review printed content if possible

---

### UC-053: Screen Capture Tool Detection

| Field | Value |
|-------|-------|
| **ID** | UC-053 |
| **Name** | Screen Capture Software Alert |
| **Category** | DLP |
| **Severity** | Medium |
| **MITRE ATT&CK** | T1113 |

**Description**: Detect installation or use of screen capture/recording software.

**Trigger**: EDR detection of screen capture tool execution

**n8n Logic**:
```javascript
const event = $input.first().json;
const screenCaptureTools = [
  'snagit', 'greenshot', 'obs', 'camtasia', 
  'loom', 'screenrecorder', 'bandicam'
];

const isScreenCapture = screenCaptureTools.some(tool => 
  event.processName.toLowerCase().includes(tool)
);

if (isScreenCapture && event.isNewInstall) {
  return {
    alert_type: "screen_capture_installed",
    user: event.username,
    tool: event.processName,
    severity: "medium"
  };
}
```

**XSOAR Actions**:
- Assess business justification
- Create incident if unauthorized
- Block tool if policy violation
- Monitor for data exfiltration

---

### UC-054: Steganography Detection

| Field | Value |
|-------|-------|
| **ID** | UC-054 |
| **Name** | Steganography Upload Detection |
| **Category** | DLP |
| **Severity** | High |
| **MITRE ATT&CK** | T1027.003 |

**Description**: Detect images/files with hidden data indicating steganographic exfiltration.

**Trigger**: File analysis indicating embedded data

**n8n Logic**:
```javascript
const event = $input.first().json;

if (event.analysisResult?.hiddenDataDetected) {
  return {
    alert_type: "steganography_detected",
    file: event.fileName,
    carrier_type: event.fileType,
    estimated_payload_kb: event.analysisResult.payloadSize,
    user: event.uploader,
    destination: event.destination,
    severity: "high"
  };
}
```

**XSOAR Actions**:
- Block file transfer
- Quarantine file for analysis
- Create high-priority incident
- Investigate user activity

---

### UC-055: DNS Tunneling Exfiltration

| Field | Value |
|-------|-------|
| **ID** | UC-055 |
| **Name** | DNS Tunneling Detection |
| **Category** | DLP |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1048.003 |

**Description**: Detect data exfiltration via DNS tunneling techniques.

**Trigger**: Unusual DNS query patterns

**n8n Logic**:
```javascript
const dnsQueries = $input.all();

const suspiciousPatterns = dnsQueries.filter(q => {
  const query = q.json.query;
  return query.length > 50 || // Long subdomain
         /^[a-z0-9]+\.[a-z0-9]+\.[a-z0-9]+/.test(query) || // Encoded data pattern
         q.json.queryCount > 1000; // High volume
});

if (suspiciousPatterns.length > 0) {
  return {
    alert_type: "dns_tunneling",
    queries: suspiciousPatterns.slice(0, 10),
    source_ip: suspiciousPatterns[0].json.sourceIP,
    severity: "critical"
  };
}
```

**XSOAR Actions**:
- Block suspicious DNS destinations
- Isolate affected host
- Create critical incident
- Capture full DNS logs

---

### UC-056: Encrypted Archive Creation

| Field | Value |
|-------|-------|
| **ID** | UC-056 |
| **Name** | Password-Protected Archive Detection |
| **Category** | DLP |
| **Severity** | Medium |
| **MITRE ATT&CK** | T1560.001 |

**Description**: Detect creation of encrypted archives that may be used for exfiltration.

**Trigger**: File creation of encrypted archive format

**n8n Logic**:
```javascript
const event = $input.first().json;
const encryptedFormats = ['.7z', '.rar', '.zip'];

if (encryptedFormats.some(f => event.fileName.endsWith(f))) {
  if (event.isEncrypted) {
    return {
      alert_type: "encrypted_archive",
      user: event.username,
      file: event.fileName,
      size_mb: event.sizeMB,
      severity: "medium"
    };
  }
}
```

**XSOAR Actions**:
- Log archive creation
- Monitor for subsequent transfer
- Create incident if transferred externally
- Request password for inspection

---

### UC-057: Clipboard Data Exfiltration

| Field | Value |
|-------|-------|
| **ID** | UC-057 |
| **Name** | Clipboard Sensitive Data Detection |
| **Category** | DLP |
| **Severity** | Medium |
| **MITRE ATT&CK** | T1115 |

**Description**: Detect sensitive data copied to clipboard and pasted to external applications.

**Trigger**: DLP agent clipboard monitoring event

**n8n Logic**:
```javascript
const event = $input.first().json;
const externalApps = ['chrome', 'firefox', 'slack', 'teams', 'telegram'];

if (event.containsSensitiveData) {
  const pastedToExternal = externalApps.some(app => 
    event.destinationApp.toLowerCase().includes(app)
  );
  
  if (pastedToExternal) {
    return {
      alert_type: "clipboard_exfil",
      user: event.username,
      data_type: event.dataType,
      destination: event.destinationApp,
      severity: "medium"
    };
  }
}
```

**XSOAR Actions**:
- Log clipboard activity
- Create incident if policy violation
- Notify user of proper channels
- Review data handling practices

---

### UC-058: FTP/SFTP Outbound Transfer

| Field | Value |
|-------|-------|
| **ID** | UC-058 |
| **Name** | Unauthorized FTP Transfer Detection |
| **Category** | DLP |
| **Severity** | High |
| **MITRE ATT&CK** | T1048.003 |

**Description**: Detect outbound FTP/SFTP transfers to unauthorized destinations.

**Trigger**: Network traffic on FTP ports to non-approved servers

**n8n Logic**:
```javascript
const event = $input.first().json;
const approvedFTPServers = await getApprovedFTPServers();

if ([20, 21, 22].includes(event.destPort)) {
  if (!approvedFTPServers.includes(event.destIP)) {
    return {
      alert_type: "unauthorized_ftp",
      source: event.sourceIP,
      destination: event.destIP,
      bytes_transferred: event.bytes,
      user: event.username,
      severity: "high"
    };
  }
}
```

**XSOAR Actions**:
- Block connection
- Create DLP incident
- Investigate transferred data
- Review user activity

---

### UC-059: Database Export Detection

| Field | Value |
|-------|-------|
| **ID** | UC-059 |
| **Name** | Large Database Export Alert |
| **Category** | DLP |
| **Severity** | High |
| **MITRE ATT&CK** | T1567 |

**Description**: Detect large exports from production databases.

**Trigger**: Database query returning large result set or export command

**n8n Logic**:
```javascript
const event = $input.first().json;
const rowThreshold = 100000;

if (event.queryType === 'SELECT' && event.rowsReturned > rowThreshold) {
  return {
    alert_type: "large_db_export",
    database: event.database,
    table: event.table,
    rows: event.rowsReturned,
    user: event.username,
    severity: "high"
  };
}
```

**XSOAR Actions**:
- Create DLP incident
- Review query purpose
- Audit user's DB access history
- Notify DBA team

---

### UC-060: Airdrop/Bluetooth File Transfer

| Field | Value |
|-------|-------|
| **ID** | UC-060 |
| **Name** | Wireless File Transfer Detection |
| **Category** | DLP |
| **Severity** | Medium |
| **MITRE ATT&CK** | T1052 |

**Description**: Detect file transfers via AirDrop, Bluetooth, or similar wireless methods.

**Trigger**: Endpoint detection of wireless file transfer

**n8n Logic**:
```javascript
const event = $input.first().json;
const wirelessMethods = ['airdrop', 'bluetooth', 'nearby_share'];

if (wirelessMethods.includes(event.transferMethod)) {
  return {
    alert_type: "wireless_transfer",
    user: event.username,
    method: event.transferMethod,
    file: event.fileName,
    size_mb: event.sizeMB,
    severity: "medium"
  };
}
```

**XSOAR Actions**:
- Log transfer attempt
- Create incident if blocked by policy
- Disable wireless sharing if permitted
- Notify security team

---

### UC-061: Slack/Teams File Sharing to External

| Field | Value |
|-------|-------|
| **ID** | UC-061 |
| **Name** | Collaboration Tool External Sharing |
| **Category** | DLP |
| **Severity** | High |
| **MITRE ATT&CK** | T1567.002 |

**Description**: Detect file sharing via Slack/Teams to external users or channels.

**Trigger**: Collaboration tool audit log for external sharing

**n8n Logic**:
```javascript
const event = $input.first().json;

if (event.eventType === 'file_shared') {
  const externalRecipients = event.recipients.filter(r => r.isExternal);
  
  if (externalRecipients.length > 0) {
    return {
      alert_type: "external_collab_share",
      platform: event.platform,
      sharer: event.user,
      file: event.fileName,
      external_recipients: externalRecipients,
      severity: "high"
    };
  }
}
```

**XSOAR Actions**:
- Review shared file content
- Create DLP incident
- Revoke sharing if policy violation
- Notify user about policy

---

### UC-062: Cloud Sync Client Data Volume

| Field | Value |
|-------|-------|
| **ID** | UC-062 |
| **Name** | Cloud Sync Excessive Upload |
| **Category** | DLP |
| **Severity** | High |
| **MITRE ATT&CK** | T1567.002 |

**Description**: Detect excessive data upload via cloud sync clients (OneDrive, Dropbox).

**Trigger**: Cloud sync traffic volume exceeds threshold

**n8n Logic**:
```javascript
const event = $input.first().json;
const dailyThresholdGB = 5;

if (event.uploadGB > dailyThresholdGB) {
  return {
    alert_type: "excessive_cloud_sync",
    user: event.username,
    service: event.cloudService,
    upload_gb: event.uploadGB,
    file_count: event.fileCount,
    severity: "high"
  };
}
```

**XSOAR Actions**:
- Investigate uploaded content
- Create DLP incident
- Pause sync if possible
- Review with user

---

### UC-063: API Data Export Abuse

| Field | Value |
|-------|-------|
| **ID** | UC-063 |
| **Name** | API Bulk Data Export Detection |
| **Category** | DLP |
| **Severity** | High |
| **MITRE ATT&CK** | T1567 |

**Description**: Detect abuse of APIs for bulk data export.

**Trigger**: API calls returning excessive data volume

**n8n Logic**:
```javascript
const event = $input.first().json;

if (event.responseSize > 100 * 1024 * 1024) { // 100MB
  return {
    alert_type: "api_data_export",
    endpoint: event.endpoint,
    user: event.apiKeyOwner,
    response_mb: event.responseSize / (1024 * 1024),
    severity: "high"
  };
}
```

**XSOAR Actions**:
- Rate limit API key
- Create DLP incident
- Review API usage patterns
- Notify API owner

---

### UC-064: Shadow IT Application Detection

| Field | Value |
|-------|-------|
| **ID** | UC-064 |
| **Name** | Unauthorized SaaS Usage |
| **Category** | DLP |
| **Severity** | Medium |
| **MITRE ATT&CK** | T1567.002 |

**Description**: Detect use of unauthorized SaaS applications for data handling.

**Trigger**: Network traffic to non-approved SaaS domains

**n8n Logic**:
```javascript
const event = $input.first().json;
const approvedSaaS = await getApprovedSaaSList();

if (event.isFileUpload && !approvedSaaS.includes(event.domain)) {
  return {
    alert_type: "shadow_it_upload",
    user: event.username,
    service: event.domain,
    file: event.fileName,
    severity: "medium"
  };
}
```

**XSOAR Actions**:
- Block application if possible
- Create compliance incident
- Assess application for approval
- Notify user of approved alternatives

---

### UC-065: Sensitive File Rename Evasion

| Field | Value |
|-------|-------|
| **ID** | UC-065 |
| **Name** | File Rename DLP Evasion |
| **Category** | DLP |
| **Severity** | High |
| **MITRE ATT&CK** | T1036.005 |

**Description**: Detect file renaming attempts to evade DLP detection.

**Trigger**: File rename from sensitive type to benign extension

**n8n Logic**:
```javascript
const event = $input.first().json;
const sensitiveExtensions = ['.xlsx', '.docx', '.pdf', '.sql', '.csv'];
const benignExtensions = ['.txt', '.log', '.tmp', '.bak'];

if (sensitiveExtensions.some(e => event.originalName.endsWith(e)) &&
    benignExtensions.some(e => event.newName.endsWith(e))) {
  return {
    alert_type: "dlp_evasion_rename",
    user: event.username,
    original: event.originalName,
    renamed: event.newName,
    severity: "high"
  };
}
```

**XSOAR Actions**:
- Block file transfer
- Create high-priority incident
- Investigate user intent
- Monitor for additional evasion

---

## Summary Table

| ID | Use Case | Severity | Channel | MITRE ATT&CK |
|----|----------|----------|---------|--------------|
| UC-046 | USB Storage Connection | Medium | Physical | T1052.001 |
| UC-047 | USB Large Copy | High | Physical | T1052.001 |
| UC-048 | Personal Cloud Upload | High | Cloud | T1567.002 |
| UC-049 | Source Code Leak | Critical | Repository | T1567 |
| UC-050 | Bulk Download | High | Network | T1567 |
| UC-051 | Email DLP | High | Email | T1048.003 |
| UC-052 | Suspicious Print | Medium | Physical | T1052 |
| UC-053 | Screen Capture | Medium | Endpoint | T1113 |
| UC-054 | Steganography | High | Files | T1027.003 |
| UC-055 | DNS Tunneling | Critical | DNS | T1048.003 |
| UC-056 | Encrypted Archive | Medium | Files | T1560.001 |
| UC-057 | Clipboard Exfil | Medium | Endpoint | T1115 |
| UC-058 | FTP Transfer | High | Network | T1048.003 |
| UC-059 | Database Export | High | Database | T1567 |
| UC-060 | Wireless Transfer | Medium | Physical | T1052 |
| UC-061 | Collab External Share | High | SaaS | T1567.002 |
| UC-062 | Cloud Sync Volume | High | Cloud | T1567.002 |
| UC-063 | API Bulk Export | High | API | T1567 |
| UC-064 | Shadow IT | Medium | SaaS | T1567.002 |
| UC-065 | Rename Evasion | High | Endpoint | T1036.005 |
