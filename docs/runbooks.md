# X-n8 Incident Response Runbooks

> **Step-by-Step Procedures for SOC Analysts**

---

## Overview

These runbooks provide standardized response procedures for handling X-n8 incidents. Each runbook aligns with NIST SP 800-61 incident response phases.

---

## Runbook 1: Ransomware Response

**Severity**: Critical | **SLA**: 15 minutes | **Use Cases**: UC-066, UC-071

### Detection Indicators
- Mass file encryption activity
- Ransom note file creation
- Shadow copy deletion
- Known ransomware process execution

### Phase 1: Containment (Immediate - 0-15 min)

```markdown
1. [ ] **Isolate Affected Host**
   - Execute: `X-n8 Auto-Isolation` playbook
   - Verify isolation in EDR console
   - Document hostname and IP

2. [ ] **Assess Blast Radius**
   - Check for lateral movement indicators
   - Identify connected file shares
   - Review authentication logs for compromised user

3. [ ] **Disable Compromised Account**
   - Disable AD account
   - Revoke all active sessions
   - Reset password if needed later
```

### Phase 2: Investigation (15-60 min)

```markdown
4. [ ] **Collect Evidence**
   - Memory dump (if system stable)
   - Disk image or snapshot
   - Network traffic logs
   - EDR timeline export

5. [ ] **Identify Ransomware Variant**
   - Check ransom note content
   - Search file extension on ID Ransomware
   - Look up TTPs on MITRE

6. [ ] **Determine Initial Access**
   - Review email logs for phishing
   - Check VPN/RDP access logs
   - Examine recent vulnerabilities
```

### Phase 3: Eradication (1-4 hours)

```markdown
7. [ ] **Remove Malware**
   - Run full EDR scan
   - Remove persistence mechanisms
   - Clean registry entries
   - Verify no scheduled tasks remain

8. [ ] **Patch Vulnerabilities**
   - Apply missing patches
   - Harden exposed services
   - Update firewall rules
```

### Phase 4: Recovery (4-24 hours)

```markdown
9. [ ] **Restore from Backup**
   - Verify backup integrity
   - Restore to clean system
   - Validate data consistency

10. [ ] **Return to Production**
    - Remove network isolation
    - Monitor for reinfection
    - Verify business operations
```

---

## Runbook 2: Business Email Compromise (BEC)

**Severity**: Critical | **SLA**: 30 minutes | **Use Cases**: UC-092, UC-101

### Detection Indicators
- Executive impersonation
- Urgent financial request
- Reply-to header mismatch
- Thread hijacking

### Phase 1: Immediate Actions (0-30 min)

```markdown
1. [ ] **Quarantine Email**
   - Remove from all inboxes
   - Block sender domain
   - Preserve for evidence

2. [ ] **Prevent Financial Loss**
   - Contact finance team immediately
   - Put hold on pending wire transfers
   - Verify with legitimate executive via phone

3. [ ] **Notify Affected Users**
   - Send warning about impersonation
   - Instruct not to respond to suspicious emails
   - Report any previous interactions
```

### Phase 2: Investigation (30 min - 2 hours)

```markdown
4. [ ] **Analyze Email Headers**
   - Document originating IP
   - Check SPF/DKIM/DMARC
   - Identify spoofing method

5. [ ] **Check for Compromised Accounts**
   - Review executive's sent folder
   - Check for forwarding rules
   - Verify no OAuth app grants

6. [ ] **Search for Related Emails**
   - Hunt for similar patterns
   - Check other executives targeted
   - Review past 30 days of email
```

### Phase 3: Remediation

```markdown
7. [ ] **Block Threat Indicators**
   - Add sender to block list
   - Block reply-to domain
   - Create email rule for pattern

8. [ ] **Strengthen Defenses**
   - Implement DMARC reject policy
   - Add external sender warning banner
   - Enable advanced anti-phishing
```

---

## Runbook 3: Data Exfiltration

**Severity**: High | **SLA**: 1 hour | **Use Cases**: UC-047, UC-050, UC-169

### Detection Indicators
- Large file downloads
- USB device data transfer
- Cloud storage upload
- Unusual working hours

### Phase 1: Assessment (0-30 min)

```markdown
1. [ ] **Verify Alert Legitimacy**
   - Check if user has business justification
   - Review user's role and normal activity
   - Contact user's manager

2. [ ] **Determine Data Sensitivity**
   - Identify file types transferred
   - Check data classification labels
   - Assess potential impact

3. [ ] **Document Evidence**
   - Screenshot DLP alert
   - Export file access logs
   - Record timestamps and volumes
```

### Phase 2: Containment (30-60 min)

```markdown
4. [ ] **Block Further Exfiltration**
   - Disable USB ports (if USB vector)
   - Block cloud storage domains
   - Revoke network access if severe

5. [ ] **Preserve Evidence**
   - Collect endpoint logs
   - Export email logs
   - Backup affected file shares
```

### Phase 3: Investigation (1-4 hours)

```markdown
6. [ ] **Interview Subject**
   - Coordinate with HR
   - Document explanation
   - Assess insider threat risk

7. [ ] **Analyze Exfiltrated Data**
   - Inventory all files copied
   - Determine regulatory impact
   - Assess customer data exposure
```

### Phase 4: Remediation

```markdown
8. [ ] **Mitigate Damage**
   - Notify affected parties (if required)
   - Engage legal team
   - File breach notification (if applicable)

9. [ ] **Prevent Recurrence**
   - Implement DLP controls
   - Restrict USB access
   - Enhance monitoring for user
```

---

## Runbook 4: Account Compromise

**Severity**: High | **SLA**: 30 minutes | **Use Cases**: UC-112, UC-129

### Detection Indicators
- MFA fatigue attack
- Impossible travel
- Password spray success
- Credential stuffing

### Phase 1: Immediate Actions (0-15 min)

```markdown
1. [ ] **Disable/Lock Account**
   - Disable in Active Directory
   - Revoke all active sessions
   - Block from all cloud apps

2. [ ] **Terminate Active Sessions**
   - Azure AD: Revoke refresh tokens
   - Okta: Clear all sessions
   - AWS: Terminate console sessions

3. [ ] **Block Attacker Access**
   - Note attacker's IP
   - Add to firewall blocklist
   - Block in CASB if applicable
```

### Phase 2: Investigation (15-60 min)

```markdown
4. [ ] **Determine Compromise Scope**
   - Review authentication logs
   - Check email access
   - Identify accessed resources
   - Look for mail forwarding rules

5. [ ] **Check for Persistence**
   - Audit OAuth app grants
   - Review MFA methods added
   - Check for API keys created

6. [ ] **Trace Attack Origin**
   - Analyze phishing emails
   - Check for credential reuse
   - Review dark web exposure
```

### Phase 3: Recovery

```markdown
7. [ ] **Reset Credentials**
   - Reset password
   - Re-enroll MFA with verification
   - Revoke and regenerate API keys

8. [ ] **Restore Account**
   - Re-enable account
   - Restore email rules
   - Verify normal access
```

---

## Runbook 5: Cloud Misconfiguration

**Severity**: Varies | **SLA**: 1 hour | **Use Cases**: UC-022, UC-027, UC-044

### Detection Indicators
- S3 bucket made public
- Storage account anonymous access
- Security group 0.0.0.0/0
- Terraform state exposed

### Phase 1: Immediate Remediation (0-30 min)

```markdown
1. [ ] **Fix Configuration**
   - Remove public access
   - Update security group rules
   - Rotate exposed credentials

2. [ ] **Verify Fix**
   - Test from external IP
   - Run security scan
   - Check access logs
```

### Phase 2: Impact Assessment

```markdown
3. [ ] **Determine Exposure Duration**
   - Review CloudTrail/Activity logs
   - Identify when misconfiguration occurred
   - Calculate exposure window

4. [ ] **Check for Unauthorized Access**
   - Review access logs during exposure
   - Identify any data downloads
   - Check for lateral movement
```

### Phase 3: Prevention

```markdown
5. [ ] **Update IaC Templates**
   - Fix Terraform/CloudFormation
   - Add preventive policies
   - Implement SCPs for guardrails

6. [ ] **Add Monitoring**
   - Create alert for configuration drift
   - Implement continuous compliance
   - Add to automated remediation
```

---

## Quick Reference Card

| Incident Type | SLA | First Action | Escalation Path |
|---------------|-----|--------------|-----------------|
| Ransomware | 15m | Isolate host | SOC → IR Team → CISO |
| BEC | 30m | Quarantine email | SOC → Finance → Legal |
| Exfiltration | 1h | Block transfer | SOC → Manager → HR |
| Account Compromise | 30m | Disable account | SOC → Help Desk |
| Cloud Misconfig | 1h | Fix config | SOC → Cloud Team |

---

## Related Documentation

- [Use Case Index](USE-CASE-INDEX.md)
- [Playbook Index](PLAYBOOK-INDEX.md)
- [Correlation Rules](correlation-rules.md)
