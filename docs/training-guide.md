# X-n8 SOC Analyst Training Guide

> **Onboarding and Training Documentation for SOC Analysts**

---

## 📚 Table of Contents

1. [Introduction to X-n8](#introduction)
2. [Understanding the Architecture](#architecture-overview)
3. [Alert Triage Workflow](#alert-triage-workflow)
4. [Working with AI Enrichment](#ai-enrichment)
5. [XSOAR Incident Handling](#xsoar-incident-handling)
6. [Hands-On Labs](#hands-on-labs)
7. [Certification Checklist](#certification-checklist)

---

## 1. Introduction to X-n8

### What is X-n8?

X-n8 (Exnate) is a hybrid SOC automation platform that combines:
- **n8n**: For agentic intelligence and alert processing
- **XSOAR**: For incident management and response orchestration
- **AI/LLM**: For intelligent alert triage and analysis

### Key Benefits

| Traditional SOC | X-n8 Enhanced SOC |
|-----------------|-------------------|
| Manual alert triage | AI-powered severity scoring |
| Alert fatigue from duplicates | Intelligent deduplication |
| Siloed tools | Unified workflow platform |
| Reactive response | Automated containment |
| Limited context | Rich enrichment |

---

## 2. Architecture Overview

### Data Flow

```
SIEM Alert → n8n Webhook → Normalize → Deduplicate → AI Triage → Route
                                                            ↓
                     ┌──────────────────────────────────────┤
                     ↓                    ↓                 ↓
               Auto-Close          Slack Notify       XSOAR Incident
              (Score < 30)       (Score 30-70)        (Score > 70)
```

### Your Role in the Flow

As a SOC analyst, you will:
1. **Review AI-triaged alerts** in Slack
2. **Investigate XSOAR incidents** with enriched context
3. **Execute response playbooks** for remediation
4. **Provide feedback** to improve AI accuracy

---

## 3. Alert Triage Workflow

### Step 1: Check Slack Channel

X-n8 sends notifications to `#soc-alerts`:

```
⚠️ X-n8 Alert - Medium Severity (Score: 52/100)

Event Type: Suspicious Login
User: john.doe@company.com
Source IP: 185.123.45.67
Host: WORKSTATION-42

AI Summary: Login from unusual location (Romania) during off-hours. 
User typically logs in from US East Coast.

MITRE: T1078 - Valid Accounts

Recommended Actions:
• Verify with user via phone
• Check for additional suspicious activity
• Review recent authentication logs

[View in XSOAR] [Mark as FP] [Acknowledge]
```

### Step 2: Quick Assessment (30 seconds)

Ask yourself:
- [ ] Is this user known to me?
- [ ] Does the activity match their role?
- [ ] Is the source IP suspicious?
- [ ] Are there related alerts?

### Step 3: Investigate or Close

**If obviously false positive:**
- Click **Mark as FP**
- Select reason (allowlist, expected activity, etc.)

**If investigation needed:**
- Click **View in XSOAR**
- Continue to full investigation

---

## 4. Working with AI Enrichment

### Understanding AI Scores

| Score | Label | Meaning | Action |
|-------|-------|---------|--------|
| 90-100 | Critical | Active threat | Immediate response |
| 70-89 | High | Likely true positive | Investigate within 15m |
| 50-69 | Medium | Needs context | Investigate within 1h |
| 30-49 | Low | Probably benign | Review when time permits |
| 0-29 | Info | Auto-closed | No action needed |

### AI Confidence Levels

- **High (0.8-1.0)**: AI is confident in assessment
- **Medium (0.5-0.79)**: Some uncertainty, verify
- **Low (0.0-0.49)**: Limited context, manual review needed

### When to Override AI

Override the AI score when:
- You have context AI doesn't (planned change, pentest)
- The AI misinterpreted the situation
- Business context changes severity (VIP user, critical asset)

---

## 5. XSOAR Incident Handling

### Incident Layout

When you open an X-n8 incident in XSOAR, you'll see:

```
┌─────────────────────────────────────────────────────────┐
│ Incident: X-n8: Suspicious Login - john.doe            │
├─────────────────────────────────────────────────────────┤
│ Severity: High (Score: 75/100)                         │
│ Status: Open                 Owner: Unassigned         │
├─────────────────────────────────────────────────────────┤
│ AI ANALYSIS                                            │
│ ─────────────────────────────────────────────────────  │
│ Summary: Login from Romania IP during US off-hours...  │
│ Confidence: 0.85                                       │
│ MITRE: T1078 - Valid Accounts                          │
│ Recommended Actions:                                   │
│  • Verify with user via phone                          │
│  • Check for additional suspicious activity            │
├─────────────────────────────────────────────────────────┤
│ INDICATORS                                             │
│ ─────────────────────────────────────────────────────  │
│ IP: 185.123.45.67 (DBot Score: 3 - Malicious)         │
│ User: john.doe@company.com                             │
│ Host: WORKSTATION-42                                   │
├─────────────────────────────────────────────────────────┤
│ TIMELINE                                               │
│ ─────────────────────────────────────────────────────  │
│ 14:32:00 - Successful login from suspicious IP         │
│ 14:32:05 - MFA prompt sent                             │
│ 14:32:08 - MFA accepted                                │
│ 14:33:00 - Email access                                │
└─────────────────────────────────────────────────────────┘
```

### Key Actions

1. **Assign to Self**: Click "Take Ownership"
2. **Run Playbook**: Execute assigned response playbook
3. **Investigate**: Use War Room for commands
4. **Document**: Add notes as you investigate
5. **Close**: Mark resolution with reason

### War Room Commands

```bash
# Get user details
!ad-get-user username=john.doe

# Check recent logins
!azure-ad-get-user-signin-logs user_id=john.doe limit=10

# Check IP reputation
!ip indicator=185.123.45.67

# Disable user account
!ad-disable-account username=john.doe

# Send feedback to X-n8
!xn8-send-feedback incident_id=${incident.id} was_true_positive=true
```

---

## 6. Hands-On Labs

### Lab 1: Phishing Email Analysis

**Scenario**: You receive an X-n8 alert for a suspicious email.

1. Review the AI summary
2. Check the sender domain
3. Analyze the URL in the email
4. Determine if it's a true phishing attempt
5. Execute the appropriate playbook

### Lab 2: Account Compromise Response

**Scenario**: X-n8 detects MFA fatigue attack.

1. Understand the attack pattern
2. Disable the affected account
3. Revoke all sessions
4. Investigate blast radius
5. Reset credentials and re-enable

### Lab 3: Ransomware Detection

**Scenario**: EDR alert triggers ransomware detection.

1. Verify isolation was automatic
2. Assess affected files
3. Determine initial access vector
4. Coordinate with IR team
5. Document and close

---

## 7. Certification Checklist

Complete these tasks to become X-n8 certified:

### Level 1: Foundation

- [ ] Understand X-n8 architecture diagram
- [ ] Navigate Slack notifications
- [ ] Open and close XSOAR incidents
- [ ] Mark false positives correctly
- [ ] Complete Lab 1

### Level 2: Intermediate

- [ ] Interpret AI severity scores
- [ ] Execute response playbooks
- [ ] Use War Room commands
- [ ] Override AI when appropriate
- [ ] Complete Lab 2

### Level 3: Advanced

- [ ] Handle critical ransomware incidents
- [ ] Create custom tuning rules
- [ ] Train other analysts
- [ ] Contribute to runbook improvement
- [ ] Complete Lab 3

---

## Quick Reference Card

### Severity Response SLAs

| Severity | Response Time | Resolution Time |
|----------|---------------|-----------------|
| Critical | 15 minutes | 4 hours |
| High | 1 hour | 8 hours |
| Medium | 4 hours | 24 hours |
| Low | 24 hours | 72 hours |

### Escalation Path

1. **Tier 1 SOC Analyst**: Initial triage
2. **Tier 2 SOC Analyst**: Complex investigation
3. **Tier 3 / IR Team**: Major incidents
4. **CISO/Management**: Critical breaches

### Key Contacts

| Role | Contact Method |
|------|---------------|
| SOC Manager | Slack: @soc-manager |
| IR Team | Slack: #incident-response |
| IT Help Desk | help@company.com |
| Legal | legal@company.com |

---

## Resources

- [Use Case Index](USE-CASE-INDEX.md)
- [Playbook Index](PLAYBOOK-INDEX.md)
- [Runbooks](runbooks.md)
- [Tuning Guide](tuning-guide.md)

---

<p align="center">
  <strong>Welcome to the X-n8 SOC Team! 🛡️</strong>
</p>
