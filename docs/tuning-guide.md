# X-n8 Alert Tuning Guide

> **Reducing False Positives and Optimizing Detection Accuracy**

---

## Overview

This guide provides best practices for tuning X-n8 alerts to maximize true positive rates while minimizing analyst fatigue.

---

## Tuning Philosophy

### The Tuning Pyramid

```
        /\
       /  \  False Positives
      /----\  (Tune Out)
     /      \
    /        \ True Positives
   /----------\ (Investigate)
  /            \
 /   Baseline   \
/________________\
```

**Goal**: Narrow the top of the pyramid by eliminating false positives while expanding true positive coverage.

---

## Phase 1: Baseline Assessment

### Step 1: Collect Metrics (2 Weeks)

```javascript
// Metrics to track
const tuningMetrics = {
  total_alerts: 0,
  true_positives: 0,
  false_positives: 0,
  
  // By category
  by_category: {},
  
  // By use case
  by_use_case: {},
  
  // By source
  by_source: {},
  
  // Closure reasons
  closure_reasons: {
    'confirmed_threat': 0,
    'false_positive': 0,
    'duplicate': 0,
    'not_actionable': 0
  }
};
```

### Step 2: Calculate Baseline Rates

```
True Positive Rate (TPR) = True Positives / Total Alerts
False Positive Rate (FPR) = False Positives / Total Alerts
Noise Ratio = False Positives / True Positives

Target: Noise Ratio < 3:1
```

---

## Phase 2: Identify Tuning Opportunities

### Top False Positive Categories

| Category | Common FP Causes | Tuning Approach |
|----------|------------------|-----------------|
| EDR | Security tools, IT admin activity | Add allowlist |
| IAM | Service accounts, batch jobs | Time-based exclusion |
| Network | Scanner traffic, CDN | IP range exclusion |
| DLP | Legitimate business transfers | User/group allowlist |
| Email | Marketing emails, newsletters | Sender allowlist |

### High-Volume Alert Analysis

```sql
-- Example: Find top FP generators
SELECT 
  use_case_id,
  alert_type,
  COUNT(*) as total,
  SUM(CASE WHEN was_false_positive THEN 1 ELSE 0 END) as fp_count,
  ROUND(100.0 * SUM(CASE WHEN was_false_positive THEN 1 ELSE 0 END) / COUNT(*), 2) as fp_rate
FROM xn8_alerts
WHERE created_at > NOW() - INTERVAL '7 days'
GROUP BY use_case_id, alert_type
HAVING COUNT(*) > 10
ORDER BY fp_rate DESC
LIMIT 20;
```

---

## Phase 3: Implement Tuning Rules

### Allowlist Configuration

```yaml
# tuning/allowlists.yaml

allowlists:
  # IT Admin Users - reduced sensitivity
  it_admins:
    type: user
    members:
      - admin@company.com
      - sysadmin@company.com
    applies_to:
      - UC-068  # PsExec Detection
      - UC-069  # LOLBin Abuse
      - UC-072  # RDP Connections
    action: reduce_severity
    severity_modifier: -30

  # Security Scanners - ignore
  security_scanners:
    type: ip
    ranges:
      - 10.10.50.0/24  # Vulnerability scanner
      - 10.10.51.0/24  # Penetration testing
    applies_to:
      - UC-135  # Port Scan
      - UC-206  # SQL Injection
      - UC-207  # XSS Detection
    action: suppress

  # Legitimate Cloud Services
  trusted_cloud:
    type: domain
    domains:
      - "*.microsoft.com"
      - "*.amazonaws.com"
      - "*.google.com"
    applies_to:
      - UC-048  # Personal Cloud Upload
    action: reduce_severity
    severity_modifier: -20

  # Service Accounts
  service_accounts:
    type: user
    pattern: "^svc_.*@company.com$"
    applies_to:
      - UC-167  # After Hours Access
      - UC-114  # Dormant Account
    action: suppress
```

### Time-Based Exclusions

```yaml
# tuning/time_exclusions.yaml

time_exclusions:
  # Maintenance Window
  maintenance:
    schedule:
      - day: sunday
        start: "02:00"
        end: "06:00"
    applies_to:
      - UC-032  # CloudTrail Disabled
      - UC-133  # Rule Change Audit
    action: reduce_severity
    severity_modifier: -40

  # Batch Processing Window
  batch_jobs:
    schedule:
      - day: "*"
        start: "00:00"
        end: "04:00"
    applies_to:
      - UC-059  # Database Export
      - UC-050  # Mass File Download
    action: add_context
    context: "batch_window"
```

### Threshold Tuning

```yaml
# tuning/thresholds.yaml

thresholds:
  # Brute Force Detection
  UC-111:
    original:
      failed_logins: 5
      window: "10m"
    tuned:
      failed_logins: 10
      window: "5m"
    reason: "High FP rate from password managers"

  # Mass Download Detection
  UC-050:
    original:
      file_count: 50
      window: "15m"
    tuned:
      file_count: 100
      window: "10m"
    reason: "Legitimate project downloads triggering"

  # Port Scan Detection
  UC-135:
    original:
      unique_ports: 10
      window: "1m"
    tuned:
      unique_ports: 25
      window: "1m"
    reason: "Normal service discovery"
```

---

## Phase 4: Implement in n8n

### Allowlist Check Node

```javascript
// Tuning Logic Node
const alert = $input.first().json;

// Load allowlists
const allowlists = await loadAllowlists();

// Check each applicable allowlist
let action = 'process'; // default
let severityModifier = 0;

for (const list of allowlists) {
  if (listAppliesToUseCase(list, alert.use_case_id)) {
    if (matchesAllowlist(alert, list)) {
      if (list.action === 'suppress') {
        return { json: { ...alert, suppressed: true, reason: list.name } };
      } else if (list.action === 'reduce_severity') {
        severityModifier += list.severity_modifier;
      }
    }
  }
}

// Apply severity modification
alert.severity_score = Math.max(0, Math.min(100, alert.severity_score + severityModifier));
alert.tuning_applied = severityModifier !== 0;

return { json: alert };
```

---

## Phase 5: Continuous Improvement

### Feedback Loop Implementation

```javascript
// Track closure reasons for ML learning
const trackClosure = async (incident) => {
  const feedback = {
    incident_id: incident.id,
    use_case_id: incident.use_case_id,
    original_severity: incident.original_severity,
    final_severity: incident.severity,
    was_true_positive: incident.closeReason !== 'false_positive',
    closure_reason: incident.closeReason,
    time_to_close: incident.closedAt - incident.createdAt,
    analyst_id: incident.closedBy
  };
  
  await saveFeedback(feedback);
  
  // Auto-suggest tuning after 5 FPs for same use case
  const fpCount = await getFPCount(incident.use_case_id, '7d');
  if (fpCount >= 5) {
    await suggestTuning(incident.use_case_id);
  }
};
```

### Weekly Tuning Review

```markdown
## Weekly Tuning Review Checklist

- [ ] Review top 10 FP-generating use cases
- [ ] Analyze new FP patterns
- [ ] Update allowlists as needed
- [ ] Adjust thresholds based on data
- [ ] Review suppressed alerts for missed TPs
- [ ] Update this quarter's tuning metrics
```

---

## Tuning Metrics Dashboard

### Key Metrics to Track

| Metric | Target | Current | Trend |
|--------|--------|---------|-------|
| Overall FP Rate | < 30% | TBD | - |
| Avg Time to Close | < 15m | TBD | - |
| Suppression Rate | < 20% | TBD | - |
| Missed TP Rate | < 1% | TBD | - |

---

## Related Documentation

- [Correlation Rules](correlation-rules.md)
- [AI Agent Prompts](../agent-prompts/triage-agent.md)
- [Use Case Index](USE-CASE-INDEX.md)
