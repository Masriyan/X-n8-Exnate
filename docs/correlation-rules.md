# X-n8 Correlation Rules

> **Advanced Alert Correlation Logic for Intelligent Clustering**

---

## Overview

X-n8 uses multi-dimensional correlation to group related alerts into actionable incidents. This reduces alert fatigue and provides analysts with complete attack context.

---

## Correlation Dimensions

### 1. Entity-Based Correlation

Group alerts by common entities:

```javascript
// Entity Correlation Rules
const entityCorrelation = {
  // Same user across multiple systems
  user: {
    window: '1h',
    threshold: 3,
    boost_severity: true
  },
  
  // Same host with multiple alerts
  host: {
    window: '30m',
    threshold: 5,
    boost_severity: true
  },
  
  // Same source IP across alerts
  src_ip: {
    window: '15m',
    threshold: 3,
    boost_severity: true
  },
  
  // Same destination (potential C2)
  dst_ip: {
    window: '1h',
    threshold: 10,
    boost_severity: true
  }
};
```

### 2. Time-Based Correlation

Cluster alerts within time windows:

```javascript
// Time Window Configuration
const timeWindows = {
  // Rapid-fire alerts (attack in progress)
  burst: {
    window: '5m',
    min_alerts: 10,
    severity_boost: 20
  },
  
  // Standard correlation window
  standard: {
    window: '15m',
    min_alerts: 3,
    severity_boost: 10
  },
  
  // Extended correlation (slow attacks)
  extended: {
    window: '1h',
    min_alerts: 5,
    severity_boost: 5
  }
};
```

### 3. Attack Chain Correlation

Detect multi-stage attacks by mapping to kill chain:

```javascript
// Kill Chain Stage Mapping
const killChainCorrelation = {
  stages: [
    { stage: 'reconnaissance', techniques: ['T1595', 'T1592', 'T1589'] },
    { stage: 'initial_access', techniques: ['T1566', 'T1190', 'T1133'] },
    { stage: 'execution', techniques: ['T1059', 'T1204', 'T1053'] },
    { stage: 'persistence', techniques: ['T1547', 'T1053', 'T1546'] },
    { stage: 'privilege_escalation', techniques: ['T1068', 'T1078', 'T1134'] },
    { stage: 'defense_evasion', techniques: ['T1562', 'T1070', 'T1027'] },
    { stage: 'credential_access', techniques: ['T1003', 'T1110', 'T1555'] },
    { stage: 'lateral_movement', techniques: ['T1021', 'T1570', 'T1563'] },
    { stage: 'collection', techniques: ['T1119', 'T1005', 'T1074'] },
    { stage: 'exfiltration', techniques: ['T1041', 'T1048', 'T1567'] },
    { stage: 'impact', techniques: ['T1486', 'T1490', 'T1489'] }
  ],
  
  // Alert if multiple stages detected for same entity
  multi_stage_threshold: 3,
  severity_multiplier: 1.5
};
```

---

## Correlation Rules by Category

### Rule: Brute Force → Successful Login

```javascript
{
  name: "Credential Compromise Chain",
  conditions: [
    { event_type: "failed_login", count: ">= 5", window: "10m" },
    { event_type: "successful_login", count: ">= 1", window: "5m" }
  ],
  correlation_key: ["user", "src_ip"],
  severity: "critical",
  mitre: ["T1110", "T1078"],
  action: "create_incident"
}
```

### Rule: Phishing → Execution → C2

```javascript
{
  name: "Phishing Attack Chain",
  conditions: [
    { category: "email_security", event_type: "phishing_click" },
    { category: "edr", event_type: "suspicious_process", window: "30m" },
    { category: "firewall", event_type: "c2_communication", window: "1h" }
  ],
  correlation_key: ["user", "host"],
  severity: "critical",
  mitre: ["T1566", "T1059", "T1071"],
  action: "immediate_isolation"
}
```

### Rule: Lateral Movement Pattern

```javascript
{
  name: "Lateral Movement Detection",
  conditions: [
    { event_type: "authentication", src_host: "!= dst_host", count: ">= 3", window: "15m" }
  ],
  filters: [
    { exclude: "service_accounts" },
    { exclude: "admin_workstations" }
  ],
  correlation_key: ["user"],
  severity: "high",
  mitre: ["T1021"],
  action: "create_incident"
}
```

### Rule: Data Exfiltration Pattern

```javascript
{
  name: "Data Exfiltration Indicators",
  conditions: [
    { event_type: "large_download", size_mb: "> 100" },
    { event_type: "external_upload", window: "1h" }
  ],
  correlation_key: ["user", "host"],
  severity: "high",
  mitre: ["T1041", "T1567"],
  action: "create_incident",
  additional_context: ["user_risk_score", "data_classification"]
}
```

---

## Severity Boosting Rules

```javascript
const severityBoost = {
  // VIP user involved
  vip_user: { boost: 20, max: 100 },
  
  // Crown jewel asset
  critical_asset: { boost: 25, max: 100 },
  
  // Multiple MITRE stages
  multi_stage_attack: { boost: 15, max: 100 },
  
  // After hours activity
  after_hours: { boost: 10, max: 100 },
  
  // Known bad IP/domain
  threat_intel_match: { boost: 20, max: 100 },
  
  // High alert volume (alert storm)
  alert_volume: { 
    threshold: 50, 
    window: "5m", 
    boost: 10, 
    max: 100 
  }
};
```

---

## Deduplication Rules

```javascript
const deduplicationRules = {
  // Content-based dedup (same alert)
  content_hash: {
    fields: ['event_type', 'src_ip', 'dst_ip', 'user', 'host'],
    ttl: 300 // 5 minutes
  },
  
  // Time-window aggregation
  time_aggregate: {
    groupBy: ['event_type', 'host'],
    window: '5m',
    action: 'count_and_merge'
  },
  
  // False positive tracking
  false_positive: {
    track_closes: true,
    auto_suppress_after: 5,
    confidence_threshold: 0.9
  }
};
```

---

## Implementation Example

```javascript
// n8n Correlation Node
const correlate = async (alert) => {
  const correlationId = generateCorrelationId(alert);
  
  // Check for existing correlation group
  const existing = await redis.get(`correlation:${correlationId}`);
  
  if (existing) {
    // Add to existing group
    const group = JSON.parse(existing);
    group.alerts.push(alert);
    group.count++;
    group.last_seen = alert.timestamp;
    
    // Check for severity boost conditions
    if (group.count >= 5) {
      group.severity = Math.min(group.severity + 10, 100);
    }
    
    // Check for kill chain progression
    const stages = detectKillChainStages(group.alerts);
    if (stages.length >= 3) {
      group.severity = Math.min(group.severity * 1.5, 100);
      group.is_multi_stage_attack = true;
    }
    
    await redis.setex(`correlation:${correlationId}`, 3600, JSON.stringify(group));
    return group;
  } else {
    // Create new correlation group
    const newGroup = {
      id: correlationId,
      alerts: [alert],
      count: 1,
      severity: alert.severity_score,
      created: alert.timestamp,
      last_seen: alert.timestamp,
      entities: extractEntities(alert)
    };
    
    await redis.setex(`correlation:${correlationId}`, 3600, JSON.stringify(newGroup));
    return newGroup;
  }
};

function generateCorrelationId(alert) {
  const entities = [
    alert.entities?.user,
    alert.entities?.host,
    alert.entities?.src_ip
  ].filter(Boolean).join('|');
  
  const timeWindow = Math.floor(Date.parse(alert.timestamp) / 900000); // 15-min window
  
  return crypto.createHash('sha256')
    .update(`${entities}:${timeWindow}`)
    .digest('hex')
    .substring(0, 16);
}
```

---

## Alert Storm Detection

```javascript
const detectAlertStorm = async (source) => {
  const key = `storm:${source}`;
  const count = await redis.incr(key);
  await redis.expire(key, 300); // 5-minute window
  
  if (count >= 100) {
    return {
      is_storm: true,
      count: count,
      action: 'aggregate_and_escalate',
      severity: 'critical'
    };
  }
  
  return { is_storm: false, count: count };
};
```

---

## Related Documentation

- [Architecture](architecture.md)
- [AI Agent Prompts](../agent-prompts/triage-agent.md)
- [Deduplication Workflow](../n8n-workflows/core/deduplication.json)
