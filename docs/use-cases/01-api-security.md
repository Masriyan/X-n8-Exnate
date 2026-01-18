# API Security Use Cases (1-20)

> **X-n8 Playbook Collection** - Protecting APIs from Shadow IT to BOLA Exploitation

---

## Overview

API Security use cases focus on detecting and responding to threats targeting application programming interfaces, including unauthorized access, data exposure, and exploitation of authentication/authorization flaws.

### MITRE ATT&CK Mapping
- **T1190** - Exploit Public-Facing Application
- **T1552** - Unsecured Credentials
- **T1078** - Valid Accounts
- **T1539** - Steal Web Session Cookie

---

## Use Cases

### UC-001: Shadow API Discovery & Alert

| Field | Value |
|-------|-------|
| **ID** | UC-001 |
| **Name** | Shadow API Discovery & Alert |
| **Category** | API Security |
| **Severity** | Medium |
| **MITRE ATT&CK** | T1190 |

**Description**: Detect undocumented or shadow APIs that are not part of the official API inventory, potentially exposing sensitive endpoints.

**Trigger**: API Gateway logs showing requests to unregistered endpoints

**n8n Logic**:
```javascript
// Detect endpoints not in known API inventory
const knownAPIs = await getKnownAPIInventory();
const requestedEndpoint = $input.first().json.endpoint;

if (!knownAPIs.includes(requestedEndpoint)) {
  return {
    alert_type: "shadow_api_detected",
    endpoint: requestedEndpoint,
    severity: "medium",
    action: "notify_api_team"
  };
}
```

**AI Agent Prompt**:
```
Analyze this potential shadow API detection:
- Endpoint: {{endpoint}}
- Request count: {{request_count}}
- Source IPs: {{source_ips}}

Determine if this is:
1. A legitimate new API not yet documented
2. A deprecated API still in use
3. A potentially malicious endpoint
4. A misconfigured client

Recommend appropriate action.
```

**XSOAR Actions**:
- Create incident for API governance review
- Notify API security team
- Update API inventory if legitimate

---

### UC-002: BOLA (Broken Object Level Authorization) Detection

| Field | Value |
|-------|-------|
| **ID** | UC-002 |
| **Name** | BOLA Attack Detection |
| **Category** | API Security |
| **Severity** | High |
| **MITRE ATT&CK** | T1078.004 |

**Description**: Detect attempts to access resources belonging to other users by manipulating object identifiers (IDOR attacks).

**Trigger**: API requests where user attempts to access objects outside their scope

**n8n Logic**:
```javascript
// Detect BOLA attempts
const userId = $input.first().json.authenticated_user;
const requestedObjectOwner = $input.first().json.object_owner;
const endpoint = $input.first().json.endpoint;

if (userId !== requestedObjectOwner) {
  const attemptCount = await countRecentAttempts(userId, "bola", "1h");
  
  return {
    alert_type: "bola_attempt",
    attacker: userId,
    target_owner: requestedObjectOwner,
    endpoint: endpoint,
    attempt_count: attemptCount,
    severity: attemptCount > 5 ? "critical" : "high"
  };
}
```

**AI Agent Prompt**:
```
Analyze this BOLA/IDOR attack attempt:
- Authenticated User: {{attacker}}
- Attempted to access object owned by: {{target_owner}}
- Endpoint: {{endpoint}}
- Attempt count in last hour: {{attempt_count}}
- Request pattern: {{request_pattern}}

Assess:
1. Is this a deliberate attack or accidental access?
2. What data could be exposed if successful?
3. Should the user session be terminated?
4. Recommended blocking actions.
```

**XSOAR Actions**:
- Block user session if > 10 attempts
- Create high-priority incident
- Enrich with user profile data
- Notify application security team

---

### UC-003: JWT Token Tampering Detection

| Field | Value |
|-------|-------|
| **ID** | UC-003 |
| **Name** | JWT Token Tampering Detection |
| **Category** | API Security |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1539, T1550.001 |

**Description**: Detect attempts to modify JWT tokens, including algorithm confusion attacks, signature stripping, and claim manipulation.

**Trigger**: JWT validation failures with specific error patterns

**n8n Logic**:
```javascript
// Detect JWT tampering patterns
const jwtError = $input.first().json.error_type;
const token = $input.first().json.token_preview;
const sourceIP = $input.first().json.source_ip;

const tamperingPatterns = [
  "algorithm_none",
  "signature_invalid",
  "header_modified",
  "claim_type_confusion",
  "expired_token_replay"
];

if (tamperingPatterns.includes(jwtError)) {
  return {
    alert_type: "jwt_tampering",
    tampering_type: jwtError,
    source_ip: sourceIP,
    severity: "critical",
    escalate_xsoar: true
  };
}
```

**AI Agent Prompt**:
```
Critical JWT tampering attempt detected:
- Tampering Type: {{tampering_type}}
- Source IP: {{source_ip}}
- Token Header: {{token_header}}
- Error Details: {{error_details}}

Analyze:
1. What attack technique is being attempted?
2. Is this part of a larger attack pattern?
3. Should the source IP be blocked immediately?
4. Are other users affected?

Provide severity score (0-100) and recommended actions.
```

**XSOAR Actions**:
- Block source IP at WAF level
- Invalidate all sessions from source IP
- Create critical incident
- Trigger threat hunting workflow

---

### UC-004: API Rate Limit Bypass Detection

| Field | Value |
|-------|-------|
| **ID** | UC-004 |
| **Name** | API Rate Limit Bypass Detection |
| **Category** | API Security |
| **Severity** | High |
| **MITRE ATT&CK** | T1499.003 |

**Description**: Detect attempts to bypass API rate limiting through header manipulation, IP rotation, or credential rotation.

**Trigger**: Unusual request patterns that suggest rate limit evasion

**n8n Logic**:
```javascript
// Detect rate limit bypass attempts
const requestPatterns = $input.first().json.request_patterns;

const bypassIndicators = {
  header_manipulation: requestPatterns.varying_xff_headers,
  ip_rotation: requestPatterns.unique_ips > 10 && requestPatterns.same_user_agent,
  credential_rotation: requestPatterns.unique_api_keys > 5 && requestPatterns.same_ip,
  request_timing: requestPatterns.requests_per_second > 100
};

const detected = Object.entries(bypassIndicators)
  .filter(([_, value]) => value)
  .map(([key, _]) => key);

if (detected.length > 0) {
  return {
    alert_type: "rate_limit_bypass",
    bypass_techniques: detected,
    severity: "high",
    source_fingerprint: requestPatterns.fingerprint
  };
}
```

**XSOAR Actions**:
- Add source fingerprint to blocklist
- Update WAF rules
- Create incident for review
- Generate threat intel indicator

---

### UC-005: Sensitive Data Exposure in API Response

| Field | Value |
|-------|-------|
| **ID** | UC-005 |
| **Name** | Sensitive Data Exposure Detection |
| **Category** | API Security |
| **Severity** | High |
| **MITRE ATT&CK** | T1530 |

**Description**: Detect API responses containing sensitive data (PII, credentials, internal IDs) that should not be exposed.

**Trigger**: DLP scanner detection in API response payloads

**n8n Logic**:
```javascript
// Analyze API response for sensitive data
const response = $input.first().json.response_body;
const endpoint = $input.first().json.endpoint;

const sensitivePatterns = {
  ssn: /\b\d{3}-\d{2}-\d{4}\b/,
  credit_card: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/,
  api_key: /\b(api[_-]?key|apikey)["\s:=]+["']?[\w-]{20,}/i,
  password_hash: /\$2[aby]?\$\d+\$[\w./]+/,
  internal_ip: /\b10\.\d+\.\d+\.\d+\b|\b172\.(1[6-9]|2\d|3[01])\.\d+\.\d+\b/
};

const exposures = Object.entries(sensitivePatterns)
  .filter(([_, pattern]) => pattern.test(JSON.stringify(response)))
  .map(([type, _]) => type);

if (exposures.length > 0) {
  return {
    alert_type: "sensitive_data_exposure",
    data_types: exposures,
    endpoint: endpoint,
    severity: "high"
  };
}
```

**XSOAR Actions**:
- Notify data privacy team
- Create compliance incident
- Flag endpoint for immediate review
- Optionally block endpoint until fixed

---

### UC-006: GraphQL Introspection Attack

| Field | Value |
|-------|-------|
| **ID** | UC-006 |
| **Name** | GraphQL Introspection Attack Detection |
| **Category** | API Security |
| **Severity** | Medium |
| **MITRE ATT&CK** | T1595.002 |

**Description**: Detect unauthorized GraphQL introspection queries used for reconnaissance.

**Trigger**: GraphQL queries containing __schema or __type introspection

**n8n Logic**:
```javascript
// Detect GraphQL introspection
const query = $input.first().json.graphql_query;
const sourceIP = $input.first().json.source_ip;
const isAuthenticated = $input.first().json.is_authenticated;

const introspectionPatterns = [
  /__schema/i,
  /__type/i,
  /queryType/i,
  /mutationType/i
];

const isIntrospection = introspectionPatterns.some(p => p.test(query));

if (isIntrospection && !isAuthenticated) {
  return {
    alert_type: "graphql_introspection",
    source_ip: sourceIP,
    severity: "medium",
    recon_indicator: true
  };
}
```

**XSOAR Actions**:
- Log reconnaissance attempt
- Add IP to watch list
- Correlate with other recon activity
- Create low-priority incident if pattern emerges

---

### UC-007: API Key Leakage Detection (External)

| Field | Value |
|-------|-------|
| **ID** | UC-007 |
| **Name** | External API Key Leakage Detection |
| **Category** | API Security |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1552.001 |

**Description**: Detect organization's API keys exposed in public repositories, paste sites, or other external sources.

**Trigger**: Threat intelligence feed or GitHub scanning alert

**n8n Logic**:
```javascript
// Process API key leakage alert
const leakSource = $input.first().json.source;
const apiKeyPrefix = $input.first().json.key_prefix;
const exposureUrl = $input.first().json.exposure_url;

// Match against known API key patterns
const keyOwner = await matchApiKeyToOwner(apiKeyPrefix);

return {
  alert_type: "api_key_leaked",
  source: leakSource,
  exposure_url: exposureUrl,
  key_owner: keyOwner,
  severity: "critical",
  immediate_action: "rotate_key"
};
```

**XSOAR Actions**:
- Immediately rotate exposed API key
- Notify key owner
- Audit key usage history
- Create critical incident
- Block old key

---

### UC-008: Mass Assignment Vulnerability Exploitation

| Field | Value |
|-------|-------|
| **ID** | UC-008 |
| **Name** | Mass Assignment Attack Detection |
| **Category** | API Security |
| **Severity** | High |
| **MITRE ATT&CK** | T1190 |

**Description**: Detect attempts to exploit mass assignment vulnerabilities by submitting unexpected parameters.

**Trigger**: API request containing unauthorized fields (isAdmin, role, permissions)

**n8n Logic**:
```javascript
// Detect mass assignment attempts
const requestBody = $input.first().json.request_body;
const endpoint = $input.first().json.endpoint;
const expectedFields = await getExpectedFields(endpoint);

const dangerousFields = ['isAdmin', 'role', 'permissions', 'is_superuser', 
                          'admin', 'privilege', 'access_level'];

const unexpectedDangerous = Object.keys(requestBody)
  .filter(field => !expectedFields.includes(field))
  .filter(field => dangerousFields.some(d => 
    field.toLowerCase().includes(d.toLowerCase())
  ));

if (unexpectedDangerous.length > 0) {
  return {
    alert_type: "mass_assignment_attempt",
    dangerous_fields: unexpectedDangerous,
    endpoint: endpoint,
    severity: "high"
  };
}
```

**XSOAR Actions**:
- Block request if not already
- Create high-priority incident
- Review user privileges
- Notify development team

---

### UC-009: API Authentication Bypass Attempt

| Field | Value |
|-------|-------|
| **ID** | UC-009 |
| **Name** | API Authentication Bypass Detection |
| **Category** | API Security |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1556 |

**Description**: Detect attempts to bypass API authentication through header manipulation, method override, or path traversal.

**Trigger**: Requests that bypass normal authentication flow

**n8n Logic**:
```javascript
// Detect auth bypass attempts
const request = $input.first().json;

const bypassIndicators = {
  method_override: request.headers['x-http-method-override'] !== undefined,
  admin_header: request.headers['x-admin'] === 'true',
  path_traversal: /\.\.\/?/.test(request.path),
  null_byte: /%00/.test(request.path),
  case_bypass: request.path !== request.path.toLowerCase() && 
               request.path.toLowerCase().includes('/admin')
};

const detected = Object.entries(bypassIndicators)
  .filter(([_, v]) => v)
  .map(([k, _]) => k);

if (detected.length > 0) {
  return {
    alert_type: "auth_bypass_attempt",
    techniques: detected,
    severity: "critical",
    escalate_immediately: true
  };
}
```

**XSOAR Actions**:
- Block source IP immediately
- Create critical incident
- Trigger threat hunt for similar patterns
- Update WAF rules

---

### UC-010: Excessive Data Retrieval (BFLA)

| Field | Value |
|-------|-------|
| **ID** | UC-010 |
| **Name** | Broken Function Level Authorization Detection |
| **Category** | API Security |
| **Severity** | High |
| **MITRE ATT&CK** | T1078 |

**Description**: Detect attempts to access administrative functions without proper authorization (BFLA).

**Trigger**: Non-admin user accessing admin-only endpoints

**n8n Logic**:
```javascript
// Detect BFLA attempts
const userRole = $input.first().json.user_role;
const endpoint = $input.first().json.endpoint;
const adminEndpoints = await getAdminEndpoints();

if (userRole !== 'admin' && adminEndpoints.some(e => endpoint.includes(e))) {
  return {
    alert_type: "bfla_attempt",
    user_role: userRole,
    attempted_endpoint: endpoint,
    severity: "high"
  };
}
```

**XSOAR Actions**:
- Log access attempt
- Create incident
- Review user permissions
- Block if repeated

---

### UC-011: API Endpoint Enumeration Detection

| Field | Value |
|-------|-------|
| **ID** | UC-011 |
| **Name** | API Endpoint Enumeration Detection |
| **Category** | API Security |
| **Severity** | Medium |
| **MITRE ATT&CK** | T1595.002 |

**Description**: Detect systematic enumeration of API endpoints through sequential requests.

**Trigger**: High 404 rate from single source with sequential patterns

**n8n Logic**:
```javascript
// Detect endpoint enumeration
const sourceIP = $input.first().json.source_ip;
const recentRequests = await getRecentRequests(sourceIP, "10m");

const notFoundCount = recentRequests.filter(r => r.status === 404).length;
const uniqueEndpoints = [...new Set(recentRequests.map(r => r.path))].length;

if (notFoundCount > 20 && uniqueEndpoints > 50) {
  return {
    alert_type: "api_enumeration",
    source_ip: sourceIP,
    not_found_count: notFoundCount,
    unique_endpoints: uniqueEndpoints,
    severity: "medium"
  };
}
```

**XSOAR Actions**:
- Rate limit source IP
- Add to watchlist
- Create incident if persistent
- Generate IOC

---

### UC-012: OAuth Token Hijacking Detection

| Field | Value |
|-------|-------|
| **ID** | UC-012 |
| **Name** | OAuth Token Hijacking Detection |
| **Category** | API Security |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1550.001 |

**Description**: Detect OAuth token usage from unexpected locations or devices.

**Trigger**: Token used from different IP/device than issued

**n8n Logic**:
```javascript
// Detect OAuth token hijacking
const tokenId = $input.first().json.token_id;
const currentIP = $input.first().json.current_ip;
const currentDevice = $input.first().json.device_fingerprint;
const tokenMetadata = await getTokenMetadata(tokenId);

const ipMismatch = tokenMetadata.issued_ip !== currentIP;
const deviceMismatch = tokenMetadata.device !== currentDevice;

if (ipMismatch && deviceMismatch) {
  return {
    alert_type: "oauth_token_hijack",
    token_id: tokenId,
    issued_to: { ip: tokenMetadata.issued_ip, device: tokenMetadata.device },
    used_from: { ip: currentIP, device: currentDevice },
    severity: "critical"
  };
}
```

**XSOAR Actions**:
- Revoke compromised token
- Force re-authentication
- Create critical incident
- Notify user

---

### UC-013: API Response Manipulation (MITM)

| Field | Value |
|-------|-------|
| **ID** | UC-013 |
| **Name** | API Response Manipulation Detection |
| **Category** | API Security |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1557 |

**Description**: Detect signs of man-in-the-middle attacks modifying API responses.

**Trigger**: Response integrity check failure

**n8n Logic**:
```javascript
// Detect response manipulation
const responseHash = $input.first().json.response_hash;
const expectedHash = $input.first().json.expected_hash;
const endpoint = $input.first().json.endpoint;

if (responseHash !== expectedHash) {
  return {
    alert_type: "response_manipulation",
    endpoint: endpoint,
    severity: "critical",
    potential_mitm: true
  };
}
```

**XSOAR Actions**:
- Alert security team immediately
- Investigate network path
- Create critical incident
- Enable enhanced logging

---

### UC-014: Server-Side Request Forgery (SSRF) via API

| Field | Value |
|-------|-------|
| **ID** | UC-014 |
| **Name** | SSRF via API Detection |
| **Category** | API Security |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1190 |

**Description**: Detect SSRF attempts through API parameters accepting URLs.

**Trigger**: API request with internal/metadata URLs

**n8n Logic**:
```javascript
// Detect SSRF attempts
const urlParams = $input.first().json.url_parameters;

const ssrfPatterns = [
  /169\.254\.169\.254/,  // AWS metadata
  /metadata\.google\.internal/,  // GCP metadata
  /127\.0\.0\.1/,
  /localhost/i,
  /0\.0\.0\.0/,
  /10\.\d+\.\d+\.\d+/,
  /192\.168\.\d+\.\d+/,
  /172\.(1[6-9]|2\d|3[01])\./
];

const ssrfAttempts = urlParams.filter(param =>
  ssrfPatterns.some(pattern => pattern.test(param))
);

if (ssrfAttempts.length > 0) {
  return {
    alert_type: "ssrf_attempt",
    malicious_urls: ssrfAttempts,
    severity: "critical"
  };
}
```

**XSOAR Actions**:
- Block request
- Create critical incident
- Review application for SSRF vulnerabilities
- Block source IP

---

### UC-015: API Versioning Exploitation

| Field | Value |
|-------|-------|
| **ID** | UC-015 |
| **Name** | Old API Version Exploitation |
| **Category** | API Security |
| **Severity** | Medium |
| **MITRE ATT&CK** | T1190 |

**Description**: Detect access to deprecated API versions with known vulnerabilities.

**Trigger**: Requests to deprecated API versions

**n8n Logic**:
```javascript
// Detect deprecated API version access
const apiVersion = $input.first().json.api_version;
const deprecatedVersions = ['v1', 'v1.0', 'v1.1', 'v2.0-beta'];

if (deprecatedVersions.includes(apiVersion)) {
  const vulnerabilities = await getKnownVulns(apiVersion);
  return {
    alert_type: "deprecated_api_access",
    version: apiVersion,
    known_vulnerabilities: vulnerabilities,
    severity: vulnerabilities.length > 0 ? "high" : "medium"
  };
}
```

**XSOAR Actions**:
- Log access attempt
- Notify API owners
- Create incident if exploitation attempted
- Consider blocking deprecated versions

---

### UC-016: WebSocket Injection Attack

| Field | Value |
|-------|-------|
| **ID** | UC-016 |
| **Name** | WebSocket Injection Detection |
| **Category** | API Security |
| **Severity** | High |
| **MITRE ATT&CK** | T1190 |

**Description**: Detect injection attacks through WebSocket connections.

**Trigger**: WebSocket messages containing injection payloads

**n8n Logic**:
```javascript
// Detect WebSocket injection
const message = $input.first().json.ws_message;

const injectionPatterns = [
  /<script[^>]*>/i,
  /javascript:/i,
  /on\w+\s*=/i,
  /['"];\s*(delete|drop|insert|update)/i,
  /\$\{.*\}/
];

const injectionType = injectionPatterns
  .find(pattern => pattern.test(message));

if (injectionType) {
  return {
    alert_type: "websocket_injection",
    message_preview: message.substring(0, 100),
    severity: "high"
  };
}
```

**XSOAR Actions**:
- Terminate WebSocket connection
- Block source
- Create incident
- Review application

---

### UC-017: API Credential Stuffing Detection

| Field | Value |
|-------|-------|
| **ID** | UC-017 |
| **Name** | API Credential Stuffing Detection |
| **Category** | API Security |
| **Severity** | High |
| **MITRE ATT&CK** | T1110.004 |

**Description**: Detect credential stuffing attacks against API authentication endpoints.

**Trigger**: High volume of failed authentications from distributed sources

**n8n Logic**:
```javascript
// Detect credential stuffing
const authAttempts = $input.first().json.auth_attempts;
const timeWindow = "5m";

const uniqueUsers = [...new Set(authAttempts.map(a => a.username))].length;
const uniqueIPs = [...new Set(authAttempts.map(a => a.ip))].length;
const failureRate = authAttempts.filter(a => !a.success).length / authAttempts.length;

if (uniqueUsers > 100 && uniqueIPs > 10 && failureRate > 0.9) {
  return {
    alert_type: "credential_stuffing",
    unique_users: uniqueUsers,
    unique_ips: uniqueIPs,
    failure_rate: failureRate,
    severity: "high"
  };
}
```

**XSOAR Actions**:
- Enable CAPTCHA
- Rate limit authentication
- Create incident
- Block aggressive IPs

---

### UC-018: API Business Logic Abuse

| Field | Value |
|-------|-------|
| **ID** | UC-018 |
| **Name** | Business Logic Abuse Detection |
| **Category** | API Security |
| **Severity** | High |
| **MITRE ATT&CK** | T1190 |

**Description**: Detect abuse of API business logic (e.g., coupon abuse, referral fraud).

**Trigger**: Unusual patterns in business-sensitive API calls

**n8n Logic**:
```javascript
// Detect business logic abuse
const userId = $input.first().json.user_id;
const action = $input.first().json.action;
const value = $input.first().json.value;

const thresholds = {
  coupon_redemption: { max: 5, period: "24h" },
  referral_bonus: { max: 10, period: "7d" },
  price_override: { max: 1, period: "1h" }
};

const threshold = thresholds[action];
if (threshold) {
  const count = await getActionCount(userId, action, threshold.period);
  if (count > threshold.max) {
    return {
      alert_type: "business_logic_abuse",
      action: action,
      count: count,
      threshold: threshold.max,
      severity: "high"
    };
  }
}
```

**XSOAR Actions**:
- Flag user account
- Create incident for fraud team
- Reverse fraudulent transactions if applicable
- Review account history

---

### UC-019: API Debug/Test Endpoint Exposure

| Field | Value |
|-------|-------|
| **ID** | UC-019 |
| **Name** | Debug Endpoint Exposure Detection |
| **Category** | API Security |
| **Severity** | High |
| **MITRE ATT&CK** | T1190 |

**Description**: Detect access to debug or test endpoints in production.

**Trigger**: Requests to debug/test endpoints

**n8n Logic**:
```javascript
// Detect debug endpoint access
const endpoint = $input.first().json.endpoint;
const environment = process.env.ENVIRONMENT;

const debugPatterns = [
  /\/debug\//i,
  /\/test\//i,
  /\/phpinfo/i,
  /\/swagger/i,
  /\/api-docs/i,
  /\/_profiler/i,
  /\/actuator/i
];

if (environment === 'production') {
  const isDebugEndpoint = debugPatterns.some(p => p.test(endpoint));
  if (isDebugEndpoint) {
    return {
      alert_type: "debug_endpoint_access",
      endpoint: endpoint,
      severity: "high"
    };
  }
}
```

**XSOAR Actions**:
- Alert DevOps team
- Create incident
- Review production deployment
- Block endpoint if sensitive

---

### UC-020: API Denial of Service Detection

| Field | Value |
|-------|-------|
| **ID** | UC-020 |
| **Name** | API DoS Attack Detection |
| **Category** | API Security |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1499 |

**Description**: Detect denial of service attacks targeting API infrastructure.

**Trigger**: Sudden spike in requests or resource exhaustion

**n8n Logic**:
```javascript
// Detect API DoS
const metrics = $input.first().json.api_metrics;

const dosIndicators = {
  request_spike: metrics.requests_per_second > metrics.baseline_rps * 10,
  error_rate: metrics.error_rate > 0.5,
  response_time: metrics.avg_response_ms > 5000,
  connection_exhaustion: metrics.active_connections > metrics.max_connections * 0.9
};

const activeIndicators = Object.entries(dosIndicators)
  .filter(([_, v]) => v)
  .map(([k, _]) => k);

if (activeIndicators.length >= 2) {
  return {
    alert_type: "api_dos",
    indicators: activeIndicators,
    severity: "critical",
    escalate_immediately: true
  };
}
```

**XSOAR Actions**:
- Enable emergency rate limiting
- Activate DDoS protection
- Create critical incident
- Notify SRE/DevOps
- Consider geographic blocking if targeted

---

## Summary Table

| ID | Use Case | Severity | MITRE ATT&CK | Primary Layer |
|----|----------|----------|--------------|---------------|
| UC-001 | Shadow API Discovery | Medium | T1190 | n8n |
| UC-002 | BOLA Detection | High | T1078.004 | n8n + XSOAR |
| UC-003 | JWT Tampering | Critical | T1539 | n8n + XSOAR |
| UC-004 | Rate Limit Bypass | High | T1499.003 | n8n |
| UC-005 | Data Exposure | High | T1530 | n8n + XSOAR |
| UC-006 | GraphQL Introspection | Medium | T1595.002 | n8n |
| UC-007 | API Key Leakage | Critical | T1552.001 | XSOAR |
| UC-008 | Mass Assignment | High | T1190 | n8n |
| UC-009 | Auth Bypass | Critical | T1556 | n8n + XSOAR |
| UC-010 | BFLA | High | T1078 | n8n |
| UC-011 | Endpoint Enumeration | Medium | T1595.002 | n8n |
| UC-012 | OAuth Hijacking | Critical | T1550.001 | XSOAR |
| UC-013 | Response Manipulation | Critical | T1557 | XSOAR |
| UC-014 | SSRF | Critical | T1190 | n8n + XSOAR |
| UC-015 | Version Exploitation | Medium | T1190 | n8n |
| UC-016 | WebSocket Injection | High | T1190 | n8n |
| UC-017 | Credential Stuffing | High | T1110.004 | n8n + XSOAR |
| UC-018 | Business Logic Abuse | High | T1190 | n8n |
| UC-019 | Debug Endpoint | High | T1190 | n8n |
| UC-020 | API DoS | Critical | T1499 | XSOAR |
