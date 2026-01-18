# WAF Use Cases (206-225)

> **X-n8n Playbook Collection** - Web Application Firewall Automation

---

## Overview

WAF use cases focus on detecting and mitigating web attacks including SQL injection, XSS, bot detection, and advanced attack patterns.

### MITRE ATT&CK Mapping
- **T1190** - Exploit Public-Facing Application
- **T1059** - Command and Scripting Interpreter
- **T1046** - Network Service Scanning

---

## Use Cases Summary

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-206 | SQL Injection Mitigation | Critical | T1190 |
| UC-207 | XSS Attack Detection | High | T1059.007 |
| UC-208 | Advanced Bot Detection | Medium | T1190 |
| UC-209 | Path Traversal Attack | High | T1190 |
| UC-210 | Command Injection | Critical | T1059 |
| UC-211 | Rate Limit Breach | Medium | T1190 |
| UC-212 | XML/XXE Injection | Critical | T1190 |
| UC-213 | SSRF via WAF Logs | Critical | T1190 |
| UC-214 | API Abuse Pattern | High | T1190 |
| UC-215 | Credential Stuffing | High | T1110.004 |
| UC-216 | Scanner Detection | Low | T1046 |
| UC-217 | Malicious File Upload | High | T1190 |
| UC-218 | Session Hijacking | Critical | T1550.001 |
| UC-219 | Log4j Attack Pattern | Critical | T1190 |
| UC-220 | Deserialization Attack | Critical | T1190 |
| UC-221 | HTTP Request Smuggling | High | T1190 |
| UC-222 | Web Shell Detection | Critical | T1505.003 |
| UC-223 | Brute Force Login | High | T1110.001 |
| UC-224 | Geo-Fencing Violation | Medium | T1090.003 |
| UC-225 | Zero-Day Pattern Analysis | Critical | T1190 |

---

## Sample Use Case Details

### UC-206: SQL Injection Mitigation

**Trigger**: WAF detection of SQL injection patterns

**n8n Logic**:
```javascript
const event = $input.first().json;
const sqliPatterns = [/union.*select/i, /or.*(1=1|'=')/i, /;.*drop\s+table/i];
if (event.ruleId === 'sqli' || sqliPatterns.some(p => p.test(event.payload))) {
  const attackSeverity = event.parameterized ? "medium" : "critical";
  return { alert_type: "sql_injection", attacker_ip: event.srcIP, 
           target_url: event.uri, severity: attackSeverity };
}
```

**XSOAR Actions**: Block IP, create incident, notify AppSec, review vulnerable endpoint

### UC-222: Web Shell Detection

**Trigger**: WAF or file integrity detection of web shell patterns

**n8n Logic**:
```javascript
const event = $input.first().json;
const webshellPatterns = [/eval\(.*\$_(POST|GET|REQUEST)/i, /base64_decode.*shell_exec/i];
if (webshellPatterns.some(p => p.test(event.fileContent || event.requestBody))) {
  return { alert_type: "web_shell_detected", file: event.filePath, host: event.hostname,
           severity: "critical" };
}
```

**XSOAR Actions**: Isolate web server, remove shell, forensic analysis, patch vulnerability

### UC-225: Zero-Day Pattern Analysis

**Trigger**: Novel attack pattern not matching existing signatures

**AI Agent Prompt**:
```
Analyze this unknown attack pattern from WAF logs:
- Request URI: {{uri}}
- Request Body: {{body}}
- Headers: {{headers}}
- Source IP: {{src_ip}}
- Geographic Location: {{geo}}

Determine:
1. What type of attack is being attempted?
2. What vulnerability is being targeted?
3. Is this a known exploit or potentially zero-day?
4. Recommended immediate actions
5. Suggested WAF rule to block similar attacks
```

**XSOAR Actions**: Create high-priority incident, engage threat research, develop custom rule
