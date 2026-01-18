# Threat Intelligence Use Cases (226-250)

> **X-n8n Playbook Collection** - Automated Enrichment & IOC Management

---

## Overview

Threat Intelligence use cases focus on automated IOC enrichment, threat feed integration, and intelligence-driven security operations.

### MITRE ATT&CK Mapping
- **T1588** - Obtain Capabilities
- **T1594** - Search Victim-Owned Websites
- **T1595** - Active Scanning

---

## Use Cases Summary

| ID | Use Case | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| UC-226 | VirusTotal Hash Enrichment | Variable | T1588 |
| UC-227 | AlienVault OTX Lookup | Variable | T1588 |
| UC-228 | MISP IOC Correlation | High | T1588 |
| UC-229 | IP Reputation Check | Variable | T1595 |
| UC-230 | Domain Age Analysis | Medium | T1594 |
| UC-231 | WHOIS History Lookup | Low | T1594 |
| UC-232 | Passive DNS Enrichment | Medium | T1594 |
| UC-233 | Certificate Transparency | Low | T1594 |
| UC-234 | Threat Actor Attribution | High | T1588 |
| UC-235 | Campaign Correlation | High | T1588 |
| UC-236 | IOC Aging & Expiry | Low | T1588 |
| UC-237 | Custom Feed Integration | Variable | T1588 |
| UC-238 | Shodan Asset Lookup | Medium | T1595 |
| UC-239 | Dark Web Mention Alert | High | T1594 |
| UC-240 | Brand Impersonation Detect | High | T1594 |
| UC-241 | Typosquatting Detection | Medium | T1594 |
| UC-242 | APT IOC Matching | Critical | T1588 |
| UC-243 | Sandbox Detonation | High | T1588 |
| UC-244 | YARA Rule Matching | High | T1588 |
| UC-245 | STIX/TAXII Consumption | Variable | T1588 |
| UC-246 | Threat Report Parsing | Low | T1588 |
| UC-247 | IOC Deduplication | Low | T1588 |
| UC-248 | Confidence Scoring | Variable | T1588 |
| UC-249 | Historical IOC Retrohunt | High | T1588 |
| UC-250 | TI Platform Sync | Low | T1588 |

---

## Sample Use Case Details

### UC-226: VirusTotal Hash Enrichment

**Trigger**: File hash detected in security alert

**n8n Logic**:
```javascript
const alert = $input.first().json;
const vtApiKey = $env.VIRUSTOTAL_API_KEY;
const vtResult = await fetch(`https://www.virustotal.com/api/v3/files/${alert.fileHash}`, {
  headers: { 'x-apikey': vtApiKey }
}).then(r => r.json());

const maliciousCount = vtResult.data?.attributes?.last_analysis_stats?.malicious || 0;
const severity = maliciousCount > 10 ? "critical" : maliciousCount > 3 ? "high" : "medium";

return { ...alert, vt_score: maliciousCount, vt_total: vtResult.data?.attributes?.last_analysis_stats?.total,
         severity, enriched: true };
```

**XSOAR Actions**: Update DBOT score, add to blocklist if malicious

### UC-228: MISP IOC Correlation

**Trigger**: New IOC to correlate against MISP threat database

**n8n Logic**:
```javascript
const ioc = $input.first().json;
const mispResult = await searchMISP(ioc.value, ioc.type);
if (mispResult.hits > 0) {
  return { ...ioc, misp_events: mispResult.events, threat_actors: mispResult.threat_actors,
           campaigns: mispResult.campaigns, severity: "high" };
}
return { ...ioc, misp_hits: 0, severity: "low" };
```

**XSOAR Actions**: Create incident if APT match, update indicator

### UC-242: APT IOC Matching

**Trigger**: IOC matches known APT threat actor indicators

**n8n Logic**:
```javascript
const alert = $input.first().json;
const aptFeeds = await getAPTIOCs(); // Premium feeds: Mandiant, CrowdStrike, etc.
const matches = aptFeeds.filter(f => 
  f.indicators.includes(alert.indicator)
);
if (matches.length > 0) {
  return { ...alert, apt_groups: matches.map(m => m.threat_actor),
           campaigns: matches.map(m => m.campaign), severity: "critical",
           alert_type: "apt_indicator_match" };
}
```

**XSOAR Actions**: Escalate to threat intel team, trigger IR playbook, brief executives

### UC-249: Historical IOC Retrohunt

**Trigger**: New threat intelligence requires searching historical logs

**n8n Logic**:
```javascript
const newIOC = $input.first().json;
// Search last 90 days of SIEM data for new IOC
const searchQuery = buildRetroHuntQuery(newIOC);
const historicalHits = await searchSIEM(searchQuery, { timeRange: '90d' });
if (historicalHits.length > 0) {
  return { ioc: newIOC, historical_hits: historicalHits, first_seen: historicalHits[0].timestamp,
           affected_hosts: [...new Set(historicalHits.map(h => h.hostname))], severity: "high" };
}
```

**XSOAR Actions**: Create incident for each affected system, timeline analysis
