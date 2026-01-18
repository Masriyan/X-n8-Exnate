# Fraud Detection Use Cases (421-450)

> **X-n8 Playbook Collection** - Financial & Transaction Fraud Detection

---

## Overview

Fraud Detection use cases focus on identifying financial fraud, account takeover, and transaction anomalies.

---

## Use Cases Summary

| ID | Use Case | Severity | Type |
|----|----------|----------|------|
| UC-421 | Account Takeover Pattern | Critical | ATO |
| UC-422 | New Device + High Value Txn | High | Transaction |
| UC-423 | Velocity Check Failure | High | Transaction |
| UC-424 | Geographic Velocity Anomaly | High | Transaction |
| UC-425 | Card Testing Pattern | Medium | Card |
| UC-426 | CNP Fraud Indicators | High | Card |
| UC-427 | Mule Account Detection | High | Money Laundering |
| UC-428 | Layering Transaction Pattern | Critical | Money Laundering |
| UC-429 | Smurfing Detection | High | Money Laundering |
| UC-430 | Refund Abuse Pattern | Medium | Abuse |
| UC-431 | Promo/Coupon Abuse | Medium | Abuse |
| UC-432 | Synthetic Identity Indicators | High | Identity |
| UC-433 | First-Party Fraud Pattern | High | Fraud |
| UC-434 | Friendly Fraud Detection | Medium | Fraud |
| UC-435 | Chargeback Pattern Analysis | Medium | Card |
| UC-436 | BIN Attack Detection | High | Card |
| UC-437 | Device Fingerprint Anomaly | Medium | Device |
| UC-438 | Bot-Driven Transaction | High | Automation |
| UC-439 | API Fraud Pattern | High | API |
| UC-440 | Affiliate Fraud Detection | Medium | Partner |
| UC-441 | Return Fraud Ring | High | Retail |
| UC-442 | Gift Card Fraud | High | Card |
| UC-443 | Subscription Fraud | Medium | Recurring |
| UC-444 | Wire Transfer Anomaly | Critical | Transfer |
| UC-445 | ACH Fraud Detection | High | Transfer |
| UC-446 | Cross-Border Txn Anomaly | High | International |
| UC-447 | High-Risk Merchant Alert | Medium | Merchant |
| UC-448 | POS Compromise Indicators | High | POS |
| UC-449 | Customer Behavior Deviation | Medium | UBA |
| UC-450 | Fraud Ring Detection | Critical | Organized |

---

## Sample Use Case Details

### UC-421: Account Takeover Pattern

**Trigger**: Multiple ATO indicators within short timeframe

**n8n Logic**:
```javascript
const events = $input.all();
const atoIndicators = {
  passwordChange: events.some(e => e.json.action === 'password_change'),
  emailChange: events.some(e => e.json.action === 'email_change'),
  phoneChange: events.some(e => e.json.action === 'phone_change'),
  newPaymentMethod: events.some(e => e.json.action === 'add_payment'),
  newShippingAddress: events.some(e => e.json.action === 'add_address')
};

const indicatorCount = Object.values(atoIndicators).filter(Boolean).length;
if (indicatorCount >= 3) {
  return {
    alert_type: "account_takeover",
    indicators: atoIndicators,
    account: events[0].json.accountId,
    severity: "critical"
  };
}
```

**XSOAR Actions**: Lock account, notify customer via SMS, reverse recent changes
