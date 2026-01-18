# Security Policy

## 🔐 Reporting a Vulnerability

We take security seriously at X-n8. If you discover a security vulnerability, please report it responsibly.

### How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please email: **security@x-n8.io** (or open a private security advisory on GitHub)

### What to Include

- Type of vulnerability
- Full path to the affected file(s)
- Step-by-step reproduction instructions
- Proof of concept if available
- Potential impact assessment

### Response Timeline

| Action | Timeframe |
|--------|-----------|
| Initial response | 48 hours |
| Vulnerability assessment | 7 days |
| Fix development | 14-30 days |
| Public disclosure | After fix deployed |

---

## 🛡️ Security Features

X-n8 includes several security-by-design features:

### Authentication & Authorization

- API key authentication for XSOAR integration
- Credential encryption in n8n
- Role-based access control recommendations

### Data Protection

- No persistent storage of sensitive data by default
- Redis TTL for deduplication data
- Audit logging for all actions

### Secure Defaults

- HTTPS required for all webhooks
- Input validation on all endpoints
- Rate limiting recommendations

---

## ✅ Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes    |
| < 1.0   | ❌ No     |

---

## 🔒 Security Best Practices

When deploying X-n8, follow these guidelines:

1. **Use HTTPS** for all n8n webhooks
2. **Rotate API keys** regularly
3. **Limit network access** to n8n instance
4. **Enable audit logging** in XSOAR
5. **Review playbooks** before deployment
6. **Keep n8n updated** to latest version

---

<p align="center">
  <a href="https://github.com/Masriyan/X-n8-Exnate">Back to Repository</a>
</p>
