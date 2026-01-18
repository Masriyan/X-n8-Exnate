# Contributing to X-n8 (Exnate)

First off, thank you for considering contributing to X-n8! 🎉

This document provides guidelines and steps for contributing to this project.

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Style Guidelines](#style-guidelines)

---

## 📜 Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code.

### Our Pledge

We pledge to make participation in our project a harassment-free experience for everyone.

### Our Standards

- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what is best for the community

---

## 🚀 Getting Started

### Prerequisites

- **Git** for version control
- **n8n** v1.0+ for workflow development
- **Node.js** 18+ for tooling
- **JSON knowledge** for playbook development
- **Security domain expertise** for use case contributions

### Repository Structure

```
X-n8-Exnate/
├── docs/                    # Documentation
│   ├── use-cases/          # 450 use case files
│   ├── architecture.md     # System architecture
│   └── *.md               # Additional docs
├── n8n-workflows/          # n8n workflow JSON files
│   ├── core/              # Core engine workflows
│   └── categories/        # Category playbooks
├── schemas/               # JSON schemas
├── agent-prompts/         # AI agent configurations
└── assets/               # Images and media
```

---

## 🤝 How Can I Contribute?

### 1. 📝 Documentation Contributions

- Improve existing documentation
- Add new use case documentation
- Translate documentation to other languages
- Fix typos and grammatical errors

### 2. 🔧 Playbook Contributions

Create new n8n workflow playbooks:

```json
{
  "name": "X-n8 [Category] - [Use Case Name]",
  "nodes": [...],
  "connections": {...},
  "tags": ["x-n8", "category-name", "UC-XXX"]
}
```

**Required elements:**
- Webhook receiver node
- Detection/analysis logic
- Decision routing
- XSOAR integration or Slack notification
- Appropriate tagging

### 3. 🎯 Use Case Contributions

Add new security use cases following this format:

```markdown
### UC-XXX: [Use Case Name]

**Trigger**: [What triggers this detection]

**n8n Logic**:
```javascript
// Detection logic here
```

**XSOAR Actions**: [Actions taken]
```

### 4. 🐛 Bug Reports

Open an issue with:
- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Environment details (n8n version, XSOAR version, etc.)

### 5. 💡 Feature Requests

Open an issue with:
- Clear description of the feature
- Use case / problem it solves
- Proposed implementation (if any)

---

## 🛠️ Development Setup

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/X-n8-Exnate.git
cd X-n8-Exnate
```

### 2. Create a Branch

```bash
# For features
git checkout -b feature/your-feature-name

# For bug fixes
git checkout -b fix/bug-description

# For documentation
git checkout -b docs/documentation-topic
```

### 3. Local n8n Setup

```bash
# Using Docker
docker run -it --rm \
  -p 5678:5678 \
  -v ~/.n8n:/home/node/.n8n \
  n8nio/n8n

# Import workflows for testing
n8n import:workflow --input=n8n-workflows/core/alert-ingestion.json
```

### 4. Test Your Changes

- Validate JSON syntax for playbooks
- Test workflows in n8n
- Verify MITRE ATT&CK mapping accuracy
- Check documentation rendering

---

## 📬 Pull Request Process

### 1. Before Submitting

- [ ] Ensure your code/documentation follows the style guidelines
- [ ] Update relevant documentation if needed
- [ ] Test your changes thoroughly
- [ ] Add appropriate tags to playbooks

### 2. PR Description Template

```markdown
## Description
[Brief description of changes]

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] New use case
- [ ] New playbook

## Related Issues
Fixes #[issue number]

## Checklist
- [ ] I have tested my changes
- [ ] I have updated documentation
- [ ] My code follows the project style guidelines
```

### 3. Review Process

1. Submit your PR
2. Automated checks will run
3. Maintainers will review
4. Address any feedback
5. Once approved, your PR will be merged

---

## 📐 Style Guidelines

### Documentation Style

- Use clear, concise language
- Include code examples where helpful
- Follow existing formatting patterns
- Use proper markdown syntax

### Playbook Style

```json
{
  "name": "X-n8 [Category] - [Descriptive Name]",
  "nodes": [
    {
      "id": "descriptive-node-id",
      "name": "Human Readable Name",
      "type": "n8n-nodes-base.nodeType",
      "position": [x, y]
    }
  ],
  "tags": ["x-n8", "category", "UC-XXX"]
}
```

### Use Case Style

- **UC-XXX format** for IDs (sequential within category)
- **Clear MITRE ATT&CK mapping** (technique IDs)
- **n8n Logic** in JavaScript
- **XSOAR Actions** as bullet points

### Commit Messages

Follow conventional commits:

```
feat: add new ransomware detection playbook
fix: correct MITRE mapping for UC-066
docs: update architecture diagram
chore: update dependencies
```

---

## 🏷️ Labels

| Label | Description |
|-------|-------------|
| `good first issue` | Good for newcomers |
| `help wanted` | Extra attention needed |
| `bug` | Something isn't working |
| `enhancement` | New feature or request |
| `documentation` | Documentation only changes |
| `playbook` | n8n workflow related |
| `use-case` | Security use case related |

---

## 🙏 Thank You!

Every contribution helps make X-n8 better for the security community. We appreciate your time and effort!

---

<p align="center">
  <a href="https://github.com/Masriyan/X-n8-Exnate">Back to Repository</a>
</p>
