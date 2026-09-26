# Contributing to Detection Engineering for Sophisticated Attacks

Thank you for your interest in contributing! This document provides guidelines for contributing to this detection catalog.

---

## 🎯 What We're Looking For

- **New detection use cases** covering emerging adversary tradecraft
- **Detection rules** (KQL, SPL, YARA-L, Sigma, Elastic EQL) for existing use cases
- **Incident response playbooks** linked to detection scenarios
- **Tuning guidance** for reducing false positives in specific environments
- **Corrections** to existing content (accuracy, clarity, completeness)

---

## 📐 Use Case Template

When adding a new detection use case, follow this structure:

```markdown
## [Number]. [Attack Name]

**Category:** [Category Name]  
**MITRE ATT&CK:** [Technique ID] ([Technique Name])

### How the Attack Works

[2–4 sentences describing the architectural mechanics and attacker objective.
Focus on the behavioral pattern, NOT offensive tooling or exploit code.]

**Attacker Objective:** [One sentence summarizing what the adversary aims to achieve.]

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **[Domain]** | [Observable behavior or telemetry signal] |

**Defensive Mitigations:**
- [Concise mitigation 1]
- [Concise mitigation 2]
```

---

## 📝 Content Guidelines

1. **No exploit code or offensive payloads** — Describe behaviors and mechanics, not attack tools
2. **Be specific about telemetry** — Name the log sources, event IDs, or data domains
3. **Map to frameworks** — Include MITRE ATT&CK or ATLAS technique IDs
4. **Keep it practical** — Write for detection engineers and SOC analysts
5. **Platform-agnostic descriptions** — Detection strategies should be implementable across SIEM platforms

---

## 🔀 Pull Request Process

1. Fork the repository and create a feature branch
2. Follow the template and content guidelines above
3. Update the index table in `README.md` if adding new use cases
4. Submit a PR with a clear title and description
5. Address any review feedback

---

## 🏷️ Detection Rule Naming Convention

When contributing detection rules, use this naming pattern:

```
<category>-<short-name>.<format>
```

Examples:
- `identity-aitm-token-replay.kql`
- `supply-chain-dependency-confusion.yml`
- `cloud-serverless-persistence.spl`

---

## 📜 Code of Conduct

- Be respectful and constructive in all interactions
- Focus on defensive security — this is a blue-team resource
- Credit original research and reference sources

---

## 📬 Questions?

Open an issue for discussion or reach out to the maintainer.
