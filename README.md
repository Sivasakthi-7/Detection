# 🛡️ Detection Engineering for Sophisticated Attacks

> A curated catalog of modern adversary tradecraft detection scenarios spanning identity, cloud, endpoint, AI systems, edge devices, and software supply chains — built for security engineering teams operating at scale.

[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](#contributing)

---

## 📋 Use Case Index

| Use Case | Category | Detection Doc |
|----------|----------|---------------|
| Adversary-in-the-Middle Token Theft | Identity Abuse | [View](detections/identity-abuse/README.md#adversary-in-the-middle-aitm-token-theft) |
| OAuth Consent Phishing via Malicious App Grants | Identity Abuse | [View](detections/identity-abuse/README.md#oauth-consent-phishing-via-malicious-app-grants) |
| Golden SAML / Federated Identity Forgery | Identity Abuse | [View](detections/identity-abuse/README.md#golden-saml--federated-identity-forgery) |
| MFA Fatigue / Push Bombing | Identity Abuse | [View](detections/identity-abuse/README.md#mfa-fatigue--push-bombing) |
| Cross-Tenant Lateral Movement via B2B Trust | Cloud / Cross-Domain | [View](detections/cloud-cross-domain/README.md#cross-tenant-lateral-movement-via-b2b-trust) |
| Serverless Function Abuse for Persistence | Cloud / Cross-Domain | [View](detections/cloud-cross-domain/README.md#serverless-function-abuse-for-persistence) |
| Cloud Storage Bucket Exfiltration via Policy Manipulation | Cloud / Cross-Domain | [View](detections/cloud-cross-domain/README.md#cloud-storage-bucket-exfiltration-via-policy-manipulation) |
| Shadow Admin via Conditional Access Policy Tampering | Cloud / Cross-Domain | [View](detections/cloud-cross-domain/README.md#shadow-admin-via-conditional-access-policy-tampering) |
| Control Plane API Abuse in Kubernetes | Cloud / Cross-Domain | [View](detections/cloud-cross-domain/README.md#control-plane-api-abuse-in-kubernetes) |
| Prompt Injection Against Agentic AI Workflows | AI & Agentic Threats | [View](detections/ai-agentic-threats/README.md#prompt-injection-against-agentic-ai-workflows) |
| AI Model Poisoning via Training Data Manipulation | AI & Agentic Threats | [View](detections/ai-agentic-threats/README.md#ai-model-poisoning-via-training-data-manipulation) |
| LLM Tool-Use Abuse and Autonomous Action Hijacking | AI & Agentic Threats | [View](detections/ai-agentic-threats/README.md#llm-tool-use-abuse-and-autonomous-action-hijacking) |
| Shadow AI and Unsanctioned Model Deployment | AI & Agentic Threats | [View](detections/ai-agentic-threats/README.md#shadow-ai-and-unsanctioned-model-deployment) |
| Firmware Implants on Edge / IoT Devices | Edge / Zero-Day | [View](detections/edge-zero-day/README.md#firmware-implants-on-edge--iot-devices) |
| Zero-Day Exploitation of Network Appliances | Edge / Zero-Day | [View](detections/edge-zero-day/README.md#zero-day-exploitation-of-network-appliances) |
| UEFI Bootkit Persistence | Edge / Zero-Day | [View](detections/edge-zero-day/README.md#uefi-bootkit-persistence) |
| Rogue Base Station / Cellular MITM on Mobile Endpoints | Edge / Zero-Day | [View](detections/edge-zero-day/README.md#rogue-base-station--cellular-mitm-on-mobile-endpoints) |
| Dependency Confusion / Namespace Hijacking | Supply Chain | [View](detections/supply-chain/README.md#dependency-confusion--namespace-hijacking) |
| CI/CD Pipeline Poisoning | Supply Chain | [View](detections/supply-chain/README.md#cicd-pipeline-poisoning) |
| Malicious Code Signing Certificate Abuse | Supply Chain | [View](detections/supply-chain/README.md#malicious-code-signing-certificate-abuse) |
| Compromised Open-Source Maintainer Account Takeover | Supply Chain | [View](detections/supply-chain/README.md#compromised-open-source-maintainer-account-takeover) |
| Living-off-the-Land Binaries (LOLBins) Abuse | Living-off-the-Land | [View](detections/living-off-the-land/README.md#living-off-the-land-binaries-lolbins-abuse) |
| Reflective DLL Injection via Trusted Processes | Living-off-the-Land | [View](detections/living-off-the-land/README.md#reflective-dll-injection-via-trusted-processes) |
| RMM Tool Abuse for Hands-on-Keyboard Access | Living-off-the-Land | [View](detections/living-off-the-land/README.md#rmm-tool-abuse-for-hands-on-keyboard-access) |
| WMI / Scheduled Task Persistence via Native OS Facilities | Living-off-the-Land | [View](detections/living-off-the-land/README.md#wmi--scheduled-task-persistence-via-native-os-facilities) |

---

## 📂 Repository Structure

```
Detection/
├── README.md                          # This file — master index & contribution guide
├── CONTRIBUTING.md
│
├── detections/                        # Detection use-case documentation & rules
│   ├── identity-abuse/
│   │   ├── README.md
│   │   └── rules/
│   │       ├── spl/                   # Splunk SPL queries
│   │       └── sigma/                 # Sigma YAML rules
│   ├── cloud-cross-domain/
│   │   ├── README.md
│   │   └── rules/{spl,sigma}/
│   ├── ai-agentic-threats/
│   │   ├── README.md
│   │   └── rules/{spl,sigma}/
│   ├── edge-zero-day/
│   │   ├── README.md
│   │   └── rules/{spl,sigma}/
│   ├── supply-chain/
│   │   ├── README.md
│   │   └── rules/{spl,sigma}/
│   └── living-off-the-land/
│       ├── README.md
│       └── rules/{spl,sigma}/
│
├── playbooks/                         # Incident response runbooks (future)
│   └── README.md
│
├── docs/                              # Architecture docs, tuning guides, data-source maps
│   ├── telemetry-mapping.md
│   └── tuning-guide.md
│
└── assets/                            # Diagrams, images, reference material
```

---

## 🎯 Design Principles

| Principle | Description |
|-----------|-------------|
| **Behavioral over Signature** | Focus on adversary behaviors (MITRE ATT&CK techniques) rather than static IOCs |
| **Telemetry-Aware** | Each use case maps to concrete log sources and data domains |
| **Platform-Agnostic Descriptions** | Detection logic described at the strategy level; implementable in Sentinel, Splunk, Chronicle, Elastic, or custom pipelines |
| **Defense-in-Depth Layers** | Prevention controls documented alongside detection signals |
| **Tunable & Maintainable** | Each scenario includes false-positive guidance and tuning levers |

---

## 🗂️ Category Overview

| Category | Scope |
|----------|-------|
| **Identity Abuse** | Credential theft, token replay, federation compromise, MFA bypass | |
| **Cloud / Cross-Domain** | Multi-cloud lateral movement, control plane abuse, serverless persistence | |
| **AI & Agentic Threats** | Prompt injection, model poisoning, autonomous agent hijacking, shadow AI | |
| **Edge / Zero-Day** | Firmware implants, appliance exploitation, bootkits, cellular MITM | |
| **Supply Chain** | Dependency confusion, CI/CD poisoning, code signing abuse, maintainer takeover | |
| **Living-off-the-Land** | LOLBins, reflective injection, RMM abuse, WMI/scheduled task persistence | |

---

## 🚀 Getting Started

1. **Browse by category** — Navigate into `detections/<category>/` to read grouped use cases.
2. **Search the index** — Use the [index table](#-use-case-index) above to jump directly to a scenario.
3. **Add detection rules** — Each use case directory is designed to hold platform-specific rule files (`.yml`, `.kql`, `.spl`) alongside the documentation.
4. **Contribute** — See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 🤝 Contributing

We welcome contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. Quick summary:

### Adding a New Detection Use Case

1. Choose the appropriate category folder under `detections/`.
2. Add your use case following the standard template:
   - **Attack Name & Category**
   - **How the Attack Works** (architectural mechanics, attacker objective)
   - **High-Level Detection Strategy** (behavioral signals, telemetry, mitigations)
3. Update the index table in this README.
4. Submit a pull request with a clear description.

### Adding Detection Rules

1. Create a subfolder under the relevant use case category (e.g., `detections/identity-abuse/rules/`).
2. Use descriptive filenames: `aitm-token-theft.kql`, `oauth-consent-abuse.yml`.
3. Include a header comment in each rule with: author, date, MITRE ATT&CK mapping, severity, and false-positive notes.

### Tuning Existing Detections

- Document environment-specific tuning in `docs/tuning-guide.md`.
- Include threshold adjustments, exclusion lists, and baseline windows.

---

## 📖 References & Frameworks

- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE ATLAS](https://atlas.mitre.org/) (AI/ML threat matrix)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [SLSA Supply Chain Framework](https://slsa.dev/)

---

> **Maintainer:** mikeytrr07  
> **Last Updated:** November 2026
