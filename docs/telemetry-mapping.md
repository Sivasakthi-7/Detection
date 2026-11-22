# 📡 Telemetry Source Mapping

> Maps each detection use case to the required telemetry sources and data domains.

---

## Telemetry Matrix

| Use Case | Primary Telemetry Sources | SIEM Data Models |
|----------|--------------------------|------------------|
| AiTM Token Theft | IdP Sign-In Logs, Proxy Logs, Email Gateway | Authentication, Web |
| OAuth Consent Phishing | Azure AD/Entra Audit Logs, App Registration Logs | Cloud Audit, Identity |
| Golden SAML | AD FS Audit Logs, Cloud Sign-In Logs, Certificate Stores | Authentication, Certificate |
| MFA Fatigue | MFA Service Logs, IdP Audit Logs, Help Desk Tickets | Authentication, Alert |
| Cross-Tenant Lateral Movement | Cross-Tenant Sign-In Logs, CloudTrail, GCP Audit Logs | Cloud Audit, Authentication |
| Serverless Persistence | CloudTrail, Cloud Audit Logs, Function Invocation Logs | Cloud Audit, Compute |
| Bucket Exfiltration | CloudTrail (S3/GCS), Storage Access Logs, Network Flow | Cloud Audit, Network |
| Shadow Admin / CA Tampering | Conditional Access Audit, PIM Logs, Policy Change Logs | Cloud Audit, Policy |
| K8s Control Plane Abuse | K8s Audit Logs, API Server Logs, Network Policy Logs | Container, Cloud Audit |
| Prompt Injection | AI Gateway Logs, Application Logs, Tool-Call Logs | Application, AI/ML |
| Model Poisoning | Data Pipeline Logs, Model Registry Audit, Training Metrics | AI/ML, Data Pipeline |
| LLM Tool-Use Abuse | Agent Execution Logs, API Gateway Logs, Tool-Call Telemetry | Application, AI/ML |
| Shadow AI | Network Proxy/CASB Logs, Cloud Resource Logs, DLP Alerts | Network, Cloud Audit, DLP |
| Firmware Implants | Device Management Logs, NetFlow, Firmware Integrity Checks | Endpoint, Network |
| Appliance Zero-Day | Appliance Syslogs, Network Anomaly Detection, Threat Intel | Network, Threat Intel |
| UEFI Bootkit | TPM Event Logs, ELAM Logs, EFI Partition Monitoring | Endpoint, Firmware |
| Cellular MITM | MDM/MTD Logs, MFA Failure Logs, RF Monitoring | Mobile, Authentication |
| Dependency Confusion | Build Pipeline Logs, Package Manager Logs, Registry Audit | CI/CD, Application |
| CI/CD Poisoning | Pipeline Execution Logs, SCM Audit Logs, Runner Telemetry | CI/CD, SCM |
| Code Signing Abuse | Certificate Transparency Logs, Endpoint Binary Logs, CT Monitors | Certificate, Endpoint |
| Maintainer Takeover | Package Registry Audit, Dependency Diff, SBOM Monitoring | Supply Chain, CI/CD |
| LOLBins Abuse | Process Creation Logs (Sysmon/4688), Command-Line Audit | Endpoint, Process |
| Reflective DLL Injection | ETW Memory Events, EDR Memory Telemetry, Module Loads | Endpoint, Memory |
| RMM Tool Abuse | Software Inventory, Network Proxy Logs, Service Install Logs | Endpoint, Network |
| WMI / Sched Task Persistence | Windows Event 4698/4699, WMI Operational Logs, Autoruns | Endpoint, Persistence |

---

## Key Data Sources by Category

### Identity & Authentication
- Entra ID / Azure AD Sign-In and Audit Logs
- Okta System Logs
- Google Workspace Admin Audit
- AD FS Event Logs
- MFA Provider Logs

### Cloud Infrastructure
- AWS CloudTrail
- Azure Activity Log / Resource Logs
- GCP Cloud Audit Logs
- Kubernetes Audit Logs

### Endpoint
- Sysmon (Windows)
- Windows Security Event Log (4688, 4698, 4699, 4697)
- EDR Telemetry (CrowdStrike, Defender, SentinelOne)
- ETW Providers (Microsoft-Windows-Kernel-Process)
- macOS Unified Logs
- Linux auditd

### Network
- DNS Query Logs
- Proxy / CASB Logs
- NetFlow / VPC Flow Logs
- Firewall Logs

### AI/ML Systems
- AI Gateway / API Proxy Logs
- Model Registry Audit Logs
- Agent Execution Traces
- Training Pipeline Logs
