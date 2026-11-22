# 🎛️ Detection Tuning Guide

> Best practices for tuning detection rules to minimize false positives while maintaining detection coverage.

---

## General Tuning Principles

### 1. Baseline Before You Alert
Establish a behavioral baseline for at least 2–4 weeks before activating alert rules. Understand what "normal" looks like for:
- Frequency of events
- Common actors (users, service accounts, IPs)
- Typical time windows for administrative activity

### 2. Tiered Alert Severity
Not every detection needs to be a high-severity alert:

| Tier | Action | Example |
|------|--------|---------|
| **P1 — Critical** | Immediate SOC triage | Golden SAML token forgery detected |
| **P2 — High** | Triage within 1 hour | Unauthorized RMM tool installation |
| **P3 — Medium** | Daily review queue | Unusual LOLBin command-line pattern |
| **P4 — Low / Hunting** | Weekly hunt review | OAuth app with broad permissions registered |

### 3. Exclusion List Management
- Maintain exclusions in a **version-controlled file**, not inline in queries
- Review exclusions quarterly — stale exclusions create blind spots
- Require justification and expiration dates for all exclusions
- Never exclude by binary name alone — use full paths and expected arguments

---

## Category-Specific Tuning

### Identity Abuse
- **AiTM:** Tune impossible-travel thresholds based on VPN and mobile workforce patterns
- **OAuth Consent:** Allowlist known business-critical third-party apps; alert on everything else
- **MFA Fatigue:** Set push-count thresholds based on MFA provider's normal retry behavior (typically >3 in 5 minutes)

### Cloud / Cross-Domain
- **Cross-Tenant:** Maintain an approved external tenant list; alert on any access from unlisted tenants
- **Serverless:** Baseline normal function deployment cadence; alert on deployments outside CI/CD pipelines
- **K8s:** Whitelist known controllers and operators that create privileged pods by design

### AI & Agentic
- **Shadow AI:** Maintain an up-to-date list of approved AI service domains; update as vendors change infrastructure
- **Tool-Use Abuse:** Baseline agent tool-call patterns per workflow; use statistical deviation rather than static thresholds

### Endpoint / LOTL
- **LOLBins:** High false-positive risk — focus on command-line argument anomalies rather than binary execution events
- **RMM Tools:** Create a strict approved-RMM allowlist; anything else is suspicious by default
- **WMI/Schtasks:** Expect noise from legitimate software; focus on task creation by interactive users and encoded commands

---

## Threshold Recommendations

| Detection | Recommended Threshold | Tuning Lever |
|-----------|----------------------|--------------|
| MFA Push Bomb | ≥ 5 denied pushes in 10 min | Adjust window and count per MFA provider |
| Token Impossible Travel | > 500 km in < 30 min | Adjust for VPN concentrator locations |
| LOLBin Network Call | Any outbound from certutil/mshta | Whitelist approved update endpoints |
| Unauthorized RMM | Any installation not on approved list | Maintain approved RMM vendor list |
| Cross-Tenant Access | Any sign-in from non-approved tenant | Update approved tenant list quarterly |

---

## False Positive Reduction Workflow

```
Detection Fires → Analyze FP Pattern → Document Root Cause
                                            ↓
                                   Is it tunable?
                                    ↓           ↓
                                   Yes          No
                                    ↓           ↓
                            Add targeted     Reclassify
                            exclusion        severity level
                                    ↓           ↓
                            Re-validate     Document as
                            detection       known noise
```

---

> See [telemetry-mapping.md](telemetry-mapping.md) for data source requirements per detection.
