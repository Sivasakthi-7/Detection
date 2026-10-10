# ☁️ Cloud / Cross-Domain — Detection Use Cases

> Attacks that exploit cloud service trust boundaries, multi-tenant configurations, control-plane APIs, and serverless infrastructure.

### 📁 Detection Rules

| Use Case | SPL Query | Sigma Rule |
|----------|-----------|------------|
| Cross-Tenant Lateral Movement | [cross-tenant-lateral-movement.spl](rules/spl/cross-tenant-lateral-movement.spl) | [cross-tenant-lateral-movement.yml](rules/sigma/cross-tenant-lateral-movement.yml) |
| Serverless Persistence | [serverless-persistence.spl](rules/spl/serverless-persistence.spl) | [serverless-persistence.yml](rules/sigma/serverless-persistence.yml) |
| Bucket Exfiltration | [bucket-exfiltration.spl](rules/spl/bucket-exfiltration.spl) | [bucket-exfiltration.yml](rules/sigma/bucket-exfiltration.yml) |
| Shadow Admin / CA Tampering | [shadow-admin-ca-tampering.spl](rules/spl/shadow-admin-ca-tampering.spl) | [shadow-admin-ca-tampering.yml](rules/sigma/shadow-admin-ca-tampering.yml) |
| K8s Control Plane Abuse | [k8s-control-plane-abuse.spl](rules/spl/k8s-control-plane-abuse.spl) | [k8s-control-plane-abuse.yml](rules/sigma/k8s-control-plane-abuse.yml) |

---

## Cross-Tenant Lateral Movement via B2B Trust

**Category:** Cloud / Cross-Domain  
**MITRE ATT&CK:** T1199 (Trusted Relationship), T1078.004 (Cloud Accounts)

### How the Attack Works

Organizations frequently establish B2B collaboration trusts (e.g., Entra ID cross-tenant access, AWS cross-account IAM roles, GCP domain-wide delegation). An adversary who compromises an account in a partner tenant can leverage these trust configurations to pivot into the target organization's resources. The access often carries permissions that were broadly scoped during initial setup and never reviewed.

**Attacker Objective:** Pivot from a compromised partner/vendor tenant into the target organization's cloud environment, exploiting pre-existing trust relationships.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **Cross-Tenant Auth** | Sign-ins from external tenant IDs that are unusual or newly established |
| **Role Assumption Logs** | Cross-account `AssumeRole` calls from unexpected source accounts or at unusual times |
| **Resource Access** | External identities accessing sensitive resources (SharePoint, S3 buckets, BigQuery datasets) for the first time |
| **Trust Configuration** | Changes to cross-tenant access settings, federation configurations, or IAM trust policies |

**Defensive Mitigations:**
- Audit and minimize cross-tenant/cross-account trust relationships quarterly
- Implement least-privilege scoping on all B2B guest and cross-account role permissions
- Monitor `AuditLogs` and `SignInLogs` for external tenant activity with anomaly baselines
- Require MFA and device compliance for all cross-tenant access

---

## Serverless Function Abuse for Persistence

**Category:** Cloud / Cross-Domain  
**MITRE ATT&CK:** T1546 (Event Triggered Execution), T1098 (Account Manipulation)

### How the Attack Works

The adversary deploys or modifies a serverless function (AWS Lambda, Azure Functions, GCP Cloud Functions) to establish persistent access. The function is triggered by a benign-looking event (e.g., S3 object upload, Cloud Pub/Sub message, timer trigger) and executes malicious logic — data exfiltration, reverse shell, credential harvesting, or further lateral movement. Because serverless functions are ephemeral and may not have traditional endpoint telemetry, they can evade standard detection.

**Attacker Objective:** Establish durable, event-driven persistence in cloud infrastructure that survives credential rotation and is difficult to discover with traditional endpoint monitoring.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **Function Deployment Logs** | New or modified serverless functions created by unusual principals or outside change windows |
| **IAM Analysis** | Functions assigned overly permissive execution roles (e.g., `AdministratorAccess`, `Owner`) |
| **Invocation Patterns** | Unexpected invocation frequency, duration, or outbound network connections from functions |
| **Code Inspection** | Function code or layers that include obfuscated logic, encoded payloads, or external dependency fetches |

**Defensive Mitigations:**
- Enforce infrastructure-as-code (Terraform/Pulumi) for all function deployments; alert on console-deployed functions
- Apply least-privilege IAM to function execution roles; block admin-level permissions
- Enable cloud-native runtime protection (e.g., AWS Lambda Extensions, GCP Security Command Center)
- Monitor CloudTrail / Cloud Audit Logs for `CreateFunction`, `UpdateFunctionCode`, and `UpdateFunctionConfiguration` events

---

## Cloud Storage Bucket Exfiltration via Policy Manipulation

**Category:** Cloud / Cross-Domain  
**MITRE ATT&CK:** T1537 (Transfer Data to Cloud Account), T1530 (Data from Cloud Storage)

### How the Attack Works

The adversary modifies the access policy on a cloud storage resource (S3 bucket, Azure Blob container, GCS bucket) to grant access to an external account or make the resource publicly readable. Data is then exfiltrated by copying it to an attacker-controlled cloud account or downloading it via public URLs. The policy change may be subtle — adding a single cross-account principal or removing a `Deny` statement.

**Attacker Objective:** Exfiltrate sensitive data from cloud storage by modifying access policies to grant external or public access, often in a way that blends with legitimate policy changes.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **Policy Change Logs** | Bucket/container policy modifications that add external account principals or public access |
| **Data Access Patterns** | Large-volume reads or list operations from unfamiliar IP ranges or cloud accounts |
| **Configuration Drift** | Storage resources shifting from private to public access or gaining cross-account policies outside of IaC deployments |
| **Network Telemetry** | Outbound data transfer spikes to external cloud provider IP ranges |

**Defensive Mitigations:**
- Enable and enforce public access block at the account/organization level
- Implement SCPs / Organization Policies that prevent policy modifications granting external access
- Deploy CSPM tools to continuously scan for publicly accessible or externally shared storage
- Alert on `PutBucketPolicy`, `SetBucketAcl`, or equivalent events that introduce external principals

---

## Shadow Admin via Conditional Access Policy Tampering

**Category:** Cloud / Cross-Domain  
**MITRE ATT&CK:** T1098.001 (Additional Cloud Credentials), T1484.002 (Domain Trust Modification)

### How the Attack Works

The adversary gains access to a cloud admin account and modifies Conditional Access policies (or equivalent policy engines like AWS SCPs, GCP Access Context Manager) to create exemptions for their controlled accounts or IPs. This effectively creates a "shadow admin" pathway — an identity that bypasses MFA, device compliance, or location restrictions while retaining high privileges. The changes can be subtle single-line additions to exclusion lists.

**Attacker Objective:** Create a privileged backdoor by exempting attacker-controlled identities from security policies, ensuring persistent admin access that evades standard enforcement controls.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **Policy Audit Logs** | Modifications to Conditional Access policies, especially additions to exclusion groups or IP allowlists |
| **Admin Activity** | Privileged actions performed without expected MFA or device compliance challenges |
| **Configuration Baselines** | Drift from known-good Conditional Access policy state (use policy-as-code baselines) |
| **Privileged Identity Logs** | PIM/JIT role activations that coincide with policy changes |

**Defensive Mitigations:**
- Implement policy-as-code with automated drift detection for all Conditional Access / SCP configurations
- Require multiple approvals (dual-control) for Conditional Access policy changes
- Alert on any modification to exclusion lists in security policies
- Audit privileged role assignments and ensure no standing admin access

---

## Control Plane API Abuse in Kubernetes

**Category:** Cloud / Cross-Domain  
**MITRE ATT&CK:** T1609 (Container Administration Command), T1610 (Deploy Container)

### How the Attack Works

An adversary who gains access to the Kubernetes API server — via compromised `kubeconfig`, leaked service account tokens, or exploiting an exposed API endpoint — can deploy malicious pods, create privileged containers, exfiltrate secrets, or pivot across namespaces. Techniques include creating `hostPath` volume mounts to access node filesystems, deploying crypto miners, or using `exec` to access running containers.

**Attacker Objective:** Leverage Kubernetes control plane access to deploy malicious workloads, access secrets, escalate privileges, or move laterally across the cluster and underlying infrastructure.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **K8s Audit Logs** | Creation of privileged pods, pods with `hostPath` mounts, or pods running as root |
| **API Server Access** | API calls from unexpected source IPs, user agents, or service accounts |
| **RBAC Changes** | Creation of `ClusterRoleBindings` granting broad permissions or new service accounts |
| **Workload Anomalies** | Containers with unusual images, entry points, or resource requests (e.g., high CPU for mining) |

**Defensive Mitigations:**
- Enforce Pod Security Standards (Restricted) via admission controllers (OPA/Gatekeeper, Kyverno)
- Disable anonymous API access and restrict `kubeconfig` distribution
- Implement RBAC with least-privilege and audit all role bindings regularly
- Enable and centralize Kubernetes audit logs with alerting on privileged workload creation

---

> **Previous:** [← Identity Abuse](../identity-abuse/README.md) | **Next:** [AI & Agentic Threats →](../ai-agentic-threats/README.md)
