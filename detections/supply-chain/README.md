# 📦 Supply Chain — Detection Use Cases

> Attacks that compromise software dependencies, build pipelines, code signing infrastructure, and open-source maintainer accounts to distribute malicious code at scale.

### 📁 Detection Rules

| Use Case | SPL Query | Sigma Rule |
|----------|-----------|------------|
| Dependency Confusion | [dependency-confusion.spl](rules/spl/dependency-confusion.spl) | [dependency-confusion.yml](rules/sigma/dependency-confusion.yml) |
| CI/CD Pipeline Poisoning | [cicd-pipeline-poisoning.spl](rules/spl/cicd-pipeline-poisoning.spl) | [cicd-pipeline-poisoning.yml](rules/sigma/cicd-pipeline-poisoning.yml) |
| Code Signing Abuse | [code-signing-abuse.spl](rules/spl/code-signing-abuse.spl) | [code-signing-abuse.yml](rules/sigma/code-signing-abuse.yml) |
| Maintainer Takeover | [maintainer-takeover.spl](rules/spl/maintainer-takeover.spl) | [maintainer-takeover.yml](rules/sigma/maintainer-takeover.yml) |

---

## Dependency Confusion / Namespace Hijacking

**Category:** Supply Chain  
**MITRE ATT&CK:** T1195.001 (Supply Chain Compromise: Compromise Software Dependencies)

### How the Attack Works

The adversary publishes a malicious package to a public registry (npm, PyPI, RubyGems, NuGet) using the same name as an internal/private package used by the target organization. When the organization's build system resolves dependencies, it may fetch the public (malicious) package instead of the internal one due to default registry resolution order. The malicious package executes attacker code during installation (via `setup.py`, `postinstall` scripts, etc.), exfiltrating data or establishing access.

**Attacker Objective:** Execute malicious code within target build environments or developer machines by hijacking private package namespaces on public registries.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **Package Manager Logs** | Installation of packages from public registries that share names with internal packages |
| **Build Pipeline Telemetry** | Outbound network connections during package installation to unexpected endpoints |
| **Registry Monitoring** | New packages appearing on public registries matching internal package naming conventions |
| **Version Anomalies** | Public packages with abnormally high version numbers designed to override internal versions |

**Defensive Mitigations:**
- Configure package managers to use private registries as the primary source with explicit scoping/namespacing
- Implement dependency pinning and lock files with integrity hashes
- Reserve internal package names on public registries as placeholders
- Use build environment network isolation to prevent outbound connections during dependency resolution
- Deploy software composition analysis (SCA) tools to flag unexpected dependency changes

---

## CI/CD Pipeline Poisoning

**Category:** Supply Chain  
**MITRE ATT&CK:** T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain)

### How the Attack Works

The adversary compromises a CI/CD system (GitHub Actions, GitLab CI, Jenkins, CircleCI) to inject malicious steps into the build, test, or deployment pipeline. This can be achieved by: modifying pipeline configuration files (`.github/workflows/`, `Jenkinsfile`), compromising shared CI/CD runner infrastructure, exploiting secrets stored in pipeline variables, or submitting malicious pull requests that trigger CI jobs. The injected code runs with the pipeline's permissions, often including access to production deployment credentials and artifact signing keys.

**Attacker Objective:** Inject malicious code into software build and deployment pipelines to compromise build artifacts, steal secrets, or gain access to production infrastructure.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **Pipeline Configuration** | Modifications to CI/CD workflow files, especially from contributors outside the core team |
| **Build Anomalies** | Build steps making unexpected network calls, accessing secrets not needed for the build, or producing artifacts with different hashes |
| **Runner Security** | Shared/self-hosted runners with persistent state, unauthorized software installations, or unexpected processes |
| **Secret Access Patterns** | Pipeline secrets accessed by jobs or stages that don't historically require them |

**Defensive Mitigations:**
- Require code review and approval for all pipeline configuration file changes
- Use ephemeral, isolated build runners that are destroyed after each job
- Implement SLSA framework controls: hermetic builds, provenance attestation, and reproducible builds
- Scope pipeline secrets to specific jobs/environments with rotation policies
- Monitor build artifact integrity with signing and verification at deployment boundaries

---

## Malicious Code Signing Certificate Abuse

**Category:** Supply Chain  
**MITRE ATT&CK:** T1553.002 (Subvert Trust Controls: Code Signing), T1588.003 (Obtain Capabilities: Code Signing Certificates)

### How the Attack Works

The adversary obtains a valid code signing certificate — through theft from a compromised development environment, purchasing from complicit or compromised certificate authorities, or using stolen identities to register as a legitimate software publisher. Malicious binaries signed with these certificates bypass OS trust controls, security software allowlists, and enterprise application control policies. Signed malware is significantly more likely to execute successfully and evade detection.

**Attacker Objective:** Sign malicious software with trusted certificates to bypass code signing verification, application allowlists, and endpoint security controls.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **Certificate Intelligence** | Executables signed by newly issued, short-lived, or unknown publisher certificates |
| **Signing Anomalies** | Code signed with certificates issued by CAs known for weak vetting, or certificates with unusual key usage attributes |
| **Endpoint Telemetry** | Signed executables exhibiting behaviors inconsistent with their stated publisher or purpose |
| **Certificate Transparency** | New code signing certificates issued to names resembling the organization or its partners |

**Defensive Mitigations:**
- Implement application allowlisting based on specific publisher certificates, not just "signed" status
- Monitor certificate transparency logs for certificates issued to names matching the organization
- Store code signing private keys in HSMs with strict access controls and audit logging
- Implement binary analysis pipelines that evaluate signed software behavior regardless of signature validity
- Revoke compromised certificates immediately and deploy revocation checks at endpoints

---

## Compromised Open-Source Maintainer Account Takeover

**Category:** Supply Chain  
**MITRE ATT&CK:** T1195.001 (Compromise Software Dependencies), T1199 (Trusted Relationship)

### How the Attack Works

The adversary targets the personal account of an open-source package maintainer — through credential phishing, session hijacking, or social engineering — to gain publish access to a widely-used package. Once in control, the adversary pushes a malicious update to the package (often as a minor version bump or patch) that gets automatically pulled by downstream consumers through normal dependency update processes. The event-stream, ua-parser-js, and colors.js incidents demonstrate this pattern.

**Attacker Objective:** Compromise a trusted open-source maintainer's publishing credentials to push malicious code to widely-used packages, achieving broad downstream impact through the software supply chain.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **Package Registry Monitoring** | Unexpected version publishes outside normal release cadence, especially from new IPs or sessions |
| **Dependency Diff Analysis** | Automated comparison of package updates revealing obfuscated code, new network calls, or unexpected dependencies added |
| **Maintainer Account Security** | Changes to maintainer account email, 2FA settings, or publish tokens for critical dependencies |
| **Build Verification** | Reproducible build failures or hash mismatches between source repository and published package |

**Defensive Mitigations:**
- Pin dependency versions and review all updates (even patch versions) before adoption
- Implement automated dependency diff analysis in CI pipelines to flag suspicious changes
- Use tools like Socket, Snyk, or Dependabot with behavioral analysis capabilities
- Maintain a software bill of materials (SBOM) and monitor critical upstream maintainer activity
- Favor packages with multiple maintainers, signed releases, and reproducible build processes

---

> **Previous:** [← Edge / Zero-Day](../edge-zero-day/README.md) | **Next:** [Living-off-the-Land →](../living-off-the-land/README.md)
