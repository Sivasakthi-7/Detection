# 🔐 Identity Abuse — Detection Use Cases

> Attacks that compromise, forge, or bypass identity and authentication mechanisms to gain unauthorized access.

### 📁 Detection Rules

| Use Case | SPL Query | Sigma Rule |
|----------|-----------|------------|
| AiTM Token Theft | [aitm-token-theft.spl](rules/spl/aitm-token-theft.spl) | [aitm-token-theft.yml](rules/sigma/aitm-token-theft.yml) |
| OAuth Consent Phishing | [oauth-consent-phishing.spl](rules/spl/oauth-consent-phishing.spl) | [oauth-consent-phishing.yml](rules/sigma/oauth-consent-phishing.yml) |
| Golden SAML Forgery | [golden-saml-forgery.spl](rules/spl/golden-saml-forgery.spl) | [golden-saml-forgery.yml](rules/sigma/golden-saml-forgery.yml) |
| MFA Fatigue | [mfa-fatigue.spl](rules/spl/mfa-fatigue.spl) | [mfa-fatigue.yml](rules/sigma/mfa-fatigue.yml) |

---

## Adversary-in-the-Middle (AiTM) Token Theft

**Category:** Identity Abuse  
**MITRE ATT&CK:** T1557 (Adversary-in-the-Middle), T1539 (Steal Web Session Cookie)

### How the Attack Works

The adversary deploys a reverse-proxy phishing site (e.g., using toolkits like Evilginx or Modlishka) that sits between the victim and a legitimate identity provider. When the victim authenticates — including completing MFA — the proxy transparently relays the session, capturing the resulting session token or cookie. The attacker then replays this token from their own infrastructure, bypassing MFA entirely since authentication already completed.

**Attacker Objective:** Obtain a valid, post-MFA session token to access cloud services (email, file shares, admin portals) without needing the user's credentials again.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **Sign-In Telemetry** | Session token used from a different IP, ASN, or geolocation than the one that performed authentication |
| **Proxy Indicators** | Sign-in logs showing the authentication originated from a known hosting/VPS provider rather than a corporate or residential ISP |
| **Token Replay** | Impossible travel — same token used from two geographically distant locations within a short time window |
| **Phishing Infrastructure** | URL/domain reputation scoring on links clicked in email prior to authentication |

**Defensive Mitigations:**
- Enforce phishing-resistant MFA (FIDO2 / passkeys) which bind authentication to the legitimate origin
- Implement Continuous Access Evaluation (CAE) to revoke tokens on IP or risk change
- Deploy conditional access policies requiring compliant/managed devices
- Monitor for anomalous token replay patterns in IdP audit logs

---

## OAuth Consent Phishing via Malicious App Grants

**Category:** Identity Abuse  
**MITRE ATT&CK:** T1550.001 (Application Access Token)

### How the Attack Works

The adversary registers a malicious OAuth application (or compromises an existing one) and tricks a user into granting it broad permissions — typically `Mail.Read`, `Files.ReadWrite`, or `Directory.Read.All`. This is done via a crafted consent URL that looks like a legitimate app authorization prompt. Once consent is granted, the adversary's app receives a long-lived access token and refresh token, providing persistent access to the victim's resources without needing their credentials.

**Attacker Objective:** Establish persistent, credential-independent access to a victim's mailbox, files, or directory data via delegated OAuth permissions.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **App Registration Logs** | New OAuth app registrations with high-privilege API scopes from unusual publishers |
| **Consent Grant Audit** | Users granting consent to unverified or newly-created applications |
| **Access Patterns** | OAuth app accessing mailbox or files at unusual hours or at high volume |
| **Scope Creep** | Application requesting permissions disproportionate to its stated function |

**Defensive Mitigations:**
- Restrict user consent to verified publisher apps only; require admin consent for high-privilege scopes
- Implement app governance policies that alert on risky permission grants
- Regularly audit active OAuth grants and revoke unused or suspicious applications
- Monitor Graph API / Google Workspace API call patterns from third-party apps

---

## Golden SAML / Federated Identity Forgery

**Category:** Identity Abuse  
**MITRE ATT&CK:** T1606.002 (Forge Web Credentials: SAML Tokens)

### How the Attack Works

After compromising the token-signing certificate of a federated identity provider (e.g., AD FS), the adversary can forge SAML assertions for any user in the organization — including privileged accounts — without authentication. The forged token is accepted by the relying party (cloud IdP) as legitimate because it carries a valid cryptographic signature. This was the core technique behind the SolarWinds / Nobelium campaign.

**Attacker Objective:** Forge authentication tokens for any user (including Global Admins) to access cloud resources without triggering normal authentication flows or MFA challenges.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **Federation Audit Logs** | SAML token issued without a corresponding authentication event at the IdP |
| **Certificate Monitoring** | Unexpected export, rotation, or access to the AD FS token-signing certificate |
| **Anomalous Claims** | SAML assertions with unusual claim values, lifetimes, or issuer metadata |
| **Privileged Access** | Cloud admin actions from federated identities that bypass Conditional Access controls |

**Defensive Mitigations:**
- Rotate AD FS token-signing certificates regularly and store them in HSMs
- Migrate to cloud-native authentication (Entra ID / Google Cloud Identity) to eliminate on-premises federation trust
- Implement SAML assertion monitoring and validate token characteristics at the relying party
- Enable sign-in log correlation between on-prem IdP events and cloud resource access

---

## MFA Fatigue / Push Bombing

**Category:** Identity Abuse  
**MITRE ATT&CK:** T1621 (Multi-Factor Authentication Request Generation)

### How the Attack Works

After obtaining a user's primary credentials (via phishing, credential stuffing, or dark-web purchase), the adversary repeatedly triggers MFA push notifications to the victim's authenticator app. The goal is to overwhelm the user until they accidentally approve a prompt, or to combine the barrage with a social engineering call (vishing) where the attacker impersonates IT support and instructs the user to approve. This was used in the 2022 Uber breach.

**Attacker Objective:** Bypass MFA by exploiting human fatigue or social engineering to obtain an approved authentication factor.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **MFA Telemetry** | Burst of MFA push requests (>3–5) within a short time window for a single user, most denied |
| **Authentication Logs** | Successful authentication immediately following a cluster of failed MFA attempts |
| **Credential Abuse** | Valid password used from an unusual IP or device preceding the MFA burst |
| **Help Desk Correlation** | User reports of unexpected MFA prompts combined with suspicious sign-in attempts |

**Defensive Mitigations:**
- Deploy number-matching or phishing-resistant MFA (FIDO2) instead of simple push approve
- Implement MFA request rate limiting and auto-block after repeated denials
- Alert SOC when MFA denial count exceeds threshold for a single user within a time window
- Educate users to report unsolicited MFA prompts immediately

---

> **Next:** [Cloud / Cross-Domain Detections →](../cloud-cross-domain/README.md)
