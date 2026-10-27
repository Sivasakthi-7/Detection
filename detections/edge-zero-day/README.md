# 🔌 Edge / Zero-Day — Detection Use Cases

> Attacks targeting firmware, network appliances, boot-level persistence, and physical-layer interception on edge and mobile devices.

### 📁 Detection Rules

| Use Case | SPL Query | Sigma Rule |
|----------|-----------|------------|
| Firmware Implants | [firmware-implants.spl](rules/spl/firmware-implants.spl) | [firmware-implants.yml](rules/sigma/firmware-implants.yml) |
| Appliance Zero-Day | [appliance-zero-day.spl](rules/spl/appliance-zero-day.spl) | [appliance-zero-day.yml](rules/sigma/appliance-zero-day.yml) |
| UEFI Bootkit | [uefi-bootkit.spl](rules/spl/uefi-bootkit.spl) | [uefi-bootkit.yml](rules/sigma/uefi-bootkit.yml) |
| Cellular MITM | [cellular-mitm.spl](rules/spl/cellular-mitm.spl) | [cellular-mitm.yml](rules/sigma/cellular-mitm.yml) |

---

## Firmware Implants on Edge / IoT Devices

**Category:** Edge / Zero-Day  
**MITRE ATT&CK:** T1542.001 (Pre-OS Boot: System Firmware), T1495 (Firmware Corruption)

### How the Attack Works

The adversary gains access to an edge device (router, firewall, IoT gateway, IP camera, or industrial controller) and modifies its firmware to include a persistent implant. This can be achieved through exploiting management interfaces, default credentials, or supply chain compromise of firmware update channels. The implant survives reboots and factory resets, provides covert command-and-control, and may serve as a pivot point into the internal network. Campaigns like VPNFilter and BlackTech have demonstrated this technique at scale.

**Attacker Objective:** Establish persistent, stealthy access on network edge devices that survives reboots and standard remediation, using the device as a covert foothold or traffic interception point.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **Firmware Integrity** | Firmware hash mismatches against known-good baselines or vendor-published digests |
| **Device Behavior** | Unexpected outbound connections from edge devices to unknown external IPs |
| **Management Plane** | Unauthorized firmware update operations, management interface access from unexpected sources |
| **Network Traffic** | Anomalous traffic patterns from infrastructure devices (unusual protocols, volumes, or destinations) |

**Defensive Mitigations:**
- Implement firmware integrity monitoring with known-good hash baselines
- Enable Secure Boot and verified boot chains where supported by hardware
- Restrict and monitor management interface access (disable HTTP, enforce SSH with key auth)
- Segment edge/IoT devices onto isolated network zones with strict egress controls
- Maintain firmware update processes from vendor-authenticated sources only

---

## Zero-Day Exploitation of Network Appliances

**Category:** Edge / Zero-Day  
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1210 (Exploitation of Remote Services)

### How the Attack Works

State-sponsored and advanced threat actors discover and exploit zero-day vulnerabilities in internet-facing network appliances — VPN concentrators, email security gateways, firewalls, and load balancers. These devices are attractive targets because they sit at the network perimeter, often lack EDR coverage, run on proprietary OS stacks, and have high-privilege access to internal networks. Recent campaigns have targeted Ivanti, Fortinet, Palo Alto, Barracuda, and Citrix appliances.

**Attacker Objective:** Exploit unpatched vulnerabilities in perimeter appliances to gain initial access to the network, often establishing persistence before the vulnerability is publicly disclosed or patched.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **Appliance Logs** | Unusual process execution, crash dumps, or error patterns on appliance management interfaces |
| **Network Anomalies** | Unexpected outbound connections from appliance management IPs, especially to non-standard ports |
| **Integrity Monitoring** | File system changes on appliance OS (new files, modified binaries, web shells in management portals) |
| **Threat Intelligence** | Appliance vendor advisories and indicators correlated against network flow data |

**Defensive Mitigations:**
- Subscribe to vendor security advisories and apply patches within hours for critical appliance vulnerabilities
- Implement network-level anomaly detection on appliance management interfaces
- Deploy out-of-band integrity monitoring for appliance filesystems where possible
- Restrict appliance management interfaces to dedicated management networks (not internet-exposed)
- Maintain incident response playbooks specific to appliance compromise scenarios

---

## UEFI Bootkit Persistence

**Category:** Edge / Zero-Day  
**MITRE ATT&CK:** T1542.003 (Pre-OS Boot: UEFI Firmware), T1014 (Rootkit)

### How the Attack Works

The adversary installs a bootkit in the UEFI firmware or EFI System Partition (ESP) of a compromised endpoint. The bootkit loads before the operating system, allowing it to intercept the boot process, disable security controls (Secure Boot, kernel integrity checks), and inject malicious drivers or modules into the OS kernel. Because it operates below the OS layer, it is invisible to standard antivirus and EDR tools. Threats like BlackLotus have demonstrated the ability to bypass Secure Boot on fully patched systems.

**Attacker Objective:** Achieve OS-level persistence that survives disk wipes, OS reinstallation, and standard security tool detection by operating below the operating system in the firmware layer.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **EFI Partition Monitoring** | Unexpected modifications to files in the EFI System Partition (bootloaders, drivers) |
| **Secure Boot State** | Changes to Secure Boot configuration, DBX revocation list, or boot policy on endpoints |
| **Boot Telemetry** | Measured boot logs (TPM event logs) showing deviations from known-good boot sequences |
| **Kernel Integrity** | Early-launch anti-malware (ELAM) driver alerts, unexpected kernel driver loads at boot |

**Defensive Mitigations:**
- Enable and enforce Secure Boot with up-to-date DBX revocation lists
- Deploy hardware-rooted integrity measurement (TPM-based attestation)
- Monitor EFI System Partition for unauthorized file changes
- Use firmware scanning tools that validate UEFI module integrity
- Implement endpoint hardware inventory to track firmware versions and flag anomalies

---

## Rogue Base Station / Cellular MITM on Mobile Endpoints

**Category:** Edge / Zero-Day  
**MITRE ATT&CK:** T1557 (Adversary-in-the-Middle), T1123 (Audio Capture)

### How the Attack Works

The adversary deploys a rogue cellular base station (IMSI catcher / stingray) in proximity to target devices. The device forces mobile endpoints to downgrade their connection to insecure protocols (e.g., 2G/GSM) or exploits weaknesses in 4G/5G authentication, enabling interception of voice calls, SMS messages (including MFA codes), and data traffic. Advanced variants can inject malicious content or perform targeted tracking of device locations.

**Attacker Objective:** Intercept mobile communications including SMS-based MFA codes, voice calls, and data traffic, or perform precise geolocation tracking of target devices.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **Mobile Device Telemetry** | Unexpected cell tower changes, signal strength anomalies, or forced protocol downgrades (4G→2G) |
| **MFA Failure Correlation** | SMS-based MFA codes being used by a different device/IP than the one that received them |
| **RF Monitoring** | Detection of unauthorized cell towers or anomalous RF emissions near facilities (requires specialized equipment) |
| **Network Authentication** | Mobile devices reporting authentication failures or being forced to re-register with the network |

**Defensive Mitigations:**
- Eliminate SMS-based MFA in favor of app-based or FIDO2 authentication
- Deploy mobile threat defense (MTD) solutions that detect rogue base stations and protocol downgrades
- Implement device management policies that prevent forced 2G downgrades where OS supports it
- Use encrypted communications (Signal, enterprise VPN) for sensitive mobile communications
- Monitor for IMSI-catcher indicators in high-security facilities with RF monitoring

---

> **Previous:** [← AI & Agentic Threats](../ai-agentic-threats/README.md) | **Next:** [Supply Chain →](../supply-chain/README.md)
