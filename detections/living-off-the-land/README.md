# 🏠 Living-off-the-Land — Detection Use Cases

> Attacks that abuse legitimate system tools, trusted binaries, and native OS capabilities to blend in with normal administrative activity.

### 📁 Detection Rules

| Use Case | SPL Query | Sigma Rule |
|----------|-----------|------------|
| LOLBins Abuse | [lolbins-abuse.spl](rules/spl/lolbins-abuse.spl) | [lolbins-abuse.yml](rules/sigma/lolbins-abuse.yml) |
| Reflective DLL Injection | [reflective-dll-injection.spl](rules/spl/reflective-dll-injection.spl) | [reflective-dll-injection.yml](rules/sigma/reflective-dll-injection.yml) |
| RMM Tool Abuse | [rmm-tool-abuse.spl](rules/spl/rmm-tool-abuse.spl) | [rmm-tool-abuse.yml](rules/sigma/rmm-tool-abuse.yml) |
| WMI/Schtask Persistence | [wmi-schtask-persistence.spl](rules/spl/wmi-schtask-persistence.spl) | [wmi-schtask-persistence.yml](rules/sigma/wmi-schtask-persistence.yml) |

---

## Living-off-the-Land Binaries (LOLBins) Abuse

**Category:** Living-off-the-Land  
**MITRE ATT&CK:** T1218 (System Binary Proxy Execution), T1059 (Command and Scripting Interpreter)

### How the Attack Works

The adversary uses pre-installed, trusted system binaries — such as `certutil`, `mshta`, `regsvr32`, `rundll32`, `msiexec`, `bitsadmin`, or `curl` — to perform malicious actions: downloading payloads, executing arbitrary code, decoding/encoding data, or establishing persistence. Because these are legitimate OS tools, they are trusted by application allowlists and may not trigger security tool alerts. The LOLBAS and GTFOBins projects catalog hundreds of such abusable binaries across Windows and Linux.

**Attacker Objective:** Execute malicious actions using trusted, pre-installed OS binaries to avoid detection by security tools that rely on executable reputation, signatures, or allowlists.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **Process Telemetry** | System binaries invoked with unusual command-line arguments (e.g., `certutil -urlcache`, `mshta http://...`) |
| **Parent-Child Process** | Unexpected parent-child process relationships (e.g., `outlook.exe` → `powershell.exe` → `certutil.exe`) |
| **Network Activity** | System utilities making outbound network connections, especially to external IPs or uncommon ports |
| **Execution Context** | LOLBins executed from unusual directories, by non-admin users, or outside normal administrative windows |

**Defensive Mitigations:**
- Implement command-line audit logging and baseline normal usage of system utilities
- Deploy behavioral EDR rules that alert on suspicious LOLBin usage patterns (not just binary execution)
- Restrict unnecessary LOLBins via application control policies where operationally feasible
- Create detection rules for known LOLBin abuse patterns from the LOLBAS project
- Monitor PowerShell, cmd.exe, and bash execution with script block logging and enhanced audit policies

---

## Reflective DLL Injection via Trusted Processes

**Category:** Living-off-the-Land  
**MITRE ATT&CK:** T1055.001 (Process Injection: Dynamic-link Library Injection), T1620 (Reflective Code Loading)

### How the Attack Works

The adversary injects a malicious DLL into the memory space of a trusted, running process — without the DLL ever being written to disk. Reflective DLL injection loads the library directly from memory by implementing a custom loader that maps the DLL into the process's address space and resolves imports manually. Because the payload never touches the filesystem and executes within a trusted process (e.g., `explorer.exe`, `svchost.exe`, `lsass.exe`), it evades file-based scanning and process-level allowlisting.

**Attacker Objective:** Execute malicious code within the memory space of a trusted process to evade disk-based detection, application allowlists, and process-level security controls.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **Memory Telemetry** | Allocation of executable memory regions (RWX) within trusted processes, followed by thread creation |
| **API Call Monitoring** | Use of `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, or `NtMapViewOfSection` targeting trusted processes |
| **Module Load Events** | DLL load events where the loaded module has no corresponding file on disk |
| **Behavioral Anomalies** | Trusted system processes exhibiting unexpected behaviors: network connections, file access patterns, or child process creation |

**Defensive Mitigations:**
- Deploy EDR solutions with memory scanning and in-memory detection capabilities
- Enable and monitor Windows ETW providers for memory allocation and thread creation events
- Implement code integrity policies (WDAC/AppLocker) that restrict unsigned DLL loading
- Use Credential Guard to protect sensitive processes like LSASS from injection
- Alert on processes with anomalous memory allocation patterns (high RWX page counts)

---

## RMM Tool Abuse for Hands-on-Keyboard Access

**Category:** Living-off-the-Land  
**MITRE ATT&CK:** T1219 (Remote Access Software), T1072 (Software Deployment Tools)

### How the Attack Works

The adversary installs or abuses legitimate Remote Monitoring and Management (RMM) tools — such as AnyDesk, TeamViewer, ConnectWise ScreenConnect, Atera, Splashtop, or similar — to establish persistent remote access to compromised endpoints. Because these tools are legitimate commercial software, they are signed, often allowlisted, and their traffic blends with normal IT administration. Threat actors may install a trial/free version, use stolen customer credentials to access existing deployments, or abuse compromised MSP (Managed Service Provider) consoles.

**Attacker Objective:** Establish reliable, persistent remote access using trusted commercial RMM tools that bypass security controls, blend with legitimate IT operations, and are resistant to credential rotation.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **Software Inventory** | Installation of RMM tools not on the organization's approved list |
| **Network Telemetry** | Outbound connections to RMM vendor infrastructure from endpoints that shouldn't have RMM clients |
| **Service/Process Monitoring** | New services or processes associated with known RMM tools appearing on non-IT-managed endpoints |
| **User Context** | RMM sessions initiated outside business hours, from unusual user accounts, or on sensitive systems |

**Defensive Mitigations:**
- Maintain an allowlist of approved RMM tools and alert on any unauthorized installations
- Block network connections to unauthorized RMM vendor domains at the firewall/proxy
- Monitor for RMM-associated service installations, registry keys, and process signatures
- Implement application control policies that restrict RMM installation to authorized IT accounts
- Audit MSP access and require MFA for all RMM administrative consoles

---

## WMI / Scheduled Task Persistence via Native OS Facilities

**Category:** Living-off-the-Land  
**MITRE ATT&CK:** T1053.005 (Scheduled Task/Job), T1546.003 (WMI Event Subscription)

### How the Attack Works

The adversary uses built-in Windows facilities — WMI event subscriptions, scheduled tasks, or systemd timers on Linux — to establish persistence that executes malicious code on a trigger: system startup, user logon, specific time intervals, or WMI events. These persistence mechanisms are native OS features used heavily by legitimate software and IT administration, making them difficult to distinguish from normal operations. WMI event subscriptions are particularly stealthy as they are stored in the WMI repository rather than the filesystem.

**Attacker Objective:** Establish persistent code execution using native OS scheduling and event mechanisms that blend with legitimate system administration activity and survive reboots.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **WMI Repository** | New WMI event consumers, filters, or bindings — especially those executing scripts or binaries |
| **Scheduled Task Logs** | Creation of scheduled tasks by non-administrative accounts, tasks with encoded command lines, or tasks running from unusual directories |
| **Persistence Enumeration** | Autoruns-style monitoring detecting new persistence entries across boot, logon, and event-based triggers |
| **Execution Chains** | `wmiprvse.exe` or `schtasks.exe` spawning scripting engines (`powershell`, `cmd`, `wscript`) or connecting to the network |

**Defensive Mitigations:**
- Monitor Windows Event IDs 4698/4699 (scheduled task creation/deletion) and WMI operational logs
- Deploy persistence monitoring tools (Autoruns, Velociraptor, osquery) to baseline and detect new entries
- Restrict WMI remote access and scheduled task creation to authorized administrative accounts
- Implement GPO policies limiting which users can create scheduled tasks on sensitive systems
- Use EDR behavioral rules to alert on WMI event subscription creation with suspicious consumers

---

> **Previous:** [← Supply Chain](../supply-chain/README.md) | **Back to Index:** [Main README](../../README.md)
