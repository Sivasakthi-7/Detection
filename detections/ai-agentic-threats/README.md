# 🤖 AI & Agentic Threats — Detection Use Cases

> Attacks targeting AI/ML systems, large language models, autonomous agents, and unsanctioned AI deployments within the enterprise.

### 📁 Detection Rules

| Use Case | SPL Query | Sigma Rule |
|----------|-----------|------------|
| Prompt Injection | [prompt-injection.spl](rules/spl/prompt-injection.spl) | [prompt-injection.yml](rules/sigma/prompt-injection.yml) |
| Model Poisoning | [model-poisoning.spl](rules/spl/model-poisoning.spl) | [model-poisoning.yml](rules/sigma/model-poisoning.yml) |
| LLM Tool-Use Abuse | [llm-tool-use-abuse.spl](rules/spl/llm-tool-use-abuse.spl) | [llm-tool-use-abuse.yml](rules/sigma/llm-tool-use-abuse.yml) |
| Shadow AI | [shadow-ai.spl](rules/spl/shadow-ai.spl) | [shadow-ai.yml](rules/sigma/shadow-ai.yml) |

---

## Prompt Injection Against Agentic AI Workflows

**Category:** AI & Agentic Threats  
**MITRE ATLAS:** AML.T0051 (LLM Prompt Injection)

### How the Attack Works

The adversary crafts malicious inputs — either directly (direct prompt injection) or embedded within data the AI system processes (indirect prompt injection) — to override the system prompt, bypass safety guardrails, or cause the AI agent to execute unintended actions. In agentic workflows where the LLM has tool-use capabilities (e.g., executing code, calling APIs, sending emails), successful injection can lead to data exfiltration, unauthorized actions, or privilege escalation through the agent's own permissions.

**Attacker Objective:** Hijack an AI agent's execution context to perform unauthorized actions using the agent's granted permissions and tool access.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **Prompt/Response Logging** | Inputs containing instruction-override patterns, role-play directives, or encoded payloads |
| **Tool-Use Telemetry** | Agent invoking tools in sequences or patterns inconsistent with the user's stated intent |
| **Action Anomalies** | Agent performing actions outside its normal behavioral baseline (e.g., accessing new APIs, sending data externally) |
| **Data Flow Analysis** | External or untrusted content being passed through the agent's context window before tool invocations |

**Defensive Mitigations:**
- Implement input/output guardrails and content classifiers to detect injection patterns
- Apply least-privilege to agent tool permissions; scope API keys and credentials narrowly
- Use structured tool-call interfaces that separate instructions from data
- Log all agent actions with full context chain for audit and incident response
- Deploy canary tokens in documents to detect unauthorized document access via agents

---

## AI Model Poisoning via Training Data Manipulation

**Category:** AI & Agentic Threats  
**MITRE ATLAS:** AML.T0020 (Poison Training Data)

### How the Attack Works

The adversary introduces malicious or manipulated samples into a model's training dataset — either by compromising the data pipeline, contributing poisoned data to public datasets, or manipulating labeling processes. The poisoned model then exhibits attacker-desired behavior: misclassifying specific inputs (targeted poisoning), degrading overall performance, or embedding backdoor triggers that activate on specific patterns while performing normally otherwise.

**Attacker Objective:** Embed backdoors or degrade the integrity of ML models by corrupting training data, causing the model to produce attacker-favorable outputs under specific conditions.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **Data Pipeline Integrity** | Unexpected changes to training data sources, volumes, or distributions |
| **Model Performance** | Sudden accuracy degradation, anomalous prediction patterns on specific input classes, or unexpected confidence score distributions |
| **Pipeline Access Logs** | Unauthorized access to data storage, labeling tools, or feature engineering pipelines |
| **Data Provenance** | Training data sourced from unvetted or recently modified external repositories |

**Defensive Mitigations:**
- Implement data provenance tracking and integrity verification (checksums, signatures) for all training data
- Conduct statistical analysis on training data distributions to detect anomalous insertions
- Use hold-out test sets from trusted sources to validate model behavior
- Restrict and audit write access to training data pipelines and labeling platforms
- Apply differential privacy and robust training techniques to reduce poisoning effectiveness

---

## LLM Tool-Use Abuse and Autonomous Action Hijacking

**Category:** AI & Agentic Threats  
**MITRE ATLAS:** AML.T0051 (LLM Prompt Injection), AML.T0048 (Command Injection via AI)

### How the Attack Works

As organizations deploy AI agents with real-world tool access (database queries, API calls, file operations, code execution), adversaries target the boundary between the LLM's reasoning and its tool invocations. By manipulating the context — through poisoned retrieval-augmented generation (RAG) documents, compromised knowledge bases, or crafted user inputs — the attacker causes the agent to invoke tools with malicious parameters: exfiltrating data via API calls, modifying records, or escalating privileges through the agent's own service identity.

**Attacker Objective:** Weaponize an AI agent's tool-use capabilities to perform unauthorized operations using the agent's elevated service permissions.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **Tool Invocation Logs** | Tool calls with parameters that deviate from expected patterns (unusual endpoints, broad queries, write operations) |
| **RAG/Knowledge Base Integrity** | Modifications to vector stores, knowledge bases, or retrieval indices from unauthorized sources |
| **Permission Usage** | Agent's service identity accessing resources outside its normal operational scope |
| **Output Analysis** | Agent returning or transmitting data that wasn't requested by the user's original prompt |

**Defensive Mitigations:**
- Implement human-in-the-loop approval for high-impact tool actions (write, delete, send)
- Scope agent service identities with strict least-privilege; use separate identities per tool domain
- Monitor and baseline agent tool-call patterns; alert on statistical deviations
- Validate RAG source integrity and restrict who can modify retrieval indices
- Implement tool-call rate limiting and anomaly detection on agent execution pipelines

---

## Shadow AI and Unsanctioned Model Deployment

**Category:** AI & Agentic Threats  
**MITRE ATT&CK:** T1204 (User Execution), T1567 (Exfiltration Over Web Service)

### How the Attack Works

Employees deploy unsanctioned AI models, fine-tuned LLMs, or third-party AI services within the corporate environment — uploading sensitive data to external AI platforms, running open-source models on corporate infrastructure without security review, or integrating AI APIs into production workflows without governance. This creates unmonitored data flows, potential compliance violations, and attack surface expansion. Adversaries may also introduce trojanized models disguised as useful open-source tools.

**Attacker Objective:** Exploit ungoverned AI usage to exfiltrate data, introduce compromised models, or establish unmonitored processing pipelines within the organization.

### High-Level Detection Strategy

| Signal Domain | Key Behavioral Indicators |
|---------------|--------------------------|
| **Network Traffic** | Connections to known AI platform APIs (OpenAI, Anthropic, HuggingFace, Replicate) from non-sanctioned endpoints or users |
| **Cloud Resource Usage** | GPU instance provisioning, large model file downloads, or container images for ML frameworks appearing outside approved projects |
| **DLP Signals** | Sensitive data (PII, source code, financial data) being transmitted to external AI services |
| **Software Inventory** | Unauthorized ML frameworks, model files, or AI development tools installed on endpoints or servers |

**Defensive Mitigations:**
- Establish an AI usage policy and approved vendor list; communicate it across the organization
- Implement network-level controls (proxy, CASB) to monitor and restrict access to unauthorized AI services
- Deploy DLP policies to prevent sensitive data from being uploaded to external AI platforms
- Create an AI asset inventory and governance process for model deployment approvals
- Monitor cloud spend and resource provisioning for unexpected GPU or compute usage

---

> **Previous:** [← Cloud / Cross-Domain](../cloud-cross-domain/README.md) | **Next:** [Edge / Zero-Day →](../edge-zero-day/README.md)
