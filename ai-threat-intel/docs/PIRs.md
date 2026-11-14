# Priority Intelligence Requirements (PIRs)

**Organisation:** Santry Fintech (Fictional)
**Programme:** AI-Threat Intelligence Tracker
**Version:** 1.0 — November 2026
**Owner:** Threat Intelligence Analyst
**Review cycle:** Quarterly, or after any major incident or significant change in the threat landscape

> Santry Fintech is a fictional organisation created for a threat intelligence portfolio project. Any resemblance to a real company is unintended.

---

## 1. Purpose

These PIRs set the **direction** phase of the intelligence lifecycle. They define what Santry Fintech's leadership and security teams most need to know about AI-enabled threats, so that collection, analysis and reporting stay focused on decisions the business actually has to make.

Every source in [`sources.md`](sources.md), every event stored in MISP and every key judgement in a monthly AI Threat Brief should trace back to at least one PIR below.

---

## 2. Organisation profile

| Attribute | Detail |
|---|---|
| Sector | Financial services (fintech) |
| Location | Dublin, Ireland; customers across Ireland and the EU |
| Size | ~300 staff |
| Corporate IT | Microsoft 365 (Entra ID, Exchange Online, Teams) |
| Product | Cloud-hosted customer web/mobile app |
| AI exposure | Customer-facing AI chatbot (LLM-based, with access to account-support functions); developers use AI coding assistants |
| Regulatory context | Central Bank of Ireland supervision; EU DORA (ICT risk, incident reporting, third-party risk); NIS2; EU AI Act obligations for deployed AI systems |

### Crown jewels
1. Customer funds and payment flows
2. Customer personal and financial data
3. Production cloud environment and CI/CD pipeline
4. Executive and finance-team identities (payment approval authority)

---

## 3. Stakeholders (intelligence consumers)

| Stakeholder | What they need from intelligence |
|---|---|
| CISO / leadership | Strategic picture, risk trends, regulatory relevance, investment priorities |
| SOC | Tactical indicators, TTPs, detection and hunting opportunities |
| Fraud & payments team | Social-engineering and impersonation techniques targeting payment approval |
| Engineering / AppSec | Supply-chain risks in AI packages, models and MCP servers; chatbot security |
| Customer support | Scam patterns customers may report; impersonation of Santry staff or brand |

---

## 4. Priority Intelligence Requirements

### PIR-1 — AI-enabled social engineering against Irish/EU finance

**Question:** How are threat actors using AI-generated content (phishing text, voice cloning, deepfake video) to target financial-sector organisations and their customers in Ireland and the EU, and which techniques are most likely to succeed against Santry Fintech?

**Why it matters:** Payment-approval fraud (CEO/CFO impersonation) and customer-facing scams have direct financial impact and DORA incident-reporting implications. AI lowers the cost and raises the quality of these attacks.

**Priority:** High | **Primary consumers:** Fraud team, SOC, CISO

**Specific intelligence requirements (SIRs):**
- SIR-1.1 Which voice-cloning or deepfake-video techniques have been used in confirmed fraud against financial organisations, and what verification controls defeated or failed to defeat them?
- SIR-1.2 Are AI-generated phishing campaigns targeting Irish banks, fintechs or their customers (including impersonation of Irish brands, Revenue or An Garda Síochána)?
- SIR-1.3 Are criminal "phishing-as-a-service" kits now offering built-in LLM features (lure generation, translation, real-time chat)?
- SIR-1.4 Which attacks target Microsoft 365 / Teams specifically (e.g., Teams vishing, adversary-in-the-middle phishing)?

**Indicators / collection triggers:** reports of deepfake-enabled payment fraud; Irish or EU finance-sector phishing advisories; new phishing kits with AI features; Teams-based social-engineering campaigns.

**Framework mapping:** ATT&CK T1566 (Phishing) incl. T1566.004 (Spearphishing Voice); T1656 (Impersonation); T1598 (Phishing for Information)

**Supports:** Payment-verification procedures; staff awareness content; email and Teams detection rules.

---

### PIR-2 — Malicious AI packages, models and MCP servers targeting developers

**Question:** What malicious or compromised AI-related software (Python/npm packages, model files, AI coding-assistant extensions, MCP servers) is being used to compromise developer environments, and does any of it affect tools or dependencies Santry Fintech uses?

**Why it matters:** Santry's developers use AI coding assistants and AI libraries. A compromised dependency or tool could give attackers access to source code, secrets and the CI/CD pipeline, a direct route to the production environment.

**Priority:** High | **Primary consumers:** Engineering / AppSec, SOC

**SIRs:**
- SIR-2.1 Which malicious packages impersonating AI SDKs or libraries (typosquatting, dependency confusion) have been found on PyPI or npm?
- SIR-2.2 Are malicious or backdoored model files (e.g., unsafe pickle serialisation) being distributed through public model hubs?
- SIR-2.3 Have malicious or vulnerable MCP servers or AI-assistant extensions been reported, and what access did they abuse (file system, tokens, shell)?
- SIR-2.4 Are AI coding assistants recommending non-existent packages that attackers then register ("slopsquatting")?

**Indicators / collection triggers:** package-registry takedown reports (Socket, Snyk, etc.); malicious package names and hashes; MCP or extension security advisories; CVEs in AI developer tooling.

**Framework mapping:** ATT&CK T1195.001 (Supply Chain Compromise: Software Dependencies and Development Tools); ATLAS AML.T0010 (ML Supply Chain Compromise)

**Supports:** Dependency blocklists; package-allowlisting policy; MCP/extension approval process; SOC hunting for known-bad package hashes.

---

### PIR-3 — Prompt-injection exploitation of customer chatbots and AI agents

**Question:** How are attackers exploiting prompt injection (direct and indirect) against customer-facing chatbots and AI agents, especially those connected to account data or actions, and what would a successful attack on Santry's chatbot look like?

**Why it matters:** Santry's chatbot can reach account-support functions. A successful injection could leak customer data, trigger unauthorised actions or damage trust in the brand. These are incidents the Central Bank and customers would expect Santry to anticipate.

**Priority:** High | **Primary consumers:** Engineering / AppSec, CISO, SOC

**SIRs:**
- SIR-3.1 What real-world (not only research) prompt-injection incidents have affected customer-service chatbots or AI agents, and what was the impact?
- SIR-3.2 Which indirect injection routes (uploaded documents, emails, web pages, tool outputs) have been abused in practice?
- SIR-3.3 What jailbreak or injection techniques are being shared on criminal forums or public repositories, and how quickly do they spread?
- SIR-3.4 What logging signals would let the SOC detect an injection attempt against an LLM application?

**Indicators / collection triggers:** disclosed chatbot incidents; vendor security advisories for LLM platforms; new injection techniques in research or threat reports; AI Incident Database entries involving finance or customer service.

**Framework mapping:** ATLAS AML.T0051 (LLM Prompt Injection, direct and indirect); AML.T0054 (LLM Jailbreak); AML.T0057 (LLM Data Leakage); OWASP Top 10 for LLM Applications (LLM01 Prompt Injection)

**Supports:** Chatbot guardrail design; red-team test cases; LLM application logging requirements; SOC detection for anomalous chatbot behaviour.

---

### PIR-4 — Threat actors using LLMs to scale operations

**Question:** Which threat actors (state-linked, criminal and hacktivist) are using LLMs to support their operations, at which stages of the attack lifecycle, and are they targeting the financial sector or Ireland/EU?

**Why it matters:** This is the strategic PIR. It tells leadership whether AI is changing who can attack Santry, how fast and at what scale, and so whether current defences and investment priorities still fit.

**Priority:** Medium | **Primary consumers:** CISO / leadership

**SIRs:**
- SIR-4.1 Which named actors have AI providers (OpenAI, Anthropic, Google, Microsoft) reported disrupting, and for what tasks (reconnaissance, scripting, malware development, influence operations)?
- SIR-4.2 Is there evidence of AI materially increasing attacker capability, or mainly productivity?
- SIR-4.3 Are any of these actors known to target financial services or Ireland/EU?
- SIR-4.4 Are criminal LLM tools or "jailbroken AI as a service" products being sold, and to whom?

**Indicators / collection triggers:** AI-provider threat-intelligence reports; government advisories (NCSC Ireland, UK NCSC, CISA, ENISA); vendor reports linking AI use to named actors.

**Framework mapping:** ATT&CK T1588.007 (Obtain Capabilities: Artificial Intelligence); T1593 (Search Open Websites/Domains); ATLAS tactics for adversary use of AI

**Supports:** Quarterly risk reporting to leadership; threat model updates; security investment prioritisation.

> **Note:** Framework IDs should be checked against the current ATT&CK and ATLAS releases when the document is reviewed. Both frameworks add and renumber techniques over time.

---

## 5. Prioritisation summary

| PIR | Topic | Priority | Time horizon | Main output |
|---|---|---|---|---|
| PIR-1 | AI-enabled social engineering | High | Tactical / operational | Detections, fraud controls, awareness |
| PIR-2 | Malicious AI packages / MCP servers | High | Tactical | Blocklists, IOCs, hunting queries |
| PIR-3 | Prompt injection vs chatbots/agents | High | Operational | Guardrails, test cases, logging needs |
| PIR-4 | Actor use of LLMs | Medium | Strategic | Leadership risk picture |

---

## 6. How the PIRs are used in this project

| Lifecycle stage | Link to PIRs |
|---|---|
| Collection | Each source in `sources.md` is mapped to the PIRs it supports. |
| Processing | The collector tags each draft item with candidate PIR(s); the analyst confirms them. |
| Storage (MISP) | Each event carries a PIR tag (e.g., `santry:pir="PIR-2"`) alongside TLP and ATT&CK/ATLAS tags. |
| Analysis | Monthly patterns are assessed per PIR. |
| Dissemination | Each AI Threat Brief has a section per PIR, with key judgements and confidence levels. |
| Feedback | Stakeholder feedback and detection outcomes are used to revise PIRs each quarter. |

### Confidence language
Key judgements use the following scale:
- **High confidence:** multiple reliable, independent sources; little room for alternative explanations.
- **Moderate confidence:** credible sources but limited corroboration, or plausible alternatives exist.
- **Low confidence:** single or less reliable source; judgement is tentative and flagged for further collection.

Source reliability and information credibility are rated using the Admiralty Code (A–F / 1–6), as documented in `sources.md`.

---

## 7. Known intelligence gaps (initial)

- Limited public reporting specific to **Irish** financial-sector AI incidents; reliance on EU/UK reporting as a proxy.
- Real-world prompt-injection incidents are under-reported compared to research demonstrations.
- Deepfake fraud cases are often reported without technical detail on the tools used.

These gaps will be revisited at each quarterly review.
