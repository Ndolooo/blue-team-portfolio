# Collection Sources

**Organisation:** Santry Fintech (Fictional)
**Programme:** AI-Threat Intelligence Tracker
**Version:** 1.0 — November 2026
**Linked document:** [`PIRs.md`](PIRs.md)

---

## 1. Purpose

This document is the **collection plan**. It lists the sources monitored for AI-enabled threats, the PIRs each source supports, how each source is collected, and how reliable it is judged to be.

Every source must support at least one PIR. Sources that stop producing useful intelligence are reviewed and may be removed at the quarterly review.

---

## 2. Rating scheme: Admiralty Code

Sources are rated for **reliability** (A–F). Each individual piece of information is separately rated for **credibility** (1–6) when it is entered into MISP. The two ratings are independent: a reliable source can still publish an unconfirmed claim.

### Source reliability

| Rating | Meaning |
|---|---|
| A | Completely reliable: no doubt about authenticity, trustworthiness or competence; history of complete reliability |
| B | Usually reliable: minor doubts; history of mostly valid information |
| C | Fairly reliable: some doubts; has provided valid information in the past |
| D | Not usually reliable: significant doubts |
| E | Unreliable: history of invalid information |
| F | Reliability cannot be judged: new or untested source |

### Information credibility

| Rating | Meaning |
|---|---|
| 1 | Confirmed by other independent sources |
| 2 | Probably true: not confirmed, but logical and consistent with other information |
| 3 | Possibly true: reasonably logical, some agreement with other information |
| 4 | Doubtful: possible but not logical, no other information supports it |
| 5 | Improbable: contradicted by other information |
| 6 | Truth cannot be judged |

**Rating approach for this programme:** no source starts at **A**. An A rating requires a proven track record, and this programme has no collection history yet. Established government agencies and major vendors start at **B**. Ratings are revisited quarterly, based on how often each source's reporting is later corroborated.

In MISP, ratings are recorded with the `admiralty-scale` taxonomy (e.g., `admiralty-scale:source-reliability="b"`, `admiralty-scale:information-credibility="2"`).

---

## 3. Source register

| ID | Source | Type | Reliability | PIRs | Collection method | Frequency |
|---|---|---|---|---|---|---|
| S01 | NCSC Ireland — advisories and alerts | Government (IE) | B | 1, 4 | Website / RSS | Weekly |
| S02 | CISA — advisories and joint guidance | Government (US) | B | 1, 3, 4 | RSS | Weekly |
| S03 | ENISA — Threat Landscape and reports | Government (EU) | B | 1, 4 | Website | Monthly |
| S04 | UK NCSC — reports and guidance | Government (UK) | B | 1, 3, 4 | RSS | Weekly |
| S05 | Microsoft Threat Intelligence blog | Vendor | B | 1, 4 | RSS | Weekly |
| S06 | Google Threat Intelligence / Mandiant blog | Vendor | B | 1, 2, 4 | RSS | Weekly |
| S07 | Palo Alto Networks Unit 42 | Vendor | B | 1, 2, 3, 4 | RSS | Weekly |
| S08 | CrowdStrike blog and annual Global Threat Report | Vendor | B | 1, 4 | RSS / annual report | Weekly / annual |
| S09 | OpenAI threat reports (disrupting malicious uses of AI) | AI provider | B | 4 | Website | Monthly |
| S10 | Anthropic threat intelligence reports | AI provider | B | 3, 4 | Website | Monthly |
| S11 | Socket — research blog | Vendor (supply chain) | B | 2 | RSS | Weekly |
| S12 | Snyk — security research blog | Vendor (supply chain) | B | 2, 3 | RSS | Weekly |
| S13 | MITRE ATLAS — techniques and case studies | Knowledge base | B | 2, 3, 4 | Website | Monthly |
| S14 | AI Incident Database | Crowd-sourced database | C | 1, 3 | Website | Monthly |

**Coverage check:** every PIR has at least four sources. PIR-2 depends most on supply-chain specialists (S11, S12); PIR-3 has the thinnest real-world incident reporting (see gaps below).

| PIR | Sources |
|---|---|
| PIR-1 AI-enabled social engineering | S01, S02, S03, S04, S05, S06, S07, S08, S14 |
| PIR-2 Malicious AI packages / MCP servers | S06, S07, S11, S12, S13 |
| PIR-3 Prompt injection vs chatbots/agents | S02, S04, S07, S10, S12, S13, S14 |
| PIR-4 Actor use of LLMs | S01–S10, S13 |

---

## 4. Rating rationale and known biases

| ID | Why this rating | Bias or limitation to keep in mind |
|---|---|---|
| S01 | National CSIRT for Ireland; most relevant geographically | Publishes less often than larger agencies; limited AI-specific reporting |
| S02, S04 | Authoritative government sources with frequent joint advisories | US/UK focus; findings may need adapting to an Irish/EU context |
| S03 | EU-level strategic view; relevant to DORA/NIS2 context | Strategic and annual; low tactical detail |
| S05–S08 | Large telemetry, named-actor attribution, technical detail | Commercial interest in highlighting threats their products address; attribution uses each vendor's own actor naming |
| S09, S10 | First-hand visibility of how attackers misuse their own models | Self-reporting: providers choose what to disclose; may emphasise successful disruptions |
| S11, S12 | Specialists in package-registry threats; publish IOCs (package names, hashes) | Commercial interest; some findings are low-impact typosquats |
| S13 | Curated framework maintained by MITRE; useful for mapping | Not a live intel feed; case studies include research demonstrations, not only real attacks |
| S14 | Broad coverage of real-world AI harms | Crowd-sourced and media-based; many entries lack technical detail; rated C until individual items are corroborated |

---

## 5. Handling rules

- **TLP:** all sources above are public. Items stored in MISP are tagged `tlp:clear` unless they are combined with internal (fictional) Santry context, in which case `tlp:green`.
- **Verification:** items drafted by the local LLM (Ollama) are never stored without analyst review against the original source.
- **Citation:** every MISP event links back to the original report URL.
- **Single-source items:** information reported by only one source is given credibility 3 or lower until it is corroborated.
- **Research vs real-world:** proof-of-concept research is labelled as such, and is not presented as observed attacker activity in briefs.

---

## 6. Known collection gaps

| Gap | Effect | Possible mitigation |
|---|---|---|
| Little Irish-specific reporting on AI-enabled attacks | PIR-1 relies on EU/UK reporting as a proxy | Monitor Central Bank of Ireland and An Garda Síochána fraud alerts; Irish media |
| Real-world prompt-injection incidents are under-reported | PIR-3 judgements will often be low/moderate confidence | Add bug-bounty disclosures and LLM vendor security advisories |
| No closed or community sharing sources | Limited early warning compared with a real CTI team | Note as a limitation; consider joining public MISP communities later |
| Deepfake fraud reports rarely include technical detail | Hard to build detections for PIR-1 | Focus outputs on process controls (verification) rather than IOCs |

---

## 7. Review

Sources and ratings are reviewed quarterly, alongside the PIRs. Each review records:
- sources added or removed, and why
- rating changes, with the evidence for them
- which PIRs are still under-covered
