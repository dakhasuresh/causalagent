# CausalAgent

**OT-Native Causal Decision Intelligence Engine for Industrial Incident Response**

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)
[![Tests](https://img.shields.io/badge/tests-93%20passing-brightgreen)]()
[![Standards](https://img.shields.io/badge/IEC%2062443--3--3-aligned-blue)]()
[![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-ICS%20Matrix-red)]()
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## The Problem This Solves

Modern OT environments generate thousands of alarms per day across PLCs, DCS, SCADA, OT network switches, and industrial cybersecurity sensors. Existing tooling — SIEMs, OT monitoring platforms, network intrusion detection — is effective at **detecting** events. None of it tells the operations team **why** the event happened, **what is safe to do about it**, and **who must authorise the action**.

The result is a decision gap: engineers correlate alerts manually, improvise under pressure, and occasionally take unsafe actions against production equipment. Mean time to respond in OT environments averages 4–8 hours for complex incidents. The cost of unplanned downtime in continuous-process industries ranges from $50K to $500K per hour.

CausalAgent addresses this gap with a **causal decision intelligence layer** that sits above existing OT infrastructure — not replacing monitoring tools, not touching process control — reasoning over multi-protocol signal streams to isolate root causes, classify threats, enforce IEC 62443 safety guardrails, and route decisions to the right human authority before any action executes.

---

## What CausalAgent Is Not

Before the architecture: hard boundaries matter in OT.

| What it is | What it is not |
|---|---|
| A causal inference engine over OT events | A process control system |
| An IEC 62443-aligned decision gating layer | A SCADA replacement |
| A MITRE ATT&CK for ICS threat classifier | A safety instrumented system (SIS) |
| An explainable AI reasoning framework | A black-box ML model |
| A human-in-the-loop governance mechanism | An autonomous response platform |

CausalAgent never writes to PLC registers, never modifies DCS setpoints autonomously, and never bypasses SIL-rated safety functions. Every action proposal that touches the control layer requires explicit human approval with a full causal justification before execution is permitted.

---

## Core Design Principles

### 1. Causal Reasoning, Not Correlation

Alert correlation maps symptoms to symptoms. Causal reasoning maps symptoms to causes. CausalAgent builds a directed acyclic graph (DAG) of OT cause-effect relationships from YAML-defined rules aligned to the ISA-95 equipment hierarchy and Purdue Model zone structure. Given a stream of normalised OT events, the engine traverses this graph to isolate the initiating root cause — distinguishing it from downstream effects and observable symptoms.

A Modbus/TCP timeout on PLC-L3-A is not the incident. A 34% packet loss spike on network switch SW-03 following a firmware maintenance window is the root cause. CausalAgent makes this distinction deterministically, not probabilistically.

### 2. Deterministic Rules + Probabilistic Confidence

The causal graph topology is deterministic — encoded in auditable YAML, versioned in git, reviewable by OT engineers without touching Python. The confidence assigned to each node is probabilistic — a Bayesian-weighted score across evidence density, signal severity, temporal coherence, Purdue zone alignment, and decision memory pattern match.

This separation matters: the *structure* of the reasoning is transparent and challengeable; the *weight* of the evidence is computed from real signal data.

### 3. IEC 62443 Safety Guardrails as First-Class Citizens

Every proposed remediation action is evaluated against IEC 62443-3-3 Security Requirements before it reaches an operator. The `SafetyEngine` produces one of four decisions:

- `ALLOW` — safe for autonomous execution; production impact NONE or MINOR; action is reversible
- `HUMAN_GATE` — requires operator approval; full causal justification surfaced in approval UI
- `ESCALATE` — must go to process safety engineer; SIL-zone or MOC-required modification
- `BLOCK` — guardrail prevents execution regardless of operator intent; blocked with normative IEC clause citation

A setpoint revert on a flow control valve during an active cyber incident is `BLOCK` under IEC 62443-3-3 SR 2.6. An emergency shutdown trigger with causal confidence below 75% is `BLOCK` under IEC 62443-3-3 SR 3.6 and IEC 61511. These are not configurable thresholds — they are normative requirements.

### 4. Explainability as an Engineering Requirement

Every `CausalInferenceResult` carries an `ExplainabilityTrace` with:

- **Ordered reasoning steps** — natural-language inference chain from observed signals to root cause conclusion
- **Evidence event IDs** — which specific protocol events support each causal node
- **Counter-evidence** — which alternative root cause hypotheses were evaluated and why they were excluded
- **Temporal sequence** — millisecond-precision causal propagation timeline
- **IEC 62443 context** — which normative clauses govern the recommended response

This is not a post-hoc explanation added for usability. It is an engineering requirement: in IEC 62443-3-3 SR 2.6 (Use Control) and EU AI Act Article 13 (Transparency), automated systems acting in safety-relevant industrial environments must produce auditable decision traces. CausalAgent generates these traces natively as part of the inference pipeline.

### 5. Continual Learning Without Black-Box ML

The `DecisionMemory` stores resolved incident patterns as structured objects — trigger tags, protocols, causal chains, resolution actions, MTTR outcomes, operator accuracy feedback. Retrieval uses Jaccard tag-set similarity against a query event stream: fully deterministic, fully explainable, auditable in plain JSON.

When a pattern matches, its similarity score, matching tags, and historical MTTR are surfaced alongside the causal inference result — giving operators institutional memory without neural opacity.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         SIGNAL INGESTION LAYER                           │
│                                                                          │
│  Modbus/TCP (FC3/FC6)  ·  DNP3 (Unsolicited Resp)  ·  OPC-UA (PubSub)  │
│  SNMP (MIB-II ifTable)  ·  Syslog (RFC 5424)  ·  SIEM  ·  NetFlow v9   │
│  WinRM / RDP (lateral movement indicators)                               │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │  raw_signals: list[dict]
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  EventNormaliser                                          [causal_engine] │
│                                                                          │
│  Protocol-agnostic OTEvent extraction. Maps each signal to canonical     │
│  tag, value, unit, severity, Purdue zone (L0–L4, DMZ), and timestamp.   │
│  Preserves raw protocol address for audit (register, nodeId, OID, etc). │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │  events: list[OTEvent]
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  CausalGraphBuilder                                       [causal_engine] │
│                                                                          │
│  Loads YAML causal rule sets from rules/causal/*.yaml.                   │
│  Evaluates each rule's trigger_conditions against the event stream.      │
│  Constructs a directed causal graph (CausalNode[], CausalEdge[]).        │
│  Infers temporal lag between causal hops from event timestamps.          │
└───────────────┬───────────────────────────────────┬──────────────────────┘
                │  fired_rules                       │  graph topology
                ▼                                   ▼
┌───────────────────────────┐       ┌───────────────────────────────────────┐
│  ConfidenceScorer         │       │  ExplainabilityEngine                 │
│                           │       │                                       │
│  Bayesian-weighted score  │       │  Generates ExplainabilityTrace:       │
│  per CausalNode:          │       │  - ordered reasoning steps            │
│  · evidence density 40%   │       │  - supporting event IDs               │
│  · severity weight  35%   │       │  - counter-evidence (ruled out why)   │
│  · temporal coherence 20% │       │  - millisecond causal timeline        │
│  · zone alignment   ~3%   │       │  - IEC 62443 normative context        │
│  · memory bonus     ~5%   │       │                                       │
│  Edge confidence =        │       │  Aligned: DARPA XAI · EU AI Act       │
│  geometric mean of nodes  │       │  Art.13 · IEC 62443-3-3 SR 2.6       │
└───────────────┬───────────┘       └───────────────────────────────────────┘
                │  CausalInferenceResult
                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  MitreICSClassifier                                  [mitre_classifier]  │
│                                                                          │
│  Scores event stream against 10 MITRE ATT&CK for ICS techniques.        │
│  Per-technique confidence = Σ(matched indicator weights) / Σ(all weights)│
│  Cyber confidence = active TTP score × 0.75 + passive TTP score × 0.25  │
│  Classification: CYBER (cyber_confidence > 0.45) | RELIABILITY           │
│                                                                          │
│  Techniques: T0836 T0855 T0814 T0816 T0801 T0828 T0813 T0835 T0831 T0840│
└───────────────────────────────┬──────────────────────────────────────────┘
                                │  MitreClassificationResult
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  SafetyEngine                                            [safety_engine] │
│                                                                          │
│  GuardrailEvaluator   — checks each action against YAML guardrail rules  │
│  ProductionImpactModel — action_type × Purdue_zone → impact assessment   │
│  ReversibilityClassifier — REVERSIBLE | RECOVERABLE | IRREVERSIBLE       │
│                                                                          │
│  Decision priority: BLOCK > ESCALATE > HUMAN_GATE > ALLOW               │
│  Sorted output: blocked actions first, auto-executable last              │
│  All violations carry normative IEC 62443 / IEC 61511 clause citation    │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │  SafetyDecision[]
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  HUMAN GOVERNANCE LAYER                                                  │
│                                                                          │
│  Operator approval UI (React) — surfaces causal trace + safety decision  │
│  Approval gates on HUMAN_GATE actions before any execution               │
│  All decisions logged to DecisionMemory for continual learning           │
│  MTTR outcome + operator accuracy feedback stored per pattern            │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
causalagent/
│
├── core/
│   ├── causal_engine.py       # OT causal inference pipeline — 834 lines
│   │                          # EventNormaliser · CausalGraphBuilder
│   │                          # ConfidenceScorer · ExplainabilityEngine
│   │                          # CausalEngine (main entry point)
│   │
│   ├── safety_engine.py       # IEC 62443 guardrail enforcement — 417 lines
│   │                          # GuardrailEvaluator · ProductionImpactModel
│   │                          # ReversibilityClassifier · SafetyEngine
│   │
│   ├── mitre_classifier.py    # MITRE ATT&CK for ICS scoring — 233 lines
│   │                          # MitreICSClassifier · TTPScore
│   │                          # Weighted indicator model, 10 techniques
│   │
│   └── decision_memory.py     # Causal pattern store — 195 lines
│                              # DecisionMemory · CausalPattern · MemoryMatch
│                              # Jaccard tag-set similarity retrieval
│
├── rules/
│   ├── causal/
│   │   ├── reliability.yaml   # 9 reliability failure causal rules
│   │   │                      # switch firmware regression, PLC CPU overload,
│   │   │                      # OPC-UA cert expiry, scan time violation
│   │   │
│   │   └── cyber.yaml         # 5 cyber incident causal rules
│   │                          # workstation compromise → DNP3 spoofing,
│   │                          # OT network enumeration → PLC probe
│   │
│   ├── safety/
│   │   └── guardrails.yaml    # 8 IEC 62443-3-3 guardrail rules
│   │                          # BLOCK · ESCALATE · HUMAN_GATE tiers
│   │
│   └── mitre_ics.yaml         # 10 MITRE ICS technique indicator sets
│                              # Weights sum to 1.0 per technique
│
├── tests/
│   ├── test_causal_engine.py  # 68 tests — normaliser, graph builder,
│   │                          # integration, confidence scorer, XAI trace,
│   │                          # edge cases (WARN-only, nulls, 1k events)
│   │
│   ├── test_safety_engine.py  # 28 tests — guardrail loading, BLOCK/ESCALATE/
│   │                          # HUMAN_GATE/ALLOW decisions, impact matrix,
│   │                          # reversibility, batch evaluation
│   │
│   └── test_decision_memory.py # 13 tests — load, Jaccard retrieval,
│                               # class bonus, top_k, min_similarity
│
├── data/
│   └── decision_memory.json   # 5 seed patterns (2 cyber, 3 reliability)
│                              # MTTR: 6–35 min · confidence: 0.88–0.97
│
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── requirements.txt
└── .gitignore
```

---

## OT Protocol Coverage

| Protocol | Address Format | Purdue Zone | Usage in CausalAgent |
|---|---|---|---|
| **Modbus/TCP** | Register (e.g. `40001`) | L1 | PLC tag polling; exception code detection (0x04) |
| **DNP3** | Object address (e.g. `0x1A4`) | L1 | FCV setpoint monitoring; unsolicited response detection |
| **OPC-UA** | NodeId (e.g. `ns=2;i=1021`) | L2 | SCADA/HMI subscription state; certificate validation |
| **SNMP** | OID (e.g. `1.3.6.1.2.1.31`) | L2 | OT switch interface statistics; packet loss, STP state |
| **Syslog** | RFC 5424 facility/severity | L2 | Network device firmware events; STP recalculation |
| **SIEM/CEF** | Key-value pairs | DMZ | Lateral movement indicators; authentication anomalies |
| **NetFlow v9** | 5-tuple + byte counts | DMZ | C2 beacon detection; exfiltration patterns |
| **WinRM/RDP** | Host:port + event rate | DMZ | Engineering workstation compromise indicators |

---

## MITRE ATT&CK for ICS — Technique Coverage

| Technique | Name | Tactic | Typical OT Signal Pattern |
|---|---|---|---|
| **T0836** | Modify Parameter | Impair Process Control | FCV deviation >30% + DNP3 activity + DMZ host |
| **T0855** | Unauthorized Command Message | Impair Process Control | FCV CRIT + DNP3 + DMZ CRIT + HMI anomaly |
| **T0814** | Denial of Service | Inhibit Response Function | HMI loss + switch packet loss + PLC CRIT |
| **T0816** | Device Restart/Shutdown | Inhibit Response Function | PLC watchdog trip + HMI CRIT + WinRM present |
| **T0801** | Monitor Process State | Collection | Network scan + PLC probe + high Modbus rate |
| **T0828** | Loss of Productivity and Revenue | Impact | Process deviation + PLC CRIT + HMI present |
| **T0813** | Denial of Control | Inhibit Response Function | HMI CRIT + OPC-UA present + DMZ CRIT |
| **T0835** | Manipulate I/O Image | Impair Process Control | FCV deviation >50% + PT deviation + DNP3 |
| **T0831** | Manipulation of Control | Impair Process Control | FCV CRIT + PT CRIT + DMZ host present |
| **T0840** | Network Connection Enumeration | Discovery | NET-SCAN CRIT + PLC probe + high Modbus rate |

Cyber classification threshold: `cyber_confidence > 0.45`. Active manipulation TTPs (T0836, T0855, T0813, T0831, T0835) weighted at 0.75; passive reconnaissance TTPs (T0801, T0840) weighted at 0.25 in the aggregate cyber confidence calculation.

---

## IEC 62443 Guardrail Rule Matrix

| Guardrail Rule | Condition | Decision | IEC Clause |
|---|---|---|---|
| Block autonomous control during cyber | `active_cyber` + control action | `BLOCK` | IEC 62443-3-3 SR 2.6 |
| Block ESD without verified root cause | `unverified_cause` + emergency_shutdown | `BLOCK` | IEC 62443-3-3 SR 3.6 |
| Block L0 commands under low confidence | `uncertain_cause` (<75%) + L0 target | `BLOCK` | IEC 62443-3-3 SR 2.6 + IEC 61511 SIL-2 |
| Escalate SIL-zone modifications | `sil_zone` (L0/L1) + config change | `ESCALATE` | IEC 61511 Clause 11 MOC |
| Human gate: network isolation | `production_active` + network_isolate | `HUMAN_GATE` | IEC 62443-3-3 SR 5.1 |
| Human gate: setpoint revert | `always` + setpoint_revert (L1/L2) | `HUMAN_GATE` | IEC 62443-3-3 SR 2.6 |
| Human gate: firmware rollback | `production_active` + firmware_rollback | `HUMAN_GATE` | IEC 62443-2-3 patch mgmt |
| Human gate: forensic capture | `always` + forensic_capture | `HUMAN_GATE` | IEC 62443-2-1 4.3.3 |

---

## Confidence Scoring Model

The `ConfidenceScorer` computes a weighted posterior for each `CausalNode`:

```
confidence = (evidence_density × 0.40)
           + (severity_weight   × 0.35)
           + (temporal_coherence× 0.20)
           + (zone_alignment    × ~0.03)
           + (memory_bonus      × ~0.05)
```

**evidence_density** — `|matched_tags ∩ required_tags| / |required_tags|`

**severity_weight** — mean of per-event weights: `CRIT=1.0, WARN=0.65, INFO=0.35`

**temporal_coherence** — 1.0 if supporting event timestamps are monotonically ordered (consistent with causal propagation direction); 0.75 otherwise

**zone_alignment** — bonus (+0.03) when ROOT_CAUSE node is in DMZ or L4, consistent with cyber-initiated incidents propagating down the Purdue stack

**memory_bonus** — bonus (+0.05) when a matching pattern exists in `DecisionMemory` for the same trigger tags and root cause

Edge confidence is the geometric mean of its two endpoint node confidences: `conf_edge = √(conf_from × conf_to)`

Overall incident confidence is a weighted mean across all nodes: ROOT_CAUSE nodes weighted at 0.55, EFFECT at 0.30, SYMPTOM at 0.15.

---

## Decision Memory — Retrieval Model

Pattern retrieval uses a composite similarity score:

```
similarity = (tag_jaccard × 0.60)
           + (protocol_overlap × 0.25)
           + (class_match_bonus × 0.15)

tag_jaccard = |query_tags ∩ pattern_tags| / |query_tags ∪ pattern_tags|
protocol_overlap = |query_protocols ∩ pattern_protocols| / |query_protocols ∪ pattern_protocols|
class_match_bonus = 0.15 if incident_class matches, else 0.0
```

Default `min_similarity = 0.30`. Default `top_k = 3`. All retrieval results include the similarity score, matched tags, and a natural-language explanation for the match — no opaque vector distances.

---

## Causal Rule Schema Reference

Rules in `rules/causal/*.yaml` define the causal graph topology. The engine is schema-driven: adding a new failure pattern requires only a YAML entry and corresponding tests — no Python changes.

```yaml
rule_id:
  name:                     # Human-readable label shown in XAI trace
  trigger_tags:             # OT tag names that must appear in the event stream
    - TAG-NAME
  trigger_conditions:       # Optional value / severity constraints (AND-logic)
    - tag: TAG-NAME
      operator: ">="        # Supported: >, >=, <, <=, ==, !=
      value: 5.0
      unit: "%loss"         # Documentation only — not evaluated
    - tag: TAG-NAME
      severity: CRIT        # INFO | WARN | CRIT
  causes:                   # Downstream rule_ids this node propagates to
    - downstream_rule_id
  node_type: ROOT_CAUSE     # ROOT_CAUSE | EFFECT | SYMPTOM
  zone: L2                  # L0 | L1 | L2 | L3 | L4 | DMZ (Purdue Model)
  mitre_ttp: T0836          # MITRE ATT&CK for ICS technique ID, or null
  iec_62443_sl: SL-3        # IEC 62443 security level at this node, or null
  explanation_template: >   # Natural language — appears in XAI reasoning trace
    Free-text explanation of what this node represents and why it fired.
```

**Important design note on trigger_conditions:** Value threshold conditions and severity conditions are independent dimensions. A value breach at `WARN` severity is a valid causal signal; the `ConfidenceScorer` handles severity weighting separately. Do not AND a severity filter into trigger_conditions unless the rule genuinely requires a severity gate (which is rare). This was a defect found and corrected during QA — see CHANGELOG.

---

## Quickstart

```bash
git clone https://github.com/dakhasuresh/causalagent.git
cd causalagent
pip install -r requirements.txt
pytest tests/ -v
```

Expected output: **93 passed** in under 1 second.

### Running inference

```python
from pathlib import Path
from core.causal_engine import CausalEngine
from core.safety_engine import SafetyEngine, ActionProposal
from core.decision_memory import DecisionMemory

# Load engines
engine = CausalEngine(rules_dir=Path("rules/causal"))
engine.load()

safety = SafetyEngine(Path("rules/safety/guardrails.yaml"))
safety.load()

memory = DecisionMemory(Path("data/decision_memory.json"))
memory.load()

# Run causal inference
result = engine.infer(
    incident_id="INC-2024-0891",
    raw_signals=[
        {"event_id":"E1","timestamp":1700000000.0,"tag":"EW-04",
         "protocol":"WinRM","raw_address":"10.0.12.44","value":18,
         "unit":"events/s","severity":"CRIT","message":"WinRM lateral move"},
        {"event_id":"E2","timestamp":1700000000.88,"tag":"FCV-R2",
         "protocol":"DNP3","raw_address":"0x1A4","value":12.1,
         "unit":"%","severity":"CRIT","message":"FCV deviation from setpoint"},
    ]
)

print(f"Root cause:     {result.root_cause.label}")
print(f"Classification: {result.classification}")
print(f"Confidence:     {result.overall_confidence:.1%}")
print(f"Inference time: {result.inference_ms}ms")
print()
for step in result.explainability.reasoning_steps:
    print(f"  → {step}")

# Check decision memory
matches = memory.retrieve(
    event_tags=["EW-04","FCV-R2"],
    event_protocols=["WinRM","DNP3"],
    incident_class="CYBER"
)
if matches:
    print(f"\nMemory match: {matches[0].pattern.pattern_id} "
          f"(similarity={matches[0].similarity_score:.2f}, "
          f"historical MTTR={matches[0].pattern.mttr_minutes:.0f}min)")

# Evaluate action safety
proposals = [
    ActionProposal("A1","Network isolate EW-04","EW-04","DMZ","network_isolate","IEC 62443-3-3 SR 5.1"),
    ActionProposal("A2","Revert FCV-R2 setpoint","FCV-R2","L1","setpoint_revert","IEC 62443-3-3 SR 2.6"),
]
decisions = safety.evaluate_actions(proposals, {
    "classification": result.classification,
    "overall_confidence": result.overall_confidence,
    "root_cause_verified": result.root_cause is not None,
    "production_active": True,
})
for d in decisions:
    print(f"  [{d.decision.value:10s}] {d.action_id} — {d.explanation[:80]}")
```

---

## Standards and References

| Standard | Version | Applicability in CausalAgent |
|---|---|---|
| **IEC 62443-3-3** | 2013 | System Security Requirements (SR) — guardrail rule citations throughout SafetyEngine |
| **IEC 62443-2-1** | 2010 | IACS Security Management System — incident response procedure (4.3.3) |
| **IEC 62443-2-3** | 2015 | Patch Management in the IACS Environment — firmware rollback guardrail |
| **IEC 61511-1** | 2016 | Functional Safety / SIL — SIL-zone escalation rule; ESD block conditions |
| **ISA-95 / IEC 62264** | Part 1 | Equipment hierarchy model — Purdue zone (L0–L4, DMZ) attribution |
| **MITRE ATT&CK for ICS** | v14 | ICS attack technique taxonomy — 10 techniques scored by MitreICSClassifier |
| **NIST SP 800-82** | Rev 3 | Guide to OT Security — incident response alignment |
| **EU AI Act** | Art. 13 | Transparency requirement — XAI trace output design |
| **DARPA XAI** | 2017 | Explainability principles — ExplainabilityEngine design rationale |

---

## Test Coverage Summary

```
tests/test_causal_engine.py      68 tests
  TestEventNormaliser              5  — protocol zone mapping, field normalisation
  TestCausalGraphBuilder          14  — YAML loading, rule evaluation, graph construction
  TestCausalEngineIntegration     15  — end-to-end inference, classification accuracy
  TestConfidenceScorer             3  — monotonicity, bounds, CRIT > WARN
  TestExplainabilityTrace          5  — completeness, IEC context, counter evidence
  TestEdgeCases                   10  — WARN-only events, nulls, 1000 events, JSON contract

tests/test_safety_engine.py      28 tests
  TestGuardrailLoading             4  — YAML load, rule presence
  TestBlockDecisions               4  — cyber block, ESD block, IEC clause, auto_executable
  TestHumanGateDecisions           5  — network isolate, firmware, forensic, prompt
  TestAllowDecisions               2  — alarm acknowledge, auto_executable
  TestProductionImpact             5  — DMZ/L1/L0 impact matrix, unknown default
  TestReversibility                4  — reversible/recoverable/irreversible classification
  TestBatchEvaluation              4  — multi-action, sort order, explanations, unloaded

tests/test_decision_memory.py    13 tests
  TestDecisionMemoryLoad           4  — JSON load, field validation, summary
  TestDecisionMemoryRetrieval      7  — Jaccard accuracy, class bonus, top_k, min_sim
  TestDecisionMemoryStore          2  — avg MTTR, avg confidence bounds

Total: 93 tests · 93 passing · avg runtime 0.85s
```

---

## Extending CausalAgent

### Add a new failure pattern (causal rule)

```bash
# 1. Add rule to rules/causal/reliability.yaml or rules/causal/cyber.yaml
# 2. Write two tests: one fires, one does not fire on unrelated signals
# 3. Run: pytest tests/test_causal_engine.py -v
# 4. All 93+ existing tests must still pass
```

### Add a new safety guardrail

```bash
# 1. Add rule to rules/safety/guardrails.yaml
# 2. Use a supported condition key (see SafetyEngine._rule_fires)
# 3. Include an IEC normative clause in iec_clause field
# 4. Write a unit test asserting the expected ActionDecision
# 5. Run: pytest tests/test_safety_engine.py -v
```

### Add a new MITRE ICS technique

```bash
# 1. Add entry to rules/mitre_ics.yaml
# 2. Verify indicator weights sum to exactly 1.0
# 3. Use a supported condition: present | value_deviation_pct |
#    severity_crit | high_event_rate | cross_zone_protocol
```

Full schema reference and worked examples: see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Author

Suresh Dakha
[github.com/dakhasuresh](https://github.com/dakhasuresh)
