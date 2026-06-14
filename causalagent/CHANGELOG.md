# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [0.1.0] — 2024-06-14

### Added

**`core/causal_engine.py`**
- `EventNormaliser` — protocol-agnostic OT signal normalisation across Modbus/TCP, DNP3, OPC-UA, SNMP, Syslog, SIEM, NetFlow, WinRM. Maps each signal to canonical `OTEvent` with Purdue zone attribution (L0–L4, DMZ).
- `CausalGraphBuilder` — YAML rule loader with directed causal graph construction. Evaluates `trigger_conditions` (value thresholds, operator comparisons, severity filters) against the normalised event stream. Infers inter-node temporal lag from event timestamps.
- `ConfidenceScorer` — Bayesian-weighted confidence per causal node: evidence density (40%), severity weight (35%), temporal coherence (20%), zone alignment bonus (~3%), decision memory pattern bonus (~5%). Edge confidence computed as geometric mean of endpoint node confidences.
- `ExplainabilityEngine` — generates `ExplainabilityTrace` with ordered reasoning steps, supporting event IDs, counter-evidence (ruled-out alternative root causes), millisecond-precision causal timeline, and IEC 62443 normative context. Aligned with EU AI Act Art. 13 and DARPA XAI principles.
- `CausalEngine` — main entry point. Stateless per-inference call. Outputs `CausalInferenceResult` with full graph, classified nodes (ROOT_CAUSE / EFFECT / SYMPTOM), overall confidence, and JSON serialisation.

**`core/safety_engine.py`**
- `GuardrailEvaluator` — evaluates `ActionProposal` objects against YAML-defined guardrail rules. Supports conditions: `active_cyber`, `uncertain_cause`, `sil_zone`, `irreversible`, `unverified_cause`, `production_active`, `always`.
- `ProductionImpactModel` — action_type × Purdue zone matrix returning `ProductionImpact` enum (NONE / MINOR / MODERATE / MAJOR / CRITICAL).
- `ReversibilityClassifier` — classifies each action as REVERSIBLE, RECOVERABLE, or IRREVERSIBLE. Irreversible actions automatically elevate to HUMAN_GATE minimum.
- `SafetyEngine` — main entry point. Decision priority: BLOCK > ESCALATE > HUMAN_GATE > ALLOW. All violations carry normative IEC 62443-3-3 SR and IEC 61511 clause citations.

**`core/mitre_classifier.py`**
- `MitreICSClassifier` — scores 10 MITRE ATT&CK for ICS techniques against a normalised event stream using a weighted indicator model. Per-technique confidence = Σ(matched weights) / Σ(all weights). Cyber confidence aggregated with active TTP weight 0.75, passive TTP weight 0.25. CYBER classification threshold: `cyber_confidence > 0.45`.
- Techniques covered: T0836 T0855 T0814 T0816 T0801 T0828 T0813 T0835 T0831 T0840.

**`core/decision_memory.py`**
- `DecisionMemory` — persistent causal pattern store. Retrieval via composite Jaccard similarity: tag-set Jaccard (60%) + protocol overlap (25%) + class match bonus (15%). Fully deterministic — no vector embeddings. Supports operator accuracy feedback and reuse count tracking. JSON persistence; PostgreSQL-ready schema.

**`rules/causal/reliability.yaml`** — 9 rules covering:
- OT switch firmware regression → Modbus/TCP timeout cascade → OPC-UA subscription loss
- PLC CPU overload → scan time violation → watchdog trip
- OPC-UA certificate expiry → HMI session drop

**`rules/causal/cyber.yaml`** — 5 rules covering:
- Engineering workstation compromise → DNP3 setpoint tampering → HMI session kill → pressure excursion (MITRE T0836, T0855, T0814)
- OT network enumeration → PLC connection probe (MITRE T0840, T0801)

**`rules/safety/guardrails.yaml`** — 8 guardrail rules: 3 BLOCK, 1 ESCALATE, 4 HUMAN_GATE.

**`rules/mitre_ics.yaml`** — 10 technique definitions. All indicator weight sums validated at exactly 1.0.

**`data/decision_memory.json`** — 5 seed patterns (2 CYBER, 3 RELIABILITY). MTTR range 6–35 min. Confidence range 0.88–0.97.

**`tests/`** — 93 unit tests across 3 modules. 93 passing. Avg runtime 0.85s.

---

### Fixed (identified during QA assessment)

**`rules/causal/reliability.yaml` — `switch_firmware_bug` trigger_conditions**

- **Defect:** Rule was gated by two AND-conditions: `value >= 5.0` (packet loss threshold) AND `severity: CRIT`. WARN-severity packet loss events at threshold correctly met the value condition but did not fire the rule because the AND-logic required both conditions simultaneously.
- **Impact:** In real OT environments, packet loss is frequently logged at WARN before monitoring escalates to CRIT. The engine was producing `UNKNOWN` classification and no root cause for valid WARN-level switch failure signals — incorrect behaviour.
- **Root cause:** Value threshold and severity are independent signal dimensions. Severity weighting already exists in `ConfidenceScorer.SEVERITY_WEIGHT` (CRIT=1.0, WARN=0.65, INFO=0.35) and appropriately depresses confidence for lower-severity signals without blocking rule firing.
- **Fix:** Removed `severity: CRIT` from `trigger_conditions` for `switch_firmware_bug`. Value threshold alone is the correct causal gate.
- **Regression coverage:** 10 new edge-case tests added to `tests/test_causal_engine.py` (`TestEdgeCases`) covering WARN-only signals, duplicate event IDs, negative sensor values, None fields, 10k-char messages, 1000-event stress load, XAI counter-evidence structure, temporal sequence ordering, and JSON output contract.
