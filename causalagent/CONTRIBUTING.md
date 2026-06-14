# Contributing to CausalAgent

CausalAgent is rule-driven by design. Adding new OT failure patterns,
adversarial scenarios, safety guardrails, or MITRE ICS technique coverage
requires YAML changes and corresponding unit tests — not Python changes to
the engine core.

---

## Repository conventions

- **No hardcoded logic in Python.** All causal knowledge lives in `rules/`.
- **Every new rule needs two tests** — one asserting it fires, one asserting it does not fire on unrelated signals.
- **Type hints and docstrings required** on all public classes and methods.
- **All tests must pass before any commit:** `pytest tests/ -v` → 93+ passing.
- **Normative IEC references required** on all safety guardrail rules.

---

## Adding a causal rule

### 1. Choose the right file

| File | Use for |
|---|---|
| `rules/causal/reliability.yaml` | Hardware degradation, firmware regression, network failures, certificate expiry, PLC faults |
| `rules/causal/cyber.yaml` | Adversarial OT manipulation patterns with MITRE TTP attribution |

### 2. Write the rule

```yaml
your_rule_id:
  name: "Human-readable label — shown in XAI reasoning trace"
  trigger_tags:
    - OT-TAG-NAME        # Canonical tag from OT asset inventory
  trigger_conditions:    # AND-logic within this list. Omit if tag presence alone suffices.
    - tag: OT-TAG-NAME
      operator: ">="     # Supported: >, >=, <, <=, ==, !=
      value: 5.0
      unit: "%loss"      # Documentation only — not evaluated by engine
  causes:
    - downstream_rule_id # Must exist in this or another causal YAML file
  node_type: ROOT_CAUSE  # ROOT_CAUSE | EFFECT | SYMPTOM
  zone: L2               # L0 (field) | L1 (control) | L2 (supervisory) |
                         # L3 (operations) | L4 (enterprise) | DMZ
  mitre_ttp: null        # T0XXX for cyber rules; null for reliability rules
  iec_62443_sl: null     # SL-1 through SL-4 if security level is breached; else null
  explanation_template: >
    Natural-language explanation of what this node represents and why it fired.
    Referenced directly in the XAI ExplainabilityTrace output visible to operators.
    Be specific: mention the protocol, the tag, the mechanism. Avoid generic text.
```

### 3. Critical design note on trigger_conditions

Value threshold conditions and severity filter conditions **must not be AND-ed together**
unless the rule genuinely requires the signal to be at a specific severity to be causally
valid. In practice, this is almost never the case.

**Correct pattern:**
```yaml
trigger_conditions:
  - tag: SW-03
    operator: ">="
    value: 5.0
    unit: "%loss"
```

**Incorrect pattern (blocks WARN-level events from firing the rule):**
```yaml
trigger_conditions:
  - tag: SW-03
    operator: ">="
    value: 5.0
  - tag: SW-03
    severity: CRIT   # ← Do not do this. Severity is handled by ConfidenceScorer.
```

Severity weighting is applied by `ConfidenceScorer.SEVERITY_WEIGHT` (CRIT=1.0, WARN=0.65,
INFO=0.35) at scoring time. It correctly depresses confidence for lower-severity signals
without blocking rule firing. Gating on severity in trigger_conditions was a defect
identified in QA — see CHANGELOG [0.1.0].

### 4. Write the tests

In `tests/test_causal_engine.py`, add to the appropriate class or create a new one:

```python
def test_your_rule_fires_on_matching_signals(self, engine):
    signals = [
        {"event_id":"T1","timestamp":time.time(),"tag":"YOUR-TAG",
         "protocol":"Modbus/TCP","raw_address":"40001","value":92.0,
         "unit":"%","severity":"CRIT","message":"test"},
    ]
    result = engine.infer("TEST-001", signals)
    assert result.root_cause is not None
    assert result.root_cause.node_id == "your_rule_id"

def test_your_rule_does_not_fire_on_unrelated_signals(self, engine):
    signals = [
        {"event_id":"T2","timestamp":time.time(),"tag":"UNRELATED-TAG",
         "protocol":"OPC-UA","raw_address":"ns=2;i=9999","value":1.0,
         "unit":"","severity":"INFO","message":"unrelated"},
    ]
    result = engine.infer("TEST-002", signals)
    # Your rule must not fire
    node_ids = [n.node_id for n in result.nodes]
    assert "your_rule_id" not in node_ids
```

---

## Adding a safety guardrail

### 1. Supported condition keys

| Condition key | Fires when |
|---|---|
| `active_cyber` | `ctx["classification"] == "CYBER"` |
| `uncertain_cause` | `ctx["overall_confidence"] < 0.75` |
| `sil_zone` | `action.target_zone in ["L0", "L1"]` |
| `irreversible` | `ctx["irreversible_action"] == True` (set automatically by ReversibilityClassifier) |
| `unverified_cause` | `ctx["root_cause_verified"] == False` |
| `production_active` | `ctx["production_active"] == True` |
| `always` | Always fires when rule applies to this action_type and zone |

### 2. Rule schema

```yaml
gr_your_rule_id:
  name: "Descriptive name"
  applies_to_action_types:
    - setpoint_revert          # Supported types: network_isolate, setpoint_revert,
    - config_change            # firmware_rollback, alarm_acknowledge, session_restore,
                               # threshold_adjust, emergency_shutdown, forensic_capture,
                               # config_change
  applies_to_zones:            # Empty list = applies to all zones
    - L1
    - L0
  condition: active_cyber      # One of the condition keys above
  decision: BLOCK              # BLOCK | ESCALATE | HUMAN_GATE
  iec_clause: "IEC 62443-3-3 SR 2.6 — Use Control"   # Normative reference required
  reason_template: >
    Explanation shown to operator. Supports {action_type}, {target_tag},
    {zone}, {classification}, {confidence} substitution variables.
```

### 3. Decision priority

`BLOCK > ESCALATE > HUMAN_GATE`

If multiple rules fire on the same action, the highest-priority decision wins.
`ALLOW` is the default when no guardrail rules fire and impact/reversibility
criteria are met.

---

## Adding a MITRE ICS technique

```yaml
T0XXX:
  name: "Technique Name"
  tactic: "Tactic Name"        # From MITRE ICS matrix
  indicators:
    - tag: OT-TAG-NAME
      condition: present        # present | value_deviation_pct | severity_crit |
      weight: 0.40              # high_event_rate | cross_zone_protocol
    - protocol: DNP3
      condition: present
      weight: 0.35
    - tag: OTHER-TAG
      condition: severity_crit
      weight: 0.25
      # Weights must sum to exactly 1.0
```

**Condition reference:**

| Condition | Required fields | Fires when |
|---|---|---|
| `present` | `tag` or `protocol` | Tag or protocol appears in event stream |
| `value_deviation_pct` | `tag`, `threshold` | `abs((value - nominal_mid) / nominal_mid) × 100 >= threshold` |
| `severity_crit` | `tag` | Tag has at least one CRIT-severity event |
| `high_event_rate` | `tag`, `threshold` | Event count for tag >= threshold |
| `cross_zone_protocol` | `protocol`, `unexpected_zones` | Protocol observed in listed zones |

---

## Running tests

```bash
pip install -r requirements.txt
pytest tests/ -v                          # all 93+ tests
pytest tests/test_causal_engine.py -v    # causal engine only
pytest tests/test_safety_engine.py -v    # safety engine only
pytest tests/test_decision_memory.py -v  # decision memory only
pytest tests/ -v -k "TestEdgeCases"      # edge cases only
```
