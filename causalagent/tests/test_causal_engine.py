"""
Tests :: CausalEngine
=====================
Unit tests for the OT causal inference pipeline.

Tests validate:
  - Event normalisation across OT protocols
  - Rule firing logic (trigger_tags + trigger_conditions)
  - Causal graph construction from YAML rules
  - Root cause isolation from multi-signal event streams
  - Confidence scoring model behaviour
  - Classification: CYBER vs RELIABILITY
  - Explainability trace generation
  - Edge: empty event streams, no rules fire, single event

Run: pytest tests/test_causal_engine.py -v
"""

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.causal_engine import (
    CausalEngine,
    CausalGraphBuilder,
    ConfidenceScorer,
    EventNormaliser,
    ExplainabilityEngine,
    NodeType,
    OTEvent,
    PurdueZone,
)

RULES_DIR = Path(__file__).parent.parent / "rules" / "causal"


# ─────────────────────────────────────────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def engine() -> CausalEngine:
    e = CausalEngine(rules_dir=RULES_DIR)
    e.load()
    return e


@pytest.fixture
def reliability_signals() -> list[dict]:
    """Modbus/SNMP signals characteristic of switch firmware regression."""
    base_ts = time.time()
    return [
        {
            "event_id":    "EVT-0001",
            "timestamp":   base_ts,
            "tag":         "SW-03",
            "protocol":    "SNMP",
            "raw_address": "1.3.6.1.2.1.31",
            "value":       34.2,
            "unit":        "%loss",
            "severity":    "CRIT",
            "message":     "SW-03 packet loss 34.2% — STP recalculation loop",
            "metadata":    {},
        },
        {
            "event_id":    "EVT-0002",
            "timestamp":   base_ts + 0.8,
            "tag":         "PLC-L3-A",
            "protocol":    "Modbus/TCP",
            "raw_address": "40001",
            "value":       0,
            "unit":        "",
            "severity":    "CRIT",
            "message":     "Modbus exception code 0x04 — server device failure",
            "metadata":    {},
        },
        {
            "event_id":    "EVT-0003",
            "timestamp":   base_ts + 1.1,
            "tag":         "HMI-01",
            "protocol":    "OPC-UA",
            "raw_address": "ns=2;i=2001",
            "value":       0,
            "unit":        "state",
            "severity":    "WARN",
            "message":     "HMI-01 OPC-UA subscription timeout (5000ms)",
            "metadata":    {},
        },
    ]


@pytest.fixture
def cyber_signals() -> list[dict]:
    """Multi-protocol signals characteristic of OT cyber attack."""
    base_ts = time.time()
    return [
        {
            "event_id":    "EVT-0010",
            "timestamp":   base_ts,
            "tag":         "EW-04",
            "protocol":    "WinRM",
            "raw_address": "10.0.12.44",
            "value":       18,
            "unit":        "events/s",
            "severity":    "CRIT",
            "message":     "WinRM lateral move attempt EW-04 → PLC-R2",
            "metadata":    {},
        },
        {
            "event_id":    "EVT-0011",
            "timestamp":   base_ts + 0.88,
            "tag":         "FCV-R2",
            "protocol":    "DNP3",
            "raw_address": "0x1A4",
            "value":       12.1,
            "unit":        "%",
            "severity":    "CRIT",
            "message":     "FCV-R2 position = 12.1% [setpoint 50.0%]",
            "metadata":    {},
        },
        {
            "event_id":    "EVT-0012",
            "timestamp":   base_ts + 1.22,
            "tag":         "PT-R2-01",
            "protocol":    "OPC-UA",
            "raw_address": "ns=2;i=1021",
            "value":       146.8,
            "unit":        "bar",
            "severity":    "WARN",
            "message":     "PT-R2-01 = 146.8 bar [HIGH — limit 150]",
            "metadata":    {},
        },
        {
            "event_id":    "EVT-0013",
            "timestamp":   base_ts + 1.89,
            "tag":         "HMI-01",
            "protocol":    "OPC-UA",
            "raw_address": "ns=2;i=2001",
            "value":       0,
            "unit":        "state",
            "severity":    "WARN",
            "message":     "HMI-01 operator session terminated unexpectedly",
            "metadata":    {},
        },
    ]


# ─────────────────────────────────────────────────────────────────────────────
# EVENT NORMALISER TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestEventNormaliser:

    def test_normalises_modbus_event(self, reliability_signals):
        normaliser = EventNormaliser()
        events = normaliser.normalise([reliability_signals[1]])
        assert len(events) == 1
        e = events[0]
        assert e.tag      == "PLC-L3-A"
        assert e.protocol == "Modbus/TCP"
        assert e.zone     == PurdueZone.L1
        assert e.severity == "CRIT"

    def test_normalises_opcua_event(self, reliability_signals):
        normaliser = EventNormaliser()
        events = normaliser.normalise([reliability_signals[2]])
        e = events[0]
        assert e.protocol == "OPC-UA"
        assert e.zone     == PurdueZone.L2

    def test_normalises_winrm_to_dmz_zone(self, cyber_signals):
        normaliser = EventNormaliser()
        events = normaliser.normalise([cyber_signals[0]])
        assert events[0].zone == PurdueZone.DMZ

    def test_normalises_full_batch(self, reliability_signals):
        normaliser = EventNormaliser()
        events = normaliser.normalise(reliability_signals)
        assert len(events) == 3
        assert all(hasattr(e, "event_id") for e in events)

    def test_handles_missing_fields_gracefully(self):
        normaliser = EventNormaliser()
        minimal = [{"tag": "TEST-TAG", "value": 1.0}]
        events = normaliser.normalise(minimal)
        assert len(events) == 1
        assert events[0].tag == "TEST-TAG"
        assert events[0].severity == "INFO"


# ─────────────────────────────────────────────────────────────────────────────
# CAUSAL GRAPH BUILDER TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestCausalGraphBuilder:

    @pytest.fixture(autouse=True)
    def builder(self):
        self.builder = CausalGraphBuilder(RULES_DIR)
        self.builder.load_rules()

    def test_loads_yaml_rules(self):
        assert len(self.builder.rules) > 0

    def test_contains_switch_firmware_rule(self):
        assert "switch_firmware_bug" in self.builder.rules

    def test_contains_ew_compromise_rule(self):
        assert "ew_workstation_compromise" in self.builder.rules

    def test_switch_firmware_rule_has_correct_node_type(self):
        rule = self.builder.rules["switch_firmware_bug"]
        assert rule["node_type"] == "ROOT_CAUSE"

    def test_modbus_timeout_rule_is_effect(self):
        rule = self.builder.rules["modbus_tcp_timeout"]
        assert rule["node_type"] == "EFFECT"

    def test_opcua_subscription_loss_is_symptom(self):
        rule = self.builder.rules["opcua_subscription_loss"]
        assert rule["node_type"] == "SYMPTOM"

    def test_cyber_root_cause_has_mitre_ttp(self):
        rule = self.builder.rules["ew_workstation_compromise"]
        assert rule["mitre_ttp"] is not None
        assert rule["mitre_ttp"].startswith("T")

    def test_reliability_root_cause_has_no_mitre_ttp(self):
        rule = self.builder.rules["switch_firmware_bug"]
        assert rule["mitre_ttp"] is None

    def test_sw03_rule_fires_on_crit_packet_loss(self, reliability_signals):
        normaliser = EventNormaliser()
        events = normaliser.normalise(reliability_signals)
        fired = self.builder.evaluate_rules(events)
        assert fired.get("switch_firmware_bug") is True

    def test_ew04_rule_fires_on_cyber_signals(self, cyber_signals):
        normaliser = EventNormaliser()
        events = normaliser.normalise(cyber_signals)
        fired = self.builder.evaluate_rules(events)
        assert fired.get("ew_workstation_compromise") is True

    def test_cyber_rule_does_not_fire_on_reliability_signals(self, reliability_signals):
        normaliser = EventNormaliser()
        events = normaliser.normalise(reliability_signals)
        fired = self.builder.evaluate_rules(events)
        assert not fired.get("ew_workstation_compromise", False)

    def test_reliability_rule_does_not_fire_on_cyber_signals(self, cyber_signals):
        normaliser = EventNormaliser()
        events = normaliser.normalise(cyber_signals)
        fired = self.builder.evaluate_rules(events)
        assert not fired.get("switch_firmware_bug", False)

    def test_builds_causal_graph_nodes(self, reliability_signals):
        normaliser = EventNormaliser()
        events = normaliser.normalise(reliability_signals)
        fired  = self.builder.evaluate_rules(events)
        nodes, edges = self.builder.build_graph(fired, events)
        assert len(nodes) >= 1
        node_ids = [n.node_id for n in nodes]
        assert "switch_firmware_bug" in node_ids

    def test_builds_causal_edges(self, reliability_signals):
        normaliser = EventNormaliser()
        events = normaliser.normalise(reliability_signals)
        fired  = self.builder.evaluate_rules(events)
        nodes, edges = self.builder.build_graph(fired, events)
        # switch_firmware_bug → modbus_tcp_timeout should produce an edge
        edge_pairs = [(e.from_node, e.to_node) for e in edges]
        assert ("switch_firmware_bug", "modbus_tcp_timeout") in edge_pairs


# ─────────────────────────────────────────────────────────────────────────────
# CAUSAL ENGINE INTEGRATION TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestCausalEngineIntegration:

    def test_reliability_incident_root_cause_is_switch_firmware(
        self, engine, reliability_signals
    ):
        result = engine.infer("INC-TEST-001", reliability_signals)
        assert result.root_cause is not None
        assert result.root_cause.node_id == "switch_firmware_bug"

    def test_cyber_incident_root_cause_is_workstation_compromise(
        self, engine, cyber_signals
    ):
        result = engine.infer("INC-TEST-002", cyber_signals)
        assert result.root_cause is not None
        assert result.root_cause.node_id == "ew_workstation_compromise"

    def test_reliability_classified_correctly(self, engine, reliability_signals):
        result = engine.infer("INC-TEST-003", reliability_signals)
        assert result.classification == "RELIABILITY"

    def test_cyber_classified_correctly(self, engine, cyber_signals):
        result = engine.infer("INC-TEST-004", cyber_signals)
        assert result.classification == "CYBER"

    def test_root_cause_has_higher_confidence_than_symptoms(
        self, engine, reliability_signals
    ):
        result = engine.infer("INC-TEST-005", reliability_signals)
        if result.root_cause and result.symptoms:
            assert result.root_cause.confidence >= min(
                s.confidence for s in result.symptoms
            )

    def test_cyber_root_cause_has_mitre_ttp(self, engine, cyber_signals):
        result = engine.infer("INC-TEST-006", cyber_signals)
        assert result.root_cause is not None
        assert result.root_cause.mitre_ttp is not None

    def test_reliability_root_cause_has_no_mitre_ttp(self, engine, reliability_signals):
        result = engine.infer("INC-TEST-007", reliability_signals)
        assert result.root_cause is not None
        assert result.root_cause.mitre_ttp is None

    def test_empty_signals_returns_unknown_classification(self, engine):
        result = engine.infer("INC-TEST-008", [])
        assert result.classification == "UNKNOWN"
        assert result.root_cause is None

    def test_single_signal_does_not_raise(self, engine, reliability_signals):
        result = engine.infer("INC-TEST-009", reliability_signals[:1])
        assert result is not None

    def test_result_contains_explainability_trace(self, engine, reliability_signals):
        result = engine.infer("INC-TEST-010", reliability_signals)
        assert result.explainability is not None
        assert len(result.explainability.reasoning_steps) > 0

    def test_inference_completes_in_under_500ms(self, engine, reliability_signals):
        result = engine.infer("INC-TEST-011", reliability_signals)
        assert result.inference_ms < 500

    def test_serialises_to_json_without_error(self, engine, reliability_signals):
        result = engine.infer("INC-TEST-012", reliability_signals)
        json_str = engine.to_json(result)
        assert len(json_str) > 0
        import json
        parsed = json.loads(json_str)
        assert parsed["incident_id"] == "INC-TEST-012"

    def test_overall_confidence_is_between_0_and_1(self, engine, reliability_signals):
        result = engine.infer("INC-TEST-013", reliability_signals)
        assert 0.0 <= result.overall_confidence <= 1.0

    def test_effects_are_not_root_causes(self, engine, reliability_signals):
        result = engine.infer("INC-TEST-014", reliability_signals)
        effect_ids = {n.node_id for n in result.effects}
        assert result.root_cause is None or result.root_cause.node_id not in effect_ids

    def test_symptoms_are_not_root_causes(self, engine, reliability_signals):
        result = engine.infer("INC-TEST-015", reliability_signals)
        symptom_ids = {n.node_id for n in result.symptoms}
        assert result.root_cause is None or result.root_cause.node_id not in symptom_ids


# ─────────────────────────────────────────────────────────────────────────────
# CONFIDENCE SCORER TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestConfidenceScorer:

    def test_crit_events_score_higher_than_warn(self):
        scorer = ConfidenceScorer()
        normaliser = EventNormaliser()

        crit_sig = [{"tag": "SW-03", "protocol": "SNMP", "value": 34.2, "severity": "CRIT", "event_id": "E1", "timestamp": time.time()}]
        warn_sig = [{"tag": "SW-03", "protocol": "SNMP", "value": 34.2, "severity": "WARN", "event_id": "E2", "timestamp": time.time()}]

        crit_events = normaliser.normalise(crit_sig)
        warn_events = normaliser.normalise(warn_sig)

        builder = CausalGraphBuilder(RULES_DIR)
        builder.load_rules()

        from core.causal_engine import CausalNode
        node = CausalNode(
            node_id="switch_firmware_bug", label="Test", node_type=NodeType.ROOT_CAUSE,
            zone=PurdueZone.L2, confidence=0.0, mitre_ttp=None, iec_62443_sl=None,
            evidence=["E1"], explanation=""
        )
        rule = builder.rules.get("switch_firmware_bug", {})

        crit_score = scorer._score_node(node, crit_events, rule, None)
        warn_score = scorer._score_node(node, warn_events, rule, None)
        assert crit_score > warn_score

    def test_confidence_is_never_above_1(self, engine, reliability_signals):
        result = engine.infer("INC-CONF-001", reliability_signals)
        for node in result.nodes:
            assert node.confidence <= 1.0

    def test_confidence_is_never_negative(self, engine, cyber_signals):
        result = engine.infer("INC-CONF-002", cyber_signals)
        for node in result.nodes:
            assert node.confidence >= 0.0


# ─────────────────────────────────────────────────────────────────────────────
# EXPLAINABILITY TRACE TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestExplainabilityTrace:

    def test_trace_contains_protocol_context(self, engine, reliability_signals):
        result = engine.infer("INC-XAI-001", reliability_signals)
        combined = " ".join(result.explainability.reasoning_steps)
        # Should mention signal count or protocols
        assert any(char.isdigit() for char in combined)

    def test_trace_references_root_cause_label(self, engine, reliability_signals):
        result = engine.infer("INC-XAI-002", reliability_signals)
        if result.root_cause:
            combined = " ".join(result.explainability.reasoning_steps)
            assert result.root_cause.label in combined

    def test_trace_iec_context_not_empty(self, engine, cyber_signals):
        result = engine.infer("INC-XAI-003", cyber_signals)
        assert "IEC" in result.explainability.iec_context

    def test_counter_evidence_excludes_fired_rules(self, engine, reliability_signals):
        result = engine.infer("INC-XAI-004", reliability_signals)
        # Counter evidence should not contain the actual root cause
        if result.root_cause:
            counter_text = " ".join(result.explainability.counter_evidence)
            assert result.root_cause.label not in counter_text

    def test_temporal_sequence_is_ordered(self, engine, reliability_signals):
        result = engine.infer("INC-XAI-005", reliability_signals)
        seq = result.explainability.temporal_sequence
        if len(seq) > 1:
            steps = [s["step"] for s in seq]
            assert steps == sorted(steps)


# ─────────────────────────────────────────────────────────────────────────────
# QA-DISCOVERED EDGE CASE TESTS (added post QA assessment)
# ─────────────────────────────────────────────────────────────────────────────

class TestEdgeCases:
    """Tests added from QA probes — cover conditions not in original test suite."""

    def test_warn_only_signals_still_fire_reliability_root_cause(self, engine):
        """
        QA finding: switch_firmware_bug previously required severity=CRIT.
        WARN-level packet loss at 5%+ is a valid causal signal and must fire.
        Fixed: removed severity condition from trigger_conditions in reliability.yaml.
        """
        base_ts = time.time()
        warn_signals = [
            {"event_id":"QA-W1","timestamp":base_ts,"tag":"SW-03","protocol":"SNMP",
             "raw_address":"1.3.6.1.2.1.31","value":34.2,"unit":"%loss","severity":"WARN","message":"warn"},
            {"event_id":"QA-W2","timestamp":base_ts+0.5,"tag":"PLC-L3-A","protocol":"Modbus/TCP",
             "raw_address":"40001","value":0,"unit":"","severity":"WARN","message":"warn"},
        ]
        result = engine.infer("QA-EDGE-001", warn_signals)
        assert result.root_cause is not None, "WARN-only signals must still produce a root cause"
        assert result.root_cause.node_id == "switch_firmware_bug"
        assert result.classification == "RELIABILITY"

    def test_warn_confidence_lower_than_crit_confidence(self, engine, reliability_signals):
        """CRIT events should produce higher confidence than WARN for same tags."""
        base_ts = time.time()
        warn_signals = [
            {"event_id":"QA-W3","timestamp":base_ts,"tag":"SW-03","protocol":"SNMP",
             "raw_address":"x","value":34.2,"unit":"%loss","severity":"WARN","message":""},
            {"event_id":"QA-W4","timestamp":base_ts+0.5,"tag":"PLC-L3-A","protocol":"Modbus/TCP",
             "raw_address":"40001","value":0,"unit":"","severity":"WARN","message":""},
        ]
        r_warn = engine.infer("QA-EDGE-002a", warn_signals)
        r_crit = engine.infer("QA-EDGE-002b", reliability_signals)
        if r_warn.root_cause and r_crit.root_cause:
            assert r_warn.root_cause.confidence <= r_crit.root_cause.confidence

    def test_duplicate_event_ids_do_not_crash(self, engine):
        """Duplicate event_id values must be handled gracefully."""
        dup = [
            {"event_id":"DUP","timestamp":time.time(),"tag":"SW-03","protocol":"SNMP",
             "raw_address":"x","value":34.2,"unit":"%loss","severity":"CRIT","message":""},
            {"event_id":"DUP","timestamp":time.time(),"tag":"SW-03","protocol":"SNMP",
             "raw_address":"x","value":34.2,"unit":"%loss","severity":"CRIT","message":""},
        ]
        result = engine.infer("QA-EDGE-003", dup)
        assert result is not None
        assert 0.0 <= result.overall_confidence <= 1.0

    def test_negative_sensor_value_does_not_crash(self, engine):
        """Physically impossible sensor values must not raise exceptions."""
        signals = [
            {"event_id":"NEG","timestamp":time.time(),"tag":"PT-R2-01","protocol":"OPC-UA",
             "raw_address":"ns=2;i=1021","value":-99.9,"unit":"bar","severity":"CRIT","message":""},
        ]
        result = engine.infer("QA-EDGE-004", signals)
        assert result is not None

    def test_10k_char_message_does_not_crash(self, engine):
        """Pathologically long messages must not cause memory or parsing issues."""
        signals = [
            {"event_id":"LONG","timestamp":time.time(),"tag":"SW-03","protocol":"SNMP",
             "raw_address":"x","value":34.2,"unit":"%loss","severity":"CRIT","message":"A"*10001},
        ]
        result = engine.infer("QA-EDGE-005", signals)
        assert result is not None

    def test_none_field_values_do_not_crash(self, engine):
        """None values in optional fields must be tolerated."""
        signals = [
            {"event_id":"NULL","timestamp":time.time(),"tag":"SW-03","protocol":"SNMP",
             "raw_address":None,"value":None,"unit":None,"severity":"CRIT","message":None},
        ]
        result = engine.infer("QA-EDGE-006", signals)
        assert result is not None

    def test_1000_events_completes_under_500ms(self, engine):
        """Engine must remain fast under high event volume."""
        import random
        tags   = ["SW-03","PLC-L3-A","HMI-01","FCV-R2","PT-R2-01","EW-04"]
        protos = ["SNMP","Modbus/TCP","OPC-UA","DNP3","WinRM","NetFlow"]
        signals = [
            {"event_id":f"S{i}","timestamp":time.time()+i*0.001,"tag":random.choice(tags),
             "protocol":random.choice(protos),"raw_address":"x","value":random.uniform(0,200),
             "unit":"x","severity":random.choice(["INFO","WARN","CRIT"]),"message":f"evt{i}"}
            for i in range(1000)
        ]
        t0 = time.perf_counter()
        result = engine.infer("QA-EDGE-007", signals)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 500, f"Inference took {elapsed_ms:.0f}ms — exceeds 500ms limit"

    def test_xai_counter_evidence_lists_unfired_root_causes(self, engine, reliability_signals):
        """Counter evidence must name alternative hypotheses that were ruled out."""
        result = engine.infer("QA-EDGE-008", reliability_signals)
        assert len(result.explainability.counter_evidence) > 0
        # Must name at least one alternative root cause
        combined = " ".join(result.explainability.counter_evidence)
        assert "excluded" in combined or "not present" in combined

    def test_xai_temporal_sequence_step_numbers_are_sequential(self, engine, cyber_signals):
        """Temporal sequence step numbers must be 1, 2, 3... with no gaps."""
        result = engine.infer("QA-EDGE-009", cyber_signals)
        seq = result.explainability.temporal_sequence
        if len(seq) > 1:
            steps = [s["step"] for s in seq]
            assert steps == list(range(1, len(steps)+1)), f"Steps not sequential: {steps}"

    def test_json_output_is_valid_and_complete(self, engine, cyber_signals):
        """Serialised JSON must parse cleanly and contain all required fields."""
        import json
        result = engine.infer("QA-EDGE-010", cyber_signals)
        json_str = engine.to_json(result)
        parsed = json.loads(json_str)
        required = ["incident_id","inferred_at","classification","nodes","edges",
                    "root_cause","overall_confidence","explainability","inference_ms"]
        for f in required:
            assert f in parsed, f"JSON missing field: {f}"
        assert isinstance(parsed["nodes"], list)
        assert isinstance(parsed["inference_ms"], int)
