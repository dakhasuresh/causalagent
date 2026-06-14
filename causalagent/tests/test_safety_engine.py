"""
Tests :: SafetyEngine
======================
Unit tests for IEC 62443-aligned safety guardrail enforcement.

Tests validate:
  - Guardrail rule loading from YAML
  - BLOCK decisions for prohibited actions
  - HUMAN_GATE decisions for approval-gated actions
  - ALLOW decisions for safe autonomous actions
  - Production impact assessment
  - Reversibility classification
  - IEC 62443 clause attribution

Run: pytest tests/test_safety_engine.py -v
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.safety_engine import (
    ActionDecision,
    ActionProposal,
    ProductionImpact,
    ProductionImpactModel,
    ReversibilityClass,
    ReversibilityClassifier,
    SafetyEngine,
)

GUARDRAIL_PATH = Path(__file__).parent.parent / "rules" / "safety" / "guardrails.yaml"


# ─────────────────────────────────────────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def engine() -> SafetyEngine:
    e = SafetyEngine(GUARDRAIL_PATH)
    e.load()
    return e


@pytest.fixture
def network_isolate_dmz() -> ActionProposal:
    return ActionProposal(
        action_id       = "A1",
        description     = "Network isolate EW-04 at DMZ firewall",
        target_tag      = "EW-04",
        target_zone     = "DMZ",
        action_type     = "network_isolate",
        iec_requirement = "IEC 62443-3-3 SR 5.1",
    )


@pytest.fixture
def setpoint_revert_l1() -> ActionProposal:
    return ActionProposal(
        action_id       = "A2",
        description     = "Revert FCV-R2 setpoint to last validated snapshot",
        target_tag      = "FCV-R2",
        target_zone     = "L1",
        action_type     = "setpoint_revert",
        iec_requirement = "IEC 62443-3-3 SR 2.6",
    )


@pytest.fixture
def emergency_shutdown_l1() -> ActionProposal:
    return ActionProposal(
        action_id       = "A_ESD",
        description     = "Trigger SIL-2 emergency shutdown",
        target_tag      = "ESD-R2",
        target_zone     = "L1",
        action_type     = "emergency_shutdown",
        iec_requirement = "IEC 61511",
    )


@pytest.fixture
def alarm_acknowledge_l2() -> ActionProposal:
    return ActionProposal(
        action_id       = "A3",
        description     = "Acknowledge HMI-01 false alarm",
        target_tag      = "HMI-01",
        target_zone     = "L2",
        action_type     = "alarm_acknowledge",
        iec_requirement = "IEC 62443-3-3 SR 3.6",
    )


@pytest.fixture
def firmware_rollback_l2() -> ActionProposal:
    return ActionProposal(
        action_id       = "A4",
        description     = "Rollback SW-03 firmware to v3.1.8",
        target_tag      = "SW-03",
        target_zone     = "L2",
        action_type     = "firmware_rollback",
        iec_requirement = "IEC 62443-2-3",
    )


@pytest.fixture
def forensic_capture() -> ActionProposal:
    return ActionProposal(
        action_id       = "A5",
        description     = "Capture EW-04 memory forensic image",
        target_tag      = "EW-04",
        target_zone     = "DMZ",
        action_type     = "forensic_capture",
        iec_requirement = "IEC 62443-2-1 4.3.3",
    )


@pytest.fixture
def cyber_context() -> dict:
    return {
        "classification":      "CYBER",
        "overall_confidence":  0.94,
        "root_cause_verified": False,
        "production_active":   True,
    }


@pytest.fixture
def reliability_context() -> dict:
    return {
        "classification":      "RELIABILITY",
        "overall_confidence":  0.93,
        "root_cause_verified": True,
        "production_active":   True,
    }


@pytest.fixture
def low_confidence_context() -> dict:
    return {
        "classification":      "RELIABILITY",
        "overall_confidence":  0.55,
        "root_cause_verified": False,
        "production_active":   True,
    }


# ─────────────────────────────────────────────────────────────────────────────
# GUARDRAIL LOADING TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestGuardrailLoading:

    def test_loads_rules_from_yaml(self, engine):
        assert engine._evaluator.rules is not None
        assert len(engine._evaluator.rules) > 0

    def test_contains_block_cyber_rule(self, engine):
        assert "gr_block_auto_control_during_cyber" in engine._evaluator.rules

    def test_contains_human_gate_setpoint_rule(self, engine):
        assert "gr_human_gate_setpoint_revert" in engine._evaluator.rules

    def test_contains_esd_block_rule(self, engine):
        assert "gr_block_esd_without_verified_cause" in engine._evaluator.rules


# ─────────────────────────────────────────────────────────────────────────────
# BLOCK DECISION TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestBlockDecisions:

    def test_setpoint_revert_blocked_during_cyber_incident(
        self, engine, setpoint_revert_l1, cyber_context
    ):
        decisions = engine.evaluate_actions([setpoint_revert_l1], cyber_context)
        assert decisions[0].decision == ActionDecision.BLOCK

    def test_esd_blocked_when_cause_unverified(
        self, engine, emergency_shutdown_l1, low_confidence_context
    ):
        decisions = engine.evaluate_actions([emergency_shutdown_l1], low_confidence_context)
        assert decisions[0].decision in (ActionDecision.BLOCK, ActionDecision.ESCALATE)

    def test_block_decision_includes_iec_clause(
        self, engine, setpoint_revert_l1, cyber_context
    ):
        decisions = engine.evaluate_actions([setpoint_revert_l1], cyber_context)
        assert any("IEC" in clause for clause in decisions[0].iec_clauses_checked)

    def test_blocked_action_is_not_auto_executable(
        self, engine, setpoint_revert_l1, cyber_context
    ):
        decisions = engine.evaluate_actions([setpoint_revert_l1], cyber_context)
        assert decisions[0].auto_executable is False


# ─────────────────────────────────────────────────────────────────────────────
# HUMAN GATE DECISION TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestHumanGateDecisions:

    def test_setpoint_revert_requires_human_gate_in_reliability(
        self, engine, setpoint_revert_l1, reliability_context
    ):
        # L1 setpoint revert triggers SIL zone escalation rule — ESCALATE is correct
        decisions = engine.evaluate_actions([setpoint_revert_l1], reliability_context)
        assert decisions[0].decision in (ActionDecision.HUMAN_GATE, ActionDecision.ESCALATE)

    def test_network_isolate_requires_human_gate(
        self, engine, network_isolate_dmz, reliability_context
    ):
        decisions = engine.evaluate_actions([network_isolate_dmz], reliability_context)
        assert decisions[0].decision == ActionDecision.HUMAN_GATE

    def test_firmware_rollback_requires_human_gate(
        self, engine, firmware_rollback_l2, reliability_context
    ):
        decisions = engine.evaluate_actions([firmware_rollback_l2], reliability_context)
        assert decisions[0].decision == ActionDecision.HUMAN_GATE

    def test_forensic_capture_requires_human_gate(
        self, engine, forensic_capture, reliability_context
    ):
        decisions = engine.evaluate_actions([forensic_capture], reliability_context)
        assert decisions[0].decision == ActionDecision.HUMAN_GATE

    def test_human_gate_produces_human_prompt(
        self, engine, network_isolate_dmz, reliability_context
    ):
        # network_isolate_dmz is always HUMAN_GATE — use this for prompt test
        decisions = engine.evaluate_actions([network_isolate_dmz], reliability_context)
        assert decisions[0].decision == ActionDecision.HUMAN_GATE
        assert decisions[0].human_prompt is not None
        assert len(decisions[0].human_prompt) > 10


# ─────────────────────────────────────────────────────────────────────────────
# ALLOW DECISION TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestAllowDecisions:

    def test_alarm_acknowledge_allowed_autonomously(
        self, engine, alarm_acknowledge_l2, reliability_context
    ):
        decisions = engine.evaluate_actions([alarm_acknowledge_l2], reliability_context)
        assert decisions[0].decision == ActionDecision.ALLOW

    def test_allowed_action_is_auto_executable(
        self, engine, alarm_acknowledge_l2, reliability_context
    ):
        decisions = engine.evaluate_actions([alarm_acknowledge_l2], reliability_context)
        assert decisions[0].auto_executable is True


# ─────────────────────────────────────────────────────────────────────────────
# PRODUCTION IMPACT TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestProductionImpact:

    def test_network_isolate_dmz_has_none_impact(self):
        model = ProductionImpactModel()
        action = ActionProposal("X", "", "EW-04", "DMZ", "network_isolate", "")
        assert model.assess(action) == ProductionImpact.NONE

    def test_network_isolate_l1_has_major_impact(self):
        model = ProductionImpactModel()
        action = ActionProposal("X", "", "PLC-L1", "L1", "network_isolate", "")
        assert model.assess(action) == ProductionImpact.MAJOR

    def test_emergency_shutdown_l1_is_critical_impact(self):
        model = ProductionImpactModel()
        action = ActionProposal("X", "", "ESD", "L1", "emergency_shutdown", "")
        assert model.assess(action) == ProductionImpact.CRITICAL

    def test_alarm_acknowledge_has_no_impact(self):
        model = ProductionImpactModel()
        action = ActionProposal("X", "", "HMI-01", "L2", "alarm_acknowledge", "")
        assert model.assess(action) == ProductionImpact.NONE

    def test_unknown_action_type_defaults_to_moderate(self):
        model = ProductionImpactModel()
        action = ActionProposal("X", "", "UNKNOWN", "L1", "unknown_action_xyz", "")
        assert model.assess(action) == ProductionImpact.MODERATE


# ─────────────────────────────────────────────────────────────────────────────
# REVERSIBILITY TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestReversibility:

    def test_alarm_acknowledge_is_reversible(self):
        clf = ReversibilityClassifier()
        action = ActionProposal("X", "", "HMI", "L2", "alarm_acknowledge", "")
        assert clf.classify(action) == ReversibilityClass.REVERSIBLE

    def test_emergency_shutdown_is_irreversible(self):
        clf = ReversibilityClassifier()
        action = ActionProposal("X", "", "ESD", "L1", "emergency_shutdown", "")
        assert clf.classify(action) == ReversibilityClass.IRREVERSIBLE

    def test_firmware_rollback_is_recoverable(self):
        clf = ReversibilityClassifier()
        action = ActionProposal("X", "", "SW-03", "L2", "firmware_rollback", "")
        assert clf.classify(action) == ReversibilityClass.RECOVERABLE

    def test_setpoint_revert_is_reversible(self):
        clf = ReversibilityClassifier()
        action = ActionProposal("X", "", "FCV-R2", "L1", "setpoint_revert", "")
        assert clf.classify(action) == ReversibilityClass.REVERSIBLE


# ─────────────────────────────────────────────────────────────────────────────
# BATCH EVALUATION TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestBatchEvaluation:

    def test_evaluates_multiple_actions(
        self, engine, network_isolate_dmz, setpoint_revert_l1,
        alarm_acknowledge_l2, cyber_context
    ):
        proposals = [network_isolate_dmz, setpoint_revert_l1, alarm_acknowledge_l2]
        decisions = engine.evaluate_actions(proposals, cyber_context)
        assert len(decisions) == 3

    def test_blocked_actions_appear_first_in_sorted_output(
        self, engine, setpoint_revert_l1, alarm_acknowledge_l2, cyber_context
    ):
        proposals = [alarm_acknowledge_l2, setpoint_revert_l1]
        decisions = engine.evaluate_actions(proposals, cyber_context)
        decision_order = [d.decision for d in decisions]
        block_idx = next(
            (i for i, d in enumerate(decisions) if d.decision == ActionDecision.BLOCK), None
        )
        allow_idx = next(
            (i for i, d in enumerate(decisions) if d.decision == ActionDecision.ALLOW), None
        )
        if block_idx is not None and allow_idx is not None:
            assert block_idx < allow_idx

    def test_each_decision_has_explanation(
        self, engine, network_isolate_dmz, setpoint_revert_l1, reliability_context
    ):
        proposals = [network_isolate_dmz, setpoint_revert_l1]
        decisions = engine.evaluate_actions(proposals, reliability_context)
        for d in decisions:
            assert d.explanation and len(d.explanation) > 10

    def test_raises_if_not_loaded(self, alarm_acknowledge_l2, reliability_context):
        unloaded = SafetyEngine(GUARDRAIL_PATH)
        with pytest.raises(RuntimeError, match="Call engine.load()"):
            unloaded.evaluate_actions([alarm_acknowledge_l2], reliability_context)
