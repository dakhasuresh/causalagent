"""
Tests :: DecisionMemory
========================
Unit tests for the causal pattern store and retrieval system.

Run: pytest tests/test_decision_memory.py -v
"""

import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.decision_memory import CausalPattern, DecisionMemory


STORE_PATH = Path(__file__).parent.parent / "data" / "decision_memory.json"


@pytest.fixture
def memory() -> DecisionMemory:
    m = DecisionMemory(STORE_PATH)
    m.load()
    return m


class TestDecisionMemoryLoad:
    def test_loads_patterns_from_json(self, memory):
        assert len(memory.patterns) > 0

    def test_patterns_have_required_fields(self, memory):
        for p in memory.patterns:
            assert p.pattern_id
            assert p.root_cause_id
            assert isinstance(p.trigger_tags, list)

    def test_summary_returns_correct_total(self, memory):
        summary = memory.summary()
        assert summary["total"] == len(memory.patterns)

    def test_summary_cyber_plus_reliability_equals_total(self, memory):
        summary = memory.summary()
        assert summary["cyber"] + summary["reliability"] == summary["total"]


class TestDecisionMemoryRetrieval:

    def test_retrieves_reliability_pattern_by_tags(self, memory):
        matches = memory.retrieve(
            event_tags=["SW-03", "PLC-L3-A", "HMI-01"],
            event_protocols=["SNMP", "Modbus/TCP", "OPC-UA"],
            incident_class="RELIABILITY",
        )
        assert len(matches) > 0
        assert matches[0].pattern.root_cause_id == "switch_firmware_bug"

    def test_retrieves_cyber_pattern_by_tags(self, memory):
        matches = memory.retrieve(
            event_tags=["EW-04", "FCV-R2", "PT-R2-01", "HMI-01"],
            event_protocols=["WinRM", "DNP3", "OPC-UA"],
            incident_class="CYBER",
        )
        assert len(matches) > 0
        assert matches[0].pattern.root_cause_id == "ew_workstation_compromise"

    def test_similarity_score_is_between_0_and_1(self, memory):
        matches = memory.retrieve(["SW-03", "PLC-L3-A"], ["SNMP"])
        for m in matches:
            assert 0.0 <= m.similarity_score <= 1.0

    def test_returns_empty_for_unrelated_tags(self, memory):
        matches = memory.retrieve(
            ["COMPLETELY-UNKNOWN-TAG-XYZ"],
            ["UNKNOWN-PROTOCOL"],
            min_similarity=0.8,
        )
        assert len(matches) == 0

    def test_top_k_respected(self, memory):
        matches = memory.retrieve(["SW-03"], ["SNMP"], top_k=1)
        assert len(matches) <= 1

    def test_class_bonus_boosts_matching_class(self, memory):
        rel_matches = memory.retrieve(
            ["SW-03", "PLC-L3-A"], ["SNMP", "Modbus/TCP"],
            incident_class="RELIABILITY"
        )
        cyber_matches = memory.retrieve(
            ["SW-03", "PLC-L3-A"], ["SNMP", "Modbus/TCP"],
            incident_class="CYBER"
        )
        if rel_matches and cyber_matches:
            # reliability match should score higher for reliability event
            rel_score = next((m.similarity_score for m in rel_matches
                if m.pattern.incident_class == "RELIABILITY"), 0)
            cyber_score = next((m.similarity_score for m in cyber_matches
                if m.pattern.incident_class == "RELIABILITY"), 0)
            assert rel_score >= cyber_score

    def test_match_explanation_is_not_empty(self, memory):
        matches = memory.retrieve(["SW-03", "PLC-L3-A"], ["SNMP"])
        if matches:
            assert len(matches[0].explanation) > 10


class TestDecisionMemoryStore:

    def test_summary_avg_mttr_is_positive(self, memory):
        summary = memory.summary()
        assert summary["avg_mttr_minutes"] > 0

    def test_summary_avg_confidence_is_between_0_and_1(self, memory):
        summary = memory.summary()
        assert 0.0 < summary["avg_confidence"] <= 1.0
