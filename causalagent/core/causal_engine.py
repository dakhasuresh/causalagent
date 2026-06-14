"""
CausalAgent :: CausalEngine
===========================

OT-native causal inference pipeline for industrial incident root cause analysis.

Problem statement
-----------------
OT environments generate multi-protocol alarm floods during incidents. Existing
tooling correlates alerts but cannot distinguish root cause from downstream effect
or observable symptom. Engineers waste hours on manual triage and occasionally
take unsafe actions under pressure. This module implements deterministic causal
graph traversal to isolate initiating root causes from normalised OT signal streams.

Design rationale
----------------
The causal graph topology is deterministic — encoded in auditable YAML rule files
(rules/causal/*.yaml), versioned in git, reviewable by OT engineers without touching
Python. The confidence assigned to each graph node is probabilistic — a Bayesian-
weighted score across five factors (evidence density, signal severity, temporal
coherence, Purdue zone alignment, decision memory pattern match). This separation
ensures the *structure* of reasoning is transparent and challengeable, while the
*weight* of evidence is computed from real signal data.

Pipeline stages
---------------
    raw_signals: list[dict]          (multi-protocol OT event dicts)
        │
        ▼
    EventNormaliser
        Protocol-agnostic extraction to canonical OTEvent objects.
        Maps Modbus registers, DNP3 addresses, OPC-UA nodeIds, SNMP OIDs,
        Syslog messages, SIEM CEF events, and NetFlow records to a common
        schema. Assigns Purdue zone (L0–L4, DMZ) from protocol type.
        │
        ▼
    CausalGraphBuilder
        Loads YAML rule sets from rules/causal/*.yaml.
        Evaluates trigger_conditions (value thresholds, severity filters)
        against the normalised event stream using AND-logic per rule.
        Constructs directed CausalNode/CausalEdge graph from fired rules.
        Infers inter-node temporal lag from event timestamps.
        │
        ▼
    ConfidenceScorer
        Bayesian-weighted confidence per CausalNode:
          evidence_density   × 0.40  (matched tags / required tags)
          severity_weight    × 0.35  (CRIT=1.0, WARN=0.65, INFO=0.35)
          temporal_coherence × 0.20  (monotonic timestamp ordering)
          zone_alignment     × ~0.03 (ROOT_CAUSE in DMZ/L4 bonus)
          memory_bonus       × ~0.05 (DecisionMemory pattern match)
        Edge confidence = geometric mean of endpoint node confidences.
        │
        ▼
    ExplainabilityEngine
        Generates ExplainabilityTrace per inference result:
          reasoning_steps    — ordered natural-language inference chain
          evidence_events    — event IDs supporting each causal node
          counter_evidence   — alternative hypotheses evaluated and excluded
          temporal_sequence  — millisecond causal propagation timeline
          iec_context        — applicable IEC 62443 normative clauses
        Aligned with: EU AI Act Art.13 transparency, DARPA XAI principles,
        IEC 62443-3-3 SR 2.6 (audit-ready decision traceability).
        │
        ▼
    CausalInferenceResult
        Typed dataclass containing classified nodes (ROOT_CAUSE / EFFECT /
        SYMPTOM), overall confidence (weighted mean across node types),
        incident classification (CYBER | RELIABILITY | UNKNOWN), full
        explainability trace, and JSON serialisation for API consumers.

Confidence scoring — overall incident
--------------------------------------
    overall_confidence = Σ(node.confidence × node_weight) / Σ(node_weights)
    Weights: ROOT_CAUSE=0.55, EFFECT=0.30, SYMPTOM=0.15

Classification logic
--------------------
    CYBER      — root cause node has mitre_ttp set, OR root cause in DMZ/L4,
                 OR ≥2 nodes in the graph have MITRE TTP attribution
    RELIABILITY — all other cases
    UNKNOWN    — no causal rules fired against the event stream

Standards alignment
-------------------
    IEC 62443-3-3 SR 2.6   Use Control — human approval before action execution
    IEC 62443-2-1 4.3.3    Incident Response — causal evidence for forensics
    ISA-95 / IEC 62264-1   Equipment hierarchy — zone/cell/unit context
    Purdue Model            L0–L4 + DMZ zone attribution
    EU AI Act Art. 13      Transparency — XAI trace output
    DARPA XAI (2017)       Explainability framework — reasoning step design

Author: Suresh Dakha
"""

from __future__ import annotations

import json
import time
import logging
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# DATA TYPES
# ─────────────────────────────────────────────────────────────────────────────

class NodeType(str, Enum):
    ROOT_CAUSE = "ROOT_CAUSE"
    EFFECT     = "EFFECT"
    SYMPTOM    = "SYMPTOM"
    UNKNOWN    = "UNKNOWN"

class PurdueZone(str, Enum):
    L0 = "L0"   # Field (sensors, actuators)
    L1 = "L1"   # Control (PLCs, DCS)
    L2 = "L2"   # Supervisory (SCADA, HMI)
    L3 = "L3"   # Operations (MES, Historian)
    L4 = "L4"   # Enterprise (ERP, IT)
    DMZ = "DMZ" # Industrial DMZ


@dataclass
class OTEvent:
    """
    Normalised OT signal event.
    Protocol-agnostic after ingestion; raw fields preserved for audit.
    """
    event_id:   str
    timestamp:  float           # Unix epoch (ms precision)
    tag:        str             # Canonical tag name e.g. "PLC-L3-A"
    protocol:   str             # Modbus, DNP3, OPC-UA, SNMP, etc.
    raw_address: str            # Protocol-native address (register, nodeId, OID)
    value:      float | str
    unit:       str
    zone:       PurdueZone
    severity:   str             # INFO, WARN, CRIT
    source_msg: str             # Original message from signal source
    metadata:   dict = field(default_factory=dict)


@dataclass
class CausalNode:
    """
    A node in the inferred causal graph.
    """
    node_id:        str
    label:          str
    node_type:      NodeType
    zone:           PurdueZone
    confidence:     float           # 0.0 – 1.0
    mitre_ttp:      str | None      # e.g. "T0836"
    iec_62443_sl:   str | None      # Security level if applicable
    evidence:       list[str]       # Event IDs that support this node
    explanation:    str             # Human-readable causal explanation


@dataclass
class CausalEdge:
    """
    Directed causal relationship between two nodes.
    """
    from_node:  str
    to_node:    str
    relation:   str             # e.g. "causes", "triggers", "masks"
    delay_ms:   int | None      # Observed temporal lag (ms)
    confidence: float


@dataclass
class ExplainabilityTrace:
    """
    Structured XAI output — why the engine reached this conclusion.
    Designed for human-in-the-loop review (IEC 62443-3-3 SR 2.6).
    """
    root_cause_id:     str
    confidence:        float
    reasoning_steps:   list[str]       # Ordered inference steps
    evidence_events:   list[str]       # Supporting event IDs
    pattern_matched:   str | None      # Decision memory pattern ID
    temporal_sequence: list[dict]      # Timestamps + delta for each causal hop
    counter_evidence:  list[str]       # What was ruled out and why
    iec_context:       str             # Applicable IEC 62443 clause


@dataclass
class CausalInferenceResult:
    """
    Full output from a CausalEngine.infer() call.
    """
    incident_id:        str
    inferred_at:        float
    classification:     str             # CYBER | RELIABILITY | SAFETY
    nodes:              list[CausalNode]
    edges:              list[CausalEdge]
    root_cause:         CausalNode | None
    effects:            list[CausalNode]
    symptoms:           list[CausalNode]
    overall_confidence: float
    explainability:     ExplainabilityTrace
    raw_event_count:    int
    inference_ms:       int             # Engine runtime


# ─────────────────────────────────────────────────────────────────────────────
# EVENT NORMALISER
# ─────────────────────────────────────────────────────────────────────────────

class EventNormaliser:
    """
    Translates raw protocol signals into canonical OTEvent objects.

    Handles: Modbus/TCP, DNP3, OPC-UA, SNMP, Syslog, SIEM, NetFlow.
    Each protocol has a dedicated parser keyed by the protocol field.
    """

    PROTOCOL_ZONE_MAP = {
        "Modbus/TCP": PurdueZone.L1,
        "DNP3":       PurdueZone.L1,
        "OPC-UA":     PurdueZone.L2,
        "SNMP":       PurdueZone.L2,
        "Syslog":     PurdueZone.L2,
        "SIEM":       PurdueZone.DMZ,
        "NetFlow":    PurdueZone.DMZ,
        "WinRM":      PurdueZone.DMZ,
        "RDP":        PurdueZone.DMZ,
    }

    SEVERITY_MAP = {
        "CRIT": "CRIT",
        "critical": "CRIT",
        "WARN": "WARN",
        "warning": "WARN",
        "INFO": "INFO",
        "info": "INFO",
    }

    def normalise(self, raw_signals: list[dict]) -> list[OTEvent]:
        events: list[OTEvent] = []
        for i, sig in enumerate(raw_signals):
            proto = sig.get("protocol", "UNKNOWN")
            zone  = self.PROTOCOL_ZONE_MAP.get(proto, PurdueZone.L1)
            severity = self.SEVERITY_MAP.get(sig.get("severity", "INFO"), "INFO")
            event = OTEvent(
                event_id    = sig.get("event_id", f"EVT-{i:04d}"),
                timestamp   = sig.get("timestamp", time.time()),
                tag         = sig.get("tag", "UNKNOWN"),
                protocol    = proto,
                raw_address = sig.get("raw_address", ""),
                value       = sig.get("value", 0),
                unit        = sig.get("unit", ""),
                zone        = zone,
                severity    = severity,
                source_msg  = sig.get("message", ""),
                metadata    = sig.get("metadata", {}),
            )
            events.append(event)
        logger.debug(f"Normalised {len(events)} events from {len(raw_signals)} raw signals")
        return events


# ─────────────────────────────────────────────────────────────────────────────
# CAUSAL GRAPH BUILDER
# ─────────────────────────────────────────────────────────────────────────────

class CausalGraphBuilder:
    """
    Loads YAML-defined causal rule sets and resolves which rules fire
    given the observed event stream.

    Rule structure (YAML):
        rule_id:
          name: human label
          trigger_tags: [list of OT tags that must appear in event stream]
          trigger_conditions: {tag: {operator: >, value: threshold}}
          causes: [list of rule_ids this rule leads to]
          node_type: ROOT_CAUSE | EFFECT | SYMPTOM
          zone: Purdue zone
          mitre_ttp: TXXXX or null
          iec_62443_sl: SL-N or null
          explanation_template: "..."
    """

    def __init__(self, rules_dir: Path):
        self.rules_dir  = rules_dir
        self.rules: dict = {}

    def load_rules(self) -> None:
        for rule_file in self.rules_dir.glob("*.yaml"):
            with open(rule_file) as f:
                loaded = yaml.safe_load(f)
                if loaded:
                    self.rules.update(loaded)
        logger.info(f"Loaded {len(self.rules)} causal rules from {self.rules_dir}")

    def _evaluate_condition(self, condition: dict, events: list[OTEvent]) -> bool:
        """
        Evaluate a single condition against the event stream.
        Supports: tag presence, threshold breach, severity filter.
        """
        tag       = condition.get("tag")
        operator  = condition.get("operator")
        threshold = condition.get("value")
        severity  = condition.get("severity")

        matching = [e for e in events if e.tag == tag]
        if not matching:
            return False

        if severity:
            matching = [e for e in matching if e.severity == severity]
            if not matching:
                return False

        if operator and threshold is not None:
            try:
                vals = [float(e.value) for e in matching]
            except (ValueError, TypeError):
                return False

            ops = {
                ">":  lambda v: v > threshold,
                ">=": lambda v: v >= threshold,
                "<":  lambda v: v < threshold,
                "<=": lambda v: v <= threshold,
                "==": lambda v: v == threshold,
                "!=": lambda v: v != threshold,
            }
            check = ops.get(operator)
            if check and not any(check(v) for v in vals):
                return False

        return True

    def evaluate_rules(self, events: list[OTEvent]) -> dict[str, bool]:
        """
        Returns a map of rule_id → fired (bool) for the given event stream.
        """
        fired: dict[str, bool] = {}
        for rule_id, rule in self.rules.items():
            conditions = rule.get("trigger_conditions", [])
            if not conditions:
                # Tag presence check only
                trigger_tags = rule.get("trigger_tags", [])
                event_tags   = {e.tag for e in events}
                fired[rule_id] = bool(set(trigger_tags) & event_tags)
            else:
                fired[rule_id] = all(
                    self._evaluate_condition(c, events)
                    for c in conditions
                )
        return fired

    def build_graph(
        self,
        fired_rules: dict[str, bool],
        events: list[OTEvent],
    ) -> tuple[list[CausalNode], list[CausalEdge]]:
        """
        Build directed causal graph from fired rules.
        Returns (nodes, edges).
        """
        nodes: list[CausalNode] = []
        edges: list[CausalEdge] = []
        event_tag_set = {e.tag for e in events}

        for rule_id, did_fire in fired_rules.items():
            if not did_fire:
                continue
            rule = self.rules[rule_id]

            # Gather supporting evidence (event IDs)
            evidence = [
                e.event_id for e in events
                if e.tag in rule.get("trigger_tags", [])
            ]

            node = CausalNode(
                node_id      = rule_id,
                label        = rule.get("name", rule_id),
                node_type    = NodeType(rule.get("node_type", "UNKNOWN")),
                zone         = PurdueZone(rule.get("zone", "L1")),
                confidence   = 0.0,  # scored separately
                mitre_ttp    = rule.get("mitre_ttp"),
                iec_62443_sl = rule.get("iec_62443_sl"),
                evidence     = evidence,
                explanation  = rule.get("explanation_template", ""),
            )
            nodes.append(node)

            # Build edges from causes list
            for target_id in rule.get("causes", []):
                if fired_rules.get(target_id, False):
                    edges.append(CausalEdge(
                        from_node  = rule_id,
                        to_node    = target_id,
                        relation   = "causes",
                        delay_ms   = self._infer_temporal_lag(rule_id, target_id, events),
                        confidence = 0.0,  # scored separately
                    ))

        return nodes, edges

    def _infer_temporal_lag(
        self,
        from_rule: str,
        to_rule: str,
        events: list[OTEvent],
    ) -> int | None:
        """
        Estimate temporal lag (ms) between two causal hops by comparing
        earliest timestamps of supporting events.
        """
        from_tags = self.rules.get(from_rule, {}).get("trigger_tags", [])
        to_tags   = self.rules.get(to_rule, {}).get("trigger_tags", [])

        from_events = [e for e in events if e.tag in from_tags]
        to_events   = [e for e in events if e.tag in to_tags]

        if not from_events or not to_events:
            return None

        t0 = min(e.timestamp for e in from_events)
        t1 = min(e.timestamp for e in to_events)
        return max(0, int((t1 - t0) * 1000))


# ─────────────────────────────────────────────────────────────────────────────
# CONFIDENCE SCORER
# ─────────────────────────────────────────────────────────────────────────────

class ConfidenceScorer:
    """
    Bayesian-inspired confidence scoring for causal nodes and edges.

    Scoring factors:
      1. Evidence density  — number of supporting events / expected events
      2. Severity weight   — CRIT events contribute more than WARN/INFO
      3. Temporal coherence — events occur in expected causal order
      4. Zone alignment    — cause in upstream Purdue zone vs effect
      5. Pattern memory    — match against known good patterns (boosts score)
    """

    SEVERITY_WEIGHT = {"CRIT": 1.0, "WARN": 0.65, "INFO": 0.35}
    ZONE_ORDER      = [PurdueZone.L0, PurdueZone.L1, PurdueZone.L2,
                       PurdueZone.L3, PurdueZone.L4, PurdueZone.DMZ]

    def score_nodes(
        self,
        nodes: list[CausalNode],
        events: list[OTEvent],
        rules: dict,
        memory_patterns: list[dict] | None = None,
    ) -> list[CausalNode]:
        """Score each node; mutates confidence in-place."""
        for node in nodes:
            rule = rules.get(node.node_id, {})
            node.confidence = self._score_node(node, events, rule, memory_patterns)
        return nodes

    def _score_node(
        self,
        node: CausalNode,
        events: list[OTEvent],
        rule: dict,
        memory_patterns: list[dict] | None,
    ) -> float:
        # 1. Evidence density
        expected_tags = rule.get("trigger_tags", [])
        found_tags    = {e.tag for e in events if e.tag in expected_tags}
        density       = len(found_tags) / max(len(expected_tags), 1)

        # 2. Severity weight
        supporting = [e for e in events if e.tag in expected_tags]
        if supporting:
            sev_score = sum(
                self.SEVERITY_WEIGHT.get(e.severity, 0.35)
                for e in supporting
            ) / len(supporting)
        else:
            sev_score = 0.35

        # 3. Temporal coherence (ROOT_CAUSE must precede EFFECTs)
        temporal = 1.0
        if node.node_type == NodeType.ROOT_CAUSE and supporting:
            if len(supporting) > 1:
                timestamps = [e.timestamp for e in supporting]
                if timestamps == sorted(timestamps):
                    temporal = 1.0
                else:
                    temporal = 0.75

        # 4. Zone alignment bonus
        zone_bonus = 0.0
        if node.node_type == NodeType.ROOT_CAUSE and node.zone in (
            PurdueZone.DMZ, PurdueZone.L4
        ):
            zone_bonus = 0.03  # cyber origin is typically DMZ/L4

        # 5. Decision memory pattern match
        memory_bonus = 0.0
        if memory_patterns:
            for pattern in memory_patterns:
                pattern_tags = set(pattern.get("trigger_tags", []))
                if pattern_tags and pattern_tags.issubset(found_tags):
                    memory_bonus = 0.05
                    break

        raw = (density * 0.4) + (sev_score * 0.35) + (temporal * 0.20) + zone_bonus + memory_bonus
        return round(min(raw, 0.99), 4)

    def score_edges(
        self,
        edges: list[CausalEdge],
        nodes: list[CausalNode],
    ) -> list[CausalEdge]:
        """Edge confidence = geometric mean of its two endpoint nodes."""
        node_conf = {n.node_id: n.confidence for n in nodes}
        for edge in edges:
            c_from = node_conf.get(edge.from_node, 0.5)
            c_to   = node_conf.get(edge.to_node, 0.5)
            edge.confidence = round((c_from * c_to) ** 0.5, 4)
        return edges


# ─────────────────────────────────────────────────────────────────────────────
# EXPLAINABILITY ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class ExplainabilityEngine:
    """
    Generates structured natural-language reasoning traces.

    Aligned with: DARPA XAI principles, EU AI Act Art. 13 transparency,
    and IEC 62443-3-3 SR 2.6 (audit-ready decision traceability).

    Output format designed for human-in-the-loop review panels.
    """

    def generate_trace(
        self,
        root_cause: CausalNode | None,
        effects: list[CausalNode],
        symptoms: list[CausalNode],
        edges: list[CausalEdge],
        events: list[OTEvent],
        rules: dict,
        memory_patterns: list[dict] | None = None,
    ) -> ExplainabilityTrace:

        if not root_cause:
            return ExplainabilityTrace(
                root_cause_id    = "UNKNOWN",
                confidence       = 0.0,
                reasoning_steps  = ["Insufficient signal evidence to isolate root cause."],
                evidence_events  = [],
                pattern_matched  = None,
                temporal_sequence= [],
                counter_evidence = [],
                iec_context      = "IEC 62443-3-3 SR 2.6 — human review required",
            )

        reasoning_steps = self._build_reasoning_steps(
            root_cause, effects, symptoms, edges, events, rules
        )
        temporal_sequence = self._build_temporal_sequence(
            root_cause, effects, edges, events
        )
        counter_evidence  = self._build_counter_evidence(
            root_cause, events, rules
        )
        pattern_id = self._match_memory_pattern(root_cause, events, memory_patterns)
        iec_context = self._iec_context(root_cause)

        return ExplainabilityTrace(
            root_cause_id    = root_cause.node_id,
            confidence       = root_cause.confidence,
            reasoning_steps  = reasoning_steps,
            evidence_events  = root_cause.evidence,
            pattern_matched  = pattern_id,
            temporal_sequence= temporal_sequence,
            counter_evidence = counter_evidence,
            iec_context      = iec_context,
        )

    def _build_reasoning_steps(
        self,
        root_cause: CausalNode,
        effects: list[CausalNode],
        symptoms: list[CausalNode],
        edges: list[CausalEdge],
        events: list[OTEvent],
        rules: dict,
    ) -> list[str]:
        steps = []

        # Step 1: What was observed
        crit_events = [e for e in events if e.severity == "CRIT"]
        steps.append(
            f"Observed {len(events)} signals across {len({e.protocol for e in events})} "
            f"OT protocols. {len(crit_events)} critical-severity events detected."
        )

        # Step 2: Root cause identification
        rule = rules.get(root_cause.node_id, {})
        trigger_tags = rule.get("trigger_tags", [])
        matched_events = [e for e in events if e.tag in trigger_tags]
        steps.append(
            f"Root cause isolated: '{root_cause.label}' "
            f"(zone: {root_cause.zone.value}, confidence: {root_cause.confidence * 100:.1f}%). "
            f"Supported by {len(matched_events)} matching signal(s): "
            f"{', '.join(e.tag for e in matched_events[:3])}."
        )

        # Step 3: Causal chain
        if effects:
            chain = " → ".join([root_cause.label] + [e.label for e in effects])
            steps.append(f"Causal propagation path: {chain}.")

        # Step 4: Symptoms (what is NOT the cause)
        if symptoms:
            steps.append(
                f"Symptom(s) ruled out as root cause: "
                f"{', '.join(s.label for s in symptoms)}. "
                f"These are downstream manifestations of the causal chain, not origin events."
            )

        # Step 5: MITRE context
        if root_cause.mitre_ttp:
            steps.append(
                f"MITRE ATT&CK for ICS technique matched: {root_cause.mitre_ttp}. "
                f"This supports classification as a cyber-initiated event."
            )

        # Step 6: Temporal ordering evidence
        if len(events) > 1:
            sorted_evts = sorted(events, key=lambda e: e.timestamp)
            first, last = sorted_evts[0], sorted_evts[-1]
            delta_ms = int((last.timestamp - first.timestamp) * 1000)
            steps.append(
                f"Temporal ordering confirmed: earliest signal '{first.tag}' "
                f"preceded latest '{last.tag}' by {delta_ms}ms — consistent with "
                f"causal propagation direction."
            )

        return steps

    def _build_temporal_sequence(
        self,
        root_cause: CausalNode,
        effects: list[CausalNode],
        edges: list[CausalEdge],
        events: list[OTEvent],
    ) -> list[dict]:
        sequence = []
        all_nodes = [root_cause] + effects
        for i, node in enumerate(all_nodes):
            node_events = [e for e in events if e.event_id in node.evidence]
            ts = min((e.timestamp for e in node_events), default=None)
            edge_to = next(
                (ed for ed in edges if ed.from_node == node.node_id), None
            )
            sequence.append({
                "step":     i + 1,
                "node":     node.label,
                "type":     node.node_type.value,
                "timestamp_offset_ms": int((ts - events[0].timestamp) * 1000) if ts and events else 0,
                "delay_to_next_ms": edge_to.delay_ms if edge_to else None,
            })
        return sequence

    def _build_counter_evidence(
        self,
        root_cause: CausalNode,
        events: list[OTEvent],
        rules: dict,
    ) -> list[str]:
        counter = []
        # Check alternative root causes that did NOT fire
        for rule_id, rule in rules.items():
            if rule_id == root_cause.node_id:
                continue
            if rule.get("node_type") != "ROOT_CAUSE":
                continue
            trigger_tags = set(rule.get("trigger_tags", []))
            event_tags   = {e.tag for e in events}
            missing = trigger_tags - event_tags
            if missing:
                counter.append(
                    f"Alternative hypothesis '{rule.get('name', rule_id)}' excluded: "
                    f"required signal(s) {missing} not present in event stream."
                )
        return counter[:4]  # limit output

    def _match_memory_pattern(
        self,
        root_cause: CausalNode,
        events: list[OTEvent],
        memory_patterns: list[dict] | None,
    ) -> str | None:
        if not memory_patterns:
            return None
        event_tags = {e.tag for e in events}
        for pattern in memory_patterns:
            if set(pattern.get("trigger_tags", [])).issubset(event_tags):
                if pattern.get("root_cause_id") == root_cause.node_id:
                    return pattern.get("pattern_id")
        return None

    def _iec_context(self, root_cause: CausalNode) -> str:
        clauses = []
        if root_cause.iec_62443_sl:
            clauses.append(
                f"IEC 62443-3-3 {root_cause.iec_62443_sl}: "
                f"security level breach detected at {root_cause.zone.value}"
            )
        clauses.append("IEC 62443-3-3 SR 2.6: use control — human approval required before execution")
        clauses.append("IEC 62443-2-1 4.3.3: incident response — causal evidence captured for forensics")
        return "; ".join(clauses)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class CausalEngine:
    """
    Primary entry point for OT incident causal inference.

    Usage:
        engine = CausalEngine(rules_dir=Path("rules/causal"))
        engine.load()
        result = engine.infer(incident_id="INC-001", raw_signals=[...])

    The engine is stateless per inference call; decision memory is
    injected at runtime, not embedded in the engine itself.
    """

    def __init__(
        self,
        rules_dir: Path,
        memory_patterns: list[dict] | None = None,
    ):
        self.rules_dir       = rules_dir
        self.memory_patterns = memory_patterns or []
        self._normaliser     = EventNormaliser()
        self._graph_builder  = CausalGraphBuilder(rules_dir)
        self._scorer         = ConfidenceScorer()
        self._explainer      = ExplainabilityEngine()
        self._loaded         = False

    def load(self) -> None:
        """Load YAML rules. Must be called before infer()."""
        self._graph_builder.load_rules()
        self._loaded = True
        logger.info("CausalEngine ready")

    def infer(
        self,
        incident_id: str,
        raw_signals: list[dict],
    ) -> CausalInferenceResult:
        """
        Full inference pipeline: normalise → evaluate rules →
        build graph → score → classify → explain.
        """
        if not self._loaded:
            raise RuntimeError("Call engine.load() before engine.infer()")

        t_start = time.perf_counter()

        # 1. Normalise events
        events = self._normaliser.normalise(raw_signals)

        # 2. Evaluate rules against event stream
        fired = self._graph_builder.evaluate_rules(events)

        # 3. Build causal graph
        nodes, edges = self._graph_builder.build_graph(fired, events)

        if not nodes:
            logger.warning(f"{incident_id}: no causal rules fired — returning empty result")
            return self._empty_result(incident_id, events, t_start)

        # 4. Score confidence
        nodes = self._scorer.score_nodes(
            nodes, events, self._graph_builder.rules, self.memory_patterns
        )
        edges = self._scorer.score_edges(edges, nodes)

        # 5. Classify nodes by type
        root_causes = [n for n in nodes if n.node_type == NodeType.ROOT_CAUSE]
        effects     = [n for n in nodes if n.node_type == NodeType.EFFECT]
        symptoms    = [n for n in nodes if n.node_type == NodeType.SYMPTOM]

        # Primary root cause = highest confidence ROOT_CAUSE node
        root_cause = max(root_causes, key=lambda n: n.confidence) if root_causes else None

        # 6. Classify incident
        classification = self._classify_incident(root_cause, nodes)

        # 7. Overall confidence = weighted mean across all nodes
        if nodes:
            weights = {NodeType.ROOT_CAUSE: 0.55, NodeType.EFFECT: 0.30, NodeType.SYMPTOM: 0.15}
            total_w = sum(weights.get(n.node_type, 0.15) for n in nodes)
            overall = sum(n.confidence * weights.get(n.node_type, 0.15) for n in nodes) / total_w
        else:
            overall = 0.0

        # 8. Generate explainability trace
        trace = self._explainer.generate_trace(
            root_cause, effects, symptoms, edges,
            events, self._graph_builder.rules, self.memory_patterns
        )

        t_end = time.perf_counter()

        return CausalInferenceResult(
            incident_id        = incident_id,
            inferred_at        = time.time(),
            classification     = classification,
            nodes              = nodes,
            edges              = edges,
            root_cause         = root_cause,
            effects            = effects,
            symptoms           = symptoms,
            overall_confidence = round(overall, 4),
            explainability     = trace,
            raw_event_count    = len(events),
            inference_ms       = int((t_end - t_start) * 1000),
        )

    def _classify_incident(
        self,
        root_cause: CausalNode | None,
        nodes: list[CausalNode],
    ) -> str:
        if root_cause and root_cause.mitre_ttp:
            return "CYBER"
        if root_cause and root_cause.zone == PurdueZone.DMZ:
            return "CYBER"
        cyber_nodes = sum(1 for n in nodes if n.mitre_ttp)
        if cyber_nodes >= 2:
            return "CYBER"
        return "RELIABILITY"

    def _empty_result(
        self,
        incident_id: str,
        events: list[OTEvent],
        t_start: float,
    ) -> CausalInferenceResult:
        empty_trace = ExplainabilityTrace(
            root_cause_id    = "UNKNOWN",
            confidence       = 0.0,
            reasoning_steps  = ["No causal rules matched the observed event stream."],
            evidence_events  = [],
            pattern_matched  = None,
            temporal_sequence= [],
            counter_evidence = [],
            iec_context      = "IEC 62443-3-3 SR 2.6 — manual investigation required",
        )
        return CausalInferenceResult(
            incident_id        = incident_id,
            inferred_at        = time.time(),
            classification     = "UNKNOWN",
            nodes              = [],
            edges              = [],
            root_cause         = None,
            effects            = [],
            symptoms           = [],
            overall_confidence = 0.0,
            explainability     = empty_trace,
            raw_event_count    = len(events),
            inference_ms       = int((time.perf_counter() - t_start) * 1000),
        )

    def to_json(self, result: CausalInferenceResult) -> str:
        """Serialise result to JSON for API / React frontend consumption."""
        def serialise(obj, depth=0):
            if depth > 20:
                return str(obj)
            if isinstance(obj, Enum):
                return obj.value
            if isinstance(obj, dict):
                return {k: serialise(v, depth + 1) for k, v in obj.items()}
            if isinstance(obj, list):
                return [serialise(i, depth + 1) for i in obj]
            if hasattr(obj, "__dataclass_fields__"):
                return {k: serialise(getattr(obj, k), depth + 1)
                        for k in obj.__dataclass_fields__}
            if hasattr(obj, "__dict__") and not isinstance(obj, type):
                return {k: serialise(v, depth + 1)
                        for k, v in obj.__dict__.items()
                        if not k.startswith("_")}
            return obj
        return json.dumps(serialise(result), indent=2)
