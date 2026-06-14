"""
CausalAgent :: MitreICSClassifier
==================================

MITRE ATT&CK® for ICS technique scoring engine for OT cyber incident classification.

Problem statement
-----------------
Distinguishing a cyber-initiated OT incident from a reliability failure is not
straightforward from raw alarm data alone. A flow control valve at 12% position
could indicate a stuck valve, a calibration drift, or an adversary exploiting
a DNP3 direct operate vulnerability. This module scores normalised OT event
streams against the MITRE ATT&CK for ICS technique taxonomy to produce a
structured, evidence-weighted cyber probability assessment.

Technique coverage (ICS matrix v14 — operationally prioritised subset)
-----------------------------------------------------------------------
    T0836  Modify Parameter          Impair Process Control    — active manipulation
    T0855  Unauthorized Command Msg  Impair Process Control    — active manipulation
    T0814  Denial of Service         Inhibit Response Function — active disruption
    T0816  Device Restart/Shutdown   Inhibit Response Function — active disruption
    T0801  Monitor Process State     Collection                — passive reconnaissance
    T0828  Loss of Productivity      Impact                    — outcome indicator
    T0813  Denial of Control         Inhibit Response Function — active disruption
    T0835  Manipulate I/O Image      Impair Process Control    — active manipulation
    T0831  Manipulation of Control   Impair Process Control    — active manipulation
    T0840  Network Connection Enum   Discovery                 — passive reconnaissance

Reference: https://attack.mitre.org/matrices/ics/

Scoring model
-------------
For each technique, a set of signal indicators is defined in rules/mitre_ics.yaml.
Each indicator has a weight in (0, 1] with all weights summing to 1.0 per technique.

    technique_confidence = Σ(matched_indicator_weights) / Σ(all_indicator_weights)

Indicator conditions supported:
    present              — tag or protocol present anywhere in event stream
    value_deviation_pct  — abs((value - nominal_mid) / nominal_mid) × 100 >= threshold
    severity_crit        — tag has at least one CRIT-severity event
    high_event_rate      — event count for tag >= threshold
    cross_zone_protocol  — protocol observed in unexpected Purdue zone

Cyber confidence aggregation
-----------------------------
Active manipulation TTPs (T0836, T0855, T0813, T0831, T0835) indicate an adversary
is actively modifying the controlled process — higher threat weight (0.75).
Passive reconnaissance TTPs (T0801, T0840) indicate collection/discovery activity
without confirmed process impact — lower weight (0.25).

    cyber_confidence = (Σ active_TTP_scores / n_active_TTPs) × 0.75
                     + (Σ passive_TTP_scores / n_passive_TTPs) × 0.25

Classification threshold: CYBER if cyber_confidence > 0.45, else RELIABILITY.

Design decisions
----------------
Indicator matching is intentionally conservative — a technique only scores if OT
signals directly supporting that technique's operational indicators are present.
Generic IT security signals (failed logins, port scans on IT ranges) are not
included as ICS technique indicators to avoid false-positive cyber classification
of reliability incidents. Protocol-specific indicators (DNP3 for T0855, OPC-UA
for T0813) are given priority over generic presence checks.

Standards alignment
-------------------
    MITRE ATT&CK for ICS v14   Primary taxonomy reference
    IEC 62443-3-3 SR 2.6       Use Control — cyber classification gates action decisions
    NIST SP 800-82 Rev 3       OT security incident categorisation

Author: Suresh Dakha
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# DATA TYPES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TTPScore:
    technique_id:  str
    name:          str
    tactic:        str
    confidence:    float        # 0.0 – 1.0
    matched_signals: list[str]  # Tags/protocols that contributed to score
    explanation:   str


@dataclass
class MitreClassificationResult:
    primary_ttp:        TTPScore | None
    all_scores:         list[TTPScore]
    classification:     str         # CYBER | RELIABILITY
    cyber_confidence:   float       # Overall probability this is a cyber event
    top_tactics:        list[str]   # Tactics with evidence


# ─────────────────────────────────────────────────────────────────────────────
# MITRE ICS CLASSIFIER
# ─────────────────────────────────────────────────────────────────────────────

class MitreICSClassifier:
    """
    Scores OT event streams against MITRE ATT&CK for ICS techniques.

    Scoring model:
      For each technique, a set of signal indicators is defined in YAML.
      Each indicator has a weight (0.0 – 1.0).
      Technique confidence = Σ(matched indicator weights) / Σ(all indicator weights).

    YAML structure (rules/mitre_ics.yaml):
        T0836:
          name: Modify Parameter
          tactic: Impair Process Control
          indicators:
            - tag: FCV-R2
              condition: value_deviation_pct
              threshold: 30
              weight: 0.40
            - protocol: DNP3
              condition: unsolicited_response
              weight: 0.35
            - tag: EW-04
              condition: present
              weight: 0.25
    """

    def __init__(self, rules_path: Path):
        self.rules_path = rules_path
        self.rules: dict = {}

    def load_rules(self) -> None:
        with open(self.rules_path) as f:
            self.rules = yaml.safe_load(f) or {}
        logger.info(f"Loaded MITRE ICS rules for {len(self.rules)} techniques")

    def classify(self, events: list[dict]) -> MitreClassificationResult:
        """
        Score all techniques against the event stream.
        events: list of normalised event dicts (from EventNormaliser output).
        """
        scores: list[TTPScore] = []

        event_tags      = {e.get("tag", "")      for e in events}
        event_protocols = {e.get("protocol", "")  for e in events}
        event_severities= {e.get("severity", "")  for e in events}

        for ttp_id, rule in self.rules.items():
            indicators = rule.get("indicators", [])
            if not indicators:
                continue

            total_weight   = sum(ind.get("weight", 0.0) for ind in indicators)
            matched_weight = 0.0
            matched_sigs   = []
            explanations   = []

            for ind in indicators:
                hit, reason = self._evaluate_indicator(ind, events, event_tags, event_protocols)
                if hit:
                    matched_weight += ind.get("weight", 0.0)
                    sig = ind.get("tag") or ind.get("protocol") or "signal"
                    matched_sigs.append(sig)
                    explanations.append(reason)

            confidence = matched_weight / total_weight if total_weight > 0 else 0.0

            scores.append(TTPScore(
                technique_id   = ttp_id,
                name           = rule.get("name", ttp_id),
                tactic         = rule.get("tactic", ""),
                confidence     = round(confidence, 4),
                matched_signals= matched_sigs,
                explanation    = "; ".join(explanations) if explanations else "No indicators matched.",
            ))

        scores.sort(key=lambda s: s.confidence, reverse=True)
        primary = scores[0] if scores and scores[0].confidence > 0.3 else None

        cyber_score  = self._cyber_confidence(scores)
        top_tactics  = list({s.tactic for s in scores if s.confidence > 0.3})
        classification = "CYBER" if cyber_score > 0.45 else "RELIABILITY"

        return MitreClassificationResult(
            primary_ttp      = primary,
            all_scores       = scores,
            classification   = classification,
            cyber_confidence = round(cyber_score, 4),
            top_tactics      = top_tactics,
        )

    def _evaluate_indicator(
        self,
        indicator: dict,
        events: list[dict],
        event_tags: set[str],
        event_protocols: set[str],
    ) -> tuple[bool, str]:
        """
        Evaluate a single indicator against the event stream.
        Returns (matched: bool, explanation: str).
        """
        condition = indicator.get("condition", "present")
        tag       = indicator.get("tag")
        protocol  = indicator.get("protocol")
        threshold = indicator.get("threshold", 0)

        # Tag presence check
        if condition == "present":
            if tag and tag in event_tags:
                return True, f"Tag {tag} observed in event stream"
            if protocol and protocol in event_protocols:
                return True, f"Protocol {protocol} observed in event stream"
            return False, ""

        # Value deviation check (percentage deviation from expected)
        if condition == "value_deviation_pct" and tag:
            for e in events:
                if e.get("tag") != tag:
                    continue
                nominal_min = e.get("nominal_min", 0)
                nominal_max = e.get("nominal_max", 100)
                value = float(e.get("value", 0))
                nominal_mid = (nominal_min + nominal_max) / 2
                if nominal_mid == 0:
                    continue
                deviation_pct = abs((value - nominal_mid) / nominal_mid) * 100
                if deviation_pct >= threshold:
                    return True, f"{tag} deviated {deviation_pct:.1f}% from nominal (threshold: {threshold}%)"
            return False, ""

        # Severity filter
        if condition == "severity_crit" and tag:
            for e in events:
                if e.get("tag") == tag and e.get("severity") == "CRIT":
                    return True, f"Critical severity event from {tag}"
            return False, ""

        # High event rate (more than threshold events from same source)
        if condition == "high_event_rate" and tag:
            count = sum(1 for e in events if e.get("tag") == tag)
            if count >= threshold:
                return True, f"{tag} generated {count} events (threshold: {threshold})"
            return False, ""

        # Cross-zone protocol usage (unexpected protocol in zone)
        if condition == "cross_zone_protocol" and protocol:
            for e in events:
                if (e.get("protocol") == protocol and
                        e.get("zone") in indicator.get("unexpected_zones", [])):
                    return True, f"Protocol {protocol} observed in unexpected zone {e.get('zone')}"
            return False, ""

        return False, ""

    def _cyber_confidence(self, scores: list[TTPScore]) -> float:
        """
        Aggregate cyber confidence from TTP scores.
        Weighted by technique relevance to active compromise vs passive monitoring.
        """
        active_ttps = {"T0836", "T0855", "T0813", "T0831", "T0835", "T0816"}
        passive_ttps= {"T0801", "T0840"}

        active_score  = sum(s.confidence for s in scores if s.technique_id in active_ttps)
        passive_score = sum(s.confidence for s in scores if s.technique_id in passive_ttps)

        n_active  = max(len(active_ttps), 1)
        n_passive = max(len(passive_ttps), 1)

        return (active_score / n_active) * 0.75 + (passive_score / n_passive) * 0.25
