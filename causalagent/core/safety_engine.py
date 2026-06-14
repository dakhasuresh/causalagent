"""
CausalAgent :: SafetyEngine
===========================

IEC 62443-aligned safety guardrail enforcement for OT incident response actions.

Problem statement
-----------------
Incident response in OT environments introduces a second risk layer: the response
action itself. A setpoint revert on a flow control valve during an active cyber
incident may compound adversarial manipulation. An emergency shutdown triggered on
insufficient causal evidence causes 8–12 hours of production loss unnecessarily.
A firmware rollback during production uptime causes a device reboot and service gap.
This module enforces normative safety constraints on every proposed action *before*
it reaches an operator or executes autonomously.

Design rationale
----------------
All guardrail logic is externalised to rules/safety/guardrails.yaml. The Python
engine evaluates conditions deterministically — no ML inference, no probabilistic
gating — and produces a typed decision with a normative IEC clause citation. This
design allows guardrail rules to be reviewed and extended by process safety engineers
without modifying application code, and produces audit-ready decision records.

Decision tiers (in priority order)
------------------------------------
    BLOCK       Action must not execute under any circumstance given current context.
                Caller cannot override. IEC clause cited in every violation.
                Example: autonomous setpoint revert during active cyber incident
                         violates IEC 62443-3-3 SR 2.6 (Use Control).

    ESCALATE    Must go to a process safety engineer or safety officer before any
                action. Applies to SIL-zone modifications requiring IEC 61511
                Management of Change (MOC) process compliance.

    HUMAN_GATE  Requires operator approval. Full causal justification surfaced in
                approval interface. Used for: network isolation (SR 5.1), setpoint
                revert (SR 2.6), firmware rollback (IEC 62443-2-3), forensic
                capture (IEC 62443-2-1 4.3.3).

    ALLOW       Safe for autonomous execution. Production impact NONE or MINOR.
                Action is REVERSIBLE. No guardrail violations. auto_executable=True.

Evaluation pipeline
-------------------
    ActionProposal
        │
        ▼
    ReversibilityClassifier
        REVERSIBLE    — can be undone in <5 min (network_isolate, setpoint_revert,
                        alarm_acknowledge, threshold_adjust)
        RECOVERABLE   — can be undone but takes effort (firmware_rollback,
                        config_change)
        IRREVERSIBLE  — cannot be undone in short term (emergency_shutdown,
                        physical field action)
        Irreversible actions auto-elevate context flag for guardrail evaluation.
        │
        ▼
    ProductionImpactModel
        action_type × Purdue_zone → ProductionImpact enum:
        NONE | MINOR (<15min) | MODERATE (15min–4hr) | MAJOR (>4hr) | CRITICAL (SIL trip)
        │
        ▼
    GuardrailEvaluator
        Evaluates each YAML guardrail rule in sequence.
        Rule applies if action_type and zone match rule scope.
        Rule fires if condition is met given evaluation context dict.
        Returns GuardrailViolation[] with rule_id, IEC clause, reason string.
        │
        ▼
    SafetyDecision
        decision           — BLOCK | ESCALATE | HUMAN_GATE | ALLOW
        reversibility      — from ReversibilityClassifier
        production_impact  — from ProductionImpactModel
        violations[]       — list of fired guardrail rules with IEC citations
        iec_clauses_checked— union of all clause references across violations
        explanation        — structured explanation for decision log
        human_prompt       — operator-facing approval text (HUMAN_GATE only)
        auto_executable    — True only for ALLOW + NONE/MINOR impact + REVERSIBLE

Context dict fields
-------------------
    classification       str   "CYBER" | "RELIABILITY" — from CausalEngine
    overall_confidence   float 0.0–1.0 — from CausalEngine
    root_cause_verified  bool  True if root_cause is not None
    production_active    bool  True if plant is in production state
    irreversible_action  bool  Set automatically by ReversibilityClassifier

Standards alignment
-------------------
    IEC 62443-3-3 SR 2.6   Use Control — setpoint and config change gating
    IEC 62443-3-3 SR 3.6   Timely Response — ESD block under low confidence
    IEC 62443-3-3 SR 5.1   Network Segmentation — isolation action gating
    IEC 62443-3-3 SR 7.7   Least Privilege — redundant path activation
    IEC 62443-2-3           Patch Management — firmware rollback gate
    IEC 62443-2-1 4.3.3     Incident Response — forensic capture gate
    IEC 61511-1 Clause 11   SIL MOC — SIL-zone modification escalation
    ISA-84                  Functional Safety — equivalent to IEC 61511

Author: Suresh Dakha
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# DATA TYPES
# ─────────────────────────────────────────────────────────────────────────────

class ActionDecision(str, Enum):
    ALLOW       = "ALLOW"       # Safe to execute autonomously
    HUMAN_GATE  = "HUMAN_GATE"  # Requires human approval before execution
    BLOCK       = "BLOCK"       # Guardrail prevents execution entirely
    ESCALATE    = "ESCALATE"    # Must go to senior engineer / safety officer

class ReversibilityClass(str, Enum):
    REVERSIBLE      = "REVERSIBLE"       # Can be undone in < 5 min
    RECOVERABLE     = "RECOVERABLE"      # Can be undone but takes time/effort
    IRREVERSIBLE    = "IRREVERSIBLE"     # Cannot be undone (ESD, physical action)

class ProductionImpact(str, Enum):
    NONE     = "NONE"     # Zero production impact
    MINOR    = "MINOR"    # < 15 min downtime
    MODERATE = "MODERATE" # 15 min – 4 hr downtime
    MAJOR    = "MAJOR"    # > 4 hr downtime or SIL trip
    CRITICAL = "CRITICAL" # Full plant shutdown


@dataclass
class ActionProposal:
    """
    A proposed remediation action from the Agentic Planner.
    """
    action_id:       str
    description:     str
    target_tag:      str            # OT tag this action touches
    target_zone:     str            # Purdue zone
    action_type:     str            # config_change, network_isolate, setpoint_revert, etc.
    iec_requirement: str            # Proposed IEC 62443 SR clause
    metadata:        dict = field(default_factory=dict)


@dataclass
class GuardrailViolation:
    """
    A specific rule that was violated by a proposed action.
    """
    rule_id:        str
    rule_name:      str
    iec_clause:     str
    reason:         str
    severity:       str             # WARNING | BLOCK | ESCALATE


@dataclass
class SafetyDecision:
    """
    Full safety evaluation output for a proposed action.
    """
    action_id:          str
    decision:           ActionDecision
    reversibility:      ReversibilityClass
    production_impact:  ProductionImpact
    violations:         list[GuardrailViolation]
    iec_clauses_checked: list[str]
    explanation:        str
    human_prompt:       str | None      # What to show the operator in the approval UI
    auto_executable:    bool


# ─────────────────────────────────────────────────────────────────────────────
# GUARDRAIL EVALUATOR
# ─────────────────────────────────────────────────────────────────────────────

class GuardrailEvaluator:
    """
    Evaluates actions against YAML-defined safety guardrails.

    Guardrail rule structure (YAML):
        rule_id:
          name: human label
          applies_to_action_types: [list]
          applies_to_zones: [list]
          condition: description of what triggers this rule
          decision: BLOCK | HUMAN_GATE | ESCALATE
          iec_clause: IEC 62443-3-3 SR X.X
          reason_template: "..."
    """

    def __init__(self, rules_path: Path):
        self.rules_path = rules_path
        self.rules: dict = {}

    def load_rules(self) -> None:
        with open(self.rules_path) as f:
            self.rules = yaml.safe_load(f) or {}
        logger.info(f"Loaded {len(self.rules)} safety guardrail rules")

    def evaluate(
        self,
        action: ActionProposal,
        context: dict | None = None,
    ) -> list[GuardrailViolation]:
        """
        Evaluate a single action against all guardrail rules.
        Returns list of violations (empty = no violations).
        """
        violations: list[GuardrailViolation] = []
        ctx = context or {}

        for rule_id, rule in self.rules.items():
            if not self._rule_applies(rule, action, ctx):
                continue

            if self._rule_fires(rule, action, ctx):
                violations.append(GuardrailViolation(
                    rule_id   = rule_id,
                    rule_name = rule.get("name", rule_id),
                    iec_clause= rule.get("iec_clause", ""),
                    reason    = self._format_reason(rule, action, ctx),
                    severity  = rule.get("decision", "BLOCK"),
                ))

        return violations

    def _rule_applies(self, rule: dict, action: ActionProposal, ctx: dict) -> bool:
        """Does this rule apply to the given action type and zone?"""
        action_types = rule.get("applies_to_action_types", [])
        zones        = rule.get("applies_to_zones", [])

        if action_types and action.action_type not in action_types:
            return False
        if zones and action.target_zone not in zones:
            return False
        return True

    def _rule_fires(self, rule: dict, action: ActionProposal, ctx: dict) -> bool:
        """
        Evaluate whether the rule's condition is met.
        Condition types: active_cyber, uncertain_cause, sil_zone,
                         irreversible, unverified_cause, production_active
        """
        condition = rule.get("condition", "")

        checks = {
            "active_cyber":       ctx.get("classification") == "CYBER",
            "uncertain_cause":    ctx.get("overall_confidence", 1.0) < 0.75,
            "sil_zone":           action.target_zone in ["L1", "L0"],
            "irreversible":       ctx.get("irreversible_action", False),
            "unverified_cause":   not ctx.get("root_cause_verified", False),
            "production_active":  ctx.get("production_active", True),
            "always":             True,
        }

        return checks.get(condition, False)

    def _format_reason(self, rule: dict, action: ActionProposal, ctx: dict) -> str:
        template = rule.get("reason_template", "Action blocked by safety guardrail.")
        return template.format(
            action_type    = action.action_type,
            target_tag     = action.target_tag,
            zone           = action.target_zone,
            classification = ctx.get("classification", "UNKNOWN"),
            confidence     = f"{ctx.get('overall_confidence', 0.0)*100:.1f}%",
        )


# ─────────────────────────────────────────────────────────────────────────────
# PRODUCTION IMPACT MODEL
# ─────────────────────────────────────────────────────────────────────────────

class ProductionImpactModel:
    """
    Estimates production impact of an action before execution.

    Uses action type + target zone to determine blast radius.
    Conservative-by-default: unknown actions get MODERATE impact.
    """

    IMPACT_MATRIX: dict[str, dict[str, ProductionImpact]] = {
        # action_type → zone → impact
        "network_isolate": {
            "DMZ": ProductionImpact.NONE,
            "L3":  ProductionImpact.MINOR,
            "L2":  ProductionImpact.MODERATE,
            "L1":  ProductionImpact.MAJOR,
            "L0":  ProductionImpact.CRITICAL,
        },
        "setpoint_revert": {
            "L1":  ProductionImpact.MINOR,
            "L0":  ProductionImpact.MODERATE,
        },
        "firmware_rollback": {
            "L2":  ProductionImpact.MINOR,
            "L1":  ProductionImpact.MODERATE,
        },
        "alarm_acknowledge": {
            "L2":  ProductionImpact.NONE,
            "L1":  ProductionImpact.NONE,
        },
        "session_restore": {
            "L2":  ProductionImpact.NONE,
        },
        "threshold_adjust": {
            "L2":  ProductionImpact.NONE,
            "L1":  ProductionImpact.NONE,
        },
        "emergency_shutdown": {
            "L1":  ProductionImpact.CRITICAL,
            "L0":  ProductionImpact.CRITICAL,
        },
        "forensic_capture": {
            "DMZ": ProductionImpact.NONE,
            "L2":  ProductionImpact.NONE,
        },
    }

    def assess(self, action: ActionProposal) -> ProductionImpact:
        zone_map = self.IMPACT_MATRIX.get(action.action_type, {})
        return zone_map.get(action.target_zone, ProductionImpact.MODERATE)


# ─────────────────────────────────────────────────────────────────────────────
# REVERSIBILITY CLASSIFIER
# ─────────────────────────────────────────────────────────────────────────────

class ReversibilityClassifier:
    """
    Classifies whether an action can be undone.
    Irreversible actions always require human approval (HUMAN_GATE minimum).
    """

    REVERSIBILITY_MAP: dict[str, ReversibilityClass] = {
        "network_isolate":    ReversibilityClass.REVERSIBLE,
        "setpoint_revert":    ReversibilityClass.REVERSIBLE,
        "firmware_rollback":  ReversibilityClass.RECOVERABLE,
        "alarm_acknowledge":  ReversibilityClass.REVERSIBLE,
        "session_restore":    ReversibilityClass.REVERSIBLE,
        "threshold_adjust":   ReversibilityClass.REVERSIBLE,
        "emergency_shutdown": ReversibilityClass.IRREVERSIBLE,
        "forensic_capture":   ReversibilityClass.REVERSIBLE,
        "config_change":      ReversibilityClass.RECOVERABLE,
    }

    def classify(self, action: ActionProposal) -> ReversibilityClass:
        return self.REVERSIBILITY_MAP.get(
            action.action_type, ReversibilityClass.RECOVERABLE
        )


# ─────────────────────────────────────────────────────────────────────────────
# SAFETY ENGINE (Main Entry Point)
# ─────────────────────────────────────────────────────────────────────────────

class SafetyEngine:
    """
    Primary entry point for IEC 62443-aligned safety evaluation.

    Usage:
        engine = SafetyEngine(guardrail_rules_path=Path("rules/safety/guardrails.yaml"))
        engine.load()
        decisions = engine.evaluate_actions(proposals, causal_context)
    """

    def __init__(self, guardrail_rules_path: Path):
        self.guardrail_rules_path = guardrail_rules_path
        self._evaluator   = GuardrailEvaluator(guardrail_rules_path)
        self._impact      = ProductionImpactModel()
        self._reversibility = ReversibilityClassifier()
        self._loaded      = False

    def load(self) -> None:
        self._evaluator.load_rules()
        self._loaded = True
        logger.info("SafetyEngine ready")

    def evaluate_actions(
        self,
        proposals: list[ActionProposal],
        causal_context: dict,
    ) -> list[SafetyDecision]:
        """
        Evaluate all proposed actions and return safety decisions.
        Sorted by priority: blocked first, then human-gated, then auto.
        """
        if not self._loaded:
            raise RuntimeError("Call engine.load() before evaluate_actions()")

        decisions = [
            self._evaluate_single(p, causal_context)
            for p in proposals
        ]
        return sorted(decisions, key=lambda d: (
            {"BLOCK": 0, "ESCALATE": 1, "HUMAN_GATE": 2, "ALLOW": 3}[d.decision.value]
        ))

    def _evaluate_single(
        self,
        action: ActionProposal,
        ctx: dict,
    ) -> SafetyDecision:
        reversibility = self._reversibility.classify(action)
        impact        = self._impact.assess(action)

        # Irreversible actions always need human gate at minimum
        if reversibility == ReversibilityClass.IRREVERSIBLE:
            ctx = {**ctx, "irreversible_action": True}

        violations = self._evaluator.evaluate(action, ctx)

        # Determine overall decision
        if any(v.severity == "BLOCK" for v in violations):
            decision = ActionDecision.BLOCK
        elif any(v.severity == "ESCALATE" for v in violations):
            decision = ActionDecision.ESCALATE
        elif (violations or
              reversibility == ReversibilityClass.IRREVERSIBLE or
              impact in (ProductionImpact.MAJOR, ProductionImpact.CRITICAL)):
            decision = ActionDecision.HUMAN_GATE
        else:
            decision = ActionDecision.ALLOW

        auto_executable = (
            decision == ActionDecision.ALLOW and
            impact in (ProductionImpact.NONE, ProductionImpact.MINOR) and
            reversibility == ReversibilityClass.REVERSIBLE
        )

        explanation = self._build_explanation(action, decision, violations, impact, reversibility)
        human_prompt = self._build_human_prompt(action, violations, impact) if decision == ActionDecision.HUMAN_GATE else None

        iec_clauses = list({v.iec_clause for v in violations if v.iec_clause})
        if action.iec_requirement:
            iec_clauses.append(action.iec_requirement)

        return SafetyDecision(
            action_id           = action.action_id,
            decision            = decision,
            reversibility       = reversibility,
            production_impact   = impact,
            violations          = violations,
            iec_clauses_checked = iec_clauses,
            explanation         = explanation,
            human_prompt        = human_prompt,
            auto_executable     = auto_executable,
        )

    def _build_explanation(
        self,
        action: ActionProposal,
        decision: ActionDecision,
        violations: list[GuardrailViolation],
        impact: ProductionImpact,
        reversibility: ReversibilityClass,
    ) -> str:
        parts = [
            f"Action '{action.description}' evaluated: {decision.value}.",
            f"Production impact: {impact.value}. Reversibility: {reversibility.value}.",
        ]
        if violations:
            parts.append(
                f"Guardrail violations: {'; '.join(v.reason for v in violations[:2])}."
            )
        if decision == ActionDecision.ALLOW:
            parts.append("All safety checks passed. Safe for autonomous execution.")
        return " ".join(parts)

    def _build_human_prompt(
        self,
        action: ActionProposal,
        violations: list[GuardrailViolation],
        impact: ProductionImpact,
    ) -> str:
        prompt_lines = [
            f"HUMAN APPROVAL REQUIRED",
            f"Action: {action.description}",
            f"Target: {action.target_tag} ({action.target_zone})",
            f"Estimated production impact: {impact.value}",
        ]
        if violations:
            prompt_lines.append(f"Safety notes: {violations[0].reason}")
        prompt_lines.append("Approve only after verifying causal reasoning trace.")
        return "\n".join(prompt_lines)
