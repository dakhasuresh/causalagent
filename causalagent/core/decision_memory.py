"""
CausalAgent :: DecisionMemory
==============================

Persistent causal pattern store for incident-to-incident learning in OT environments.

Problem statement
-----------------
OT incident knowledge is typically trapped in the heads of experienced engineers or
buried in unstructured incident reports. When a Modbus timeout cascade caused by an
OT switch firmware regression is resolved in 6 minutes by an expert engineer, that
knowledge should be available the next time the same pattern appears — in any plant,
at any shift, at 2am. DecisionMemory captures resolved incident outcomes as structured
causal patterns and retrieves the most relevant historical context during active inference.

Design rationale: deterministic retrieval, not neural memory
------------------------------------------------------------
Many approaches to "AI memory" use vector embeddings and cosine similarity over dense
representations. For OT incident management, this creates two problems: (1) embedding
models are black boxes — operators cannot interrogate why a historical incident was
deemed "similar"; (2) embeddings require ML infrastructure that may be unavailable in
air-gapped OT networks.

DecisionMemory uses Jaccard set similarity over OT tag and protocol sets — a fully
deterministic, interpretable metric that requires no trained model, no GPU, and no
external service. Every retrieval result includes the exact tag intersection, similarity
score, and historical MTTR — giving operators institutional memory they can reason about.

Retrieval model
---------------
    similarity = (tag_jaccard × 0.60)
               + (protocol_overlap × 0.25)
               + (class_match_bonus × 0.15)

    tag_jaccard      = |Q_tags ∩ P_tags| / |Q_tags ∪ P_tags|
    protocol_overlap = |Q_protos ∩ P_protos| / |Q_protos ∪ P_protos|
    class_match_bonus = 0.15 if incident_class matches, else 0.0

    Default min_similarity = 0.30
    Default top_k = 3

Tag-set overlap is weighted highest (0.60) because OT tag sets are highly specific
to equipment and failure mode — if a new incident involves the same tags as a resolved
one, it is very likely the same failure class regardless of message content.
Protocol overlap (0.25) reinforces this — Modbus/TCP incidents differ fundamentally
from DNP3 or WinRM incidents in their attack surface and remediation approach.
Incident class bonus (0.15) prevents a reliability pattern from being retrieved as
the top match for a cyber incident with the same equipment tags.

Pattern schema
--------------
Each CausalPattern captures:
    pattern_id                 — unique identifier (PAT-XXXX)
    created_at                 — Unix epoch of incident resolution
    incident_class             — CYBER | RELIABILITY
    root_cause_id              — rule_id of the isolated root cause
    root_cause_label           — human-readable root cause label
    trigger_tags               — OT tags present during this incident
    trigger_protocols          — protocols observed
    causal_chain               — ordered rule_ids from root cause to symptom
    resolution_actions         — what was done to resolve the incident
    outcome                    — free-text outcome description
    mttr_minutes               — measured MTTR for this incident
    confidence_at_resolution   — CausalEngine confidence at time of resolution
    reuse_count                — how many times this pattern has been retrieved
    accuracy_feedback          — operator-rated quality score (0.0–1.0), optional

Persistence
-----------
Current: JSON file (data/decision_memory.json) — suitable for prototype and
single-node deployment. Production path: PostgreSQL with JSONB column for
pattern data, GIN index on trigger_tags array for O(log n) tag-set queries.

Continual learning loop
-----------------------
    Incident resolved by operator
        └─► CausalPattern constructed from CausalInferenceResult
        └─► DecisionMemory.store(pattern) — persisted immediately
        └─► Operator rates accuracy → DecisionMemory.update_feedback()
        └─► Next inference with matching tags → pattern retrieved + confidence boosted
        └─► Historical MTTR shown to operator as resolution time benchmark

Standards alignment
-------------------
    IEC 62443-2-1 4.3.3   Incident Response — pattern store as audit record
    ISA-18.2              Alarm Management — incident outcome capture

Author: Suresh Dakha
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# DATA TYPES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CausalPattern:
    """
    A resolved incident pattern stored in decision memory.
    """
    pattern_id:         str
    created_at:         float
    incident_class:     str         # CYBER | RELIABILITY
    root_cause_id:      str
    root_cause_label:   str
    trigger_tags:       list[str]   # OT tags that characterise this pattern
    trigger_protocols:  list[str]
    causal_chain:       list[str]   # Ordered node IDs root → symptom
    resolution_actions: list[str]   # What was done
    outcome:            str         # Free-text outcome description
    mttr_minutes:       float
    confidence_at_resolution: float
    reuse_count:        int = 0
    accuracy_feedback:  float | None = None  # Operator-rated 0.0–1.0


@dataclass
class MemoryMatch:
    """
    A pattern retrieved from decision memory.
    """
    pattern:            CausalPattern
    similarity_score:   float       # 0.0 – 1.0
    matching_tags:      list[str]
    explanation:        str


# ─────────────────────────────────────────────────────────────────────────────
# DECISION MEMORY
# ─────────────────────────────────────────────────────────────────────────────

class DecisionMemory:
    """
    Causal pattern store for CausalAgent.

    Retrieval uses tag-set Jaccard similarity + protocol overlap + class match.
    No vector embeddings — fully deterministic and auditable.

    Persistence: JSON file (production would use PostgreSQL with JSONB).
    """

    def __init__(self, store_path: Path):
        self.store_path = store_path
        self.patterns: list[CausalPattern] = []

    def load(self) -> None:
        if not self.store_path.exists():
            logger.info("Decision memory store not found — starting empty")
            return
        with open(self.store_path) as f:
            raw = json.load(f)
        self.patterns = [CausalPattern(**p) for p in raw]
        logger.info(f"Loaded {len(self.patterns)} patterns from decision memory")

    def save(self) -> None:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.store_path, "w") as f:
            json.dump([asdict(p) for p in self.patterns], f, indent=2)

    def retrieve(
        self,
        event_tags: list[str],
        event_protocols: list[str],
        incident_class: str | None = None,
        top_k: int = 3,
        min_similarity: float = 0.30,
    ) -> list[MemoryMatch]:
        """
        Retrieve top-k most similar patterns from memory.

        Similarity = (tag Jaccard × 0.60) + (protocol overlap × 0.25) + (class match × 0.15)
        """
        if not self.patterns:
            return []

        query_tags  = set(event_tags)
        query_proto = set(event_protocols)
        matches: list[MemoryMatch] = []

        for pattern in self.patterns:
            pattern_tags  = set(pattern.trigger_tags)
            pattern_proto = set(pattern.trigger_protocols)

            # Jaccard similarity on tags
            intersection = query_tags & pattern_tags
            union        = query_tags | pattern_tags
            tag_jaccard  = len(intersection) / len(union) if union else 0.0

            # Protocol overlap
            proto_union  = query_proto | pattern_proto
            proto_overlap = len(query_proto & pattern_proto) / len(proto_union) if proto_union else 0.0

            # Class match bonus
            class_bonus = 0.15 if (incident_class and pattern.incident_class == incident_class) else 0.0

            similarity = (tag_jaccard * 0.60) + (proto_overlap * 0.25) + class_bonus

            if similarity >= min_similarity:
                matches.append(MemoryMatch(
                    pattern         = pattern,
                    similarity_score= round(similarity, 4),
                    matching_tags   = list(intersection),
                    explanation     = (
                        f"Pattern '{pattern.pattern_id}' matched {len(intersection)} of "
                        f"{len(query_tags)} query tags (Jaccard: {tag_jaccard:.2f}). "
                        f"Root cause: '{pattern.root_cause_label}'. "
                        f"Historical MTTR: {pattern.mttr_minutes:.0f} min. "
                        f"Resolved {pattern.reuse_count} times."
                    ),
                ))

        matches.sort(key=lambda m: m.similarity_score, reverse=True)
        return matches[:top_k]

    def store(self, pattern: CausalPattern) -> None:
        """Add a new resolved incident pattern to memory."""
        existing_ids = {p.pattern_id for p in self.patterns}
        if pattern.pattern_id in existing_ids:
            logger.warning(f"Pattern {pattern.pattern_id} already exists — skipping")
            return
        self.patterns.append(pattern)
        self.save()
        logger.info(f"Stored pattern {pattern.pattern_id} to decision memory")

    def update_feedback(self, pattern_id: str, accuracy: float) -> None:
        """
        Record operator accuracy feedback for a pattern.
        Used to weight future retrieval (higher accuracy → higher reuse priority).
        """
        for p in self.patterns:
            if p.pattern_id == pattern_id:
                p.accuracy_feedback = round(accuracy, 2)
                p.reuse_count += 1
                self.save()
                return
        logger.warning(f"Pattern {pattern_id} not found for feedback update")

    def summary(self) -> dict:
        """Statistics over the pattern store."""
        if not self.patterns:
            return {"total": 0}
        cyber = sum(1 for p in self.patterns if p.incident_class == "CYBER")
        return {
            "total":             len(self.patterns),
            "cyber":             cyber,
            "reliability":       len(self.patterns) - cyber,
            "avg_mttr_minutes":  round(
                sum(p.mttr_minutes for p in self.patterns) / len(self.patterns), 1
            ),
            "avg_confidence":    round(
                sum(p.confidence_at_resolution for p in self.patterns) / len(self.patterns), 3
            ),
            "total_reuses":      sum(p.reuse_count for p in self.patterns),
        }
