"""Strict Pydantic state schema for the Threat-Intel Briefing Agent.

Same shape of design as the Senior Security Engineering Agent: one strict Pydantic model IS the
LangGraph StateGraph schema, so the type system carries the contract end-to-end. The state tracks
BOTH the collected intel AND the governance posture of the run (which feed each agent was allowed to
touch, and whether the external PUBLISH step cleared the Kartikeya gate + human review).

Kartikeya tie-in: fetching from an external feed and, especially, PUBLISHING the briefing outward are
expressed as *capability requests*. Publishing is DATA_EGRESS (high blast) — so it runs through
`shiva.gate` and a human-in-the-loop before anything leaves. The model/agents only *request*; the
governed layer *performs* the fetch and the egress under policy.
"""
from __future__ import annotations
from enum import Enum
from pydantic import BaseModel, Field


# ---- controlled vocabularies -----------------------------------------------------------------
class Category(str, Enum):
    PHISHING = "Phishing, credential theft & BEC"
    RANSOMWARE = "Ransomware & extortion"
    EXPLOITATION = "Exploitation of internet-facing systems"
    SUPPLY_CHAIN = "Software supply-chain & SDLC compromise"
    CLOUD = "Cloud, SaaS & API abuse"
    AI_AGENTS = "AI, LLM & agentic-system attacks"


class Feed(str, Enum):
    CERT_KEV = "cert-kev"          # CISA/CERT Known Exploited Vulnerabilities
    CSIRT = "csirt"                # CSIRT / vendor security advisories
    OSINT_TWITTER = "osint-twitter"  # OSINT / X (Twitter) threat chatter


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AccessLevel(str, Enum):
    READ_ONLY = "read-only"   # feed-fetch tools — always permitted (per source grant)
    ADMIN = "admin"           # publish/egress tool — only after human approval


class Verdict(str, Enum):
    APPROVE = "approve"
    NEEDS_HUMAN = "needs-human"
    REJECT = "reject"


# ---- intel records ---------------------------------------------------------------------------
class ThreatItem(BaseModel):
    id: str
    category: Category
    title: str
    actor: str = ""
    cve: str | None = None
    feed: Feed
    source_name: str = ""
    published: str = ""                          # ISO date
    severity: Severity = Severity.MEDIUM
    in_kev: bool = False
    impact_target: str = ""
    example_tags: list[str] = Field(default_factory=list)
    summary: str = ""
    refs: list[str] = Field(default_factory=list)
    priority: int = 0                            # computed by the analyst (ranking score)
    analyst_note: str = ""                       # correlation insight from the user's rough tips
    user_reported: bool = False                  # True if this item originated from a user tip only


class ToolInvocation(BaseModel):
    """One call the orchestrator made against the Governed MCP Server — the audit trail."""
    agent: str
    tool: str
    access_level: AccessLevel
    capability: str                              # the Shiva capability the tool exercises
    args: dict = Field(default_factory=dict)
    result: str = ""
    blocked: bool = False                        # True if the governed layer refused it


class GateReview(BaseModel):
    """The Evaluator's capability-delta review of the outbound PUBLISH step (Kartikeya)."""
    step: str
    capability_delta: list[str] = Field(default_factory=list)
    blast_radius: int = 0
    verdict: Verdict = Verdict.NEEDS_HUMAN
    rationale: str = ""


class Approval(BaseModel):
    step: str
    approver: str
    approved: bool
    reason: str = ""


# ---- the top-level LangGraph state -----------------------------------------------------------
class BriefingState(BaseModel):
    as_of: str                                   # the "today" the briefing is for
    requested_per_category: int = 2
    # rough, freeform tips the user has heard — correlated against the feeds for extra insight
    analyst_tips: list[str] = Field(default_factory=list)
    # least-privilege source grant for the collector (which feeds it may touch)
    granted_feeds: list[Feed] = Field(default_factory=lambda: list(Feed))
    # collected + processed intel
    raw_items: list[ThreatItem] = Field(default_factory=list)
    selected_items: list[ThreatItem] = Field(default_factory=list)
    # governance
    tool_trace: list[ToolInvocation] = Field(default_factory=list)
    gate_reviews: list[GateReview] = Field(default_factory=list)
    approvals: list[Approval] = Field(default_factory=list)
    reasoning_chain: list[str] = Field(default_factory=list)
    # workflow control
    status: str = "new"
    published: bool = False

    def is_approved(self, step: str) -> bool:
        return any(a.step == step and a.approved for a in self.approvals)

    def needs_human_steps(self) -> "list[str]":
        return [r.step for r in self.gate_reviews if r.verdict == Verdict.NEEDS_HUMAN]
