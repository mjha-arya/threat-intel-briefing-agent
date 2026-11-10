"""The Evaluator Node — the capability-delta gate on the OUTBOUND step (Kartikeya).

Collecting intel is read-only and low-blast. The risk in a briefing pipeline is EGRESS: publishing
the assembled brief outward can carry internal context (which feeds you watch, which tips your staff
reported) out of the trust boundary. So the publish step is expressed as a *capability request* for
DATA_EGRESS and run through Shiva's gate:  Gate = Blast Radius x Capability Delta.

The 'briefing' skill declares only read/collect capabilities — it never declares DATA_EGRESS. So the
publish's required DATA_EGRESS is an *unjustified capability delta* with high blast radius -> the gate
flags/quarantines it, and the verdict is NEEDS_HUMAN. Nothing leaves without a human clearing the
interrupt. (The model/agents only *request* egress; the governed layer *performs* it under policy.)
"""
from __future__ import annotations
from shiva.capabilities import Capability
from shiva.ir import AgentSpec, Skill
from shiva import gate
from .state import BriefingState, GateReview, Verdict


def evaluator(state: BriefingState) -> dict:
    reviews = list(state.gate_reviews)
    reasoning = list(state.reasoning_chain)

    # The briefing skill's DECLARED capabilities: it may read feeds, nothing more.
    declared = [Capability.EXTERNAL_API, Capability.MEMORY_RETRIEVAL]
    spec = AgentSpec(name="threat-briefing", purpose="assemble a daily threat brief",
                     skills=[Skill(name="publish", purpose="egress the brief",
                                   declared_capabilities=declared)])

    observed = [Capability.DATA_EGRESS]          # what publishing would actually exercise
    decision = gate.evaluate(spec, "publish", observed)

    unjustified = [c.value for c in decision.delta]
    verdict = Verdict.NEEDS_HUMAN if decision.delta else Verdict.APPROVE
    rationale = (f"Publish exercises {[c.value for c in observed]}; declared={[c.value for c in declared]}. "
                 f"Capability delta (Kartikeya): {unjustified or 'none'}, blast radius {decision.blast_radius}, "
                 f"gate verdict '{decision.verdict}'. Egress of internal-context brief -> human must clear it.")
    reviews.append(GateReview(step="publish_briefing", capability_delta=unjustified,
                              blast_radius=decision.blast_radius, verdict=verdict, rationale=rationale))
    reasoning.append(f"[evaluator] publish_briefing: {verdict.value}. {rationale}")
    return {"gate_reviews": reviews, "reasoning_chain": reasoning, "status": "reviewed"}
