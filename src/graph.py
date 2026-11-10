"""The LangGraph Orchestrator — real langgraph, kept cleanly separate from the Governed MCP Server.

Wiring:

    START -> collector -> tip_correlator -> analyst -> evaluator
          -> [interrupt_before] publish -> END

Safety: the ONLY outbound action (publish_briefing, DATA_EGRESS) sits behind
`interrupt_before=["publish"]`, so the graph PAUSES before anything leaves the trust boundary. A
human clears it (run.py injects the Approval into checkpointed state) before the graph resumes. The
MCP server's publish tool ALSO refuses without an approval token — defense in depth. A MemorySaver
checkpointer holds the paused run so it can resume on the same thread_id.

Reading the brief is free; EGRESSING it is gated. If you only want the brief on your own screen you
never approve publish — the assembled `selected_items` are already in state at the interrupt.
"""
from __future__ import annotations
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

from .state import BriefingState
from .tools_client import GovernedMCPClient
from . import agents, evaluator

_client = GovernedMCPClient()


def publish(state: BriefingState) -> dict:
    """Runs ONLY after the interrupt is cleared by a human. Egresses the brief via the admin tool."""
    trace = list(state.tool_trace)
    reasoning = list(state.reasoning_chain)

    if not state.is_approved("publish_briefing"):
        reasoning.append("[publish] not approved by a human — brief kept local, nothing egressed.")
        return {"reasoning_chain": reasoning, "status": "assembled-not-published", "published": False}

    token = "APPROVED:publish_briefing:human-analyst"
    digest = "\n".join(f"{i.id} [{i.category.value}] {i.title}" for i in state.selected_items)
    inv = _client.call("publish", "publish_briefing", approval_token=token,
                       channel="soc-daily-brief", digest=digest)
    trace.append(inv)
    reasoning.append("[publish] brief egressed via admin tool under human approval.")
    return {"tool_trace": trace, "reasoning_chain": reasoning, "status": "published", "published": True}


def build_app():
    """Compile the orchestrator. Returns a LangGraph app with HITL interrupt + checkpointer."""
    g = StateGraph(BriefingState)
    g.add_node("collector", agents.collector)
    g.add_node("tip_correlator", agents.tip_correlator)
    g.add_node("analyst", agents.analyst)
    g.add_node("evaluator", evaluator.evaluator)
    g.add_node("publish", publish)

    g.add_edge(START, "collector")
    g.add_edge("collector", "tip_correlator")
    g.add_edge("tip_correlator", "analyst")
    g.add_edge("analyst", "evaluator")
    g.add_edge("evaluator", "publish")
    g.add_edge("publish", END)

    saver = MemorySaver(serde=JsonPlusSerializer(allowed_msgpack_modules=True))
    return g.compile(checkpointer=saver, interrupt_before=["publish"])
