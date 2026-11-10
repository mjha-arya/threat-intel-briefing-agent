"""The governed client the LangGraph orchestrator uses to reach the MCP server.

The clean boundary: the orchestrator NEVER imports tool internals, credentials, or the live feed
transports — it calls `client.call(agent, tool, granted_feeds=..., **args)` and the client enforces
the server's governance:

  * READ-ONLY feed tools: allowed ONLY if the tool's source feed is in the caller's grant
    (least-privilege source access). A collector scoped to OSINT cannot pull the CERT-KEV feed.
  * the ADMIN `publish_briefing` tool: REFUSED unless a valid human-approval token is passed
    (defense-in-depth — the graph's interrupt_before is the first gate, this is the second).

For deterministic runs it invokes the server's registered tool implementations in-process. To go
cross-process, swap the body of `call` for `fastmcp.Client(<transport>).call_tool(...)` — the
signature the orchestrator sees does not change.
"""
from __future__ import annotations
from .state import ToolInvocation, AccessLevel, Feed
from .mcp_server import TOOLS


class GovernedMCPClient:
    def call(self, agent: str, tool: str, *, approval_token: str = "",
             granted_feeds: "list[Feed] | None" = None, **args) -> ToolInvocation:
        spec = TOOLS.get(tool)
        if spec is None:
            return ToolInvocation(agent=agent, tool=tool, access_level=AccessLevel.READ_ONLY,
                                  capability="unknown", args=args,
                                  result=f"[mcp] unknown tool '{tool}'", blocked=True)

        # Least-privilege SOURCE access: a read-only feed tool is refused unless its feed is granted.
        if spec.access_level == AccessLevel.READ_ONLY and spec.feed is not None:
            granted = {f.value for f in (granted_feeds or [])}
            if spec.feed not in granted:
                return ToolInvocation(agent=agent, tool=tool, access_level=spec.access_level,
                                      capability=spec.capability.value, args=args,
                                      result=f"[mcp] refused: feed '{spec.feed}' not in {agent}'s grant",
                                      blocked=True)

        # Admin tools require the human-approval token; read-only tools never do.
        if spec.access_level == AccessLevel.ADMIN and not approval_token.startswith("APPROVED:"):
            return ToolInvocation(agent=agent, tool=tool, access_level=spec.access_level,
                                  capability=spec.capability.value, args=args,
                                  result="[mcp] admin tool refused: human approval required",
                                  blocked=True)

        if spec.access_level == AccessLevel.ADMIN:
            args = {**args, "approval_token": approval_token}
        result = spec.fn(**args)
        return ToolInvocation(agent=agent, tool=tool, access_level=spec.access_level,
                              capability=spec.capability.value, args=args,
                              result=str(result), blocked=False)
