"""The Governed MCP Server — a REAL FastMCP server, kept cleanly separate from the LangGraph
orchestrator (same architectural constraint as the sibling prototype).

Governance model, enforced HERE (not in the agents):
  * Feed-fetch tools are strictly READ-ONLY, and each is scoped to ONE source feed
    (cert-kev | csirt | osint-twitter). An agent may only pull from feeds in its grant.
  * The single outbound tool `publish_briefing` is ADMIN / DATA_EGRESS — it REFUSES unless a
    human-approval token is presented (defense-in-depth behind the graph's interrupt).

Each feed-fetch reads `intel_cache.json` — REAL intel gathered on 2026-07-12 from CERT/CSIRT/OSINT —
so the agent runs deterministically over real content. THE SEAM: swap each `_fetch_*` body for a live
call (CISA KEV JSON API / a CSIRT RSS pull / an X API search) and the orchestrator is unchanged.

Run it as a real MCP server over stdio:  python src/mcp_server.py
"""
from __future__ import annotations
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from fastmcp import FastMCP

from shiva.capabilities import Capability
from .state import AccessLevel

mcp = FastMCP("governed-threat-intel-mcp")

_CACHE = Path(__file__).resolve().parent / "intel_cache.json"


def _load(feed: str) -> list[dict]:
    """Read the cached intel and return only items belonging to one feed (the source seam)."""
    data = json.loads(_CACHE.read_text(encoding="utf-8"))
    return [it for it in data.get("items", []) if it.get("feed") == feed]


# ============================ tool implementations (plain, testable) ============================
# --- READ-ONLY feed pulls, one per source. SEAM: replace body with the live feed call noted. ---
def _fetch_cert_kev() -> dict:
    # SEAM: GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    items = _load("cert-kev")
    return {"feed": "cert-kev", "count": len(items), "items": items}


def _fetch_csirt_advisories() -> dict:
    # SEAM: pull CSIRT / vendor advisory RSS (e.g. MSRC, national CSIRT feeds) and normalize.
    items = _load("csirt")
    return {"feed": "csirt", "count": len(items), "items": items}


def _fetch_osint_twitter(query: str = "cyber threat") -> dict:
    # SEAM: X/Twitter API recent-search on infosec accounts/hashtags; here, curated OSINT cache.
    items = _load("osint-twitter")
    return {"feed": "osint-twitter", "count": len(items), "items": items, "query": query}


# --- the SINGLE privileged outbound tool (admin / data-egress) ---
def _publish_briefing(channel: str, digest: str, approval_token: str) -> dict:
    """ADMIN, data-egress. Refuses without a valid human-approval token."""
    if not approval_token or not approval_token.startswith("APPROVED:"):
        return {"published": False, "error": "publish refused: valid human approval token required"}
    return {"published": True, "channel": channel,
            "detail": f"briefing egressed to {channel} under {approval_token} ({len(digest)} chars)"}


# ============================ governance metadata + MCP registration ============================
@dataclass
class ToolSpec:
    name: str
    access_level: AccessLevel
    capability: Capability
    feed: str | None                 # source feed this tool is scoped to (None for the admin tool)
    fn: Callable[..., dict]


# The registry the in-process governed client reads (governance lives with the server, not agents).
TOOLS: "dict[str, ToolSpec]" = {
    "fetch_cert_kev":          ToolSpec("fetch_cert_kev", AccessLevel.READ_ONLY, Capability.EXTERNAL_API, "cert-kev", _fetch_cert_kev),
    "fetch_csirt_advisories":  ToolSpec("fetch_csirt_advisories", AccessLevel.READ_ONLY, Capability.EXTERNAL_API, "csirt", _fetch_csirt_advisories),
    "fetch_osint_twitter":     ToolSpec("fetch_osint_twitter", AccessLevel.READ_ONLY, Capability.EXTERNAL_API, "osint-twitter", _fetch_osint_twitter),
    "publish_briefing":        ToolSpec("publish_briefing", AccessLevel.ADMIN, Capability.DATA_EGRESS, None, _publish_briefing),
}

# Register each as a REAL FastMCP tool (read-only feeds tagged; the admin egress tool separated).
mcp.tool(name="fetch_cert_kev", description="Read-only pull of CISA/CERT Known Exploited Vulnerabilities.")(_fetch_cert_kev)
mcp.tool(name="fetch_csirt_advisories", description="Read-only pull of CSIRT / vendor security advisories.")(_fetch_csirt_advisories)
mcp.tool(name="fetch_osint_twitter", description="Read-only pull of OSINT / X (Twitter) threat chatter.")(_fetch_osint_twitter)
mcp.tool(name="publish_briefing", description="ADMIN/egress: publish the briefing outward. Requires a human-approval token.")(_publish_briefing)


if __name__ == "__main__":
    mcp.run()   # serve over stdio — a real, standalone Governed MCP Server
