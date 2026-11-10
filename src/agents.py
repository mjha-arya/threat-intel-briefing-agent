"""The specialist agents, written as LangGraph nodes: each takes the BriefingState and returns a
partial update. All feed access goes through the GovernedMCPClient (read-only, per-feed grant) —
agents never touch the live-feed transports or the outbound egress tool directly.

Agents:
  * collector       -- pulls each granted source feed (CERT-KEV / CSIRT / OSINT) through the governed
                       client. A feed outside its grant is refused at the boundary (least privilege).
  * tip_correlator  -- takes the user's ROUGH freeform tips, correlates them against the collected
                       intel, adds an insight note to matched items (and boosts their priority), and
                       promotes any unmatched tip into a clearly-flagged 'user-reported (unverified)'
                       item so the human always sees their own lead alongside the vetted feeds.
  * analyst         -- scores every item and selects the top N per category (default 2) for the brief.
"""
from __future__ import annotations
import re
from .state import (BriefingState, ThreatItem, Category, Feed, Severity)
from .tools_client import GovernedMCPClient

_client = GovernedMCPClient()
_SEV_SCORE = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
_FEED_TOOL = {Feed.CERT_KEV: "fetch_cert_kev", Feed.CSIRT: "fetch_csirt_advisories",
              Feed.OSINT_TWITTER: "fetch_osint_twitter"}

# lightweight keyword -> category guess for unmatched user tips
_CATEGORY_HINTS = [
    # AI/LLM terms are distinctive, so match them first before the more generic buckets below
    (Category.AI_AGENTS, ("prompt injection", "prompt-injection", "jailbreak", "llm", "copilot",
                          "agentic", "ai agent", "ai assistant", "mcp server", "model context protocol",
                          "rag poison", "tool abuse", "echoleak")),
    (Category.RANSOMWARE, ("ransom", "extort", "encrypt", "leak site", "qilin", "warlock", "lockbit")),
    (Category.SUPPLY_CHAIN, ("npm", "pypi", "supply chain", "dependency", "package", "ci/cd", "maintainer")),
    (Category.EXPLOITATION, ("cve", "zero-day", "0day", "vpn", "firewall", "rce", "exploit", "patch")),
    (Category.CLOUD, ("cloud", "aws", "azure", "gcp", "api key", "s3", "saas", "oauth token", "cryptomin")),
    (Category.PHISHING, ("phish", "bec", "mfa", "credential", "consent", "device code", "email")),
]


# ------------------------------------------------------------------- Collector -----------------
def collector(state: BriefingState) -> dict:
    trace = list(state.tool_trace)
    raw: list[ThreatItem] = list(state.raw_items)
    reasoning = list(state.reasoning_chain)

    for feed in Feed:                                  # try every feed; the grant decides what runs
        tool = _FEED_TOOL[feed]
        inv = _client.call("collector", tool, granted_feeds=state.granted_feeds)
        trace.append(inv)
        if inv.blocked:
            reasoning.append(f"[collector] {tool} BLOCKED — {feed.value} not in grant (least privilege).")
            continue
        # the governed result is a stringified dict; re-pull structured items straight from the seam
        from .mcp_server import TOOLS
        payload = TOOLS[tool].fn()
        for d in payload.get("items", []):
            raw.append(ThreatItem(**d))
        reasoning.append(f"[collector] pulled {payload.get('count', 0)} item(s) from {feed.value}.")

    reasoning.append(f"[collector] collected {len(raw)} raw intel item(s) across granted feeds.")
    return {"raw_items": raw, "tool_trace": trace, "reasoning_chain": reasoning,
            "status": "collected"}


# --------------------------------------------------------------- User-tip correlation ----------
# generic words that must NOT count as a correlation signal (only distinctive terms should match)
_STOP = {"being", "sold", "forum", "mentioned", "someone", "this", "that", "these", "those", "week",
         "hard", "hitting", "heard", "chatter", "some", "they", "with", "from", "into", "over", "more",
         "than", "been", "have", "were", "will", "your", "about", "there", "their", "which", "when",
         "what", "could", "would", "should", "after", "before", "using", "used", "also", "just", "like",
         "very", "much", "many", "most", "news", "said", "says", "seen", "saw", "new", "seeing", "lot",
         "reported", "reports", "reporting", "attack", "attacks", "threat", "threats", "campaign",
         # generic security vocabulary — too common to be a correlation signal on its own
         "zero-day", "0day", "exploit", "exploited", "exploiting", "exploits", "exploitation",
         "vulnerability", "vulnerabilities", "vuln", "vulns", "flaw", "flaws", "rumor", "rumour",
         "rumors", "breach", "breached", "hacked", "actor", "actors", "group", "gang", "victim",
         "victims", "active", "actively", "critical", "advisory", "patch", "patched"}


def _tokens(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9\-]+", text.lower()) if len(t) > 3 and t not in _STOP}


def _guess_category(tip: str) -> Category:
    low = tip.lower()
    for cat, keys in _CATEGORY_HINTS:
        if any(k in low for k in keys):
            return cat
    return Category.EXPLOITATION      # neutral default; the human can recategorize


def tip_correlator(state: BriefingState) -> dict:
    raw = [i.model_copy(deep=True) for i in state.raw_items]
    reasoning = list(state.reasoning_chain)
    if not state.analyst_tips:
        reasoning.append("[tip_correlator] no user tips supplied — feeds only.")
        return {"raw_items": raw, "reasoning_chain": reasoning}

    for tip in state.analyst_tips:
        tip_tok = _tokens(tip)
        scored = []
        for idx, item in enumerate(raw):
            hay = _tokens(" ".join([item.title, item.summary, item.actor, item.cve or "",
                                    " ".join(item.example_tags)]))
            overlap = tip_tok & hay
            if overlap:
                scored.append((len(overlap), idx, overlap))
        if scored:
            scored.sort(reverse=True)
            _, idx, overlap = scored[0]
            item = raw[idx]
            item.priority += 2                          # the user independently flagged it -> corroboration
            note = (f"Corroborates your tip (\"{tip[:70]}\") — overlap on "
                    f"{', '.join(sorted(overlap))}. Independent user sighting raises confidence/urgency.")
            item.analyst_note = (item.analyst_note + " " + note).strip()
            reasoning.append(f"[tip_correlator] tip matched {item.id} ({item.title[:50]}...) — priority boosted.")
        else:
            cat = _guess_category(tip)
            new = ThreatItem(
                id=f"USR-{len(raw)+1:03d}", category=cat, title=f"User-reported: {tip[:60]}",
                actor="user-reported", feed=Feed.OSINT_TWITTER, source_name="user tip (UNVERIFIED)",
                published=state.as_of, severity=Severity.MEDIUM, in_kev=False,
                impact_target="unknown — needs verification against a primary feed",
                example_tags=["user-reported", "unverified"], summary=tip,
                analyst_note="No match in today's CERT/CSIRT/OSINT pull. Flagged UNVERIFIED — "
                             "treat as a lead to confirm, not a confirmed incident.",
                priority=1, user_reported=True)
            raw.append(new)
            reasoning.append(f"[tip_correlator] tip had no feed match -> added {new.id} as UNVERIFIED ({cat.value}).")

    return {"raw_items": raw, "reasoning_chain": reasoning}


# ------------------------------------------------------------------- Analyst -------------------
def _score(item: ThreatItem) -> int:
    s = _SEV_SCORE[item.severity]
    if item.in_kev:
        s += 3
    if item.published >= "2026-07-01":        # recency bump for "this month"
        s += 2
    return s + item.priority


def analyst(state: BriefingState) -> dict:
    reasoning = list(state.reasoning_chain)
    ranked = sorted(state.raw_items, key=_score, reverse=True)
    for it in ranked:
        it.priority = _score(it)

    n = state.requested_per_category
    selected: list[ThreatItem] = []
    for cat in Category:
        in_cat = [i for i in ranked if i.category == cat]
        picks = in_cat[:n]
        # ALWAYS surface the user's own leads: pin any user-reported or tip-correlated item in this
        # category even if it didn't make the top-N by score (your tip never silently drops off).
        pinned = [i for i in in_cat if (i.user_reported or i.analyst_note) and i not in picks]
        selected.extend(picks + pinned)
        extra = f" (+{len(pinned)} pinned user lead)" if pinned else ""
        reasoning.append(f"[analyst] {cat.value}: selected top {len(picks)} of {len(in_cat)} by score{extra}.")

    reasoning.append(f"[analyst] briefing assembled: {len(selected)} incidents "
                     f"(top {n} per category + pinned user leads across {len(Category)} categories).")
    return {"selected_items": selected, "reasoning_chain": reasoning, "status": "analyzed"}
