"""Entrypoint: assemble today's threat-intel brief (top N per category) through the orchestrator,
stop at the human-in-the-loop interrupt before any outbound EGRESS, then optionally publish.

    python src/run.py                             # today's brief, 2 incidents/category, kept local
    python src/run.py --publish                   # ...and approve egress to the SOC channel
    python src/run.py --tip "heard Qilin hitting Check Point VPNs"   # add a rough user tip (repeatable)
    python src/run.py --feeds cert-kev,csirt      # restrict the collector's source grant (least-priv demo)
    python src/run.py --per 3                      # N incidents per category

Runs over intel_cache.json — REAL, current intel pulled live from the analyst source list
(The Hacker News, BleepingComputer, Krebs, CISA/KEV, The Record, DarkReading, SANS ISC, Unit 42,
Mandiant, Talos, Microsoft MSTIC, MITRE ATT&CK, CVE/NVD, ransomware.live). The brief's "as of"
date is taken from the cache's capture date. EVERY run also writes a dated Markdown report to
reports/naarad-briefing-<as-of>.md — this is the standing output of the agent.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

try:                                    # make non-ASCII (em-dashes, @) render on any console
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

_SHIVA_SRC = Path(__file__).resolve().parents[1] / "vendor"
sys.path.insert(0, str(_SHIVA_SRC))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.graph import build_app                                           # noqa: E402
from src.state import BriefingState, Category, Feed, Approval, Verdict    # noqa: E402

_CACHE = Path(__file__).resolve().parent / "intel_cache.json"
_REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"


def _as_of() -> str:
    """The brief is dated to when the intel was captured (single source of truth: the cache)."""
    try:
        return json.loads(_CACHE.read_text(encoding="utf-8")).get("captured", "unknown")
    except Exception:
        return "unknown"


AS_OF = _as_of()
_LINE = "  " + "-" * 100


def _parse_args(argv: list[str]) -> dict:
    tips, feeds, per, publish = [], None, 2, False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--tip" and i + 1 < len(argv):
            tips.append(argv[i + 1]); i += 2
        elif a == "--feeds" and i + 1 < len(argv):
            feeds = [Feed(f.strip()) for f in argv[i + 1].split(",")]; i += 2
        elif a == "--per" and i + 1 < len(argv):
            per = int(argv[i + 1]); i += 2
        elif a == "--publish":
            publish = True; i += 1
        else:
            i += 1
    return {"tips": tips, "feeds": feeds, "per": per, "publish": publish}


def _kev(item) -> str:
    return "KEV" if item.in_kev else "-"


def _print_brief(s: BriefingState) -> None:
    print(f"\n  DAILY CYBER THREAT BRIEF  --  as of {s.as_of}  |  top {s.requested_per_category} "
          f"incidents/category  |  feeds: {', '.join(f.value for f in s.granted_feeds)}")
    if s.analyst_tips:
        print(f"  User tips folded in: {len(s.analyst_tips)}")
    print(_LINE)
    hdr = f"  | {'Category':<34} | {'Incident (id)':<52} | {'Sev':<8} | {'KEV':<3} | {'Src':<13} |"
    print(hdr); print("  |" + "-" * (len(hdr) - 3) + "|")
    for cat in Category:
        picks = [i for i in s.selected_items if i.category == cat]
        for j, it in enumerate(picks):
            label = cat.value if j == 0 else ""
            title = (it.title[:49] + "...") if len(it.title) > 52 else it.title
            print(f"  | {label:<34} | {title + ' (' + it.id + ')':<52} | {it.severity.value:<8} "
                  f"| {_kev(it):<3} | {it.feed.value:<13} |")
    print(_LINE)

    # detail block: impact target, examples, source, and any user-tip correlation note
    print("\n  INCIDENT DETAIL")
    for cat in Category:
        print(f"\n  == {cat.value} ==")
        for it in [i for i in s.selected_items if i.category == cat]:
            flag = "  [UNVERIFIED USER TIP]" if it.user_reported else ""
            cve = f" | {it.cve}" if it.cve else ""
            print(f"   - {it.id}{cve} | {it.actor} | impact: {it.impact_target}{flag}")
            print(f"       {it.summary}")
            print(f"       examples: {', '.join(it.example_tags)}  |  source: {it.source_name}")
            if it.analyst_note:
                print(f"       >> insight: {it.analyst_note}")
            if it.refs:
                print(f"       ref: {it.refs[0]}")


def _render_markdown(s: BriefingState, final_status: str, published: bool) -> str:
    """The standing deliverable: the brief as a Markdown document written to reports/."""
    feeds = ", ".join(f.value for f in s.granted_feeds)
    out: list[str] = []
    out.append(f"# 🗞️ Naarad — Daily Cyber Threat Brief")
    out.append("")
    out.append(f"**Intel as of {s.as_of}** · top {s.requested_per_category} incidents/category · "
               f"feeds: `{feeds}`")
    out.append(f"*Generated by the Naarad threat-intel agent (Shiva/Kartikeya governed). "
               f"Egress status: **{final_status}**.*")
    if s.analyst_tips:
        out.append(f"*User tips folded in: {len(s.analyst_tips)}.*")
    out.append("")
    out.append("## Summary table")
    out.append("")
    out.append("| Category | Incident (id) | Sev | KEV | Source |")
    out.append("|---|---|---|---|---|")
    for cat in Category:
        for it in [i for i in s.selected_items if i.category == cat]:
            flag = " ⚠️UNVERIFIED" if it.user_reported else ""
            out.append(f"| {cat.value} | {it.title} (`{it.id}`){flag} | {it.severity.value} | "
                       f"{'✅' if it.in_kev else '—'} | {it.feed.value} |")
    out.append("")
    out.append("## Incident detail")
    for cat in Category:
        out.append("")
        out.append(f"### {cat.value}")
        for it in [i for i in s.selected_items if i.category == cat]:
            cve = f" · `{it.cve}`" if it.cve else ""
            kev = " · **KEV**" if it.in_kev else ""
            flag = " · ⚠️ **UNVERIFIED USER TIP**" if it.user_reported else ""
            out.append("")
            out.append(f"**{it.id} — {it.title}**{flag}")
            out.append(f"`{it.severity.value}`{cve}{kev} · actor: {it.actor} · "
                       f"impact: {it.impact_target}")
            out.append("")
            out.append(it.summary)
            out.append("")
            out.append(f"*Examples:* {', '.join(it.example_tags)}  ")
            out.append(f"*Source:* {it.source_name}  ")
            if it.analyst_note:
                out.append(f"*Insight:* {it.analyst_note}  ")
            for r in it.refs:
                out.append(f"*Ref:* {r}  ")
    out.append("")
    out.append("## Governance (Shiva / Kartikeya)")
    out.append("")
    for inv in s.tool_trace:
        flag = "BLOCKED" if inv.blocked else inv.access_level.value
        out.append(f"- `[{flag}]` {inv.agent} → {inv.tool} ({inv.capability})")
    for r in s.gate_reviews:
        out.append(f"- `gate[{r.step}]`: **{r.verdict.value}** — delta={r.capability_delta or 'none'}, "
                   f"blast={r.blast_radius}")
    out.append(f"- **Egress decision:** {'PUBLISHED outward' if published else 'HELD — brief kept local'} "
               f"→ status `{final_status}`")
    out.append("")
    out.append("---")
    out.append("*Feeds are read-only under least-privilege grants; publishing the brief is the only "
               "DATA_EGRESS action and is gated behind the Kartikeya capability-delta check + a "
               "human-in-the-loop interrupt. The harness holds the privilege, not the model.*")
    out.append("")
    return "\n".join(out)


def _write_report(s: BriefingState, final_status: str, published: bool) -> Path:
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = _REPORTS_DIR / f"naarad-briefing-{s.as_of}.md"
    path.write_text(_render_markdown(s, final_status, published), encoding="utf-8")
    return path


def main() -> None:
    args = _parse_args(sys.argv[1:])
    app = build_app()
    cfg = {"configurable": {"thread_id": f"brief-{AS_OF}"}}

    init = BriefingState(as_of=AS_OF, requested_per_category=args["per"], analyst_tips=args["tips"])
    if args["feeds"] is not None:
        init.granted_feeds = args["feeds"]

    # 1) run until the human-in-the-loop interrupt (before any outbound egress)
    state_dict = app.invoke(init, cfg)
    s = BriefingState.model_validate(state_dict)
    _print_brief(s)

    print(_LINE)
    print("  GOVERNANCE (Shiva / Kartikeya)")
    for inv in s.tool_trace:
        flag = "BLOCKED" if inv.blocked else inv.access_level.value
        print(f"    [{flag}] {inv.agent} -> {inv.tool} ({inv.capability})")
    for r in s.gate_reviews:
        print(f"    gate[{r.step}]: {r.verdict.value} | delta={r.capability_delta or 'none'} "
              f"blast={r.blast_radius}")

    snap = app.get_state(cfg)
    if snap.next:
        print(_LINE)
        print(f"  >> HUMAN-IN-THE-LOOP: paused before '{snap.next[0]}' (outbound egress).")
        decision = args["publish"]
        s.approvals.append(Approval(step="publish_briefing", approver="human-analyst",
                                    approved=decision,
                                    reason="reviewed brief, cleared for SOC channel" if decision
                                    else "keep local — not egressed"))
        app.update_state(cfg, {"approvals": s.approvals})
        print(f"  >> Human decision: {'APPROVED — publishing' if decision else 'HELD — brief stays local'}")
        final = BriefingState.model_validate(app.invoke(None, cfg))
        print(f"  >> Status: {final.status}\n")
        report = _write_report(final, final.status, published=decision)
    else:
        print("  (no outbound step queued)\n")
        report = _write_report(s, s.status, published=False)

    print(_LINE)
    print(f"  >> REPORT WRITTEN: {report}")
    print(_LINE + "\n")


if __name__ == "__main__":
    main()
