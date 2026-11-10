# Naarad: Threat-Intel Briefing Agent
### Daily "top N per category" cyber-threat brief from CERT/CSIRT/OSINT — LangGraph · FastMCP · Pydantic · Shiva gate

A multi-agent system that assembles a **daily threat brief** — the top *N* incidents (default 2) in
each of six categories — by pulling **CERT/CSIRT/OSINT** feeds through a **governed FastMCP** layer,
folding in the analyst's **own rough tips**, and gating the one outbound action (publishing the brief)
behind the **Kartikeya capability-delta gate** + a **human-in-the-loop** interrupt.

> Built on the Shiva architecture: real **LangGraph** orchestration, a real **FastMCP** governed server, strict **Pydantic** state, and a minimal open copy of the [Shiva](https://github.com/mjha-arya/shiva) gate in `vendor/shiva/` (*Gate = Blast Radius × Capability Delta*). Runs over `src/intel_cache.json`, which holds **real intel pulled live** from the analyst source list below, and reproduces deterministically between refreshes. Every live feed transport is an honest **seam** with the real API call noted inline.

> **Standing output:** every run writes a dated Markdown brief to
> **`reports/naarad-briefing-<as-of>.md`** (the `<as-of>` is the intel capture date). This is how the
> agent always runs — a fresh, dated `.md` report each time, gated behind the human-in-the-loop egress check.

## Live sources (the analyst feedstock)
Naarad's intel is drawn from these high-trust sources, mapped onto the three governed feeds so the
least-privilege source grant still holds. Great feedstock for the **Foundry's** threat input.

| Governed feed | Real sources behind it |
|---|---|
| **`cert-kev`** (official vuln/exploit) | **CISA** (cisa.gov alerts + **KEV** catalog), **CVE / NVD**, **ransomware.live** |
| **`csirt`** (primary research / advisories) | **Unit 42**, **Mandiant**, **Cisco Talos**, **Microsoft MSTIC/MSRC**, **SANS Internet Storm Center**, **FBI/CISA advisories**, vendor PSIRTs |
| **`osint-twitter`** (breach/news OSINT) | **The Hacker News**, **BleepingComputer**, **Krebs on Security**, **The Record** (Recorded Future), **DarkReading** |

TTPs are named against **MITRE ATT&CK** where applicable. Refresh the cache by re-running the live
collector (Claude-harness pull) or by wiring the fetch seams in `mcp_server.py` to these transports.

## The six categories (the brief's spine)
| Category | Typical volume | Revenue / impact target | Common examples |
|---|---:|---:|---|
| Phishing, credential theft & BEC | Very high | Low→high; fraud + account takeover | MFA-fatigue, fake invoices, OAuth-consent phishing, BEC |
| Ransomware & extortion | High | High; orgs able to pay + sensitive data | Double/triple extortion, data theft, encryption, DDoS pressure |
| Exploitation of internet-facing systems | High | Medium→very high; exposed asset + downstream | VPN/firewall zero-days, unpatched web apps, mass exploitation |
| Software supply-chain & SDLC compromise | Lower volume, high leverage | Very high; one compromise reaches many | Compromised deps, CI/CD credential theft, malicious package updates, vendor compromise |
| Cloud, SaaS & API abuse | High and rising | Medium→high; data, compute, identities, payment flows | Misconfigured storage, exposed API keys, token theft, cryptomining, SaaS ATO |
| AI, LLM & agentic-system attacks | Lower volume, fast-rising | High; tool-enabled agents move ~16× human data volume | Prompt injection (OWASP LLM #1), zero-click agent exfil, agent/tool hijack, model & MCP supply chain |

The agent emits **2 real incidents per category** (12 total), each with actor, CVE, impact target,
example TTPs, and source — see a live run below.

## Architecture (clean separation, mirrors the sibling)
```
        ┌──────────────────────────── LangGraph Orchestrator ─────────────────────────────┐
 START → collector → tip_correlator → analyst → evaluator ──[interrupt_before]── publish → END
        │ (governed    (your rough    (rank +    (Kartikeya                      (egress,   │
        │  feed pulls)   tips)         pick N)    egress gate)                    gated)     │
        └───────────────────────────────────────────────────────────────────────────────────┘
                         ▲ read-only, per-feed grant                 ▲ human approval clears egress
   ┌─────────────────────┴─────────────────┐        Governed MCP Server (FastMCP) — separate process-able
   │ strict Pydantic BriefingState          │        read-only: fetch_cert_kev, fetch_csirt_advisories,
   │ (intel + governance posture)           │                   fetch_osint_twitter  (each scoped to 1 feed)
   └────────────────────────────────────────┘        admin (gated): publish_briefing  (DATA_EGRESS)
```

## The two things you asked for
1. **Your rough tips, folded in.** Pass `--tip "..."` (repeatable). `tip_correlator` matches each tip
   against the collected intel on **distinctive** terms (vendor/actor/CVE, with a stopword filter so
   generic words like "zero-day" don't false-match):
   - **Match** → adds an *insight note* to that incident and boosts its priority ("independent user
     sighting raises confidence/urgency").
   - **No match** → promotes the tip to a clearly-flagged **`USR-xxx` UNVERIFIED** item, always pinned
     into the brief so your own lead never silently drops off.
2. **A real, current brief** — not fixtures. `intel_cache.json` holds intel pulled live (latest capture
   **2026-07-15**) from the source list above; the fetch tools are the seam to keep it live. Every run
   emits the dated `.md` in `reports/`.

## The governance story (the Shiva / Kartikeya differentiator)
- **Least-privilege source access.** Each feed tool is scoped to ONE feed; the collector only pulls
  feeds in its grant. `--feeds cert-kev,csirt` proves it — the OSINT feed is **BLOCKED at the
  boundary** and the trace shows `[BLOCKED] collector -> fetch_osint_twitter`.
- **Egress is the real risk, so egress is gated.** Reading the brief is free. *Publishing* it outward
  is `DATA_EGRESS` (blast weight 3). The `evaluator` expresses publish as a capability request and runs
  it through `shiva.gate`; the briefing skill never declared `DATA_EGRESS`, so it's an **unjustified
  capability delta** → `needs-human`. `interrupt_before=["publish"]` pauses the graph; nothing leaves
  until a human clears it (and the MCP tool *also* refuses without an approval token — defense in depth).
- **The harness holds the privilege, not the model.** Agents only *request* feeds/egress; the governed
  layer *performs* them under policy.

## Run it
    pip install -r requirements.txt        # langgraph, fastmcp, pydantic (already present if the sibling ran)
    python src/run.py                                   # today's brief, 2/category, kept local
    python src/run.py --publish                         # ...and approve the outbound egress
    python src/run.py --tip "Qilin hitting Check Point VPNs" --tip "odd Fortinet SSL-VPN chatter"
    python src/run.py --feeds cert-kev,csirt            # restrict the source grant (least-privilege demo)
    python src/run.py --per 3                           # N incidents per category

**Every** run writes `reports/naarad-briefing-<as-of>.md` (whether held or published). The console
shows the brief + governance trace; the `.md` is the durable, shareable deliverable.

## What's real vs. seam (so you can speak to it honestly)
- **Real:** the LangGraph orchestration + HITL interrupt + checkpointer; the FastMCP server and its
  tool registrations; the strict Pydantic state; the Kartikeya egress gate (`shiva.gate`); the
  read-only-feed / admin-egress governance split; the per-feed least-privilege enforcement; the tip
  correlation; the dated `.md` report writer; **and the intel content itself** (pulled live 2026-07-15
  from the sources above).
- **Live collection today = the Claude harness.** The current-events pull is performed by the agent's
  LLM harness (web research across the source list) and written into `intel_cache.json`; the governed
  agent then ranks, gates, and reports over it. This keeps runs deterministic between refreshes while
  the content stays genuinely current.
- **Seam (fully autonomous transport, real call noted inline):** the in-process feed tools —
  `fetch_cert_kev` → CISA KEV JSON API, `fetch_csirt_advisories` → CSIRT/vendor RSS, `fetch_osint_twitter`
  → X API recent-search. Swap each `_fetch_*` body for the live transport and the orchestrator is unchanged.

## Files
    src/state.py         strict Pydantic BriefingState (intel + governance) — the schema
    src/mcp_server.py    Governed MCP Server (FastMCP): per-feed read-only tools + gated egress tool
    src/tools_client.py  the governed bridge (per-feed least-privilege + admin-approval enforcement)
    src/agents.py        collector · tip_correlator (your rough tips) · analyst (rank + pick N)
    src/evaluator.py     the Kartikeya capability-delta gate on the outbound publish step
    src/graph.py         the LangGraph orchestrator (interrupt_before egress + checkpointer)
    src/run.py           entrypoint (--tip / --feeds / --per / --publish) + dated Markdown report writer
    src/intel_cache.json REAL intel pulled live from the source list (latest capture 2026-07-15)
    reports/             dated Markdown briefs, one per run: naarad-briefing-<as-of>.md

---
Built by **[Manish Jha](https://github.com/mjha-arya)**, secure and provable AI agents. MIT licensed; `vendor/shiva/` is a minimal open subset of the Shiva gate.
