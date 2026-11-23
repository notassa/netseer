# NetSeer — progress

Last updated: 2026-11-23

## Change log
Format: `[YYYY-MM-DD] change`, newest first. One line per finished task. Details: `docs/RAD-PLAN.md` (Build record, decisions to confirm), `docs/WRITEUP.md` §8 (Tables 4.12/4.13), `docs/PROTOTYPE-BRIEF.md` §3a (environment).

- [2026-11-23] Line Traffic Volume, total traffic card, Log out in topbar, attribution table scroll, alert class bars, severity chips; unslop rules added
- [2026-11-23] Home Traffic Volume on a 5-second table (5–3600 s bins, wheel + Reset), cards swapped; Log out always visible
- [2026-11-23] C4 live check passed (alerts stored in 11.0–29.5 s); worker browser checks, token rules, startnetseer note, empty feedback log
- [2026-11-23] Real mirrored live capture verified (session 7: 85/85 alerts stored); C4 alert-delay check still open
- [2026-11-23] opencode workers load the caveman and ponytail skills (AGENTS.md)
- [2026-11-23] Traffic Source card, AI prompt view + copy, Home Traffic Rate (packet_stats by direction), Data Representation setting
- [2026-11-23] Alert ID and Incident ID columns first in their tables; left panel fixed to screen height
- [2026-11-18] Risk redesign reviewed: asset criticality counted once (network roll-up no longer weights by I1/9), k^1.5 damping relabelled as a NetSeer heuristic, health framed as a triage index; A5.6 health 62 → 47; model version A5-1.1. 213 tests
- [2026-11-18] Risk spec reviewed: keep CONCEPTS A5; add model version + data-quality flags to factors_json, stable incident order, `eval/risk_eval.py` (sensitivity, ablation, Spearman) and suppression count in `unsw_validate`. 213 tests
- [2026-11-18] Add token-economy and loop-guard rules (`CLAUDE.md`, `AGENTS.md`)
- [2026-11-18] Online MAC vendor fallback (maclookup.app, OUI only, cached, setting on by default); progress.md is now the change log only (environment → brief §3a, Tables 4.12/4.13 + demo commands → WRITEUP §8/§10, build record + decisions → RAD-PLAN). 208 tests
- [2026-11-18] dump.md ideas 1–3: Alerts table shows 8 columns with Severity = Suricata priority as [1] High…[4] Info (also on the incident raw-alerts table; ET severity column and filter removed); network map leaves out broadcast, multicast and unspecified addresses that are not devices; Home shows the Analysis card first. 203 tests
- [2026-11-18] Add caveman + ponytail style rules (`CLAUDE.md`, ponytail rules for workers in `AGENTS.md`)
- [2026-11-18] Add orchestrator/worker workflow: Claude plans and reviews, DeepSeek workers (opencode) code (`CLAUDE.md`, new `AGENTS.md`); `dump.md` becomes an idea inbox reviewed against `docs/`; this dated change log
- [2026-11-03] Commit the prototype to GitHub (`6030a05 Add NetSeer FYP2 prototype`)
- [2026-10-22 – 2026-11-03] C3 change requests 2–5: algorithm review, inside-LAN detection, upload checks, AI stop, map and alert-page changes (exact dates not recorded; see RAD-PLAN decisions)
- [2026-10-22] Steps 11 + 12: live mode code done; hardware check partly done (switch SPAN source ports still to set)
- [2026-10-21] C3 change request 1: services fold, MACs + Wireshark vendors, saved AI, tree map, Clear log, Settings tabs
- [2026-10-21] Steps 8–10: knowledge base + RAG, evidence + LLM + verifier + AI page, optional TI + cloud backend
- [2026-10-21] Subnet auto-adopt
- [2026-10-21] C2 change request: timeline, 20-row tables, pie %, health model, capture checks, subnets, map
- [2026-10-21] Steps 5–7: contextor, scorer + roll-up, incidents + Home + NetSeer configuration
- [2026-10-21] C1 polish, change request 3, Fix + Detonate, C1 change request (large uploads, progress bar, Information page)
- [2026-10-21] Steps 0–4: environment audit, skeleton, auth, offline ingest, devices
