# dump.md — owner's idea inbox

How it works (see CLAUDE.md "dump.md: idea inbox"):
- Write new ideas under **Inbox**, one bullet each. Rough wording is fine.
- Claude reviews each idea against `docs/` (new / conflicts / duplicate / already done) and waits for your go-ahead before building it.
- Reviewed ideas move to **Reviewed** as `[YYYY-MM-DD] idea → verdict → commit`.
- Prompt "read dump.md #Inbox"

## Inbox

## Reviewed
- [2026-11-23] Playwright usable by orchestrator and workers → new; done, cleaned DB copy via `netseer.eval.browser_env`, tested from a real worker → CLAUDE.md, AGENTS.md → 8547369
- [2026-11-23] Orchestration token rules → partly adopted: same-session fixes for rejected diffs, 8-read budget, no file dumps; shared plan file rejected (conflicts with copied constants in briefs), rest already covered → CLAUDE.md, AGENTS.md → 8547369
- [2026-11-23] Site runs via `./startnetseer.sh` on Tailscale → new note; done; Tailscale vs W9 UFW LAN-only left for the owner → CLAUDE.md, RAD-PLAN decisions → 8547369
- [2026-11-23] Orchestrator-worker + RAD efficiency → good for building, weak on recorded user feedback; empty feedback log created; Claude cost not measured → docs/feedback-log.md → 8547369
- [2026-11-23] Network: Traffic Source, Network Adapter option, required Session Name → new; done → CONCEPTS A10, brief §9 → 6598fac
- [2026-11-23] AI: toggleable prompt view + copy button → new; done, buttons do not run the LLM → CONCEPTS A10, brief §9 → 6598fac
- [2026-11-23] Home: Alert Trend → Traffic Rate (Ingress-Egress / Total) → conflicted with A10; owner approved, packet_stats schema changed; per second → CONCEPTS A10, brief §5/§9 → 6598fac
- [2026-11-23] Settings: Data Representation (bit/byte/packet) → new; done, applies to Traffic Rate → CONCEPTS A15 → 6598fac
- [2026-11-23] Alert ID column first → existing alerts.id shown, no schema change → CONCEPTS A10 → 0a90eb2
- [2026-11-23] Incident ID column first → existing incidents.id shown, no schema change → CONCEPTS A10 → 0a90eb2
- [2026-11-23] Left panel fixed to screen height → new; done → CONCEPTS A10 → 0a90eb2
- [2026-11-18] Implement docs/risk_scoring_redesign.md → partly adopted: I1 once (unweighted roll-up), k^1.5 = NetSeer heuristic, health = triage index; weighted mean, EMA, lookback window not adopted; ATT&CK breadth deferred → CONCEPTS A5.4/A5.6 → 8049477
- [2026-11-18] Review docs/netseer-risk-scoring-implementation-spec.md vs current model → not adopted as a whole (would undo A5 decisions; weaker evidence); adopted its audit fields, stable order, evaluation → CONCEPTS A5.3/A5.4
- [2026-11-18] Don't burn tokens; smarter route when stuck in a loop → new; done → CLAUDE.md "Token economy and loop guard", AGENTS.md "Save tokens"
- [2026-11-18] maclookup.app API when the local OUI lookup returns unknown → new; done, setting on by default, OUI only, cached → CONCEPTS A3/A9/A15
- [2026-11-18] progress.md = change log only → conflicted with CLAUDE.md/KICKOFF/WRITEUP pointers; done: environment → brief §3a, Tables 4.12/4.13 + demo commands → WRITEUP §8/§10, build record + decisions → RAD-PLAN; pointers updated
- [2026-11-18] Alerts table: Time (UTC), Severity, Signature, Class, Direction, Source, Destination, Proto; Priority → Severity [1] High…[4] Info → new; done (also incident raw alerts, filters, pie) → CONCEPTS A5.5/A10, brief §9
- [2026-11-18] Map shouldn't show "netmask" as a source → no netmask node existed; meant broadcast/multicast/unspecified addresses → hidden unless a device (.0 hosts kept) → CONCEPTS A17
- [2026-11-18] Home: Analysis card above Network health & Top incidents → new; done → CONCEPTS A10, brief §9

## Archive
Original raw notes (before cycle C1). Absorbed into `docs/CONCEPTS.md` on 2026-10-21; CONCEPTS.md wins where they differ.

Title: "Netseer: AI-Assisted Alert Interpretation System for Intrusion Detection Monitoring in Small Networks"

Overview:
- Helps local network owner/admin/user to view the network security status within their flat network (no segmentation).
- Aims to make non-technical users to understand alerts and reduce alert fatigue.
- No machine learning. The LLM (local/cloud) uses the evidence (processed alerts) and turns it into actionable output.
- Runs on Ubuntu Server 24.04 inside a mini PC (i5-9500T, 16-24GB RAM, 256GB SATA SSD).

System:
- Uses Suricata (ET-Open + Abuse.ch) to filter raw pcaps into eve.json.
- Uses custom modules/engines: logger (normalize & enrich), contextor, (aggregate & correlate) & prompt-maker (generate evidence-based prompt for LLM)
- Uses SQLite (database), Nginx, FastAPI, python, html, javascript, css, etc.
- Uses RAG pipeline to pull relevant data from database for prompt-maker.
- Uses mitreattack-python, AbuseIPDB & VirusTotal for enrichment (prompting for user-owned API).
- Scrap specific metada from pcap for enrichment.
- Dashboard colour theme: Black or white (default).

Features:
- Works offline (inputs a raw pcap) and real time (2 wired ethernets: to managed switch on port mirroring mode & LAN connection).
- Provides risk score on overall network security health based on ?
- Account management: Administrator (view & manage), User (view only). Includes strong password policy. Secured login and logout. 5 minutes account lock after 5 times failed login attempts.
- Account creation: There's no admin account yet > 1st user must create an admin account upon 1st launch. User account can only be created by admin. There can only be 2 accounts: admin & user.
- Logout: Logout action will be brought to login page.
- Device attribution: Assigns devices type (workstation, phone, server, etc.) upon inputting pcap (offline) or real network detection (real time). Influences risk scoring. 
- Prompt Maker: Provides simple customizable prompt (buttons to prompt) for user.
- Dashboard accessible via local network.
- Network selection: If not yet selected, user can choose run offline or real time mode. Offline mode asks for pcap file(s) then DA. Real time mode asks for ethernet connections (mirror & LAN) then DA. If ethernet connections are not complete, the real time analysis will be stalled until it detects and confirms. Both modes' analysis will be stored locally, & the naming is auto assigned or manually renamed. Each real time analysis will not be stored separately even if it's the same network.
- Offline analysis: Upload pcap and automates analysis. The output will be displayed in dashboard and stored locally. User can browse back analyzed network (pcap).
- Netseer configuration: Admin can adjust overall netseer settings (time-window)

Dashboard:
- Home: ?
- Alerts: Packets/Hour Graph, Suricata-filtered alerts, etc.
- Incidents: Finding table, etc.
- Devices: Devices list & attribution.
- AI: Analysis (summarize & recommend) & Prompt Maker.
- Network: Browse offline & real time network status/analysis. Upload pcap & real time network security status.
- Settings: Colour theme, API management, account management, Netseer configuration (admin only).
- Login: Username, Password & Account creation.

Must do:
- Prioritize on 5 years latest research papers for references/sources.
- Follow cybersecurity industry gold standards.

To research:
- Risk scoring framework/algorithm for device & network security health.
- LLM (local/cloud) output verification (hallucination check).
- ISO/IEC 27001, OCTAVE Framework (www.sei.cmu.edu/library/operationally-critical-threat-asset-and-vulnerability-evaluation-octave-framework-version-10/), NIST.