# dump.md — owner's idea inbox

How it works (see CLAUDE.md "dump.md: idea inbox"):
- Write new ideas under **Inbox**, one bullet each. Rough wording is fine.
- Claude reviews each idea against `docs/` (new / conflicts / duplicate / already done) and waits for your go-ahead before building it.
- Reviewed ideas move to **Reviewed** as `[YYYY-MM-DD] idea → verdict → commit`.
- Prompt "read dump.md #Inbox"

## Inbox

## Reviewed
- [2026-11-24] `GET /health` 404s in the app log → not a NetSeer bug: opencode 2.3.2's `serve --service` probes for a local vLLM at 127.0.0.1:8000 every ~25 s; `disabled_providers` alone did not stop it; fixed outside the repo with `providers.vllm.settings.baseURL = "off"` in ~/.config/opencode/opencode.json; 0 probes in 75 s after the restart, DeepSeek models still listed → no docs → no code commit
- [2026-11-24] Home Traffic Volume: Total default, button left, x-axis follows bin → new; done, HH:MM for whole-minute bins → CONCEPTS A10, brief §9 → a40e319
- [2026-11-24] SSDP false positive 192.168.100.24 → 192.168.100.1:1900 → rule is `any → $HOME_NET 1900`, not caused by inside_rules; sender process not identified; owner chose (a): no change, use the "Ignore NetSeer and Tailscale alerts" dev setting → no docs → a40e319
- [2026-11-24] Traffic Volume on Network page → new; done, full width below Traffic Source + Analyses, one shared chart (static/js/traffic.js) → CONCEPTS A10, brief §9 → a40e319
- [2026-11-24] Network map: Internet click toggles outside nodes, hidden by default, links to Internet, curved links → conflicted with A17; done → CONCEPTS A17, brief §9 → a40e319
- [2026-11-24] Gateway from ARP "who has" and IPv6 router advertisement → /24 grouping already done; new: ARP (≥3 askers, .1/.254 first, probable) and RA (MAC → IPv4 device, strong), Suricata ARP log on; RA seen in real eve (fe80::1 = 192.168.100.1's MAC), 1-min real ARP capture had only the router asking → CONCEPTS A17 → a40e319
- [2026-11-24] Test VirusTotal, ensure enrichment works → key and API work (8.8.8.8: 92 engines, 1 malicious); fixed live enrichment, 20-IP cap, rate limit; real session lookup not run → CONCEPTS A9, RAD-PLAN → 0d05065
- [2026-11-24] Alerts table filter rework → new; done with port, UTC time, proto, IP prefix/CIDR, removable chips → CONCEPTS A10, brief §9, RAD-PLAN → 0d05065
- [2026-11-24] Live stores eve.json + re-analyse → storing already done; Reprocess added, no new Suricata detection, device types kept → CONCEPTS A10/A13, brief §6c/§9 → 5cba687
- [2026-11-24] Settings tick to ignore NetSeer + Tailscale → new; done, default off, live only, alerts only; session 7: 20,551 of 23,540 hidden → CONCEPTS A3/A15, brief §6c → 5cba687
- [2026-11-24] Delete "## Archive" → done; text stays in git history → 5cba687
- [2026-11-24] Network: Traffic Source left, Analyses list right, row pop-up → conflicted with A10/brief §9; done → CONCEPTS A10, brief §9 → 1e01d12
- [2026-11-24] Alerts: new columns, row pop-up, copy raw eve.json → conflicted with A10/brief §9; done, Signature and Direction moved to the pop-up, incident page keeps its drawer → CONCEPTS A10, brief §9 → 1e01d12
- [2026-11-24] LAN CIDRs auto from local subnet → conflicted with A15; done for live sessions, custom list wins, offline unchanged → CONCEPTS A15 → e4d48f7
- [2026-11-24] Decay / half-life → mostly done; demo default 3 h, production 7 days, health fades on read; Elastic 30 days recorded as a window → CONCEPTS A5.4/A15 → e4d48f7
- [2026-11-24] Remove I1 from impact, criticality as device weight (Option B) → conflicted with A5.2/A5.4; done, applied once at network step → CONCEPTS A5.2/A5.4/A5.6 → e4d48f7
- [2026-11-24] Replace damped_union with rank-weighted sum, no k^1.5 → conflicted with itself (Elastic example matches k^1.5); owner took the recommendation, damped_union kept → CONCEPTS A5.4 → e4d48f7
- [2026-11-24] Network health, contributors, triage label → done; A5.6 health 62 → CONCEPTS A5.4/A5.6 → e4d48f7
- [2026-11-24] Alert severity / volume unchanged → duplicate, no work → e4d48f7
- [2026-11-24] Scoring tests and risk_eval → done; "split never raises" is impossible for identical incidents, so the rise is bounded below 0.09 → e4d48f7
- [2026-11-24] Spec sync, papers in report/references → done in docs; report text still to update on Windows → WRITEUP §4.5 → e4d48f7
- [2026-11-24] Commit README.md → done → f20f2d3
- [2026-11-23] Reorganize Settings → done in f93cc03, reverted by owner with the unslop UI, back in Inbox → 83c7255
- [2026-11-23] Proper mobile UI → done in f93cc03, reverted by owner with the unslop UI, back in Inbox → 83c7255
- [2026-11-23] All graphs broken → new bug from stale cached app.js; fixed with no-cache on static files → 92f8c77
- [2026-11-23] Alerts severity without [x] → conflicted with CONCEPTS A5.5, brief §9; done everywhere → CONCEPTS, brief §9, WRITEUP → 92f8c77
- [2026-11-23] Use /unslop for UI/UX after logic → new; adopted with limits (polish only, audit first, protected risk and wording), pinned 620163e → CLAUDE.md, AGENTS.md → c6efa5d
- [2026-11-23] Traffic Volume as lines → new; done → CONCEPTS A10 → c6efa5d
- [2026-11-23] Sidebar bound to browser height, Log out to topbar → height already done; move done → CONCEPTS A10, brief §9 → c6efa5d
- [2026-11-23] Device Attribution scrolls only its table → new; done → c6efa5d
- [2026-11-23] Detected Alert Classes as scrollable bars → conflicted with pie in A5.5/brief §9; done → CONCEPTS A5.5, brief §9 → c6efa5d
- [2026-11-23] Alert severity chips like Top Incidents → new; done, also on incident detail → CONCEPTS A10 → c6efa5d
- [2026-11-23] Home Analysis: Alert Groups → Total bit/byte/packets → new; done, follows Data Representation → CONCEPTS A10 → c6efa5d
- [2026-11-23] Left panel: Log out always visible → partly done before; only links scroll now → CONCEPTS A10 → a7f0e76
- [2026-11-23] Home: Traffic Volume, amount per bin, input + wheel + Reset, swap with Top Incidents → reversed the per-second choice; owner set a 5 s minimum, new `traffic_stats` → CONCEPTS A10, brief §5/§9 → a7f0e76
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
