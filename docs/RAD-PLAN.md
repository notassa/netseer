# NetSeer — RAD Development Plan

## Context
NetSeer is a post-detection alert interpretation layer on top of Suricata (FYP2, UniKL BIT Computer System Security). This plan schedules the build using Rapid Application Development. It covers **what to build when**; **what** NetSeer is lives in `docs/CONCEPTS.md`, and **how** to build each part is in `docs/PROTOTYPE-BRIEF.md`.

**Current decisions (revision 2):**

| Area | Decision |
|---|---|
| Backend | FastAPI + Uvicorn, Jinja2, Chart.js, SQLite |
| LLM | Ollama with `llama3.2:3b`; cloud LLM optional (user key) |
| Modes | Offline (one or more pcaps, merged) **and** real-time (mirror + LAN NICs). Real-time is a **Must**, built after offline |
| Risk model | Hybrid: OWASP-style 0–9 incident factors + OWASP 3×3 band matrix; device/network roll-up by probabilistic union (Munir, 2014, Ch.3); alert mix is descriptive only (CONCEPTS A5) |
| Accounts | First-launch admin setup; max 2 accounts (1 admin, 1 user) |
| Code layout | The existing `netseer/` skeleton (`src/api`, `src/engine`, `src/database`, `ai`, `web`, `config`, `tests`) |
| Time | About 10 weeks (8-week compression below) |

**What changed since revision 1:**
- The Munir (2014) thesis was assessed and the risk model replaced: the old `R = 10·L·I` with 0–1 weights, CVSS bands and the "0.6·max + 0.4·mean" health formula are gone.
- dump.md features added: first-launch setup, two-account cap, logout redirect, white/black theme, network selection, multi-pcap merge, live stall states, one record per live session, analyses browser with rename, NetSeer configuration.
- Real-time moved from stretch to Must.
- Layout moved to the user's skeleton.
- Hardware: 256 GB SATA, 16–24 GB RAM.

## RAD loop
Each construction cycle runs **build → test → demo to Oriental Tech/supervisor → log feedback → refine**, and ends with a working, demo-able increment. `docs/feedback-log.md` records each session (date, who, what was shown, feedback, change made). This is the evidence for report Ch.4–5.

## MoSCoW
| Priority | Items |
|---|---|
| **Must** | First-launch setup + 2 accounts + auth/lockout/RBAC; offline mode (multi-pcap); real-time mode (stall flow, sessions); Suricata → ACP 1–7; hybrid risk model with breakdown; device attribution; analyses browser; 7 dashboard pages; local LLM + RAG + verifier; NetSeer configuration |
| **Should** | Prompt Maker buttons; AbuseIPDB/VirusTotal enrichment; cloud LLM adapter; alert-mix chart; white/black theme |
| **Could** | CSV export of incidents; PDF summary of an analysis |
| **Won't** | ML detection, IPS blocking, SIEM features, multi-site, more than two accounts |

## Schedule (10 weeks)
| Week | Phase | Work | Exit / demo |
|---|---|---|---|
| W1 | Requirements Planning | Freeze CONCEPTS.md; FR/NFR with acceptance criteria; server setup (Suricata 8 + rules, Ollama, mergecap, Python venv); measure tokens/s on the i5-9500T; get UNSW-NB15 subset + GT CSV; record the lab demo pcap | Supervisor sign-off; Suricata makes eve.json; Ollama answers |
| W2 | User Design | Low-fi wireframes: Setup/Login, Network selection (offline + live states), attribution modal, Home, Incidents detail with breakdown, AI; freeze `schema.sql`, evidence and LLM-output schemas, API routes; clickable mock | **Feedback #1** (wording, Home metrics, attribution flow) |
| W3–4 | Construction **C1**: foundation & offline | Brief §10 steps 1–4: package skeleton, setup/auth/accounts/theme, multi-pcap ingest + mergecap + Suricata, logger, analyses browser + rename, Alerts + alert mix, Devices + attribution | **Demo #2**; tests: auth, ingest, logger |
| W5–6 | Construction **C2**: ACP & risk | Brief steps 5–7: contextor R1–R4, scorer (factors, matrix, roll-up), Incidents, Home, NetSeer configuration; `eval/unsw_validate.py` + `eval/acp_metrics.py`; **calibrate** windows and factor values on UNSW-NB15 + demo pcaps; run the union saturation check | **Demo #3** (does the ordering match human judgement?); tests: contextor, scorer (A5.6) |
| W7 | Construction **C3**: interpretation | Brief steps 8–10: KB + RAG, evidence package, Prompt Maker, Ollama caller, verifier, AI page; optional TI + cloud LLM behind flags | **Demo #4** with non-expert users; tests: verifier |
| W8 | Construction **C4**: real-time | Brief steps 11–12: NIC discovery, stall state machine, `netseer-live@` unit + sudoers, tailer with offset/rotation, incremental ACP, live attribution, session records | **Demo #5** on the managed switch; tests: live state machine, tailer |
| W9 | Cutover | Deploy on the mini PC (systemd units, Nginx TLS, UFW LAN-only, retention); ASVS 5.0 L1 (+L2 auth/session) hardening; full evaluation run | Evaluation numbers collected |
| W10 | Cutover | User comprehension study + SUS; fix defects; code freeze; report Ch.4–6 + CONCEPTS A11 fixes; rehearsal | Submission |

**8-week compression:** W1 + W2 become one week (wireframes by sketch). C3 and C4 stay one week each. Cutover becomes one week (evaluation and report in parallel). If C4 slips, ship live mode with incremental ACP but without live attribution, and finish attribution in cutover.

**Risk buffer:** CPU LLM latency (about 1 min per explanation) is handled by background generation and pre-generation. Live-mode privileges come from the narrow sudoers rule, which is tested in W1 on the real box. UNSW-NB15 pcap size is handled by using a subset.

## Phase details
### Phase 1 — Requirements Planning (W1)
- FR/NFR list = report Tables 3.1–3.2, updated:
  - FR for first-launch setup, the two-account cap and logout redirect
  - FR for network selection, live stall states and session records
  - FR for analysis rename/browse and NetSeer configuration
  - real-time moves to Must
- Acceptance criteria are the brief's §10 "Check" lines.
- Environment per brief §3. Confirm both NICs are seen, the switch's mirror port works, and `sudo systemctl start netseer-live@<nic>` works for the `netseer` user.

### Phase 2 — User Design (W2)
- Wireframes focus on the non-expert: band before numbers, plain-language titles, one clear next action, the "unknown" state shown honestly.
- Live-mode wireframe shows each stall state with a human message, e.g. "Waiting for traffic on enp2s0 — check the switch mirror port".
- Update report diagrams (architecture, activity, use case, misuse case) for setup, network selection and live mode.

### Phase 3 — Construction (W3–W8)
Cycles C1–C4 as in the schedule; step-level detail and checks are in the brief §10. Every cycle re-runs the regression check: a fixed small pcap → full pipeline → expected counts, plus the A5.6 worked example.

### Phase 4 — Cutover (W9–W10)
1. **Deploy:** systemd (`netseer`, `ollama`, `netseer-live@`), `config/nginx/netseer.conf` with TLS (local CA), UFW allowing only the LAN, log rotation, retention setting.
2. **Hardening:** OWASP ASVS 5.0 walk-through; ISO/IEC 27001:2022 Annex A mapping (report Table 4.9); OWASP ZAP baseline scan.
3. **Evaluation (report §3.4):**
   - **Suricata validation:** TP/FP/uncertain per UNSW-NB15 category.
   - **ACP:** volume reduction %, group/incident purity against GT, traceability = 100%; risk-model sanity (ordering vs expert ranking; saturation behaviour of the health score).
   - **AI:** faithfulness, unsupported-claim rate, accuracy on about 30 sampled incidents, uncertainty clarity, action relevance (expert Likert).
   - **System:** seconds per MB, live alert delay, LLM latency, CPU/RAM; SUS; comprehension study (raw alert vs NetSeer explanation).
4. **Report:** Ch.4–6 and the CONCEPTS A11 items (hybrid risk model, hardware, password length, real-time scope); add screenshots via `report/tools/build_report.py`.

## Verification (how each increment is proven)
- **Unit tests (pytest):**
  - logger (eve fixture)
  - contextor (synthetic sequences per rule)
  - **scorer** (CONCEPTS A5.6 worked example; matrix edges at 3.0 and 6.0; L5 omitted when TI is off)
  - **roll-up** (Note excluded; decay halves p at one half-life; health = 53 for the example)
  - verifier (fake IP, wrong band, missing ref, overclaim)
  - auth (**setup locks after first admin**, **third account refused**, lockout after 5, RBAC 403, **logout → /login**)
  - ingest (bad magic rejected; multi-file merge order)
  - **live** (state machine on stubbed sysfs; tailer offset and rotation)
- **Integration:** fixed small pcap → full pipeline → expected alert/group/incident counts and a verified explanation, every cycle.
- **Ground truth:** `eval/unsw_validate.py`, `eval/acp_metrics.py` (new folder `netseer/eval/`).
- **On hardware:** `eval/sys_metrics.py` for timing and resources; a live demo on the managed switch.

## Build record
One row per brief §10 step or change request, with the evidence that its Check passed. Dated one-liners: `docs/progress.md`.

| Step | Status | Check | Notes |
|---|---|---|---|
| 0 Environment audit | Done | — | See above |
| 1 Skeleton, schema, init-db, layout + theme | Done | ✅ app starts; first visit → 303 `/setup` | 3 tests. `netseer.yaml` generated from the system config; Chart.js vendored; password blocklist (5,540 entries ≥15 chars) |
| 2 Setup, login/logout, lockout, sessions, CSRF, RBAC, account cap | Done | ✅ after setup `/setup` → 404; 3rd account refused; user → 403 on admin routes; logout → `/login` (verified on a live server with curl) | 18 tests total. Argon2id; sessions stored by SHA-256 of the cookie token; lockout applies to unknown usernames too (no enumeration); pre-login CSRF via cookie |
| 3 Offline ingest + logger + analyses browser + Alerts + alert mix | Done | ✅ two demo pcaps uploaded together → one analysis whose alerts span both files (08:53 from part A, 09:53 from part B); rename persists (pytest integration test + live server via curl) | 39 tests total. Test pcaps are generated by `tests/pcapgen.py` (pcaps never committed). Suricata on the 22-packet demo: ~24 s, almost all rule loading (109k rules) |
| 4 Devices + attribution modal | Done | ✅ after upload the modal lists the 4 internal hosts (not the external IP, broadcast or unanswered scan target); saved type persists and the analysis moves to `done` (pytest integration test + live server) | 45 tests total (2 integration tests run real Suricata). Risk column reads "not scored yet" until C2 |

| C1 change request (2026-10-21): large uploads, progress bar, sidebar rail, Information page | Done | ✅ 1.6 GB + 1 file: upload 7 s, analysis 52 s with stages merging → loading rules (~23 s) → reading capture 0–100% → processing; merged copy removed. Login/logout rows carry IP + MAC (MAC resolved for a LAN client via `ip neigh`) | 63 tests total. 2048 MB per file + free-disk guard (2.5×). Streaming PUT upload (no multipart temp copy). Fixed: mergecap pcapng with mixed snaplen made Suricata read nothing yet exit 0 — now merge to classic pcap and fail on read errors in suricata.log |

| Fix + Detonate (2026-10-21) | Done | ✅ owner's `27.pcap` (568 MB, last packet cut off at recording) now analyses: 1,067,724 packets, 34,385 events, 233 alerts, 2 devices in 27 s (21 MB/s), flagged with a note + `capture_truncated` warning | 71 tests. Upload size must equal the announced size; Re-analyse button; Detonate (password + DETONATE) wipes all and returns to `/setup` |

| Change request 3 (2026-10-21) | Done | ✅ live: two single-file uploads into one session (first `pending`, second analysed) → one analysis spanning both files; packets per 30 min; session 10 min, Extend → +10 min; External sources lists testmynids.org | 87 tests. 10-min session + Extend (requests no longer extend it); upload sessions; External sources; packets per x minutes; sortable tables + Reset; type-or-pick search; admin notes; fixed `startnetseer.sh`. Owner capture `18.pcap`: 1,907 MB in 33 s (57.6 MB/s), 92,002 events |

| C1 polish (2026-10-21) | Done | ✅ alert mix is a pie chart (top 7 + "other"); Reset order uses the Clear button style and sits next to Clear on filtered tables | Owner request; CONCEPTS A5.5 and brief §9 now say "pie chart" |
| 5 Contextor (R1–R4) | Done | ✅ synthetic alerts give the expected incidents per rule: gap split, R1, R2 (5 hosts yes / 4 no), R3, R4, window edge, several rules on one incident (`test_contextor.py`) | 95 tests. Owner analysis "big": 750 alerts → 564 groups → 17 possible incidents in 0.02 s |
| 6 Scorer + roll-up | Done | ✅ A5.6 reproduces exactly, from pure functions and end to end through contextor + DB: L 5.84/5.34, I 3.0/7.5, Medium/High, R 2.16/4.94, P(d) 0.216/0.494, P(N) 0.474, health 53 (`test_scorer.py`) | 109 tests. Matrix edges at 3.0/6.0, Note excluded, decay halves p at one half-life, L5 left out of the mean. ACP 3–6 now runs at the end of every offline analysis (stage "correlating"); `python -m netseer.cli acp <id|all>` backfills C1 analyses |
| 7 Incidents + Home + NetSeer configuration | Done | ✅ changing a device type re-scores (server → guest: I1 9 → 3, score and health change) and changing the correlation window rebuilds incidents and updates Home (`test_incidents.py`); live on a copy of the owner DB: window 30 → 5 min gives 17 → 89 incidents, back to 30 gives 17, both logged as `config_changed` | 121 tests. Incidents table (band, score, title, rule, hosts, span, alerts; search/band/rule filters); detail with factor breakdown, group timeline, raw alerts + drawer; Home gauge, top 3 devices, top 5 incidents, devices at risk, alerts per hour, analysis card; Devices risk %; Settings → NetSeer configuration. Eval: `python -m netseer.eval.acp_metrics <id> --rerun`, `python -m netseer.eval.unsw_validate <id> --gt UNSW-NB15_GT.csv` |
| C2 change request (2026-10-21): timeline, 20-row tables, pie %, health, capture checks, subnets, map | Done | ✅ on a copy of the owner DB ("big", UNSW-NB15 14/16/17/18.pcap): Info shows the 25 min 48 s gap where 15.pcap is missing and 90,625 TCP reassembly gaps; health 55 (was 100) and stable across windows; timeline scrolls at 1/5/10/20/40/60-min steps; Networks finds 59.166.0.0/24, 149.171.126.0/24 and 175.45.176.0/24 as "looks local"; map pans, zooms and drags in both layouts (headless Chromium, no console errors). Fresh demo run: DHCP + gateway give 192.168.100.0/24 "certain" | 137 tests. CONCEPTS A5.4/A5.6 (rank-damped union, health 53 → 62), new A16/A17, brief schema (`analysis_info`, `host_links`), CLAUDE.md test line. The packets chart now keeps empty bins as 0, so capture gaps show |
| Subnet auto-adopt (2026-10-21, owner request before C3) | Done | ✅ re-analysing "big" (UNSW-NB15 14/16/17/18.pcap) on a copy of the owner DB: 175.45.176.0/24, 59.166.0.0/24 and 149.171.126.0/24 adopted as the analysis's LAN (`lan_adopted`), devices 2 → 36, health 41, 44 possible incidents; two Suricata passes, 216 s for 7.6 GB | 139 tests. CONCEPTS A15/A17 + brief §6a. Per-analysis LAN stored as settings key `lan_cidrs:<id>` (no schema change); HOME_NET, directions, devices, ACP and discovery all read it |
| 8 KB build + RAG | Done | ✅ SID 2008362 (ET SCAN bsqlbf Brute Force SQL Injection) → rule, T1190 Exploit Public-Facing Application, mitigations M1016/M1026, classtype, playbook PB-EXPLOIT; fixture test does the same for a scan SID | 144 tests. `python -m netseer.cli build-kb` in 17 s: 109,263 rules, 765 ATT&CK objects (tactics, techniques, mitigations), 1,477 mitigation links, 43 classtypes, 8 playbooks. Separate `ai/kb/kb.db`; ATT&CK STIX bundle downloaded to `ai/kb/enterprise-attack.json` (gitignored). Settings → "Rebuild knowledge base" (admin, background) |
| 9 Evidence + LLM + verifier + AI page + Prompt Maker | Done | ✅ `pregen 2 --top 5` on the UNSW copy with `llama3.2:3b`: 5 explanations, 46–117 s (mean 91 s), 4 verified, 1 flagged for a real band mismatch ("high risk" for a Critical incident); crafted outputs: fake IP + port → entity, wrong band → band, missing/unknown ref → schema/citation, "was compromised" → overclaim, "may have been compromised" → not flagged | 153 tests. `ai/schemas.py`, `prompt_maker.py` (E#/K#/unknowns, 5 intents), `llm_caller.py` (Ollama `/api/chat` + JSON-schema format), `verifier.py` (checks 1–5), `explain.py` (cache by incident, intent, evidence hash; background job). AI page with Prompt Maker buttons, Verified/N-flagged badge, highlighted sentences, ref chips; Incident → "Explain with AI"; `cli pregen` |
| 10 Optional TI + cloud backend | Done | ✅ with no keys: TI off, L5 left out, A5.6 still health 62, Settings/AI pages work, Ollama backend chosen; a mocked AbuseIPDB result of 90% gives L5 = 8.1 and a TI fact in the evidence | 157 tests. Keys Fernet-encrypted in `api_keys` (key file `src/database/netseer.key`, mode 600, gitignored), write-only in Settings. `engine/ti.py`: AbuseIPDB + VirusTotal for public outside IPs of the top incidents, cached 24 h, VT spaced 15 s; runs after an analysis (outside the Suricata lock) and re-scores. Cloud LLM: any OpenAI-compatible `/chat/completions`, only with URL + model + key |
| C3 change request (2026-10-21): services fold, MACs + Wireshark vendors, full width, saved AI, tree map, Clear log, Settings tabs | Done | ✅ headless Chromium on the UNSW copy, no console errors: page frame 1,390 px of a 1,600 px window (sidebar 210); 42 long service cells fold behind "+N more"; map hides all links, a clicked host shows its 10 alert links, empty-space click hides them, dragging a network moved its child by exactly (+50, +30); Settings opens one tab (`#tab-oui`); AI page lists 5 saved explanations; Clear process log button present. Wireshark manuf downloaded: 58,575 entries, dated 2026-10-21 10:40 UTC (TShark 5.1.0rc0). UNSW SLL capture: MACs read in 9.6 s | 165 tests. CONCEPTS A3, A10, A15, A17 + brief §9 |
| 11 + 12 Live: NIC discovery, stall states, capture unit, sudoers, tailer, incremental ACP | Done | ✅ on the box (2026-10-22): session 6 `waiting_interfaces` → `waiting_traffic` → `ready` in 10 s; Start runs `netseer-live@enxec1ac300527e` as netseer via sudoers (Suricata af-packet, 6 workers, engine up in 24 s); the tailer reads eve.json; Stop closes the record and stops the unit; session 7 is a new record. Fixed: relative OUT_DIR made Suricata exit. ✅ 2026-11-23 on the TP-Link ES208G (mirror port 5; mirrored ports 4, 6, 7, 8, both directions): with promiscuous mode the mirror matched `eno1` traffic (idle 1,755 vs 1,731 packets, 0 drops). The earlier "multicast only" reading came from counters on a non-promiscuous NIC. Live session 7: `waiting_traffic` → `ready` in 15 s, Suricata set promiscuous mode itself, 465 events, 85/85 eve alerts stored (including 40 from a test ping), 9 incidents, Stop closed the record and the unit. ✅ Alert delay (session 8, ping trigger because `testmynids.org` is NXDOMAIN): 5/5 alerts stored within the 30 s interval (11.0–29.5 s, median 17.0 s); sessions 7 and 8 are separate records | 197 tests. `engine/live.py`: physical NICs from `/sys/class/net` (lo and virtual skipped), state machine `waiting_interfaces → waiting_traffic → ready → running → stopped` (stubbed sysfs tests), `netseer-live@<nic>` started via `sudo -n systemctl` with a per-session env file, tailer from `eve_offset` with half-line and rotation handling, ACP rebuilt per interval with **incident ids kept** (first alert id) so explanations survive. Monitor thread starts with the server. Network page: NIC picker, stall message, Start capture / Stop. Live attribution banner + modal. Settings: live interval; "Update Suricata rules" (sudo `suricata-update`, no args) + KB rebuild. Files: `config/systemd/netseer-live@.service`, `config/sudoers.d/netseer`, `config/netplan/90-netseer-mirror.yaml` |
| dump.md ideas (2026-11-18): alert Severity column, map non-hosts, Home order | Done | ✅ alerts table 8 columns in the owner's order, `[1] High` shown; map of "realnetwork" no longer draws 192.168.100.255, 224.0.0.251, 239.255.255.250, ff02::…, :: while UNSW's .0 devices stay; Analysis card first | 203 tests. Commit 0c46937 |
| dump.md ideas (2026-11-18): online MAC vendor fallback, progress.md = change log only | Done | ✅ fake-API tests: fill + cache, setting off, randomised/known MACs never sent, network error → 0 and no cache, not-found cached; real API: 005056 → "VMware, Inc.", FFFFF0 → found false (same JSON shape as the code expects). progress.md sections moved word for word (every old line found in docs/) | 208 tests. Lookups run after an offline analysis (before TI) and on each live tick; at most 100 per run (limit 25/s, 25k per 6 h) |
| Risk spec review (2026-11-18): keep A5, adopt audit fields, stable order, eval | Done | ✅ A5.6 still health 62 with `_meta` present; unattributed device → LLM unknown; `risk_eval` on a DB copy of "unsw" (analysis 5, 71 incidents, stored scores): ±20% sensitivity L1 7.0%, L2 7.0%, L3 8.5%, L4 8.5%, L5 0.0%, I1 7.0%, I2 7.0%, **I3 43.7%**; ablating I3 moves bands from 2/8/3/57/1 (Critical/High/Medium/Low/Note) to 0/5/59/7/0 | 213 tests |
| Risk redesign review (2026-11-18, `docs/risk_scoring_redesign.md`): I1 counted once, k^1.5 relabelled heuristic, health = triage index | Done | ✅ A5.6 recomputed by hand: P(N) = 1 − 0.506 × 0.924 = 0.533 → health **47** (was 62), test passes; device-type change still lowers unrounded P(N); real DB read-only with stored scores: realnetwork 61, unsw 10, test_ssh 79 | 213 tests; model version A5-1.1 |
| dump.md ideas (2026-11-23): Alert ID, Incident ID, fixed left panel | Done | ✅ `pytest netseer/tests`: 213 passed; IDs show the existing primary keys, no schema change |
| dump.md ideas (2026-11-23): Traffic Source, AI prompt, Traffic Rate, Data Representation | Done | ✅ `pytest netseer/tests`: 223 passed; Playwright Chromium on a DB copy: 27/27 checks, no console errors; migration kept all 118 `packet_stats` rows. Not exercised: a real upload or live capture through the new card. `realnetwork`: 43.2% of packets classified, the rest is global IPv6 outside the LAN CIDRs |
| dump.md ideas (2026-11-23): worker Playwright, token rules, startnetseer note, RAD review | Done | ✅ `browser_env` smoke check from Claude and from a real opencode worker: 7 pages 200, 0 console errors, cleaned DB copy; `docs/feedback-log.md` created with no sessions logged |
| dump.md ideas (2026-11-23): Traffic Volume, 5 s table, card swap, pinned Log out | Done | ✅ `pytest netseer/tests`: 227 passed; Playwright on a cleaned DB copy: 25/25 checks, no console errors; UNSW logger 38.0 s → 39.7 s, 1,317 rows, split packets and bytes equal `packet_stats` |
| dump.md ideas (2026-11-23): line chart, total traffic, topbar Log out, attribution scroll, class bars, severity chips, unslop rules | Done | ✅ `pytest netseer/tests`: 233 passed; Playwright on a cleaned DB copy: 18/18 checks at 390–1366 px, no console errors. `unslop` audit awaits owner approval |
| Owner request (2026-11-23): consistent UI/UX across the system, approved unslop fixes | Done | ✅ `pytest netseer/tests`: 233 passed; Playwright on a cleaned DB copy: 9 pages × 2 themes × 2 widths (36/36), 14/14 interaction checks, no console errors |
| dump.md ideas (2026-11-23): stale-script chart fix, severity labels without [n] | Done | ✅ static files send `Cache-Control: no-cache`; browser check on DB copy: 4 charts drawn on Home + Alerts, no page errors, no [n] labels; `pytest netseer/tests` 234 passed |
| dump.md ideas (2026-11-23): Settings structure, mobile layout | Done | ✅ browser check on DB copy at 390 px: 8 pages with no sideways overflow, drawer opens and closes by button, Esc and scrim, 7 Settings sections open, config save works; `pytest netseer/tests` 236 passed |
| dump.md ideas (2026-11-24): auto LAN subnet for live, risk model A5-1.2 (Option B, 3 h demo half-life) | Done | ✅ `pytest netseer/tests`: 242 passed; A5.6 by hand and in tests: P(N) 0.381, health 62. Real DB copy re-scored: analyses 4/5/6/7 health 53/25/83/53 (before 61/10/80/43); `risk_eval` on analysis 5 ran | Rank-weighted sum not adopted: `damped_union` kept (CONCEPTS A5.4). The real DB keeps old scores until `python -m netseer.cli acp all` |
| Owner request (2026-11-23): revert UI to `1a2add9`, disable unslop | Done | ✅ `netseer/web` matches `1a2add9` except one severity label line; browser check on DB copy: Home and Alerts charts draw, Settings tabs open, no page errors; `pytest netseer/tests` 234 passed |

## Decisions to confirm at the demo
Moved from `docs/progress.md` (2026-11-18). Rules that the owner confirmed belong in CONCEPTS.md; remove them here once confirmed.

### C1
- **RBAC for changes:** uploads, deletes, device attribution and type changes are admin-only ("User = view only", A9/A12). Renaming is allowed for both accounts because A13 says "Users can rename; the admin can delete". Say if the User should be read-only for renames too.
- **What counts as a device:** an internal IP that sent traffic or answered a flow. This keeps broadcast addresses and unanswered scan targets out of the inventory (brief §6a says "every internal IP in any event").
- **Schema additions (no column changes):** `UNIQUE(analysis_id, ip)` on `devices` and a primary key `(analysis_id, hour)` on `packet_stats`, so re-processing (and C4's incremental logger) merges instead of duplicating.
- **classtype:** eve.json alerts carry only the classtype description (`alert.category`); the logger maps it to the short name via `classification.config` for I3 in C2.
- **AI** is a placeholder until C3 (Home and Incidents were built in C2).

### C2
- **Alert mix is a pie chart** (owner request, 2026-10-21). CONCEPTS A5.5 and brief §9 were updated. The top 7 slices are shown and the rest is folded into "other".
- **Several rules on one incident:** union-find can link one incident by several rules. All of them are stored (e.g. `R4,R1,R2`, strongest first), and L3 and the title template use the strongest.
- **R4 progression:** fires when one internal host has at least 2 distinct MITRE tactics within the correlation window, in any order. Titles list the tactics in time order.
- **I2 service port:** the most sensitive port on either side of the alert. Suricata can report a C2 response with the server port (443) as the *source* port, so only checking the destination port would miss it.
- **I1 with no internal device involved** (for example ext→ext) uses Unknown (5).
- **Age reference for decay (offline):** the last alert of the analysis, not the time it was processed.
- **Window/half-life changes re-run only the selected analysis** (A15 wording). Other analyses keep their results until they are re-analysed or `cli acp all` is run.
- **LAN CIDRs:** the configuration form stores them, but they apply to the next analysis or a re-analyse. Directions and devices are set when the eve.json is read.
- **The "big" analysis is UNSW-NB15 traffic** (Feb 2015; hosts 175.45.176.x / 149.171.126.x, which are public addresses). With the RFC1918 default those hosts are not devices, so Home shows health 100 and devices at 0%. For evaluation, set LAN CIDRs to `149.171.126.0/24` and `175.45.176.0/24`, re-analyse, then run `eval/unsw_validate.py` with `UNSW-NB15_GT.csv`. The GT file is not on the server yet; calibrating the windows waits for it.
- **Data retention, LLM backend, KB rebuild, rules update, live interval** appear in Settings as "still to come" (C3/C4/cutover).
- **Health model** (owner choice): rank-damped union over every non-Note incident (CONCEPTS A5.4). Home explains it with each incident's share of the drop (log-additive split, so the shares add up to 100 − health).
- **Timeline:** drawn as an SVG Gantt with the labels pinned on the left, not as Chart.js. It is exact to the pixel and scrolls sideways; the plan had suggested a second Chart.js axis canvas, but this meets the same goal more reliably.
- **Broadcast evidence** tries the common masks only (/16 for x.x.255.255, then /24, /25, /26), because an address like x.x.1.255 is also the broadcast of a /23.
- **Network map for analyses made before this change** uses alert pairs and external peers for links (shown as "links from alerts only"). Re-analyse to get every flow and the VLAN/DHCP/gateway evidence.
- **UNSW-NB15 networks** are flagged "looks local, outside LAN". To score them as your own, set LAN CIDRs to 59.166.0.0/24, 149.171.126.0/24 and 175.45.176.0/24, then re-analyse.

### Subnet auto-adopt
- **Rule:** networks outside the LAN CIDRs whose hosts talk among outside networks are adopted for that analysis when they hold more hosts than its internal devices. Once per analysis; the global LAN CIDRs stay RFC1918. Re-analyse keeps the adoption; delete removes it.
- **Trade-off on UNSW-NB15:** the attacker range 175.45.176.0/24 is adopted too, so Suricata's `$EXTERNAL_NET → $HOME_NET` rules no longer fire between attacker and victims: alerts 1,630 → 1,342. To score only the victims and clients, set LAN CIDRs to `59.166.0.0/24` and `149.171.126.0/24` in Settings and re-analyse (then 175.45.176.0/24 is too small to be adopted).

### C3
- **Steps 9 and 10 are one commit**: the evidence package reads the TI cache, so they could not be split cleanly.
- **Prompt size:** at most 5 hosts, 5 alert groups and about 10 knowledge items (250 characters each), so the prompt stays near 2,300 tokens inside `num_ctx` 4096. The first try (25 knowledge items, ~3,800 tokens) timed out.
- **Ollama threads = 4** (`num_thread`) and **max 900 output tokens**: with the crash-looping `suricata.service` holding one core, 6 threads were much slower (step 0). Disabling that service (`sudo systemctl disable --now suricata`) should speed things up; then try 5–6 threads.
- **Refs are required by the schema** (1–4 per claim and action), so the model's JSON grammar forces citations. Before that, 3 of 3 explanations were flagged only for missing refs.
- **"Summarise this analysis"** is stored on the analysis's top incident (the `interpretations` table is keyed by incident), with the network health and the top 5 incidents as evidence.
- **Who may explain:** both accounts (it only reads the analysis); keys, backend and the KB rebuild are admin-only.
- **Overclaim check** flags assertive wording ("was compromised", "gained access", "succeeded") unless the sentence hedges (may, might, no sign, whether…) or a `successful-*` classtype is in the evidence.
- **TI runs only for public outside IPs** (`is_global`), at most 20 per analysis, after the analysis finishes. Analyses made before a key was added get TI on re-analyse.

### C3 change request
- **Why devices had no MAC:** UNSW-NB15 pcaps are Linux cooked (SLL) captures. They have no Ethernet header, so Suricata writes no MACs. A vendor list alone could not fix that, so NetSeer now reads the sender MAC that SLL keeps per packet (first 2 M packets, `tcpdump -e`).
- **Router MACs are not given to hosts:** a MAC seen for 3 or more source IPs is a router's (UNSW: Palo Alto firewall for 20 servers, a randomised MAC for 13 hosts). Those hosts stay "unknown" instead of showing the router's MAC. On UNSW, 3 of 36 devices get their own MAC (VMware); your own Ethernet captures are unaffected (Suricata reads both MACs).
- **Wireshark list:** stored as `src/database/manuf` (gitignored). The "version date" is the file's Last-Modified date on wireshark.org. Updating also refreshes vendors of stored devices. Wireshark asks not to download more than once a week.
- **Clear log** deletes one tab's entries after a confirm dialog and keeps one entry saying who cleared how many (so a wipe is never invisible). No password prompt (Detonate has one).
- **Saved explanations:** every explanation stays in `interpretations`; the AI page lists the analysis's last 100. One whose evidence changed since opens with a note.
- **Map:** the Network (force) layout and the "only links with alerts" box are gone; "Reset layout" redraws the tree.
- **Re-analyse "big"** to get the MACs (a single pass now: its LAN adoption is kept).

### C3 change request 2 (algorithm review)
- **R2/R3 need the same SID.** Before, a sweep/fan-in counted hosts across any signatures, so unrelated alerts between busy hosts chained into blobs (43% of "big"'s alerts in two incidents). "big": 45 → 204 incidents, largest incident 25% → 17% of alerts, health 41 → 44.
- **R4 needs a forward kill-chain step** (ATT&CK tactic order). Reverse pairs such as "Lateral Movement → Initial Access" no longer fire it.
- **Correlation window = longest quiet gap** inside an incident (chaining kept, now written down in CONCEPTS A4/A0).
- **L5 is raise-only** (a clean reputation no longer lowers the top incidents); VirusTotal = min(1, malicious engines/5); VT with no engine results is unknown, not safe. Cached VT results keep the old ratio until refetched (24 h).
- **Device colour = worst incident band** on Devices, Home and the map; the % is still P(d). Home "devices at risk" = worst band Medium or above.
- **Still open:** the largest "big" incident (17%) is one Suricata decoder event (STREAM ESTABLISHED packet out of window) between 10 → 10 hosts. With one SID it is a genuine R3 under the rules; leaving engine events (SIDs 2200000–2299999) out of R2/R3 would remove it.
- **Munir check:** A5.1 now says the independence assumption is NetSeer's own (the thesis never states it and its department figures disagree, Eq. 3.3 vs 3.18). The PDF sits in `docs/`, gitignored.
- **Glossary:** CONCEPTS A0.

### C3 change request 3
- **Why "realnetwork" missed the attack:** the nmap scan from 192.168.100.139 (998 ports on 7 hosts) was in the capture, but Suricata raised no scan alert: ET SCAN rules mostly need `$EXTERNAL_NET → $HOME_NET`, and Suricata has no port-scan tracker. The vulnerability scan of 192.168.100.142 was **not in the capture at all** (zero packets to .142): the capture point did not see it. Use the switch mirror port.
- **Fixes:** Suricata runs with `EXTERNAL_NET=any`, and NetSeer adds its own port-scan alert from flow events (≥ 50 probed ports per host, SID 9000001). Re-analysed "realnetwork": 7 NETSEER scan alerts + ~30 ET SCAN alerts → one Medium incident "192.168.100.139 → 192.168.100.1: 14 different signatures" (R1, R2); the Attack → Victim panel lists all scanned hosts.
- **Stop** (admin) kills Suricata within about a second, deletes the run's results and eve.json, keeps the capture; status `stopped`; Re-analyse works. A row left running by a restart is cleared at once.
- **AI progress %** is an estimate (mean of the last 10 timed explanations, 90 s before any), held at 95% until done.
- **Alert filters:** collapsible frame; tick boxes for priority, severity, direction, class (values in a group are OR-ed, groups AND-ed).
- **Auto-logout toggle** (Settings > Accounts): global; off = no countdown, sessions still end 12 h after sign-in.

### C3 change request 4
- **ET SCAN alerts read as `attempted-recon`** (ET files many under bad-unknown/misc). **L1: "Informational" no longer overrides the priority** (other severities still do), so ET scans with priority 2 get L1 6. The A5.6 example is unchanged (health 62).
- **Recon is its own incident:** recon groups link only with recon; R4 leaves them out; a later incident on the same hosts shows "Preceded by recon". Titles use the widest rule (R4 > R3 > R2 > R1). "realnetwork": "Sweep from 192.168.100.139 to 7 hosts (ET SCAN Potential SSH Scan OUTBOUND)", Medium.
- **"Detect attacks from inside the LAN"** (EXTERNAL_NET = any) is now a setting, default on. On "big" it adds ~65,000 LAN policy alerts (1,337 → 66,569; one incident 93% of alerts), so the Table 4.13 run uses it **off**.
- **Global data until Detonate:** TI results no longer expire (each IP looked up once); new `ip_names` table (IP → name from DNS/SNI/HTTP/DHCP) fills names an analysis lacks.
- **Map:** clients hang under their gateway; right-drag pans; left click selects; left-drag moves a node with its subtree.
- **Alerts page:** alerts per x minutes chart (shares the bin size) and top 5 devices by alerts.
- **Tooltips** on every table column head (one shared map in `deps.COLUMN_HELP`).
- **AI:** Stop closes the Ollama stream (verified on the real model: stopped 4 s into a long reply). While Ollama is still reading the prompt (up to ~50 s) no tokens arrive, so the model keeps working until its first token; the page shows "Stopped" at once and nothing is saved. Clear saved explanations (admin).

### C3 change request 5
- **Uploads:** refused when the file header is not a real pcap/pcapng (magic + version/snaplen or the pcapng section header) or when its SHA-256 is already stored in any analysis.
- **Delete a file** from a session (admin): results cleared, status `pending`; the last file deletes the session.
- **AI page:** one button toggles "Explain with AI" ↔ "Stop".
- **Alerts page:** packets and alerts charts side by side, each with its own bin size; the pie is now "Detected Alert Classes".
- **Map:** scroll to zoom (own wheel handler; Cytoscape's stops when user panning is off).
- **Information → NetSeer details:** system facts and live usage/temperatures (5 s refresh), read from /proc and /sys only.
- **Audit labels:** 15 new actions (stop, file delete, live, rules update, auto-logout…) were missing from the Information page catalogue; a test now checks every audited action has a label.

### dump.md ideas (2026-11-18)
- **Severity column** also replaced Priority + ET Severity on the incident page's raw-alerts table, so "Severity" means one thing everywhere. The incident Alert groups table still says "Priority".
- **MAC vendor fallback** is on by default and reuses `ti_cache` (no schema change). In live mode a failed lookup is retried on the next tick (one request, 5 s timeout).
- **Risk redesign:** network health no longer weights incidents by I1/9 (I1 is already in each incident's impact), so health numbers drop (A5.6 62 → 47); report Table 4.7 needs 47. Weighted mean rejected (more incidents would raise health); ATT&CK-breadth signal deferred. Confirm.
- **Risk spec review:** I3 (attack type) dominates the bands on "unsw": ablating it to "other" (4) lifts recon incidents from Low to Medium. That is by design (A5.2: the attack type sets the ceiling), but say it in the report. Analyses scored before this change have no `_meta` until re-analysed or `cli acp <id>`.

### Remote access (2026-11-23)
- The owner reaches the site over Tailscale during development, while W9 plans UFW LAN-only. Decide before cutover whether Tailscale access stays.
