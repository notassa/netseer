# NetSeer — progress

Last updated: 2026-11-18

## Change log
Format: `[YYYY-MM-DD] change`, newest first. One line per finished task; details go in the Step log and decision sections below.

- [2026-11-18] Add orchestrator/worker workflow: Claude plans and reviews, DeepSeek workers (opencode) code (`CLAUDE.md`, new `AGENTS.md`); `dump.md` becomes an idea inbox reviewed against `docs/`; this dated change log
- [2026-11-03] Commit the prototype to GitHub (`6030a05 Add NetSeer FYP2 prototype`)
- [2026-10-22 – 2026-11-03] C3 change requests 2–5: algorithm review, inside-LAN detection, upload checks, AI stop, map and alert-page changes (exact dates not recorded; see the decision sections below)
- [2026-10-22] Steps 11 + 12: live mode code done; hardware check partly done (switch SPAN source ports still to set)
- [2026-10-21] C3 change request 1: services fold, MACs + Wireshark vendors, saved AI, tree map, Clear log, Settings tabs
- [2026-10-21] Steps 8–10: knowledge base + RAG, evidence + LLM + verifier + AI page, optional TI + cloud backend
- [2026-10-21] Subnet auto-adopt
- [2026-10-21] C2 change request: timeline, 20-row tables, pie %, health model, capture checks, subnets, map
- [2026-10-21] Steps 5–7: contextor, scorer + roll-up, incidents + Home + NetSeer configuration
- [2026-10-21] C1 polish, change request 3, Fix + Detonate, C1 change request (large uploads, progress bar, Information page)
- [2026-10-21] Steps 0–4: environment audit, skeleton, auth, offline ingest, devices

## Environment (step 0 audit, 2026-10-21)

| Item | Value |
|---|---|
| OS | Ubuntu 24.04.5 LTS, kernel 6.8.0-147-generic, timezone UTC |
| CPU | Intel Core i5-**9600T** (6 cores, AVX2/FMA). The docs say i5-9500T; the box has the 9600T |
| RAM | 15 GiB + 4 GiB swap |
| Disk | `/` 98 GB LVM volume, 85 GB free (the SSD has unallocated space left in the VG) |
| Suricata | 8.0.7 (OISF PPA), config `netseer/config/suricata/netseer.yaml` |
| Rules | `/var/lib/suricata/rules/suricata.rules`: 109,262 alert rules (ET Open + abuse.ch SSLBL blacklist, SSLBL C2, Feodo Tracker, URLhaus). ThreatFox has no suricata-update source |
| Tools | mergecap/editcap 4.2.2, jq, ethtool, tcpdump, ieee-data OUI (`/usr/share/ieee-data/oui.csv`) |
| Python | 3.12.3, venv `.venv`: fastapi 0.156.4, uvicorn 0.54.0, jinja2 3.1.6, python-multipart 0.0.32, argon2-cffi 25.1.0, httpx 0.28.1, pydantic 2.14.1, cryptography 50.0.2, mitreattack-python 6.3.1, pytest 9.1.1 |
| Chart.js | 4.4.9, vendored at `netseer/web/static/vendor/chart.umd.min.js` |
| Ollama | service active, `llama3.2:3b` pulled (2.0 GB), 100% CPU |
| Permissions | `netseer` is in group `suricata` (needed to read rules and `/etc/suricata`) |

### NICs

| NIC | Driver | Role | State at audit |
|---|---|---|---|
| `eno1` | e1000e (Intel I219-V, onboard) | **LAN** — dashboard, 192.168.100.24/24, gw 192.168.100.1 | up |
| `enxec1ac300527e` | r8152 (UGREEN USB 3.0 adapter) | **Mirror port** (C4) — no IP, promiscuous | no carrier (not yet connected to the switch SPAN port) |

### Ollama speed (`llama3.2:3b`, short prompt, warm model)

| Run | Prompt eval | Generation |
|---|---|---|
| 6 threads, one core busy with a crash-looping `suricata.service` | 85 tok/s | **1.8 tok/s** (thread contention) |
| 5 threads | 48 tok/s | **8.1 tok/s** |
| 4 threads | 42 tok/s | **8.8 tok/s** |

Estimate for one explanation (~2,500 prompt tokens, ~400 output tokens): about 50 s prompt + 50 s output ≈ 1.5–2 min. Re-measure with all 6 threads once the system `suricata.service` is disabled.

### Open environment items
- The packaged `suricata.service` is enabled and crash-loops on the non-existent `eth0` (325+ restarts), burning one core. NetSeer doesn't use it: `sudo systemctl disable --now suricata`.

## Cycle status (report Table 4.12)

| Cycle | Scope | Status |
|---|---|---|
| C1 | Foundation & offline mode (brief §10 steps 1–4) | Completed (awaiting owner demo) |
| C2 | ACP & risk (steps 5–7) | Completed (awaiting owner demo) |
| C3 | Interpretation (steps 8–10) | Completed (awaiting owner demo) |
| C4 | Real-time mode (steps 11–12) | In progress (code and tests done; hardware check on the switch pending) |

## Step log

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
| 11 + 12 Live: NIC discovery, stall states, capture unit, sudoers, tailer, incremental ACP | Code done; hardware check partly done | ✅ on the box (2026-10-22): session 6 `waiting_interfaces` → `waiting_traffic` → `ready` in 10 s; Start runs `netseer-live@enxec1ac300527e` as netseer via sudoers (Suricata af-packet, 6 workers, engine up in 24 s); the tailer reads eve.json; Stop closes the record and stops the unit; session 7 is a new record. Fixed: relative OUT_DIR made Suricata exit. ⏳ **Open:** the mirror only receives multicast (1 mDNS packet in minutes), so the switch SPAN source ports are not set yet; and `testmynids.org` no longer exists (NXDOMAIN), so the alert-delay check needs another trigger (e.g. `nmap 192.168.100.24` from a mirrored host → NETSEER Port scan + ET SCAN alerts) | 197 tests. `engine/live.py`: physical NICs from `/sys/class/net` (lo and virtual skipped), state machine `waiting_interfaces → waiting_traffic → ready → running → stopped` (stubbed sysfs tests), `netseer-live@<nic>` started via `sudo -n systemctl` with a per-session env file, tailer from `eve_offset` with half-line and rotation handling, ACP rebuilt per interval with **incident ids kept** (first alert id) so explanations survive. Monitor thread starts with the server. Network page: NIC picker, stall message, Start capture / Stop. Live attribution banner + modal. Settings: live interval; "Update Suricata rules" (sudo `suricata-update`, no args) + KB rebuild. Files: `config/systemd/netseer-live@.service`, `config/sudoers.d/netseer`, `config/netplan/90-netseer-mirror.yaml` |

## C1 decisions to confirm at the demo
- **RBAC for changes:** uploads, deletes, device attribution and type changes are admin-only ("User = view only", A9/A12). Renaming is allowed for both accounts because A13 says "Users can rename; the admin can delete". Say if the User should be read-only for renames too.
- **What counts as a device:** an internal IP that sent traffic or answered a flow. This keeps broadcast addresses and unanswered scan targets out of the inventory (brief §6a says "every internal IP in any event").
- **Schema additions (no column changes):** `UNIQUE(analysis_id, ip)` on `devices` and a primary key `(analysis_id, hour)` on `packet_stats`, so re-processing (and C4's incremental logger) merges instead of duplicating.
- **classtype:** eve.json alerts carry only the classtype description (`alert.category`); the logger maps it to the short name via `classification.config` for I3 in C2.
- **AI** is a placeholder until C3 (Home and Incidents were built in C2).

## C2 decisions to confirm at the demo
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

## Subnet auto-adopt decisions to confirm at the demo
- **Rule:** networks outside the LAN CIDRs whose hosts talk among outside networks are adopted for that analysis when they hold more hosts than its internal devices. Once per analysis; the global LAN CIDRs stay RFC1918. Re-analyse keeps the adoption; delete removes it.
- **Trade-off on UNSW-NB15:** the attacker range 175.45.176.0/24 is adopted too, so Suricata's `$EXTERNAL_NET → $HOME_NET` rules no longer fire between attacker and victims: alerts 1,630 → 1,342. To score only the victims and clients, set LAN CIDRs to `59.166.0.0/24` and `149.171.126.0/24` in Settings and re-analyse (then 175.45.176.0/24 is too small to be adopted).

## C3 decisions to confirm at the demo
- **Steps 9 and 10 are one commit**: the evidence package reads the TI cache, so they could not be split cleanly.
- **Prompt size:** at most 5 hosts, 5 alert groups and about 10 knowledge items (250 characters each), so the prompt stays near 2,300 tokens inside `num_ctx` 4096. The first try (25 knowledge items, ~3,800 tokens) timed out.
- **Ollama threads = 4** (`num_thread`) and **max 900 output tokens**: with the crash-looping `suricata.service` holding one core, 6 threads were much slower (step 0). Disabling that service (`sudo systemctl disable --now suricata`) should speed things up; then try 5–6 threads.
- **Refs are required by the schema** (1–4 per claim and action), so the model's JSON grammar forces citations. Before that, 3 of 3 explanations were flagged only for missing refs.
- **"Summarise this analysis"** is stored on the analysis's top incident (the `interpretations` table is keyed by incident), with the network health and the top 5 incidents as evidence.
- **Who may explain:** both accounts (it only reads the analysis); keys, backend and the KB rebuild are admin-only.
- **Overclaim check** flags assertive wording ("was compromised", "gained access", "succeeded") unless the sentence hedges (may, might, no sign, whether…) or a `successful-*` classtype is in the evidence.
- **TI runs only for public outside IPs** (`is_global`), at most 20 per analysis, after the analysis finishes. Analyses made before a key was added get TI on re-analyse.

## C3 change request decisions to confirm at the demo
- **Why devices had no MAC:** UNSW-NB15 pcaps are Linux cooked (SLL) captures. They have no Ethernet header, so Suricata writes no MACs. A vendor list alone could not fix that, so NetSeer now reads the sender MAC that SLL keeps per packet (first 2 M packets, `tcpdump -e`).
- **Router MACs are not given to hosts:** a MAC seen for 3 or more source IPs is a router's (UNSW: Palo Alto firewall for 20 servers, a randomised MAC for 13 hosts). Those hosts stay "unknown" instead of showing the router's MAC. On UNSW, 3 of 36 devices get their own MAC (VMware); your own Ethernet captures are unaffected (Suricata reads both MACs).
- **Wireshark list:** stored as `src/database/manuf` (gitignored). The "version date" is the file's Last-Modified date on wireshark.org. Updating also refreshes vendors of stored devices. Wireshark asks not to download more than once a week.
- **Clear log** deletes one tab's entries after a confirm dialog and keeps one entry saying who cleared how many (so a wipe is never invisible). No password prompt (Detonate has one).
- **Saved explanations:** every explanation stays in `interpretations`; the AI page lists the analysis's last 100. One whose evidence changed since opens with a note.
- **Map:** the Network (force) layout and the "only links with alerts" box are gone; "Reset layout" redraws the tree.
- **Re-analyse "big"** to get the MACs (a single pass now: its LAN adoption is kept).

## C3 change request 2 (algorithm review) decisions to confirm at the demo
- **R2/R3 need the same SID.** Before, a sweep/fan-in counted hosts across any signatures, so unrelated alerts between busy hosts chained into blobs (43% of "big"'s alerts in two incidents). "big": 45 → 204 incidents, largest incident 25% → 17% of alerts, health 41 → 44.
- **R4 needs a forward kill-chain step** (ATT&CK tactic order). Reverse pairs such as "Lateral Movement → Initial Access" no longer fire it.
- **Correlation window = longest quiet gap** inside an incident (chaining kept, now written down in CONCEPTS A4/A0).
- **L5 is raise-only** (a clean reputation no longer lowers the top incidents); VirusTotal = min(1, malicious engines/5); VT with no engine results is unknown, not safe. Cached VT results keep the old ratio until refetched (24 h).
- **Device colour = worst incident band** on Devices, Home and the map; the % is still P(d). Home "devices at risk" = worst band Medium or above.
- **Still open:** the largest "big" incident (17%) is one Suricata decoder event (STREAM ESTABLISHED packet out of window) between 10 → 10 hosts. With one SID it is a genuine R3 under the rules; leaving engine events (SIDs 2200000–2299999) out of R2/R3 would remove it.
- **Munir check:** A5.1 now says the independence assumption is NetSeer's own (the thesis never states it and its department figures disagree, Eq. 3.3 vs 3.18). The PDF sits in `docs/`, gitignored.
- **Glossary:** CONCEPTS A0.

## C3 change request 3 decisions to confirm at the demo
- **Why "realnetwork" missed the attack:** the nmap scan from 192.168.100.139 (998 ports on 7 hosts) was in the capture, but Suricata raised no scan alert: ET SCAN rules mostly need `$EXTERNAL_NET → $HOME_NET`, and Suricata has no port-scan tracker. The vulnerability scan of 192.168.100.142 was **not in the capture at all** (zero packets to .142): the capture point did not see it. Use the switch mirror port.
- **Fixes:** Suricata runs with `EXTERNAL_NET=any`, and NetSeer adds its own port-scan alert from flow events (≥ 50 probed ports per host, SID 9000001). Re-analysed "realnetwork": 7 NETSEER scan alerts + ~30 ET SCAN alerts → one Medium incident "192.168.100.139 → 192.168.100.1: 14 different signatures" (R1, R2); the Attack → Victim panel lists all scanned hosts.
- **Stop** (admin) kills Suricata within about a second, deletes the run's results and eve.json, keeps the capture; status `stopped`; Re-analyse works. A row left running by a restart is cleared at once.
- **AI progress %** is an estimate (mean of the last 10 timed explanations, 90 s before any), held at 95% until done.
- **Alert filters:** collapsible frame; tick boxes for priority, severity, direction, class (values in a group are OR-ed, groups AND-ed).
- **Auto-logout toggle** (Settings > Accounts): global; off = no countdown, sessions still end 12 h after sign-in.

## C3 change request 4 decisions to confirm at the demo
- **ET SCAN alerts read as `attempted-recon`** (ET files many under bad-unknown/misc). **L1: "Informational" no longer overrides the priority** (other severities still do), so ET scans with priority 2 get L1 6. The A5.6 example is unchanged (health 62).
- **Recon is its own incident:** recon groups link only with recon; R4 leaves them out; a later incident on the same hosts shows "Preceded by recon". Titles use the widest rule (R4 > R3 > R2 > R1). "realnetwork": "Sweep from 192.168.100.139 to 7 hosts (ET SCAN Potential SSH Scan OUTBOUND)", Medium.
- **"Detect attacks from inside the LAN"** (EXTERNAL_NET = any) is now a setting, default on. On "big" it adds ~65,000 LAN policy alerts (1,337 → 66,569; one incident 93% of alerts), so the Table 4.13 run uses it **off**.
- **Global data until Detonate:** TI results no longer expire (each IP looked up once); new `ip_names` table (IP → name from DNS/SNI/HTTP/DHCP) fills names an analysis lacks.
- **Map:** clients hang under their gateway; right-drag pans; left click selects; left-drag moves a node with its subtree.
- **Alerts page:** alerts per x minutes chart (shares the bin size) and top 5 devices by alerts.
- **Tooltips** on every table column head (one shared map in `deps.COLUMN_HELP`).
- **AI:** Stop closes the Ollama stream (verified on the real model: stopped 4 s into a long reply). While Ollama is still reading the prompt (up to ~50 s) no tokens arrive, so the model keeps working until its first token; the page shows "Stopped" at once and nothing is saved. Clear saved explanations (admin).

## C3 change request 5 decisions to confirm at the demo
- **Uploads:** refused when the file header is not a real pcap/pcapng (magic + version/snaplen or the pcapng section header) or when its SHA-256 is already stored in any analysis.
- **Delete a file** from a session (admin): results cleared, status `pending`; the last file deletes the session.
- **AI page:** one button toggles "Explain with AI" ↔ "Stop".
- **Alerts page:** packets and alerts charts side by side, each with its own bin size; the pie is now "Detected Alert Classes".
- **Map:** scroll to zoom (own wheel handler; Cytoscape's stops when user panning is off).
- **Information → NetSeer details:** system facts and live usage/temperatures (5 s refresh), read from /proc and /sys only.
- **Audit labels:** 15 new actions (stop, file delete, live, rules update, auto-logout…) were missing from the Information page catalogue; a test now checks every audited action has a label.

## How to run the demo
```bash
cd ~/FYP2_netseer && . .venv/bin/activate
uvicorn netseer.src.api.main:app --host 0.0.0.0 --port 8000     # then open http://192.168.100.24:8000
pytest netseer/tests                                            # integration tests need the 'suricata' group (log in again after usermod)
python -m netseer.cli run-offline a.pcap b.pcap                 # CLI alternative to the upload page
python -m netseer.cli acp all                                   # build incidents for analyses made before C2
curl -sSLo netseer/ai/kb/enterprise-attack.json https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
python -m netseer.cli build-kb                                   # AI knowledge base (rules + ATT&CK + playbooks)
python -m netseer.cli pregen <id> --top 5                       # pre-generate AI explanations for a demo
python -m netseer.eval.acp_metrics <id> --rerun                 # Table 4.13 numbers + saturation check
```

## Demo numbers (report Table 4.13)

| Metric | Value |
|---|---|
| Capture size | 7,629 MB ("big": UNSW-NB15 14/16/17/18.pcap, 13.7 M packets); earlier 568 MB (`27.pcap`) |
| Raw alerts | 1,349 ("big", with its LAN adoption and "Detect attacks from inside the LAN" off; 1,630 before adoption); 233 (`27.pcap`) |
| Alert groups | 1,004 ("big": 25.6% fewer than alerts) |
| Possible incidents | 209 (Critical 6, High 19, Medium 84, Low 93, Note 7); network health 41; largest incident 17% of alerts ("big", rules of change request 4) |
| Reduction % | 84.5% (alerts → possible incidents, "big"; 96.7% before the stricter R2/R3/R4, which had merged unrelated alerts) |
| Processing time | ACP 3–6: 0.15 s for 1,349 alerts; whole analysis 137 s for 7,629 MB (55.8 MB/s) ("big") |
| LLM seconds per explanation | 91 s mean (46–117 s, 5 incidents, `llama3.2:3b`, CPU, 4 threads, ~2,300-token prompt) |
| Verified explanations | 4 / 5 (the fifth flagged correctly: band mismatch; measured before C3 change request 2) |
| Tests passed | 202 / 202 |
