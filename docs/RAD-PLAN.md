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
