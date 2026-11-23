# NetSeer — Development Brief (for the Claude Code session on the Ubuntu server)

> Give this file and `docs/CONCEPTS.md` to Claude Code on the server: "Read docs/PROTOTYPE-BRIEF.md and docs/CONCEPTS.md, then build cycle C1." Build **one RAD cycle at a time** (§10). Each cycle ends at a checkpoint, a demo and a commit. `CONCEPTS.md` is the source of truth; this brief is how to build it. The schedule is in `docs/RAD-PLAN.md`.

## 1. What NetSeer is (one paragraph)
NetSeer is an AI-assisted alert interpretation layer for small flat networks. Suricata detects. NetSeer runs **Alert-Context Processing (ACP)**: a deterministic pipeline that normalises, enriches, aggregates, correlates and risk-scores Suricata alerts into *possible incidents*. It then builds a structured evidence package that a **local LLM (Ollama)** explains in plain language for non-expert admins. A **verifier** checks every explanation against the evidence. There is **no machine learning**; the LLM never detects, scores or confirms a compromise. NetSeer works on **uploaded pcaps (offline)** and on **live traffic from a switch mirror port (real-time)**.

## 2. Scope
All features in `CONCEPTS.md`, built in four cycles:
- **C1 — Foundation & offline mode:** first-launch setup, two accounts, auth, theme, network selection (offline), multi-pcap upload, Suricata, logger, devices + attribution, analyses browser, Alerts page with alert mix.
- **C2 — ACP & risk:** aggregation, correlation, hybrid risk model (CONCEPTS A5), Incidents, Home, NetSeer configuration.
- **C3 — Interpretation:** evidence package, RAG knowledge base, Prompt Maker, Ollama, verifier, AI page; optional TI (AbuseIPDB/VirusTotal) and cloud LLM.
- **C4 — Real-time mode:** NIC detection and stall states, live Suricata unit, eve tailer, incremental ACP, live attribution, session records.

Out of scope: ML detection, IPS/blocking, multi-site, more than two accounts.

## 3. Environment (Ubuntu Server 24.04 · i5-9500T · 16–24 GB RAM · 256 GB SATA SSD · 2 wired NICs)
```bash
sudo add-apt-repository -y ppa:oisf/suricata-stable && sudo apt update
sudo apt install -y suricata jq python3-venv ieee-data tcpdump wireshark-common ethtool iproute2
sudo suricata-update                      # ET Open -> /var/lib/suricata/rules/suricata.rules
sudo suricata-update list-sources         # then enable the abuse.ch sources (sslbl, urlhaus, threatfox) and run suricata-update again
curl -fsSL https://ollama.com/install.sh | sh && ollama pull llama3.2:3b
python3 -m venv .venv && . .venv/bin/activate
pip install fastapi "uvicorn[standard]" jinja2 python-multipart argon2-cffi httpx pydantic cryptography mitreattack-python pytest
```
- Copy `/etc/suricata/suricata.yaml` to `netseer/config/suricata/netseer.yaml`. In its eve-log output set `ethernet: yes`, alert `metadata: yes`, dhcp `extended: yes`, and enable `alert, anomaly, flow, dns, http, tls, dhcp, ssh, smb, fileinfo`.
- Download Chart.js 4 once to `netseer/web/static/vendor/chart.umd.min.js` (works offline).
- `mergecap` comes with `wireshark-common`. Answer "No" to the non-root capture prompt.

### 3a. As built (step 0 audit, 2026-10-21)
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

#### NICs

| NIC | Driver | Role | State at audit |
|---|---|---|---|
| `eno1` | e1000e (Intel I219-V, onboard) | **LAN** — dashboard, 192.168.100.24/24, gw 192.168.100.1 | up |
| `enxec1ac300527e` | r8152 (UGREEN USB 3.0 adapter) | **Mirror port** (C4) — no IP, promiscuous | connected to TP-Link ES208G port 5 (mirror of ports 4, 6, 7, 8, both directions); verified 2026-11-23 |

#### Ollama speed (`llama3.2:3b`, short prompt, warm model)

| Run | Prompt eval | Generation |
|---|---|---|
| 6 threads, one core busy with a crash-looping `suricata.service` | 85 tok/s | **1.8 tok/s** (thread contention) |
| 5 threads | 48 tok/s | **8.1 tok/s** |
| 4 threads | 42 tok/s | **8.8 tok/s** |

Estimate for one explanation (~2,500 prompt tokens, ~400 output tokens): about 50 s prompt + 50 s output ≈ 1.5–2 min. Re-measure with all 6 threads once the system `suricata.service` is disabled.

#### Open environment items
- The packaged `suricata.service` is enabled and crash-loops on the non-existent `eth0` (325+ restarts), burning one core. NetSeer doesn't use it: `sudo systemctl disable --now suricata`.

## 4. Code layout (existing skeleton; *new* = add)
```
netseer/
  config/        netseer.toml (defaults, CONCEPTS A15), common-passwords.txt, suricata/netseer.yaml,
                 systemd/{netseer.service, netseer-live@.service}, nginx/netseer.conf, sudoers.d/netseer   (new files)
  eval/          (new) unsw_validate.py, acp_metrics.py, ai_eval.py, sys_metrics.py
  src/
    api/         main.py, deps.py, auth.py, routers/{setup,auth,home,network,alerts,incidents,devices,ai,settings,api}.py
    engine/      (new) ingest.py, live.py, logger.py, contextor.py, scorer.py, oui.py, alert_mix.py
    database/    schema.sql, db.py, pcaps/<analysis_id>/, eves/<analysis_id>/
  ai/            prompt_maker.py, rag.py, llm_caller.py, verifier.py, schemas.py, prompts/*.j2, kb/build_kb.py, kb/playbooks/*.md
  web/           templates/, static/{css,js,vendor}/
  tests/         fixtures/{eve_sample.json, small.pcap}, test_*.py
  cli.py         (new) init-db, rebuild-kb, run-offline <pcaps...>, pregen <analysis_id>
```
- Rename `ai/llm-caller.py` → `ai/llm_caller.py` and `ai/prompt-maker.py` → `ai/prompt_maker.py`.
- Add `__init__.py` files so `netseer` is importable.
- `.gitignore` the `src/database/pcaps/`, `src/database/eves/` and `*.db` contents.

## 5. Database (`src/database/schema.sql`, SQLite in WAL mode)
```sql
users(id PK, username UNIQUE, pw_hash, role CHECK(role IN('admin','user')), theme DEFAULT 'white', created_at)
CREATE UNIQUE INDEX one_per_role ON users(role);          -- enforces 1 admin + max 1 user
login_attempts(username, ts, success)
sessions(token PK, user_id, csrf, created_at, last_seen, expires_at)   -- 10 min, extendable
audit_log(id PK, ts, user_id, action, detail, ip, mac)     -- ip/mac of the client for account events
settings(key PK, value)                                    -- overrides config/netseer.toml
api_keys(name PK, ciphertext)                              -- Fernet-encrypted (abuseipdb, virustotal, cloud_llm)
analyses(id PK, name, mode CHECK(mode IN('offline','live')), status, created_at, started_at, stopped_at, note,
         mirror_if, lan_if, eve_offset DEFAULT 0, n_events DEFAULT 0, n_alerts DEFAULT 0, error)
analysis_files(analysis_id, filename, sha256, size)
alerts(id PK, analysis_id, ts, flow_id, src_ip, src_port, dest_ip, dest_port, proto, app_proto,
       sid, signature, category, classtype, priority, sig_severity, mitre_tactic, mitre_technique,
       direction, raw_json)
devices(id PK, analysis_id, ip, mac, vendor, hostname, services_json, first_seen, last_seen,
        type DEFAULT 'unknown', criticality REAL DEFAULT 5, risk REAL DEFAULT 0, attributed INTEGER DEFAULT 0)
alert_groups(id PK, analysis_id, src_ip, dest_ip, sid, signature, classtype, proto, dest_port,
             first_seen, last_seen, count, max_priority, rep_alert_id, alert_ids_json)
incidents(id PK, analysis_id, title, rule, src_ips_json, dest_ips_json, first_seen, last_seen, n_alerts,
          likelihood REAL, impact REAL, band, score REAL, factors_json, evidence_json)
incident_groups(incident_id, group_id)
interpretations(id PK, incident_id, intent, model, evidence_hash, output_json, verification_json, created_at, latency_s)
packet_stats(analysis_id, minute, packets, bytes)            -- per minute; flows spread over their duration
traffic_stats(analysis_id, second, ii_packets, ii_bytes, ie_packets, ie_bytes, ei_packets, ei_bytes)  -- per 5 s (UTC epoch); ii = INT>INT, ie = INT>EXT, ei = EXT>INT
external_hosts(id PK, analysis_id, ip, hostname, direction, first_seen, last_seen, n_flows, n_alerts, bytes,
               ports_json, peers_json, UNIQUE(analysis_id, ip))
ti_cache(indicator PK, source, result_json, fetched_at)
analysis_info(id PK, analysis_id, kind, level CHECK(level IN('info','warning')), title, detail_json, created_at)
                                                           -- kind 'capture' (A16) or 'network' (A17)
host_links(analysis_id, a, b, flows, bytes, alerts, first_seen, last_seen, PRIMARY KEY(analysis_id, a, b))   -- a < b; map edges
```
Index every `analysis_id` column. All pages read through `analysis_id`.

## 6. Pipeline (`src/engine/`)
### 6a. Offline (C1)
1. **ingest.py**
   - Accept ≥1 files and validate each: pcap magic `d4c3b2a1`/`a1b2c3d4`/`4d3cb2a1`/`a1b23c4d` or pcapng `0a0d0d0a`, size ≤ the per-file cap (2048 MB).
   - Upload flow (streams to disk, no multipart): `POST /api/uploads` (one file: name + size, optional existing session `analysis_id`; disk guard) → `PUT /api/analyses/<id>/files/0` raw body → `POST /api/analyses/<id>/start` (`analyse` true → merge all session files and run; false → `pending`).
   - Save to `src/database/pcaps/<id>/` and record SHA-256 in `analysis_files`.
   - If there are several files, run `mergecap -F pcap -w merged.pcap <files...>` (chronological merge; classic pcap because libpcap rejects a pcapng whose interfaces differ in snaplen or link type); one analysis per upload.
   - Run `suricata -c config/suricata/netseer.yaml -r <pcap> -l src/database/eves/<id>/ -k none`.
   - Status: `uploading → (pending →) queued → running_suricata → processing → awaiting_attribution → done | failed`.
   - Auto name: `Offline — <first file> (+N) — <YYYY-MM-DD HH:MM>`.
2. **logger.py (ACP 1–2)**
   - Stream eve.json.
   - `alert` → `alerts` (keep `raw_json`; `classtype` and `priority` from the alert; `sig_severity`, MITRE IDs from `alert.metadata`).
   - `direction` comes from `LAN_CIDRS` (`ext->int`, `int->ext`, `int->int`, `ext->ext`).
   - Devices = every internal IP in any event:
     - `mac` from `ether`
     - `vendor` from the OUI in `/usr/share/ieee-data/oui.csv`
     - `hostname` from `dhcp.hostname`
     - `services` from flows where the device is the destination
   - `flow` → `packet_stats` per minute (total) and `traffic_stats` per 5 s (by packet direction).
   - Missing values stay NULL and display as **unknown**.
   - Then network discovery (A17). If the looks-local networks hold more hosts than the devices, store them as the analysis's LAN (`settings` key `lan_cidrs:<id>`), clear the results and run Suricata + logger once more (HOME_NET and directions use the analysis's LAN everywhere).
3. After ACP, set `awaiting_attribution`. The UI shows the Device Attribution modal for unattributed devices; saving it (or "skip, keep Unknown") moves the analysis to `done`.

### 6b. ACP 3–6 (C2)
- **contextor.py:** aggregation key and gap, rules R1–R4, union-find, `rule` stored per incident, incident enrichment and a plain title template (CONCEPTS A4). Windows come from `settings`.
- **scorer.py:** implement CONCEPTS A5 exactly. Constants live in one module:
```python
L1_PRIORITY = {1: 9, 2: 6, 3: 3, 4: 1}
L1_SIG_SEVERITY = {"Critical": 9, "Major": 7, "Minor": 4, "Informational": 1}   # overrides priority
L3_RULE = {"single": 2, "R1": 6, "R2": 5, "R3": 7, "R4": 9}
L4_DIRECTION = {"ext->int": 9, "int->ext": 7, "int->int": 6, "ext->ext": 1}
# L2 = min(9, 3*log10(1+n_alerts));  L5 = max(abuseipdb/100, min(1, vt_malicious/5))*9, in the mean only if it raises L
DEVICE_TYPE = {"server": 9, "network": 8, "workstation": 6, "phone": 5, "iot": 5, "guest": 3, "unknown": 5}
I2_PORTS_9 = {21, 22, 23, 139, 445, 1433, 3306, 3389, 5432, 5900}; I2_PORTS_6 = {80, 443, 8080, 8443}  # else 4
I3_CLASSTYPE = {
  9: ["trojan-activity", "command-and-control", "successful-admin", "successful-user"],
  8: ["attempted-admin", "shellcode-detect", "exploit-kit"],
  7: ["attempted-user", "web-application-attack"],
  6: ["attempted-dos", "denial-of-service", "default-login-attempt", "credential-theft"],
  3: ["attempted-recon", "network-scan", "successful-recon-limited"],
  2: ["policy-violation", "misc-activity"],
  1: ["not-suspicious"],
}  # anything else -> 4
# L = mean(L1..L5 present);  A = (I1+I2)/2;  I = I3*(0.5+0.5*A/9)
# level(x): <3 Low, <6 Medium, else High
MATRIX = {("Low","Low"): "Note", ("Low","Medium"): "Low", ("Low","High"): "Medium",
          ("Medium","Low"): "Low", ("Medium","Medium"): "Medium", ("Medium","High"): "High",
          ("High","Low"): "Medium", ("High","Medium"): "High", ("High","High"): "Critical"}   # key = (L level, I level)
# score R = 10*(L/9)*(I/9); sort by band then R
# p_i = R_i/10 * 0.5**(age/half_life), Note excluded;  D(x sorted desc) = 1 - prod_k(1 - x_k / k**1.5)
# P(d) = D(p_i of incidents involving d);  P(N) = D((I1_i/9)*p_i over all non-Note incidents)
# health = round(100*(1-P(N)))   (CONCEPTS A5.4: rank-damped union)
```
- `factors_json` stores, per factor, `{value, evidence, why}`.
- Re-score when a device type changes, when TI arrives, or when a window or half-life setting changes.
- **alert_mix.py:** `SELECT classtype, COUNT(*)` and `SELECT priority, COUNT(*)` per analysis → shares, used only for the "Detected Alert Classes" chart.

### 6c. Real-time (C4)
- **live.py, interface discovery:**
  - List `/sys/class/net/*`, excluding `lo` and virtual interfaces.
  - Show `operstate`, `carrier`, `address`, and whether the interface has an IPv4 address (`ip -j addr`).
  - The user picks the mirror NIC and the LAN NIC; they must differ. Warn if the mirror NIC has an IP.
- **Stall state machine** (`analyses.status`):

| State | Leaves when |
|---|---|
| `waiting_interfaces` | Both carriers are up |
| `waiting_traffic` | The mirror's `statistics/rx_packets` rises across two polls 5 s apart |
| `ready` | The user confirms |
| `running` | The user stops the session |
| `stopped` | — |

  If a carrier drops while `running`, the session goes back to `waiting_interfaces`, keeps its data, and shows a banner.
- **Capture service:** `config/systemd/netseer-live@.service` runs `suricata -c … --af-packet=%i -l /…/eves/<id>/` as user `netseer` with `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`. The app starts and stops it via `sudo systemctl start|stop netseer-live@<nic>`. The sudoers rule allows only those two commands for the `netseer` user. Pass the output dir through an environment file written per session.
- **Tailer:**
  - Every *live processing interval*, read eve.json from `analyses.eve_offset` and handle log rotation (inode change → offset 0).
  - Run logger on the new lines, then contextor + scorer over the session (incremental: new groups merge into open groups inside the windows).
  - Save the offset.
- New internal devices raise the attribution prompt (a non-blocking banner and modal).
- **One record per session:** every start creates a new `analyses` row named `Live — <mirror NIC> — <start time>`; Stop sets `stopped_at`.

## 7. AI (`ai/`, C3)
- **llm_caller.py:**
  - `POST http://localhost:11434/api/chat` with `{"model": <setting>, "stream": false, "format": <ExplainOutput JSON schema>, "options": {"temperature": 0.2, "num_ctx": 4096}, "messages": [system, user]}`, timeout 300 s.
  - Wrapped in an `LLMBackend` interface with `OllamaBackend` and `CloudBackend` (user key, opt-in).
- **schemas.py:** `ExplainOutput` = summary, what_happened, why_it_matters, risk_explanation, uncertainty, recommended_actions[{action, reason, refs}], claims[{text, refs}].
- **prompt_maker.py:**
  - Evidence package with `E#` facts: groups, hosts with device type, each A5 factor, band, score, timeline, TI.
  - `K#` knowledge from rag.py.
  - `unknowns[]`.
  - Intent templates for the Prompt Maker buttons.
- **rag.py + kb/build_kb.py:** keyed lookup (SID → rule → ATT&CK → mitigations) plus FTS5/BM25 over playbooks (CONCEPTS A6).
- **System prompt rules:**
  - Plain language; use ONLY the evidence.
  - Cite `E#`/`K#` in `refs`.
  - Never claim compromise or success unless the evidence says so.
  - Put unknowns in `uncertainty`.
  - Restate (don't re-score) the band.
  - About 250 words or fewer.
- **verifier.py:** checks 1–5 inline (CONCEPTS A8) → `verification_json = {passed, flags[]}`.
- Cache interpretations by `(incident, intent, evidence_hash)`. Generate in the background; `cli.py pregen <id> --top 5` pre-generates for demos.

## 8. Auth, accounts & security (`src/api/auth.py`, C1)
- **First launch:** middleware checks `SELECT 1 FROM users WHERE role='admin'`. If absent, redirect everything (except static) to `/setup`. `/setup` creates the admin, then returns 404 forever.
- **Accounts:** at most 1 admin + 1 user (the unique index plus a friendly error). Admin-only routes: create/reset/delete the user, API keys, NetSeer configuration, delete analyses.
- **Passwords:** Argon2id; ≥15 characters, not in `config/common-passwords.txt`, not equal to the username; no composition rules.
- **Lockout:** 5 failures within 15 min → locked for 5 min; generic error; every attempt logged.
- **Sessions:** 32-byte random token cookie (HttpOnly, SameSite=Lax, Secure when behind TLS), server-side row, 10-minute session (`expires_at`) with a top-bar countdown and `POST /api/session/extend` (+10 min, cap 60 min); requests do not extend it. **Logout** deletes the row and redirects to `/login`.
- **CSRF** token on every POST form. **RBAC** dependency `require_role("admin")`.
- Theme stored in `users.theme` (`white` default, `black`). CSS variables switch it.

## 9. Pages (Jinja2, left sidebar, analysis selector in the header)
| Page | Must show | Cycle |
|---|---|---|
| Setup / Login | First launch: "Create administrator". Otherwise username + password, lockout message | C1 |
| Network | **Traffic Source** card (Session: New session + Session Name / Add to / Network Adapter); one-file upload into a session + job progress; analyses browser (open, rename, files, **Info** capture checks (A16), re-analyse, admin note, delete as admin); live NIC picker, state badge and stall message, Start/Stop | C1 / C4 |
| Devices | Table (IP, MAC, vendor, hostname, services, type, risk %), type dropdown (re-scores); attribution modal after offline analysis and for new live devices; **External sources** table; **Networks** (probable subnets/VLANs) and a movable, zoomable tree **network map** (A17); long service lists fold behind "+N more" | C1–C2 |
| Alerts | Packets per *x* minutes line chart (Update button), **"Detected Alert Classes"** pie chart, filterable table (Alert ID, Time, Severity [1] High…[4] Info, Signature, Class, Direction, Source, Destination, Proto), raw-JSON drawer | C1 |
| Incidents | Table: Incident ID, band chip, score, title, rule, hosts, span, count. Detail: group timeline (Gantt of group spans, scrollable, steps of 1/5/10/20/40/60 min), **factor breakdown table** (factor, value, why, evidence), raw alerts, "Explain with AI" | C2 |
| Home | Analysis status card on top, then health gauge + top 3 contributing devices, Traffic Volume (Ingress-Egress / Total, 5–3600 s bins), devices at risk, top 5 incidents | C2 |
| AI | Sectioned explanation, Prompt Maker buttons, Prompt section (view + copy), verifier badge, flagged sentences highlighted, ref chips that expand to the evidence; **Saved explanations** list (every generated explanation stays re-openable) | C3 |
| Information | Admin only: Account activity (time, user, event, IP, MAC, vendor) and Process log (time, level, event, analysis, detail); **Clear log** per tab | C1 |
| Settings | One tab per section: Theme (all); Accounts, Configuration, AI (backend + API keys), Knowledge base, MAC vendors (Wireshark list update), **Detonate** factory reset (admin) | C1–C3 |

## 10. Build order & checkpoints (commit after each step)
**C1 — Foundation & offline**
1. Package skeleton, `schema.sql`, `cli.py init-db`, base layout and theme. **Check:** app starts; first visit → `/setup`.
2. Setup, login/logout, lockout, sessions, CSRF, RBAC, account cap. **Check:** after setup `/setup` returns 404; a 3rd account is refused; the user gets 403 on admin routes; logout → login page.
3. Offline ingest (multi-pcap + mergecap) + logger + analyses browser + Alerts page + alert mix. **Check:** two demo pcaps make one analysis whose alerts span both files; rename persists.
4. Devices + attribution modal. **Check:** after upload the modal lists the internal hosts; the type persists.

**C2 — ACP & risk**

5. Contextor (R1–R4). **Check:** synthetic alerts produce the expected incident count per rule.
6. Scorer + roll-up. **Check:** the CONCEPTS A5.6 worked example reproduces exactly (L, I, band, R, P(d), health 53).
7. Incidents + Home + NetSeer configuration. **Check:** changing a device type or a window re-scores and updates Home.

**C3 — Interpretation**

8. KB build + RAG. **Check:** for a known SID, retrieval returns the rule, its technique and a playbook.
9. Evidence package + LLM + verifier + AI page + Prompt Maker. **Check:** one incident explained; a fake IP / wrong band / missing ref / overclaim in a crafted output is flagged.
10. Optional TI + cloud backend (feature-flagged). **Check:** with no keys the app works and L5 is omitted.

**C4 — Real-time**

11. Interface discovery + state machine. **Check:** with the mirror unplugged → `waiting_interfaces`; plugged in but idle → `waiting_traffic`.
12. systemd unit + sudoers + tailer + incremental ACP. **Check:** a `curl testmynids.org/uid/index.html` from a mirrored host appears as an alert within one interval; Stop closes the record; a second session creates a new record.

**Tests (pytest, `tests/`):** logger (fixture eve), contextor (synthetic), scorer (A5.6 + matrix edges at 3.0/6.0), roll-up (Note excluded, decay), verifier (4 crafted cases), auth (setup lock, account cap, lockout, RBAC, logout), ingest (bad magic rejected, merge order), live (state machine with stubbed sysfs; tailer offset + rotation).

Run: `uvicorn netseer.src.api.main:app --host 0.0.0.0 --port 8000` (behind Nginx + TLS in cutover; Nginx needs `client_max_body_size 2100m` and `proxy_request_buffering off` for uploads).

## 11. Demo data
- **Lab pcap:** `sudo tcpdump -i <nic> -w demo.pcap` for about 2 minutes while running, from another LAN host, `nmap -sV <server>`; on a host, `curl http://testmynids.org/uid/index.html`; optionally a few failed SSH logins.
- **Multi-file test:** split it with `editcap -c 500 demo.pcap part.pcap` and upload the parts together.
- **Evaluation:** selected UNSW-NB15 pcaps + `UNSW-NB15_GT.csv`.

## 12. Screenshots for the report (Chapter 4)
Save to `docs/screenshots/` with exactly these names (the report builder embeds them):
`01-login.png, 02-home.png, 03-network-upload.png, 04-alerts.png, 05-incidents.png, 06-incident-detail.png, 07-devices.png, 08-ai.png, 09-settings-users.png, 10-lockout.png, 11-tests.png`. Add later: `12-setup.png, 13-network-live.png`.

Also record: alerts → groups → incidents (reduction %), processing time per pcap, LLM latency per explanation, and the live alert delay.
