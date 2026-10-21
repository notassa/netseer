# NetSeer — Concepts (single source of truth)

**Decisions:** FastAPI backend · Ollama local LLM (llama3.2:3b) · offline mode **and** real-time mode, with real-time built after offline · the code follows the existing `netseer/` skeleton · hybrid risk model (OWASP-style factors per incident, probabilistic roll-up for devices and the network).

Source of requirements: `dump.md`. When this file and other docs disagree, this file wins.

---

### A1. What NetSeer is and is not (fixed)
- **Is:** Suricata eve.json → **ACP** (deterministic, 7 stages) → evidence package → **RAG** → LLM explanation → **verifier** → web dashboard on a LAN-only mini PC.
- **Is not:** a detector, an ML model, an IPS or a SIEM. The LLM never detects, scores or confirms a compromise. It only *explains* evidence that ACP has already prepared.

### A2. Module map: dump.md names ↔ ACP stages ↔ code paths
All paths are relative to `netseer/`. Folders marked *new* are added to the existing skeleton.

| Module | ACP stage(s) | Path | Responsibility |
|---|---|---|---|
| ingest | — | `src/engine/ingest.py` *(new folder)* | Validate one or more pcaps, merge them (mergecap), run Suricata offline, register the analysis |
| live | — | `src/engine/live.py` | Real-time: NIC detection and stall states, start/stop the Suricata live unit, tail eve.json |
| logger | 1 Normalise, 2 Preliminary enrich | `src/engine/logger.py`, `src/engine/oui.py` | eve.json → common schema (raw JSON kept); network, device, application and TI context; missing values stored as **unknown**, never guessed |
| contextor | 3 Aggregate, 4 Correlate, 5 Incident enrich | `src/engine/contextor.py` | Alerts → alert groups → possible incidents; ATT&CK, device type and TI at incident level |
| scorer | 6 Risk prioritisation | `src/engine/scorer.py` | Incident factors, band and score; device and network roll-up (A5) |
| prompt maker + RAG | 7 Evidence package | `ai/prompt_maker.py`, `ai/rag.py`, `ai/kb/` | Evidence package with IDs, knowledge retrieval, prompt rendering |
| LLM caller | — | `ai/llm_caller.py` | Ollama (local) or user-key cloud adapter; structured JSON output |
| verifier | — | `ai/verifier.py`, `ai/schemas.py` | Hallucination and faithfulness checks before display |
| API / web | — | `src/api/`, `web/templates/`, `web/static/` | FastAPI routes, Jinja2 pages, Chart.js |
| storage | — | `src/database/schema.sql`, `src/database/db.py`, `src/database/pcaps/`, `src/database/eves/` | SQLite DB; uploaded pcaps and per-analysis eve.json |
| config | — | `config/netseer.toml`, `config/suricata/netseer.yaml` | Defaults (overridden by the `settings` table), Suricata config |

> Rename `ai/llm-caller.py` → `ai/llm_caller.py` and `ai/prompt-maker.py` → `ai/prompt_maker.py`. Python cannot import module names that contain hyphens.

### A3. Data sources: Suricata's own protocol logs instead of a custom pcap scraper
Enable the eve.json types `alert, anomaly, flow, dns, http, tls, dhcp, smb, ssh, fileinfo` and `ethernet: yes` (MAC addresses). These give "metadata from the pcap" with no extra parser:
- **Device context:** MAC → vendor (offline IEEE OUI file), DHCP hostname, DNS/mDNS names, TLS JA3/JA4, HTTP user-agent, observed services.
- **Packets/hour graph:** sum `flow.pkts_toserver + pkts_toclient` per hour. Alerts alone carry no packet counts.
- **Rulesets:** ET Open plus the abuse.ch Suricata sets (SSLBL, URLhaus, ThreatFox), managed with `suricata-update`. Many ET rules carry `metadata: mitre_tactic_id, mitre_technique_id, signature_severity, attack_target`; use them directly.

### A4. Aggregation & correlation: deterministic rules, each one recorded
- **Aggregate** on the key `(src_ip, dest_ip, signature_id, proto, dest_port)`. A gap longer than the aggregation window (default 300 s, configurable) starts a new group. A group stores first_seen, last_seen, count, a representative alert and every raw alert ID. Report this as *volume reduction*, never as *false-positive removal*.
- **Correlate** groups into a *possible* incident when a rule fires within the correlation window (default 30 min, configurable):
  - R1: same attacker → same victim, different SIDs
  - R2: one source → ≥5 destinations (sweep/scan)
  - R3: ≥5 sources → one destination (brute force / DoS)
  - R4: MITRE tactic progression (e.g. Discovery → Initial Access → C2)
- Each incident stores *which rule linked it*. Windows are tuned on UNSW-NB15.

### A5. Risk scoring (hybrid model): fills dump.md's "based on ?"

#### A5.1 Basis: what was taken from Munir (2014)
The reference thesis (Munir, R., 2014, *A Quantitative Security Assessment of Modern Cyber Attacks*, PhD thesis, University of Bradford, `ref/`) offers three techniques:

| Thesis technique | What it does | Fit for NetSeer | Verdict |
|---|---|---|---|
| Ch.3: CVSS severity counts per node → probability of attack; inclusion–exclusion union over nodes → department → whole network (example result: 28.9%) | Scores **vulnerability-scan** data (Nexpose) | NetSeer has no vulnerability scanner, so the inputs don't exist. The **aggregation step** transfers directly: under independence, P(at least one) = 1 − Π(1 − pᵢ), which is the closed form of the thesis's inclusion–exclusion sums (Eq. 3.17, 3.27) | **Adopt the aggregation** for device and network roll-up (A5.4) |
| Ch.4: OWASP Risk Rating (8 likelihood + 8 impact factors, each 0–9, averaged; levels [0,3) Low, [3,6) Medium, [6,9] High; 3×3 matrix → Note/Low/Medium/High/Critical) | Rates one scenario by hand | The factors are manual and subjective, and business-impact factors (financial, reputation) can't be known from traffic. The **structure** is transparent and suits non-experts | **Adapt**: evidence-derived factors on the same 0–9 scale, the same levels and the same matrix (A5.2–A5.3) |
| Ch.5: SL(Aᵢ) = nᵢ / N per classtype and per priority, read as "X% secure" | Shares of alerts | Not a risk measure: shares dilute (adding low-priority alerts shrinks every other share), and "46.4% of alerts ⇒ 53.6% secure" doesn't follow. Its classtype → priority table (Table 5.3) is useful | **Descriptive only**: "alert mix" chart (A5.5); classtype priorities inform factor I3 |

**Citation note.** The thesis is from 2014, so it breaks the "latest 5 years" rule. Cite it as methodological precedent only. The primary sources are the **OWASP Risk Rating Methodology** (OWASP Foundation), **NIST SP 800-30 Rev.1** (risk = f(likelihood, impact)) and **CVSS v4.0** (FIRST, 2023; environmental requirement modifiers).

#### A5.2 Incident factors (0–9 scale, computed automatically from evidence)
**Likelihood factors.** L = mean of the available factors.

| ID | Factor | Values |
|---|---|---|
| L1 | Detection confidence | Suricata priority 1/2/3/4 → 9/6/3/1. If ET `signature_severity` is present it overrides: Critical 9, Major 7, Minor 4, Informational 1. Take the max over the incident's groups |
| L2 | Activity volume | min(9, 3·log10(1 + n_alerts)) |
| L3 | Correlation strength | single 2 · R1 6 · R2 5 · R3 7 · R4 9 |
| L4 | Exposure | ext→int 9 · int→ext 7 · int→int 6 · ext→ext 1 (dominant direction of the incident) |
| L5 | Threat reputation *(optional)* | max(AbuseIPDB confidence/100, VT malicious ratio) × 9. **Left out of the mean** when TI is off or the result is unknown; unknown never counts as safe |

**Impact factors.**

| ID | Factor | Values |
|---|---|---|
| I1 | Asset criticality | Highest value among the internal devices involved, from Device Attribution (A14) |
| I2 | Service sensitivity | 9: ports 21, 22, 23, 139, 445, 1433, 3306, 3389, 5432, 5900 · 6: 80, 443, 8080, 8443 · 4: other |
| I3 | Potential technical impact (by Suricata classtype; worst in the incident) | 9: trojan-activity, command-and-control, successful-admin, successful-user · 8: attempted-admin, shellcode-detect, exploit-kit · 7: attempted-user, web-application-attack · 6: attempted-dos, denial-of-service, default-login-attempt, credential-theft · 3: attempted-recon, network-scan, successful-recon-limited · 2: policy-violation, misc-activity · 1: not-suspicious · 4: other/unknown |

**Impact combination.** The attack type sets the ceiling, and the asset scales it, the same way CVSS environmental requirements modify impact:

`A = (I1 + I2) / 2`  `I = I3 × (0.5 + 0.5 × A / 9)`

Why not a plain mean: averaging let asset value outvote the attack type. With a mean, an external port scan against an SSH server came out Critical. With the modifier, a scan stays at most Medium impact, while malware traffic on a workstation stays High.

#### A5.3 Band and sort score
- **Levels** for L and for I: Low [0,3) · Medium [3,6) · High [6,9].
- **Band** comes from the OWASP matrix:

| Likelihood \ Impact | Low | Medium | High |
|---|---|---|---|
| **Low** | Note | Low | Medium |
| **Medium** | Low | Medium | High |
| **High** | Medium | High | Critical |

- **Score** R = 10 · (L/9) · (I/9), on a 0–10 scale (NIST likelihood × impact). Incidents sort by band first, then by R.
- **Breakdown** (stored as `factors_json`): every factor's value, the evidence it came from (alert IDs, device, port, classtype) and a one-line reason, e.g. `"L2": {"value": 6.0, "why": "100 alerts"}`. The UI and the LLM both read it, so "why is this High?" is always answerable from stored data.

#### A5.4 Device risk and network health (probabilistic roll-up from Munir Ch.3)
- **Per-incident probability proxy:** pᵢ = (Rᵢ / 10) · 0.5^(ageᵢ / half_life). Note-band incidents are excluded. Age is measured from the incident's last_seen to the analysis end (offline) or to now (live). half_life defaults to 7 days and is configurable.
- **Device risk:** P(d) = 1 − Π over incidents i involving d of (1 − pᵢ). Shown as a percentage. Colours use the same cut-offs as R ×10: <40 Low · 40–69 Medium · 70–89 High · ≥90 Critical.
- **Network risk:** P(N) = 1 − Π over internal devices d of (1 − w_d · P(d)), where w_d = I1(d)/9 is the asset weight. The thesis weights nodes uniformly; NetSeer weights them by asset value, per NIST SP 800-30 impact.
- **Network health (Home gauge)** = round(100 · (1 − P(N))). The Home page lists the top 3 contributing devices (largest w_d·P(d)) so the number can be explained.
- **Saturation guard:** the union assumes independence and rises as devices are added. Note-band exclusion, time decay and asset weighting limit this. Check it during calibration on UNSW-NB15 and the demo captures, and report it as a limitation.

#### A5.5 Alert mix (Munir Ch.5, descriptive only)
On the Alerts page, show nᵢ / N by classtype and by priority as a bar chart titled **"Share of alerts (not risk)"**. It never feeds the health score.

#### A5.6 Worked example (use as a unit-test fixture)
LAN 10.0.0.0/24. Server 10.0.0.5 is typed **Server** (I1 9). Workstation 10.0.0.23 is typed **Workstation** (I1 6).

**Incident (a): external sweep, 60 alerts, R2, ET Minor, attempted-recon, SSH on the server.**
- L = (4 + 5.36 + 5 + 9) / 4 = **5.84** → Medium
- A = (9 + 9) / 2 = 9; I = 3 × 1.0 = **3.0** → Medium
- Band **Medium**; R = 10 × 0.649 × 0.333 = **2.16**

**Incident (b): workstation → external C2, 12 alerts, single, ET Critical, trojan-activity, port 443.**
- L = (9 + 3.34 + 2 + 7) / 4 = **5.34** → Medium
- A = (6 + 6) / 2 = 6; I = 9 × 0.833 = **7.5** → High
- Band **High**; R = 10 × 0.593 × 0.833 = **4.94**

**Roll-up (no decay):**
- P(server) = 0.216; P(workstation) = 0.494
- P(N) = 1 − (1 − 1.0 × 0.216)(1 − 0.667 × 0.494) = 1 − 0.784 × 0.671 = **0.474**
- Health = **53**

### A6. RAG: what is retrieved, and how
The knowledge base lives in SQLite (`ai/kb/build_kb.py`), **built offline** once and rebuildable from Settings:
1. `kb_rules`: parsed rule text and metadata (msg, classtype, MITRE IDs, CVE, attack_target) for every loaded SID.
2. `kb_attack`: MITRE ATT&CK Enterprise via `mitreattack-python` from a locally stored STIX bundle.
3. `kb_classtype`: Suricata `classification.config`, rewritten in plain language.
4. `kb_playbooks`: short guidance for non-experts per category (scan, brute force, malware/C2, exploit attempt, policy, DoS), aligned with NIST SP 800-61 Rev.3.

Retrieval is hybrid and deterministic first: keyed lookup (SID → rule → technique → mitigations), then SQLite **FTS5/BM25** over playbooks. Embeddings are out of scope.

### A7. Evidence package & LLM output contract
- **Evidence package (JSON):** every fact gets an ID. `E#` for alert groups, hosts and their device types, TI, each risk factor, band and timeline; `K#` for retrieved knowledge. An explicit `unknowns[]` list says what is missing.
- **LLM output (Ollama JSON-schema `format`):** `summary`, `what_happened`, `why_it_matters`, `risk_explanation`, `uncertainty`, `recommended_actions[{action, reason, refs[]}]`, `claims[{text, refs[]}]`.
- **Prompt Maker buttons:** "Explain simply", "What should I do now?", "Is this serious?", "Explain technically", "Summarise this analysis". Each changes only the instruction template.

### A8. Hallucination check (verifier)
1. Schema check (pydantic; retry once).
2. Citation check: every claim and action cites an existing `E#`/`K#`.
3. Entity check: IPs, ports, SIDs, CVEs, ATT&CK IDs, counts and timestamps must exist in the evidence package.
4. Overclaim check: assertions of compromise or success are flagged unless the evidence confirms them.
5. Risk consistency: the stated band equals ACP's band.
6. Faithfulness score (RAGAS-style, Es et al. 2024), run in evaluation only.

The UI shows "Verified" or "N flagged claims" and highlights flagged sentences.

### A9. Security of NetSeer itself
- **Auth:** Argon2id. Password policy per **NIST SP 800-63B-4**: at least 15 characters, checked against a common/breached-password blocklist, not equal to the username, no composition rules. Lockout: 5 failures → 5-minute lock, with a generic error message.
- **Sessions:** random token, HttpOnly + SameSite (+ Secure behind TLS) cookie, server-side row, 30-minute idle timeout. Logout deletes the row and redirects to `/login`.
- **RBAC:** Admin (view and manage) vs User (view only), enforced server-side on every route.
- **Further controls:** audit log (logins, setup, uploads, live start/stop, setting and API-key changes); pcap validation (magic bytes, size cap); unprivileged services; API keys encrypted at rest (Fernet); Nginx TLS, bound to the LAN, rate-limited.
- **Live-mode privilege:** the web app never runs as root. Packet capture runs in a systemd unit with only `CAP_NET_RAW`/`CAP_NET_ADMIN`, started through a narrow sudoers/polkit rule (A13).
- **Mapping:** ISO/IEC 27001:2022 Annex A (A.5.15, A.5.17, A.8.2, A.8.5, A.8.15, A.8.20, A.8.24, A.8.26, A.8.28) and OWASP ASVS 5.0.
- **Privacy:** VirusTotal, AbuseIPDB and the cloud LLM are opt-in, use the user's own key, look up external IPs only, and are cached.

### A10. Dashboard pages (fills "Home: ?")
| Page | Content |
|---|---|
| Login | Username and password. On first launch (no admin yet) it shows **Create administrator** instead (A12) |
| Home | Network health gauge (A5.4) with the top 3 contributing devices, top 5 incidents (band chip, title, time), devices at risk, alert trend, current analysis status |
| Network | **Mode selection** (offline / real-time), multi-pcap upload, live NIC status and stall messages, **analyses browser** (list, open, rename, delete as admin) |
| Alerts | Packets/hour chart, **alert mix** chart (A5.5), filterable alert table, raw JSON drawer |
| Incidents | Table (band, score, title, rule, hosts, span) → detail: timeline, alert groups, factor breakdown (A5.2), linked raw alerts |
| Devices | Inventory (IP, MAC/vendor, hostname, services, type, risk %), device-type editor; the attribution prompt appears after each offline analysis and for new devices in live mode |
| AI | Per-incident interpretation, Prompt Maker buttons, verifier badge, regenerate |
| Settings | Theme (**White** default / **Black**); API keys (admin); accounts (admin: create/reset/delete the one User); **NetSeer configuration** (admin, A15) |

Every page except Login and Settings is scoped to the **selected analysis** (selector in the header). Frontend: Jinja2 + vanilla JS + Chart.js, served locally. No build step.

### A11. Report alignment
Done in report revision 2 (`report/REVISION-NOTES.md`):
- hybrid risk model (§2.3.4, §4.4.6, Tables 4.4–4.7)
- hardware (256 GB SATA, 16–24 GB RAM)
- 15-character passwords
- first-launch setup and two-account cap
- real-time mode in scope
- network selection, analyses browser and alert mix
- references to Munir (2014) and OWASP Risk Rating

Still open: fill Table 4.12 statuses and the Table 4.13 numbers after building; add the screenshots (including `12-setup.png` and `13-network-live.png`).

### A12. Accounts & first launch
- **First launch:** if no admin exists, every route redirects to `/setup`, which creates the administrator (same password policy). Once an admin exists, `/setup` returns 404.
- **Two accounts maximum:** exactly one Admin and at most one User. Enforce it in code and with a `UNIQUE` index on `users.role`.
- Only the Admin can create, reset or delete the User. The Admin account can't be deleted from the UI.
- **Logout** invalidates the session and redirects to `/login`.
- Theme preference is stored per account.

### A13. Analyses & network selection
- **Analysis** = one stored unit of work with: id, name, mode (`offline` | `live`), status, timestamps, files or interfaces, and counts.
  - Auto names: `Offline — <first file> (+N) — <YYYY-MM-DD HH:MM>`, `Live — <mirror NIC> — <start time>`. Users can rename; the admin can delete.
- **Network selection:** if no analysis is selected, the Network page asks for the mode.
- **Offline flow:**
  1. Upload ≥1 pcap/pcapng (validated).
  2. Files uploaded together are **merged into one analysis** (`mergecap -w`, chronological).
  3. Run Suricata offline, then ACP 1–7.
  4. Show the **Device Attribution** prompt.
  5. Results are stored locally under `src/database/pcaps/<id>/` and `src/database/eves/<id>/` and stay browsable.
- **Real-time flow:**
  1. The user picks the **mirror NIC** (connected to the switch's SPAN port, no IP, promiscuous) and the **LAN NIC** (dashboard access). Interfaces are listed from `/sys/class/net` with their carrier state.
  2. The session **stalls** through states `waiting_interfaces` (both links must be up) → `waiting_traffic` (the mirror's rx packet counter must increase) → `ready` (user confirms) → `running` → `stopped`.
  3. In `running`: the systemd unit `netseer-live@<mirror>` runs Suricata in af-packet mode, writing to `src/database/eves/<id>/`. A tailer reads eve.json from a checkpointed byte offset. ACP runs incrementally every *live processing interval*. Newly seen devices raise the attribution prompt.
  4. **Every live session (start → stop) is its own analysis record**, even on the same network.
- If a link drops while running, the session returns to `waiting_interfaces` and shows a banner. Data collected so far is kept.

### A14. Device attribution
Seven types, used as I1 (0–9):

| Type | Value |
|---|---|
| Server/NAS | 9 |
| Network device (router/switch/AP) | 8 |
| Workstation/Laptop | 6 |
| Phone/Tablet | 5 |
| IoT (printer/CCTV/smart device) | 5 |
| Guest device | 3 |
| Unknown (default) | 5 |

Attribution is asked after each offline analysis and for each new device in live mode. It can be changed any time on the Devices page. A change **re-scores** the affected incidents and the roll-up immediately.

### A15. NetSeer configuration (Settings, admin only)
Stored in the `settings` table, with defaults from `config/netseer.toml`:

| Setting | Default |
|---|---|
| Aggregation gap | 300 s |
| Correlation window | 30 min |
| Live processing interval | 30 s |
| Risk decay half-life | 7 days |
| LAN CIDRs | RFC1918 |
| Max pcap upload size | 500 MB |
| LLM backend and model | local `llama3.2:3b` / cloud with key |
| Rules update | `suricata-update` button |
| KB rebuild | button |
| Data retention | keep all, or delete analyses older than N days |

Changing a window or the half-life re-runs ACP 3–6 for the selected analysis.
