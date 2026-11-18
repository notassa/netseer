# NetSeer — Concepts (single source of truth)

**Decisions:** FastAPI backend · Ollama local LLM (llama3.2:3b) · offline mode **and** real-time mode, with real-time built after offline · the code follows the existing `netseer/` skeleton · hybrid risk model (OWASP-style factors per incident, probabilistic roll-up for devices and the network).

Source of requirements: `dump.md`. When this file and other docs disagree, this file wins.

---

### A0. Glossary
| Term | Meaning |
|---|---|
| **Alert** | One Suricata alert event from eve.json. |
| **Alert group** | Alerts with the same (src_ip, dest_ip, SID, proto, dest_port) and no silence longer than the aggregation gap. Reduces volume; removes nothing. |
| **Aggregation gap** | The longest silence inside one alert group (default 300 s). |
| **Possible incident** | Alert groups linked by R1–R4, or one unlinked group (rule "single"). "Possible" because NetSeer correlates; it does not confirm compromise. Recon is always its own incident. |
| **Correlation window** | The longest quiet gap inside one possible incident (default 30 min). It does not cap an incident's length. |
| **Sweep (R2)** | One source hits ≥5 destinations with the same SID inside the window. |
| **Fan-in (R3)** | ≥5 sources hit one destination with the same SID inside the window. |
| **Tactic progression (R4)** | On one internal host, a later group shows an ATT&CK tactic further along the kill chain than an earlier group. |
| **Band** | Note / Low / Medium / High / Critical, from the OWASP matrix of the likelihood and impact levels (A5.3). The main ranking. |
| **Score R** | 10 · (L/9) · (I/9), 0–10. Sorts incidents inside a band and feeds the roll-up. |
| **Device risk** | P(d), the rank-damped union of the decayed incident probabilities involving a device, as a %. Coloured by the device's worst band. |
| **Network health** | 100 · (1 − P(N)), where P(N) is the rank-damped union over every non-Note incident weighted by asset value. |

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
Enable the eve.json types `alert, anomaly, flow, dns, http, tls, dhcp, smb, ssh, fileinfo` and `ethernet: yes` (MAC addresses). These give "metadata from the pcap" with no extra parser. Exception: **Linux cooked (SLL) captures** (e.g. UNSW-NB15) have no Ethernet header, so eve.json has no MACs; NetSeer then reads the sender MAC that SLL keeps per packet (`tcpdump -e`, most common MAC per source IP, first 2 M packets; a MAC shared by 3 or more source IPs is a router's and is not given to them):
- **Device context:** MAC → vendor (Wireshark `manuf` list with 24/28/36-bit blocks, updatable from Settings; the offline IEEE OUI file until it is downloaded), DHCP hostname, DNS/mDNS names, TLS JA3/JA4, HTTP user-agent, observed services.
- **Packets/hour graph:** sum `flow.pkts_toserver + pkts_toclient` per hour. Alerts alone carry no packet counts.
- **Rulesets:** ET Open plus the abuse.ch Suricata sets (SSLBL, URLhaus, ThreatFox), managed with `suricata-update`. Many ET rules carry `metadata: mitre_tactic_id, mitre_technique_id, signature_severity, attack_target`; use them directly.
- **Detect attacks from inside the LAN** (setting `inside_rules`, default on): Suricata runs with **EXTERNAL_NET = any** (HOME_NET stays the analysis's LAN). Many ET rules are written `$EXTERNAL_NET → $HOME_NET`; with the default `!$HOME_NET` an attacker inside the LAN never matches them (the "realnetwork" capture: an nmap scan from 192.168.100.139 raised no ET SCAN alert). The cost is LAN policy alerts: on UNSW-NB15 ("big") it adds about 65,000 (BitTorrent, portmap, ICQ between the testbed hosts), so turn it off for testbed captures.
- **ET SCAN signatures are read as `attempted-recon`.** ET files many of them under `bad-unknown` or `misc-activity`; the rule's own category stays in the alert's category and raw JSON.
- **IP names and threat intelligence are global** and kept until Detonate: every name seen for an IP (DNS answers, TLS SNI, HTTP host, DHCP) goes into `ip_names` and fills the names an analysis lacks; AbuseIPDB/VirusTotal results stay in `ti_cache`, so each IP is looked up once.
- **NetSeer port-scan check (the one thing NetSeer detects itself).** Suricata has no port-scan tracker. From `flow` events, a source that probes **≥ 50 TCP ports on one host** (flows with ≤ 3 packets to the server) gets one alert per host: SID 9000001 "NETSEER Port scan: N ports probed", classtype attempted-recon, priority 2, ATT&CK TA0007/T1046. It is deterministic and goes through ACP like any Suricata alert, so scanning several hosts becomes an R2 sweep. One-port-many-hosts scans still rely on Suricata's rules and R2.
- **Capture placement matters.** On a switch, a capture sees only the traffic that reaches its port. In "realnetwork" the vulnerability scan of 192.168.100.142 never reached the capture (zero packets to .142), so nothing can detect it; use the switch's mirror port (C4).

### A4. Aggregation & correlation: deterministic rules, each one recorded
- **Aggregate** on the key `(src_ip, dest_ip, signature_id, proto, dest_port)`. A gap longer than the aggregation window (default 300 s, configurable) starts a new group. A group stores first_seen, last_seen, count, a representative alert and every raw alert ID. Report this as *volume reduction*, never as *false-positive removal*.
- **Correlate** groups into a *possible* incident when a rule fires within the correlation window (default 30 min, configurable). The window is the **longest quiet gap** allowed inside an incident: a group joins when it starts within the window of the latest end so far, so a slow scan that keeps going stays one incident however long it lasts.
  - R1: same attacker → same victim, different SIDs
  - R2: one source → ≥5 destinations **with the same SID** (sweep/scan)
  - R3: ≥5 sources → one destination **with the same SID** (brute force / DoS)
  - R4: MITRE tactic progression on one internal host: a later group shows a tactic **further along the kill chain** (ATT&CK tactic order) than an earlier group (e.g. Initial Access → Execution → C2). Two tactics in reverse order do not fire it.
  - **Recon stays its own incident:** groups of recon classtypes (attempted-recon, network-scan, successful-recon-*) link only with recon groups, and R4 leaves them out. An incident that follows a recon incident on the same hosts shows "Preceded by recon" with a link.
  - The title uses the widest rule that fired (R4 > R3 > R2 > R1), so a scan reads "Sweep from X to N hosts".
- Same SID for R2/R3: without it, unrelated signatures between busy hosts chained into one incident (on UNSW-NB15 the two largest incidents held 43% of the alerts). Forward order for R4: it gets the strongest L3 (9), so it must mean an actual progression.
- Each incident stores *which rule linked it*. Windows are tuned on UNSW-NB15.

### A5. Risk scoring (hybrid model): fills dump.md's "based on ?"

#### A5.1 Basis: what was taken from Munir (2014)
The reference thesis (Munir, R., 2014, *A Quantitative Security Assessment of Modern Cyber Attacks*, PhD thesis, University of Bradford; local copy in `docs/`, not committed) offers three techniques:

| Thesis technique | What it does | Fit for NetSeer | Verdict |
|---|---|---|---|
| Ch.3: CVSS severity counts per node → probability of attack; inclusion–exclusion union over nodes → department → whole network (example result: 28.9%) | Scores **vulnerability-scan** data (Nexpose) | NetSeer has no vulnerability scanner, so the inputs don't exist. The **aggregation step** transfers: P(at least one) = 1 − Π(1 − pᵢ) is the closed form of the thesis's inclusion–exclusion sums (Eq. 3.17, 3.27) **under an independence assumption the thesis does not state** (it never defines P(Nᵢ) or the intersections, and its department results are not internally consistent, e.g. Eq. 3.3 vs 3.18), so cite the method, not its numbers | **Adopt the aggregation** for device and network roll-up (A5.4) |
| Ch.4: OWASP Risk Rating (8 likelihood + 8 impact factors, each 0–9, averaged; levels [0,3) Low, [3,6) Medium, [6,9] High; 3×3 matrix → Note/Low/Medium/High/Critical) | Rates one scenario by hand | The factors are manual and subjective, and business-impact factors (financial, reputation) can't be known from traffic. The **structure** is transparent and suits non-experts | **Adapt**: evidence-derived factors on the same 0–9 scale, the same levels and the same matrix (A5.2–A5.3) |
| Ch.5: SL(Aᵢ) = nᵢ / N per classtype and per priority, read as "X% secure" | Shares of alerts | Not a risk measure: shares dilute (adding low-priority alerts shrinks every other share), and "46.4% of alerts ⇒ 53.6% secure" doesn't follow. Its classtype → priority table (Table 5.3) is useful | **Descriptive only**: "alert mix" chart (A5.5); classtype priorities inform factor I3 (I3 raises attempted-dos and default-login-attempt above Table 5.3's Medium) |

**Citation note.** The thesis is from 2014, so it breaks the "latest 5 years" rule. Cite it as methodological precedent only. The primary sources are the **OWASP Risk Rating Methodology** (OWASP Foundation), **NIST SP 800-30 Rev.1** (risk = f(likelihood, impact)) and **CVSS v4.0** (FIRST, 2023; environmental requirement modifiers).

#### A5.2 Incident factors (0–9 scale, computed automatically from evidence)
**Likelihood factors.** L = mean of the available factors.

| ID | Factor | Values |
|---|---|---|
| L1 | Detection confidence | Suricata priority 1/2/3/4 → 9/6/3/1. If ET `signature_severity` is present it overrides: Critical 9, Major 7, Minor 4, Informational 1, except **Informational, which yields to the priority** (ET marks many real scans Informational). Take the max over the incident's groups |
| L2 | Activity volume | min(9, 3·log10(1 + n_alerts)) |
| L3 | Correlation strength | single 2 · R1 6 · R2 5 · R3 7 · R4 9 |
| L4 | Exposure | ext→int 9 · int→ext 7 · int→int 6 · ext→ext 1 (dominant direction of the incident) |
| L5 | Threat reputation *(optional)* | max(AbuseIPDB confidence/100, min(1, VT malicious engines/5)) × 9. **Raise-only:** it enters the mean only when it is above the mean of L1–L4, because no reports is not evidence of safety (and TI runs only for the top incidents' IPs, so a two-sided L5 would lower exactly those). **Left out** when TI is off or the result is unknown (VT with no engine results); unknown never counts as safe. VT is scaled by engine count because a ratio over ~90 engines stays near 0 even for known-bad IPs |

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

#### A5.4 Device risk and network health (probabilistic roll-up from Munir Ch.3, rank-damped)
- **Per-incident probability proxy:** pᵢ = (Rᵢ / 10) · 0.5^(ageᵢ / half_life). Note-band incidents are excluded. Age runs from the incident's last_seen to the analysis end (offline) or to now (live). half_life defaults to 7 days and is configurable.
- **Rank-damped union.** Munir's union P = 1 − Π(1 − xᵢ) assumes independent events. Its result also grows with the *number* of incidents, and that number depends on how the contextor splits the same alerts. NetSeer therefore damps each term by its rank, with the Riemann-zeta weighting (p = 1.5) used in Elastic's entity risk scoring:
  `D(x₁ ≥ x₂ ≥ … ≥ xₙ) = 1 − Π_k (1 − x_k / k^1.5)`
  - One value: D = x, which is the plain union.
  - Adding values never lowers D.
  - D stays below 1 even for unlimited values, because Σ k^-1.5 converges, so it does not saturate.
  - It hardly changes when one incident is split into two. On UNSW-NB15 the health was 56/55/55 at correlation windows of 60/30/5 minutes, against 7/2/0 for the plain union.
- **Device risk:** P(d) = D over pᵢ of the incidents involving device d, shown as a percentage. The device's **colour and label are the worst band** among its non-Note incidents (Low when it has none), so a device in a High incident always shows High. The percentage cut-offs (<40 Low · 40–69 Medium · 70–89 High · ≥90 Critical) colour only the network health gauge: pᵢ = R/10, and R ≥ 9 needs L and I both ≥ 8.5, so %-based device colours disagreed with the bands. Home lists as "devices at risk" those whose worst band is Medium or above, by P(d).
- **Network risk:** P(N) = D over **every non-Note incident** of xᵢ = wᵢ · pᵢ, where wᵢ = I1ᵢ / 9 is the asset weight of the incident (Unknown = 5/9 when no attributed internal device is involved). Every scored incident therefore moves the health, including incidents between hosts outside the LAN CIDRs. The thesis weights nodes uniformly; NetSeer weights them by asset value, per NIST SP 800-30 impact.
- **Network health (Home gauge)** = round(100 · (1 − P(N))). To explain the number, the Home page lists the top 3 incidents with the points each one costs, and the top 3 devices (largest w_d·P(d)). An incident's points are its share of the drop (100 − health) in proportion to −ln(1 − x_(k)/k^1.5), the log-additive split of the product, so the points add up to the drop (within rounding).
- **Saturation check:** `eval/acp_metrics.py` prints health as incidents are added worst first. Report the remaining independence assumption as a limitation.

#### A5.5 Alert mix (Munir Ch.5, descriptive only)
On the Alerts page, show nᵢ / N by classtype and by severity (the Suricata priority shown as [1] High, [2] Medium, [3] Low, [4] Info) as a pie chart titled **"Detected Alert Classes"** (with the note that shares are not risk). It never feeds the health score.

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
- P(server) = 0.216; P(workstation) = 0.494 (one incident each, so D = p)
- x(b) = 0.667 × 0.494 = 0.329; x(a) = 1.0 × 0.216 = 0.216. Sorted worst first, the second term is damped by 2^1.5 = 2.828:
- P(N) = 1 − (1 − 0.329)(1 − 0.216 / 2.828) = 1 − 0.671 × 0.924 = **0.381**
- Health = **62**

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
- **Sessions:** random token, HttpOnly + SameSite (+ Secure behind TLS) cookie, server-side row, **10-minute session** from sign-in with a countdown in the top bar and an **Extend (+10 min)** button (browsing does not extend it; at most 60 min ahead). Logout deletes the row and redirects to `/login`. **Auto-logout toggle** (Settings > Accounts, admin, both accounts, audited): off = no countdown, and a session still ends **12 h** after sign-in.
- **RBAC:** Admin (view and manage) vs User (view only), enforced server-side on every route.
- **Further controls:** audit log (logins, logouts, failed logins and session expiry with client **IP and MAC**, setup, uploads, analysis success/failure, live start/stop, setting and API-key changes). The MAC comes from the server's neighbour (ARP) table, so it is known only for clients on the same LAN; otherwise it is stored as unknown; pcap validation (magic bytes, size cap); unprivileged services; API keys encrypted at rest (Fernet); Nginx TLS, bound to the LAN, rate-limited.
- **Live-mode privilege:** the web app never runs as root. Packet capture runs in a systemd unit with only `CAP_NET_RAW`/`CAP_NET_ADMIN`, started through a narrow sudoers/polkit rule (A13).
- **Mapping:** ISO/IEC 27001:2022 Annex A (A.5.15, A.5.17, A.8.2, A.8.5, A.8.15, A.8.20, A.8.24, A.8.26, A.8.28) and OWASP ASVS 5.0.
- **Privacy:** VirusTotal, AbuseIPDB and the cloud LLM are opt-in, use the user's own key, look up external IPs only, and are cached.

### A10. Dashboard pages (fills "Home: ?")
| Page | Content |
|---|---|
| Login | Username and password. On first launch (no admin yet) it shows **Create administrator** instead (A12) |
| Home | Current analysis card (name, status, counts) on top, then the network health gauge (A5.4) with the top 3 contributing devices, top 5 incidents (band chip, title, time), devices at risk, alert trend |
| Network | **Mode selection** (offline / real-time), one-file-at-a-time upload into a **session**, live NIC status and stall messages, **analyses browser** (list, open, rename, files, re-analyse, admin **note**, delete as admin), **Stop** a queued/running analysis (admin; kills Suricata, clears its results, keeps the capture; status `stopped`, can be re-analysed) |
| Alerts | **Packets per *x* minutes** and **alerts per *x* minutes** charts side by side, each with its own bin size and Update button, **top 5 devices by alerts** (sent, received, total), **alert mix** chart (A5.5), alert table with the columns Time (UTC), Severity, Signature, Class, Direction, Source, Destination, Proto (**Severity** = Suricata priority as [1] High, [2] Medium, [3] Low, [4] Info; ET `signature_severity` is kept for scoring and the raw JSON, not shown as a column) and a collapsible **Filters** frame (search, IPs, SID, and tick boxes for severity, direction and class; ticked values in one group are OR-ed), raw JSON drawer |
| Incidents | Table (band, score, title, rule, hosts, span) → detail: **Attack → Victim** pairs (source → destination IPs as Suricata saw them, with device name/type or "outside the LAN", alerts, main signature; top 10), timeline, alert groups, factor breakdown (A5.2), linked raw alerts |
| Devices | Inventory (IP, MAC/vendor, hostname, services, type, risk %), device-type editor; the attribution prompt appears after each offline analysis and for new devices in live mode. **External sources** table: every IP outside the LAN CIDRs seen in the analysis (hostname from DNS/TLS SNI/HTTP host, direction, first/last seen, flows, bytes, alerts, ports, internal peers) |
| AI | Per-incident interpretation, Prompt Maker buttons, verifier badge, regenerate, **progress %** while generating (an estimate from the last 10 timed runs, held at 95% until done), **Stop** (the stream to Ollama is closed, nothing is saved), **Clear saved explanations** of the analysis (admin, confirm, audited) |
| Information | **Admin only.** A **NetSeer details** tab (hostname, OS, CPU, up since, Suricata/Ollama versions, database size, CPU %, load, memory, disk, temperatures from hwmon refreshed every 5 s, and the network cards with link state, MAC and addresses) and system logs in two tabs: **Account activity** (login, logout, failed login, lockout, session expiry, account changes, with time, IP and MAC) and **Process log** (upload, analysis succeeded/failed with reason, attribution, rename, delete). Each tab has a **Clear log** button (confirm); one entry recording who cleared how many is kept. Not scoped to the selected analysis |
| Settings | Theme (**White** default / **Black**); API keys (admin); accounts (admin: create/reset/delete the one User); **NetSeer configuration** (admin, A15); **Detonate** (admin, A12) |

Every table column head shows what it holds as a tooltip. The left panel can collapse to a narrow icon rail (remembered per browser). Every page except Login, Information and Settings is scoped to the **selected analysis** (selector in the header). Frontend: Jinja2 + vanilla JS + Chart.js (+ Cytoscape.js for the network map), served locally. No build step. Every table shows 20 rows with **Show all / Hide**, sorts by clicking a column head and has a **Reset** button; every search box is a type-or-pick list of values from the data.

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
- **Detonate (factory reset):** the Admin can wipe every analysis with its stored pcap/eve files, both accounts, settings, API keys and logs, returning NetSeer to first launch. Needs the Admin password and the typed word DETONATE; refused while an analysis runs. One audit entry (`netseer_detonated`, with IP/MAC) is kept.

### A13. Analyses & network selection
- **Analysis** = one stored unit of work with: id, name, mode (`offline` | `live`), status, timestamps, files or interfaces, and counts.
  - Auto names: `Offline — <first file> (+N) — <YYYY-MM-DD HH:MM>`, `Live — <mirror NIC> — <start time>`. Users can rename; the admin can delete.
- **Network selection:** if no analysis is selected, the Network page asks for the mode.
- **Offline flow:**
  1. Upload **one** pcap/pcapng at a time (validated: a real pcap/pcapng file header, not only the magic bytes, and a **SHA-256 not already stored** in any analysis, so each capture is kept once) into a **session**: a new one or an existing offline session. "Analyse after upload" keeps its last state in the browser. The admin can **delete any file** of a session: its results are cleared and it waits as `pending` for Analyse; deleting the last file deletes the session.
  2. All files of a session are **merged into one analysis** in time order (`mergecap`), so adding files makes a longer analysis. "Analyse after upload" can be turned off to collect several files first (status `pending`), then **Analyse**.
  3. Files stream straight to disk (status `uploading`), then run Suricata offline, then ACP 1–7. A progress bar shows each stage (upload %, merging, loading rules, reading capture %, processing %).
  4. Show the **Device Attribution** prompt.
  5. Results are stored locally under `src/database/pcaps/<id>/` and `src/database/eves/<id>/` and stay browsable. The merged capture is deleted after a successful run; the original files are kept. A capture that ends mid-packet (recording cut off) is analysed up to the cut and flagged with a note; a capture Suricata cannot open fails the analysis. The Admin can **Re-analyse** a stored analysis without uploading again.
- **Real-time flow:**
  1. The user picks the **mirror NIC** (connected to the switch's SPAN port, no IP, promiscuous) and the **LAN NIC** (dashboard access). Interfaces are listed from `/sys/class/net` with their carrier state.
  2. The session **stalls** through states `waiting_interfaces` (both links must be up) → `waiting_traffic` (the mirror's rx packet counter must increase) → `ready` (user confirms) → `running` → `stopped`.
  3. In `running`: the systemd unit `netseer-live@<mirror>` runs Suricata in af-packet mode, writing to `src/database/eves/<id>/`. A tailer reads eve.json from a checkpointed byte offset (half-written lines wait; a new inode or shorter file restarts at 0). Every *live processing interval* the new lines go through ACP 1–2 and ACP 3–6 is rebuilt for the session; an incident keeps its id while its first alert stays the same, so its saved explanations survive. Newly seen devices raise the attribution banner and modal. If links drop while running and come back, capture carries on without a new confirm.
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
| LAN CIDRs | RFC1918 (an analysis may adopt looks-local networks on top, A17) |
| Detect attacks from inside the LAN | on (EXTERNAL_NET = any, A3); applies to the next analysis or Re-analyse |
| Max pcap upload size | 2048 MB **per file** (any number of files; an upload is refused if free disk < 2.5 × its size) |
| LLM backend and model | local `llama3.2:3b` / cloud with key |
| Rules update | "Update Suricata rules" button (`sudo suricata-update`, no arguments allowed by sudoers), then the KB is rebuilt |
| KB rebuild | button |
| MAC vendor list | Wireshark `manuf`, "Update to the latest version" button; shows the list's version date |
| Data retention | keep all, or delete analyses older than N days |

Changing a window or the half-life re-runs ACP 3–6 for the selected analysis.

### A16. Capture checks (shown as Info under each analysis)
The captures are checked so that gaps in the evidence are visible next to the results. Each finding is stored in `analysis_info` (`kind = 'capture'`, level `info` or `warning`) and listed under the analysis on the Network page.

| Check | Source | Finding |
|---|---|---|
| File facts | `capinfos` per file: link type, snaplen, packets, first/last packet, strict time order | Listed per file |
| Gap between files | First/last packet of the files, sorted by start | Silence > 60 s between two files → "a capture file may be missing" |
| Overlap | Same | Files overlap > 1 s → interleaved in the merge (a duplicate or a second capture point) |
| Duplicate file | SHA-256 in `analysis_files` | The same file uploaded twice |
| Mixed formats | Link type / snaplen differ | Merged as classic pcap; a smaller snaplen cuts packets |
| Time order | `capinfos -o` | Packets out of order inside a file |
| Silent stretch | `packet_stats` | ≥ 5 consecutive minutes inside the capture span with no active flow. Conservative: a minute that no flow spans had no IP packets |
| Capture loss | Suricata's final `stats` event | `tcp.reassembly_gap` > 0 (TCP segments missing: loss or one-sided mirroring); `decoder.invalid` |
| Truncated file | `suricata.log` | Last packet cut off (analysed up to the cut) |

### A17. Network discovery and network map (Devices page)
**Probable subnets and VLANs.** Each network found is stored in `analysis_info` (`kind = 'network'`) with its evidence and a confidence:
1. **Certain:** 802.1Q VLAN IDs on events (eve `vlan`); a DHCP `subnet_mask` with `routers`.
2. **Strong:** a directed broadcast (an internal destination whose host bits are all 1 for a /16–/30 prefix); the gateway MAC, meaning the destination MAC of internal→external traffic, whose internal IP is the gateway.
3. **Probable:** the remaining internal hosts grouped by /24. Adjacent /24s that share a gateway MAC or DHCP mask are merged into the covering prefix.
4. **Looks local, outside the LAN CIDRs:** external /24s with DHCP or broadcast traffic, or with 3 or more hosts offering services to others. These are shown with a hint to add them to the LAN CIDRs (Settings).
   **Auto-adopt:** when the networks outside the LAN CIDRs whose hosts talk among outside networks (looks local, even if DHCP or VLAN evidence also marks them) hold more hosts than the analysis's internal devices (a testbed on public addresses such as UNSW-NB15), NetSeer adopts them as that analysis's LAN (stored per analysis, key `lan_cidrs:<id>`), logs `lan_adopted` and runs the analysis once more with the wider HOME_NET. Adoption happens at most once per analysis; the global LAN CIDRs do not change.

**Network map.** A movable and zoomable graph built with Cytoscape.js (vendored):
- **Nodes:** networks as groups, internal devices coloured by their worst incident band (A5.4), the top 40 external sources by alerts then bytes (the rest collapsed into one node), and an Internet node. Broadcast (directed or 255.255.255.255), multicast and unspecified addresses are not hosts and are left out unless they are devices.
- **Edges:** observed communication from `host_links` (flows, bytes, alerts; red when alerts > 0).
- Layout: **Tree** only (Internet → network → **gateway → its clients**; hosts go straight under the network when no gateway is known; outside sources under Internet). Traffic links are hidden; clicking a host shows its links that carried alerts, clicking empty space hides them. **Hold the right button and drag to pan**; left click selects and shows details; left-dragging a node moves everything under it.

