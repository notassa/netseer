# NetSeer — Writeup

A guide for explaining NetSeer to a supervisor or examiner: what it is, how each part works and why it was built
that way, what the results are, where it falls short, and how to demo it. The detailed specification is
`docs/CONCEPTS.md`. This document points to it by section (A1, A5.4, …) instead of repeating it.

**Terms used throughout:**

| Term | Meaning |
|---|---|
| Suricata | Open-source network intrusion detection engine; writes its findings to `eve.json` |
| ET / ET Open | Emerging Threats Open, the free Suricata ruleset (plus abuse.ch blocklists) |
| SID | Signature ID: the number of the rule that fired |
| Classtype, priority | The rule's attack category (e.g. `attempted-recon`) and Suricata's 1 (high) – 4 (low) priority |
| signature_severity | ET metadata: Critical / Major / Minor / Informational |
| HOME_NET / EXTERNAL_NET | Suricata variables for "our LAN" and "everything else"; rules are written between them |
| ATT&CK | MITRE ATT&CK: tactics (goals, in kill-chain order from Reconnaissance to Impact) and techniques |
| UNSW-NB15 | Public research dataset of attack traffic (pcaps with ground truth) |
| "big" | The evaluation analysis: UNSW-NB15 files 14, 16, 17 and 18 (7.6 GB) |
| "realnetwork" | A capture from the owner's own LAN while one host ran nmap scans against the others |
| C1–C4 | The four RAD construction cycles; C4 (real-time mode) is still to be built |

---

## 1. What NetSeer is

**Problem.** An intrusion detection system such as Suricata produces many alerts. Each one is short, technical
and isolated ("ET SCAN Possible Nmap User-Agent Observed", priority 1). A small organisation without a security
analyst cannot tell which alerts belong together, which matter and what to do about them.

**What NetSeer does.** It sits *after* Suricata and turns its alerts into a short list of ranked **possible
incidents**, each with:
- a **band** (Note, Low, Medium, High, Critical) and a breakdown of *why* it got that band;
- the hosts involved (attacker → victim), a timeline and every raw alert behind it;
- an optional plain-language **explanation** from a local language model, checked by a **verifier** before it is shown.

It also gives a **network health** score (0–100) and a risk percentage per device.

**What NetSeer is not** (CONCEPTS A1). It is not a detector, an IPS, a SIEM or a machine-learning model.
Suricata does the detection, with one small exception: NetSeer's port-scan check (§3.4). Correlation and scoring
are fixed, recorded rules. The language model never detects, scores or confirms anything; it only explains
evidence that has already been prepared.

**Why "possible" incident.** NetSeer links alerts by rules. It cannot prove a compromise happened, so it never
says one did. The verifier enforces that wording in the AI output (§5.3).

**Setting.** One small LAN, one mini PC (Intel i5, 16 GB RAM, no GPU) running Ubuntu Server. The dashboard is
reachable only on the LAN. Two modes:
- **Offline:** upload one or more pcap files. They are merged in time order and analysed.
- **Real-time:** capture from a switch mirror port (cycle C4, planned).

---

## 2. Architecture and pipeline

```
pcap(s) ──► mergecap ──► Suricata 8 (ET Open + abuse.ch rules) ──► eve.json
                                                                     │
        ┌──────────────────────── ACP (Alert-Context Processing) ────┘
        │  1 Normalise    2 Enrich      3 Aggregate    4 Correlate    5 Incident enrich   6 Score
        │  (logger)       (devices,     (alert         (R1–R4 →       (ATT&CK, ports,      (L, I, band, R;
        │                 MACs, flows)  groups)        incidents)     hosts, title)        device + health)
        └────────────────────────────────────────────────────────────────────────┬────────
                                                                                  │
                      7 Evidence package (facts E#, knowledge K#, unknowns) ◄─────┘
                                │                    ▲
                                ▼                    │ RAG: rules, ATT&CK, classtypes, playbooks (SQLite FTS5)
                      Local LLM (Ollama, llama3.2:3b, JSON schema)
                                │
                                ▼
                      Verifier (schema, citations, entities, overclaim, band) ──► Web dashboard
```

| Stage | Code | What it produces |
|---|---|---|
| Ingest | `src/engine/ingest.py` | Validated, merged capture; runs Suricata with the analysis's LAN as `HOME_NET` |
| ACP 1–2 | `src/engine/logger.py`, `oui.py` | Alerts in one schema (raw JSON kept), devices (MAC, vendor, hostname, services), packet statistics, NetSeer scan alerts |
| ACP 3–5 | `src/engine/contextor.py` | Alert groups, possible incidents, titles, ATT&CK tactics |
| ACP 6 | `src/engine/scorer.py`, `constants.py` | Factors, band, score, device risk, network health |
| ACP 7 + AI | `ai/prompt_maker.py`, `rag.py`, `llm_caller.py`, `verifier.py`, `explain.py` | Evidence package, explanation, verification |
| Web | `src/api/`, `web/templates/` | FastAPI + Jinja2 + vanilla JS + Chart.js, no build step |
| Storage | `src/database/schema.sql` | One SQLite file (WAL); pcaps and eve.json per analysis on disk |

**Design choices worth defending:**
- **Suricata's own logs instead of a custom packet parser** (A3). eve.json already has flows, DNS, TLS, HTTP, DHCP and
  MACs, so NetSeer reads metadata without a second parser.
- **Missing values stay "unknown"** and are never guessed (A2). An unknown factor is left out of a mean, not counted as safe.
- **Deterministic and traceable.** Every incident records which rule linked it, and every alert ID is kept, so any
  number on screen can be traced back to raw alerts.

---

## 3. ACP: from alerts to possible incidents (A4)

### 3.1 Aggregation (ACP 3)
Alerts with the same **(source IP, destination IP, signature ID, protocol, destination port)** form one **alert group**.
If that key is silent for more than the **aggregation gap** (default 300 s), the next alert starts a new group.
This is *volume reduction*, not false-positive removal: no alert is thrown away.

### 3.2 Correlation (ACP 4)
Groups are linked into **possible incidents** by four rules, each applied only to groups that fall inside the
correlation window (below). Linking is transitive (union-find), and each incident stores every rule that fired.

| Rule | Fires when | Typical attack |
|---|---|---|
| R1 | Same source → same destination, **different** signatures | One attacker trying several things on one victim |
| R2 | One source → **≥ 5 destinations**, **same** signature | Sweep / scan |
| R3 | **≥ 5 sources** → one destination, **same** signature | Brute force, DoS |
| R4 | On one internal host, a later group shows an ATT&CK tactic **further along the kill chain** than an earlier one | Attack progressing (e.g. Initial Access → Execution → C2) |
| single | No rule fired | One stand-alone group |

**Recon is always its own incident.** Groups whose class is reconnaissance (attempted-recon, network-scan,
successful-recon-*) link only with other recon groups, and R4 leaves them out. So a scan never hides inside an
exploit incident. When an incident follows a recon incident on the same hosts, its page says "Preceded by recon"
and links to it.

**Correlation window** (default 30 min) = the longest quiet gap allowed inside one incident. A slow scan that keeps
going stays one incident however long it lasts.

**Why "same signature" for R2/R3, and "forward order" for R4.** An algorithm review (October 2026) found that,
without them, unrelated alerts between busy hosts chained into huge incidents: on UNSW-NB15 the two largest
incidents held 43% of all alerts before the fix (the largest holds 17% after it, see §9). R4 also fired on tactics in reverse order, although it carries the strongest
correlation weight. After the change, "big" went from 45 to about 200 incidents. The reduction figure fell from
96.7% to about 85%, which is the honest one.

### 3.3 Incident enrichment (ACP 5)
Each incident gets a template title from the widest rule that fired (R4 > R3 > R2 > R1), e.g. "Sweep from
175.45.176.1 to 7 hosts (…)", plus its signatures, classtypes, ATT&CK
tactics and techniques, directions, ports and internal hosts. The Incident page shows the **Attack → Victim** pairs
with device names.

### 3.4 Attacks from inside the LAN (A3)
Suricata, unlike Snort's sfPortscan, ships no port-scan detector; its scan rules match specific probes. Many ET
rules also only match `$EXTERNAL_NET → $HOME_NET`, so a scan from *inside* the LAN raised nothing. Fixes:
1. **"Detect attacks from inside the LAN"** (Settings, on by default) runs Suricata with `EXTERNAL_NET = any`, so
   those rules also fire for an inside attacker. Its cost is LAN policy alerts: on the UNSW-NB15 testbed it adds
   about 65,000 (file sharing and chat between the testbed hosts), so it is turned off for that dataset.
2. From flow records, a source that probes **≥ 50 TCP ports on one host** (flows with ≤ 3 packets to the server)
   gets one alert per host: SID 9000001 "NETSEER Port scan: N ports probed" (attempted-recon, ATT&CK T1046).
   It then goes through ACP like any other alert, so scanning several hosts becomes an R2 sweep.
3. ET SCAN signatures are read as `attempted-recon` (ET files many under "bad-unknown"), and an ET severity of
   "Informational" no longer pulls a priority-2 rule down to the lowest confidence (§4.2).

---

## 4. Risk model (A5)

### 4.1 Basis
The model is a **hybrid**:
- **Per incident:** the OWASP Risk Rating structure (0–9 factors, Low/Medium/High levels, 3×3 matrix), with factors
  computed from evidence instead of chosen by hand.
- **Device and network roll-up:** the probabilistic union used by Munir (2014, Ch.3).
- NIST SP 800-30 (risk = likelihood × impact) and CVSS v4.0 (environmental modifiers) are the primary sources.

Munir, R. (2014) *A Quantitative Security Assessment of Modern Cyber Attacks*, PhD thesis, University of
Bradford. It is from 2014, so it is cited as a methodological precedent only. What was taken and what was not:

| Munir technique | Used? | Why |
|---|---|---|
| Ch.3 union over nodes (inclusion–exclusion) | Yes, for roll-up | Fits; NetSeer adds an explicit independence assumption (the thesis does not state one) and rank damping |
| Ch.4 OWASP rating | Structure yes, hand-picked factors no | Business factors (financial, reputation) can't be read from traffic |
| Ch.5 "share of alerts = % secure" | No (only a descriptive chart) | Shares dilute: adding harmless alerts makes everything else look safer |

### 4.2 Incident factors (0–9)

**Likelihood L** = mean of the factors that are present:

| Factor | Value |
|---|---|
| L1 Detection confidence | Suricata priority 1/2/3/4 → 9/6/3/1; ET signature_severity overrides (Critical 9, Major 7, Minor 4), except Informational (1), which yields to the priority |
| L2 Activity volume | min(9, 3·log10(1 + alerts)) |
| L3 Correlation strength | single 2 · R1 6 · R2 5 · R3 7 · R4 9 |
| L4 Exposure | ext→int 9 · int→ext 7 · int→int 6 · ext→ext 1 |
| L5 Threat reputation (optional) | 9 × max(AbuseIPDB confidence/100, min(1, VirusTotal malicious engines/5)). **Counts only when it raises L**: no reports is not evidence of safety |

**Impact I:** I1 asset criticality (device type, A14: Server 9 … Guest 3, Unknown 5), I2 service sensitivity
(SSH/SMB/RDP/databases 9, web 6, other 4), I3 technical impact by classtype (trojan/C2 9 … recon 3).

`A = (I1 + I2) / 2`  `I = I3 × (0.5 + 0.5 × A/9)`

The attack type sets the ceiling and the asset scales it. With a plain mean, a scan against an SSH server came out
Critical. With this formula, a scan (recon classtypes have I3 = 3) stays at most Medium impact.

### 4.3 Band and score
Levels for L and I: Low [0,3) · Medium [3,6) · High [6,9]. The band comes from the OWASP matrix:

| L \ I | Low | Medium | High |
|---|---|---|---|
| **Low** | Note | Low | Medium |
| **Medium** | Low | Medium | High |
| **High** | Medium | High | Critical |

Score `R = 10 · (L/9) · (I/9)` (0–10) sorts incidents inside a band and feeds the roll-up. Every factor is stored
with its value, evidence and a one-line reason, so "why is this High?" is always answerable.

### 4.4 Device risk and network health
- Per incident: `pᵢ = R/10 · 0.5^(age / half-life)` (half-life 7 days; Note incidents left out).
- **Rank-damped union** of values x sorted worst first: `D = 1 − Π (1 − x_k / k^1.5)`, where k is the rank. One
  incident gives exactly its own value. More incidents never lower it. It stays below 1 unless an incident has
  R = 10 and age 0. If one attack is split into two similar incidents, the second counts at 1/2.83 of its value, so
  D rises far less than the plain union, which nearly doubles it. On UNSW-NB15 (measured before the October rule
  fixes) the plain union gave health 7/2/0 at windows of 60/30/5 min; the damped one gave 56/55/55.
- **Device risk** P(d) = D over its incidents, shown as a %. Its **colour is the worst band** among its incidents.
- **Network health** = 100 · (1 − P(N)), where P(N) = D over all non-Note incidents of xᵢ = pᵢ. Asset value
  is counted once, inside each incident's impact. Health is a triage index, not a probability of compromise; Home
  lists the incidents that cost the most points. The k^1.5 damping is a NetSeer heuristic, backed by the
  split-stability measurement above, not by a published source.

### 4.5 Worked example (A5.6, a unit test)
LAN 10.0.0.0/24; server 10.0.0.5 (Server, I1 9), workstation 10.0.0.23 (Workstation, I1 6).

| | (a) external SSH sweep | (b) workstation → C2 |
|---|---|---|
| Alerts, rule, severity, classtype, port | 60, R2, ET Minor, attempted-recon, 22 (SSH, I2 9), ext→int | 12, single, ET Critical, trojan-activity, 443 (web, I2 6), int→ext |
| L | (4 + 5.36 + 5 + 9)/4 = **5.84** Medium | (9 + 3.34 + 2 + 7)/4 = **5.34** Medium |
| I | 3 × 1.0 = **3.0** Medium | 9 × 0.833 = **7.5** High |
| Band, R | **Medium**, 2.16 | **High**, 4.94 |

Roll-up (age 0, so no decay): x(b) = 0.494; x(a) = 0.216, damped by 2^1.5 →
P(N) = 1 − 0.506 × 0.924 = 0.533 → **health 47**.

> **Report action:** report Table 4.7 still shows health = 53, the value from before rank damping. Update it to 47 (I1 counted once since 2026-11-18).

---

## 5. AI explanation and verifier (A6–A8)

### 5.1 Evidence package
Every fact gets an ID: `E#` for alert groups, hosts, device types, TI, each factor, the band and the timeline;
`K#` for retrieved knowledge. An `unknowns[]` list says what is missing. The model may only use these.

### 5.2 Retrieval (RAG)
A local SQLite knowledge base, built offline: 109,263 parsed rules, MITRE ATT&CK (765 objects), plain-language
classtypes and 8 short playbooks aligned with NIST SP 800-61. Retrieval is a keyed lookup (SID → rule → technique →
mitigations), then full-text search (FTS5/BM25) over the playbooks. There are no embeddings, so retrieval is
deterministic.

### 5.3 Model and checks
- `llama3.2:3b` on Ollama, CPU only, with a JSON schema that forces 1–4 citations per claim and action. An optional
  cloud model can be used with the owner's own key.
- **Prompt Maker** buttons change only the instruction: Explain simply · What should I do now? · Is this serious? ·
  Explain technically · Summarise this analysis.
- **Verifier** before display: (1) schema, retried once; (2) every claim cites an existing E#/K#; (3) every IP, port,
  SID, CVE, ATT&CK ID, count and time exists in the evidence; (4) overclaim: "was compromised" is flagged unless the
  evidence confirms it, while hedged wording ("may have") is not; (5) the stated band equals ACP's band.
  The checks do not block the output: the UI shows "Verified" or "N flagged claims" and highlights the flagged
  sentences, so the reader sees exactly which statements are not supported.
- Explanations are cached per incident, question and evidence hash. A progress % (an estimate from past runs) shows
  while one is generating, with a **Stop** button that closes the stream to Ollama (nothing is saved). The admin can
  clear an analysis's saved explanations.

---

## 6. Pages tour (A10)

| Page | What to point out |
|---|---|
| Setup / Login | First launch creates the admin; then `/setup` is gone. Lockout after 5 failures |
| Network | Traffic Source: upload into a named session or pick network adapters; upload into a session (files merged; a file already uploaded or with a broken header is refused), delete single files, progress per stage, **Stop**, Re-analyse, capture checks (gaps, loss, truncation), notes |
| Home | Health gauge and what costs it points, Traffic Volume (ingress/egress and stacked total), devices at risk, top incidents |
| Alerts | Packets and alerts per *x* minutes (each its own bin size), top 5 devices by alerts, "Detected Alert Classes" bar chart (shares, not risk), filter frame with tick boxes, raw JSON drawer. Hover a column head to see what it holds |
| Incidents | Ranked by band then score → detail: Attack → Victim, timeline, groups, factor table, raw alerts |
| Devices | Inventory (MAC, vendor, hostname, services, type, risk), attribution prompt, external sources, network map |
| AI | Explanation with the verifier badge, viewable and copyable prompt, ref chips, progress % and Stop, saved explanations (admin can clear) |
| Information | Admin audit log (account activity and process log, with IP and MAC) and NetSeer details (the box's CPU, memory, temperatures, network cards) |
| Settings | Theme, accounts and the auto-logout toggle, configuration (windows, half-life, LAN, inside-LAN rules), AI keys, KB rebuild, vendor list, Detonate (factory reset: password + typed word) |

---

## 7. Security of NetSeer itself (A9, A12)
- **Accounts:** one Admin and at most one User (a database constraint). Argon2id. Passwords of at least 15
  characters, checked against a breached-password list (NIST SP 800-63B-4). 5 failures → 5-minute lock.
- **Sessions:** server-side, cookie HttpOnly + SameSite, 10 minutes with an Extend button. Browsing does not extend
  a session, so a forgotten tab logs out. The admin can turn auto-logout off; a session then still ends after 12 h.
- **RBAC:** User = view only, checked on every route. CSRF tokens on every form.
- **Audit log** of logins, failures, expiry, uploads, analyses, setting and key changes, with IP and MAC.
- **External services are opt-in** (AbuseIPDB, VirusTotal, cloud LLM): own keys, encrypted at rest, public outside
  IPs only, cached.
- Mapped to ISO/IEC 27001:2022 Annex A and OWASP ASVS 5.0 (report Table 4.9/4.11).

---

## 8. Results (report Tables 4.12 and 4.13)

Updated after every change that moves a number. How each step was checked: `docs/RAD-PLAN.md` → Build record.

**Cycles (Table 4.12):**

| Cycle | Scope | Status |
|---|---|---|
| C1 | Foundation & offline mode (brief §10 steps 1–4) | Completed (awaiting owner demo) |
| C2 | ACP & risk (steps 5–7) | Completed (awaiting owner demo) |
| C3 | Interpretation (steps 8–10) | Completed (awaiting owner demo) |
| C4 | Real-time mode (steps 11–12) | Completed (awaiting owner demo) |

**Demo numbers (Table 4.13):**

| Metric | Value |
|---|---|
| Capture size | 7,629 MB ("big": UNSW-NB15 14/16/17/18.pcap, 13.7 M packets); earlier 568 MB (`27.pcap`) |
| Raw alerts | 1,349 ("big", with its LAN adoption and "Detect attacks from inside the LAN" off; 1,630 before adoption); 233 (`27.pcap`) |
| Alert groups | 1,004 ("big": 25.6% fewer than alerts) |
| Possible incidents | 209 (Critical 6, High 19, Medium 84, Low 93, Note 7); network health 41 (I1-weighted roll-up before 2026-11-18; analysis no longer in the DB, re-measure); largest incident 17% of alerts ("big", rules of change request 4) |
| Reduction % | 84.5% (alerts → possible incidents, "big"; 96.7% before the stricter R2/R3/R4, which had merged unrelated alerts) |
| Processing time | ACP 3–6: 0.15 s for 1,349 alerts; whole analysis 137 s for 7,629 MB (55.8 MB/s) ("big") |
| LLM seconds per explanation | 91 s mean (46–117 s, 5 incidents, `llama3.2:3b`, CPU, 4 threads, ~2,300-token prompt) |
| Verified explanations | 4 / 5 (the fifth flagged correctly: band mismatch; measured before C3 change request 2) |
| Tests passed | 213 / 213 (2026-11-18) |

---

## 9. Limits and likely questions

**Honest limits:**
1. **NetSeer can only see what the capture saw.** In the "realnetwork" test, the vulnerability scan of
   192.168.100.142 never reached the capture point (zero packets to .142), so nothing could detect it. On a
   switch, capture from the mirror port.
2. **Detection quality is Suricata's.** NetSeer ranks and explains; it adds only the port-scan check.
3. **Independence assumption** in the roll-up. Incidents are not truly independent; damping only limits how much
   many incidents can add, it does not model dependence.
4. **Factor values are expert choices**, tuned on UNSW-NB15 and the lab captures, not learned. Because the same data
   was used for tuning and for the reported numbers, they show behaviour, not proof of accuracy on new networks.
5. **Small CPU model:** about 1.5 minutes per explanation, and it can still word things wrongly. The verifier
   catches entity, citation, band and overclaim errors, not every subtle error. "4 of 5 verified" is a small sample;
   the planned evaluation uses about 30 incidents.
6. **Correlation can still group too much or too little**, for example Suricata decoder events (packet-level anomalies, not attacks) between many hosts on one
   signature (17% of "big"'s alerts in one incident).
7. **Inside-LAN rules trade noise for coverage.** With them on, LAN policy traffic (file sharing, chat) raises
   many alerts; with them off, an attacker inside the LAN is seen only through the port-scan check and the rules
   that do not depend on direction.
8. **Real-time mode (C4)** is not built yet.

**Likely examiner questions:**

| Question | Short answer |
|---|---|
| Why not machine learning? | Small sites have no labelled data, and every result must be explainable and traceable. Rules are recorded per incident |
| Why trust a 3B model? | It never decides anything. It explains prepared facts, must cite them, and the verifier checks every entity and the band |
| Why OWASP + Munir and not CVSS alone? | CVSS scores vulnerabilities, not alerts. OWASP gives a transparent likelihood × impact structure; Munir gives the roll-up |
| Why damp the union? | The plain union depends on how many pieces one attack is split into and saturates to 0 health. Damping fixes both (§4.4) |
| What if threat intelligence is off? | L5 is left out of the mean and the other factors decide; this is the default |
| How is an incident traced back? | Incident → alert groups → raw alert IDs → original eve.json record (drawer) |
| Why did the reduction % fall? | The earlier figure came partly from merging unrelated alerts. 85% is after fixing that |
| Privacy? | Everything stays on the LAN box unless the admin adds an external key |

---

## 10. Demo script (about 10 minutes)

1. **Login** as admin. Point out the session countdown and Extend button.
2. **Network:** show the analyses list. Open "big" (UNSW-NB15). Show the capture checks: the 25-minute gap where a
   file is missing. Optionally start a small upload and press **Stop** to show the clean-up.
3. **Home:** health 41 and the incidents that cost the most points; devices at risk.
4. **Alerts:** packets chart, alert mix ("not risk"), tick-box filters (e.g. severity High + Medium), one raw JSON record.
5. **Incidents:** sort by band. Open a Critical one: Attack → Victim, timeline, factor table. Explain one factor
   end to end, e.g. L3 = 5 because R2 fired.
6. **Devices:** change a device's type (e.g. Server → Guest) and show the score and health change at once.
7. **AI:** open a pre-generated explanation (`cli pregen`), show the Verified badge and ref chips, then one that was
   flagged and why.
8. **realnetwork:** show the inside scan as its own recon incident, "Sweep from 192.168.100.139 to 7 hosts"
   (NETSEER Port scan + ET SCAN alerts), then explain why the .142 vulnerability scan is missing (capture
   placement, limit 1). On Devices, show the map: right-drag to pan, clients under their gateway.
9. **Settings:** configuration (windows, half-life) and the security controls; Information page audit log.

**Before the demo:** pre-generate explanations for the top incidents (`python -m netseer.cli pregen <id> --top 5`;
about 1.5 min each); re-analyse older analyses so
they use the current rules; check the screenshots in `docs/screenshots/`.

**Commands:**
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
