# FYP2 Report — Revision Notes

Output: `report/FYP2-Report-revised.docx` and `report/FYP2-Report-revised.pdf` (87 pages).
The original `FYP2-Report.pdf` is unchanged.

## Revision 2: hybrid risk model, real-time scope, dump.md features
- **§2.3.4 and Table 2.8:** added OWASP Risk Rating Methodology and Munir (2014): the 0–9 factors and severity matrix, the probabilistic union across nodes, and a critique of the alert-share metric. Table 2.9 and §2.3.5 now cite NIST/OWASP/Munir for prioritisation. Table 2.15 has a new Munir limitation row.
- **§4.4.6 rewritten:**
  - Table 4.4 Likelihood Factors (L1–L5)
  - Table 4.5 Impact Factors (I1–I3)
  - impact formula I = I3 × (0.5 + 0.5·A/9)
  - Table 4.6 Risk Band Matrix (Note → Critical)
  - score R
  - device risk P(d) and network health from the probabilistic union
  - alert mix as descriptive only
  - Table 4.7 Worked Example (health = 53, the same numbers as `docs/CONCEPTS.md` A5.6)
- **Renumbered:** later Chapter 4 tables are now 4.8–4.13, and the text references were updated.
- **Real-time scope:**
  - §1.6 now lists both modes, and the abstracts mention them
  - FR7 real-time is a Must
  - Iteration 4 is required
  - §4.3 has a real-time paragraph (stall states, privilege-separated capture, tailer, one record per session)
  - Table 4.1 has a new Live module row
- **dump.md features:** first-launch setup, the two-account cap, logout to the login page, network selection, multi-pcap merge, analyses browser with rename, the 7 device types, NetSeer configuration and the white/black theme. These are reflected in Table 3.1 (now FR1–FR21), §4.4.2, the Table 4.9 database, Table 4.10 pages, §4.8 security and Table 4.11 controls.
- **Hardware (Table 3.4):** 16 GB (up to 24 GB) RAM, 256 GB SATA SSD, two Ethernet interfaces. NFR6 matches.
- **Password length:** 15 characters (NFR3, §4.8).
- **Software (Table 3.5):** added mergecap (Wireshark CLI 4.2).
- **Figure 4.1:** the Scorer box now reads "OWASP factors + 3x3 matrix / device/network risk (union)", and the Input box now covers multiple files and the live SPAN port.
- **Two new screenshot placeholders:** Figure 4.11 First-Launch Setup (`12-setup.png`) and Figure 4.12 Real-Time Mode (`13-network-live.png`).
- **Table 4.12 Development Progress:** now has an Iteration column, and every Status cell is a yellow `FILL: status` for you to complete (Completed / In progress / Planned). The old version claimed modules were complete before anything was built.
- **References added:** Munir (2014), Bradford thesis (hdl 10454/14251), and OWASP Foundation (n.d.) OWASP Risk Rating Methodology.

## Before you submit (must do)
1. **Screenshots (Figures 4.2–4.10).** Save them from the prototype into `docs/screenshots/` using the names in `docs/PROTOTYPE-BRIEF.md` §12, then rebuild (commands below). Until then the figures show yellow placeholder boxes.
2. **Table 4.11 (yellow `FILL` cells).** Enter the real numbers from your demo run: alerts, groups, incidents, reduction %, processing time, LLM time, verifier pass count and test pass count. Edit `report/src/04_ch4.txt`, then rebuild.
3. **Table 4.10 (development progress).** It lists the modules the brief scopes as done. Downgrade anything that isn't actually working by tomorrow ("Completed" → "In progress").
4. **Dates.** The cover month is now **OCTOBER 2026**, and both Date lines are blank for signing. Change `MONTH` in `report/tools/build_report.py` if your faculty wants a different month.
5. **Hardware (Table 3.4).** It keeps the report's 16 GB RAM / 512 GB NVMe, but `dump.md` says 256 GB SATA and 16–24 GB. Make it match the real machine. A second NIC (USB adapter) was added for live mode.
6. **Figure 3.2 and Figure 3.3.** These are unchanged from FYP1. Figure 3.2 still shows tshark and p0f; that's fine as the planned design, but redraw it in draw.io if you'd rather it match the prototype. In Figure 3.4, "Flask" was relabelled "FastAPI" on the image.

## Rebuild
```bash
python report/tools/build_report.py
```
```bash
powershell -NoProfile -ExecutionPolicy Bypass -File report/tools/finalize.ps1
```
The first command writes the .docx from `report/src/*.txt`. The second updates the table of contents and the lists of tables and figures in Word, then exports the PDF. Close the report in Word before running it.

## What changed

### Front matter
- Approval page: the text was a copy of the student declaration; it's now a supervisor certification statement. **Check it against the official UniKL template.**
- Abstrak: "Penjanaan Tambahan Pemulihan" was a mistranslation of RAG → "Penjanaan Diperkaya Dapatan Semula (RAG)".
- Abstract and Abstrak each gained a sentence on the verifier and one on prototype progress.
- Abbreviations: CVSS was truncated; added ASVS, ATT&CK, CSRF, DHCP, FTS, LAN, MAC, NIST, OUI, OWASP, RBAC, SPAN, SUS and XAI.

### Chapter 1
- Grammar fixes: "thhe", "a few of reasons", the informal "it gets worse when you add…".
- §1.3: the hallucination claim now has a citation (Alhuzali, 2025).
- §1.6 Scope: added that live mode is an extension and that external services are optional and opt-in.
- §1.7: qualified the privacy claim, since the cloud LLM, VirusTotal and AbuseIPDB are optional.

### Chapter 2
- §2.4.4 *Interpretation Validation* repeated §2.4.3 word for word. It's **rewritten**: validation at detection, explanation and human levels, plus the run-time checks the system adopts.
- §2.3.4 and Table 2.8: added NIST SP 800-30 Rev. 1 as the basis for likelihood × impact.
- §2.4.1: "increase in analyst response time" (which would be bad) → "improved analyst response time".
- §2.2.4: an alert was described as "an email…"; redefined as a notification.
- Table 2.12 note: replaced the self-note "a dedicated source … is still required".
- Tables 2.13 and 2.15 each gained an Alhuzali (2025) row.
- Typos and grammar fixed throughout ("seccurity", "approacches", "he or she", "hybridization" and others).

### Chapter 3
- §3.2: the RAD citation pointed to an IDS review (Abdulganiyu et al.); replaced with Pressman & Maxim (2020).
- §3.3.1: **new** Table 3.1 Functional Requirements and Table 3.2 Non-Functional Requirements, prioritised with MoSCoW, plus the constraints.
- §3.3.2: figure references fixed (the text cited use case = Fig 3.2, but it is 3.5) and each diagram is now described.
- §3.3.3: Flask → FastAPI; construction is now laid out as Iterations 1–4, matching the Gantt chart.
- §3.3.4: added Nginx TLS deployment and an OWASP ASVS hardening review.
- §3.4: **new** Table 3.3 Evaluation Metrics.
- Table 3.5 Software: corrected versions (Nginx 1.24, SQLite 3.45, FastAPI/Uvicorn, Ollama, Chart.js, ATT&CK).
- §3.6: the Gantt chart was referenced as Figure 3.6; it is Figure 3.8.

### Chapter 4 (new, about 16 pages)
Sections 4.1 to 4.10 cover the refined architecture, data acquisition, ACP stages 1–7 (with the schema, correlation rules R1–R4, the risk formula with weights and CVSS bands, device risk and network health), the RAG knowledge base, prompt construction, Ollama integration, the verifier checks, the database, the dashboard pages, security controls mapped to ISO/IEC 27001:2022 Annex A and OWASP ASVS 5.0, and development progress with preliminary results.

### References added (please double-check author lists and DOIs)
ISO/IEC (2022); Lewis (2018); MITRE Corporation (2025); Nelson et al. (2025) NIST SP 800-61r3; NIST (2012) SP 800-30r1; OWASP Foundation (2025); Pressman & Maxim (2020); Temoshok et al. (2025) NIST SP 800-63B-4. Elastic (2024) is now cited in the text.
