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