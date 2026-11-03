# Kickoff prompts for Claude Code on the server

Open `~/FYP2_netseer` in VS Code (Remote-SSH), start Claude Code, and paste one of these.

## First session
```
You are building NetSeer on this Ubuntu server. CLAUDE.md has the rules; read docs/CONCEPTS.md, docs/PROTOTYPE-BRIEF.md and docs/RAD-PLAN.md before doing anything.

Step 0 — environment audit (read-only):
- Report: Ubuntu version, CPU, RAM, free disk, network interfaces (ip -br link, ip -br addr), and which of these exist: suricata (version), suricata rules at /var/lib/suricata/rules/suricata.rules, mergecap, jq, ethtool, ieee-data OUI file, python3-venv, ollama (service + whether llama3.2:3b is pulled).
- Give me ONE block of sudo commands for whatever is missing (per PROTOTYPE-BRIEF §3). Don't run sudo yourself.
- After I say "done", re-check everything, create .venv and install the Python packages from §3, measure Ollama speed with one short prompt (tokens/s), then create docs/progress.md with: the environment summary, which NIC is LAN and which is free for the mirror port, the Ollama speed, and a C1–C4 status table.

Then start cycle C1, step 1 of PROTOTYPE-BRIEF §10. Work step by step through C1 as CLAUDE.md describes (implement → test → pass the Check → update progress.md → commit → push) and stop at the end of C1 for my demo.
```

## Later sessions
```
Continue NetSeer. Read CLAUDE.md and docs/progress.md, then carry on from the next unfinished step in PROTOTYPE-BRIEF §10. Stop at the end of the current cycle for my demo.
```

## Useful one-liners
- After a cycle demo: `Cycle C1 approved. Start C2.`
- If you want a change: `Change request: <what>. Update docs/CONCEPTS.md first, show me the diff, then implement.`
- For report material: `Take the screenshots for the finished pages per brief §12 and update the Table 4.12/4.13 data in docs/progress.md.`
