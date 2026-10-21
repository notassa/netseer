# NetSeer — instructions for Claude Code

NetSeer is an AI-assisted alert interpretation layer for small flat networks (FYP2, UniKL). Suricata detects; NetSeer's deterministic Alert-Context Processing (ACP) turns alerts into scored possible incidents; a local LLM (Ollama) explains them; a verifier checks the explanation. No machine learning.

## Read these first, in this order
1. `docs/CONCEPTS.md`: **what** to build. Source of truth for features, risk model (A5), accounts (A12), modes (A13), device types (A14) and settings (A15).
2. `docs/PROTOTYPE-BRIEF.md`: **how** to build it: environment (§3), layout (§4), schema (§5), pipeline (§6), AI (§7), auth (§8), pages (§9), **build steps and checks (§10)**.
3. `docs/RAD-PLAN.md`: **when**: cycles C1–C4 and the schedule.
4. `docs/progress.md`: where we are. Create it in step 0 and keep it current.

`dump.md` holds the owner's raw notes. If it conflicts with CONCEPTS.md, ask.

## How to work
- Build **one brief §10 step at a time**. For each step: implement it, write and run its tests, pass its **Check**, update `docs/progress.md`, commit, push, then summarise what changed. Continue through the steps of the current cycle. **Stop at the end of each cycle (C1–C4)** for the owner's demo and go-ahead.
- **Don't change** the risk constants, database schema, feature list or page set on your own. If something looks wrong, explain why and propose an edit to `docs/CONCEPTS.md` first.
- Prefer small, readable modules matching the paths in CONCEPTS A2. Type hints, docstrings on public functions, no dead code.
- Never commit secrets, API keys, pcaps, eve.json, databases or `.venv`; see `.gitignore`.
- Commit messages: imperative summary line (e.g. `Add offline ingest with mergecap`), optional body, and the Co-Authored-By attribution line your environment specifies.

## sudo: you can't type the password
For anything that needs root (apt installs, `suricata-update`, files under `/etc`, systemd units, sudoers, `ufw`, Ollama install), **don't run it yourself**. Print the exact commands as one block for the owner to run in the VS Code terminal, wait for "done", then verify the result yourself with read-only commands.

## Environment
- Ubuntu Server 24.04, user `netseer`, host 192.168.100.24 (LAN). Repo at `~/FYP2_netseer`.
- Python venv: `~/FYP2_netseer/.venv` (`python3 -m venv .venv && . .venv/bin/activate`).
- App: `uvicorn netseer.src.api.main:app --host 0.0.0.0 --port 8000`, run from the repo root. Never run the app as root.
- Ollama on `localhost:11434`, model `llama3.2:3b`. CPU only (i5-9500T), so expect about a minute per explanation.
- Two NICs: one LAN (dashboard), one for the switch mirror port (real-time, cycle C4). Record their names in `docs/progress.md` during step 0.

## Code conventions
- Package root `netseer/` with the existing skeleton: `src/api`, `src/engine` (new), `src/database` (+ `pcaps/`, `eves/`), `ai`, `web/templates`, `web/static`, `config`, `tests`, `eval` (new), `cli.py` (new). Add `__init__.py` files.
- Rename `ai/llm-caller.py` → `ai/llm_caller.py` and `ai/prompt-maker.py` → `ai/prompt_maker.py`.
- SQLite via the stdlib `sqlite3` (WAL mode). FastAPI + Jinja2 + vanilla JS + Chart.js (vendored, offline). No frontend build step.
- Tests: `pytest netseer/tests`. The scorer must reproduce the CONCEPTS A5.6 worked example exactly (health = 53).

## Hand-back for the report (written on the Windows machine)
- Screenshots go to `docs/screenshots/` with the names in brief §12 (`01-login.png` … `13-network-live.png`).
- Record in `docs/progress.md`: per-cycle status (Completed / In progress / Planned) for report Table 4.12, and demo numbers for Table 4.13 (capture size, raw alerts, groups, incidents, reduction %, processing time, LLM seconds per explanation, verified explanations, tests passed).
