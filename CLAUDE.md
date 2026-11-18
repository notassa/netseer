# NetSeer — instructions for Claude Code

NetSeer is an AI-assisted alert interpretation layer for small flat networks (FYP2, UniKL). Suricata detects; NetSeer's deterministic Alert-Context Processing (ACP) turns alerts into scored possible incidents; a local LLM (Ollama) explains them; a verifier checks the explanation. No machine learning.

## Read these first, in this order
1. `docs/CONCEPTS.md`: **what** to build. Source of truth for features, risk model (A5), accounts (A12), modes (A13), device types (A14) and settings (A15).
2. `docs/PROTOTYPE-BRIEF.md`: **how** to build it: environment (§3), layout (§4), schema (§5), pipeline (§6), AI (§7), auth (§8), pages (§9), **build steps and checks (§10)**.
3. `docs/RAD-PLAN.md`: **when**: cycles C1–C4 and the schedule.
4. `docs/progress.md`: change log only, one line per finished task: `[YYYY-MM-DD] change`, newest first.
   Build record (step Checks) and decisions to confirm: `docs/RAD-PLAN.md`. Report Tables 4.12/4.13 + demo commands: `docs/WRITEUP.md` §8/§10. Environment as built: `docs/PROTOTYPE-BRIEF.md` §3a.
5. `dump.md`: the owner's idea inbox (see below).

## Style: always caveman + ponytail
- At session start, and whenever it applies, use the `caveman:caveman` skill (short, blunt replies, no filler) and the `anthropic-skills:ponytail` skill (smallest complete change, no unrequested extras, end with what was skipped + risks).
- Never cut for brevity: evidence, numbers, risks, safety, anything the owner asked for.
- Worker briefs follow the same rules; workers get them through the Ponytail section of `AGENTS.md`.

## Roles: Claude orchestrates, DeepSeek workers code
- **Claude (orchestrator):** analyse, plan, split work into small tasks, write worker briefs, review every worker diff, run tests, update docs, commit and push. Claude may write code itself only for fixes too small to brief (a few lines) or when a worker failed twice.
- **Workers:** DeepSeek models through opencode, one scoped coding task each. Their rules are in `AGENTS.md`.
- **Call a worker** from the repo root:
  ```bash
  opencode run -m deepseek/deepseek-v4-pro --auto --title "<task>" "<brief>"
  ```
  Use `deepseek/deepseek-flash` for trivial, mechanical edits. Independent tasks may run in parallel only if they touch different files.
- **A brief contains:** goal; exact files to edit (and files to read); the interfaces/functions to use, with paths; constants and numbers copied from the docs (never "as in the docs"); the test to add and the command that must pass; what is out of scope.

## Token economy and loop guard
- Read with grep or line ranges, not whole files; never re-read what is already in context.
- Briefs give exact paths, line ranges and helper names so workers don't explore. `deepseek-flash` for mechanical edits, `deepseek-v4-pro` only for logic.
- While iterating, run only the relevant test files; run the full suite once, before the commit.
- Wait on exit notifications instead of polling; kill a worker that reported but still hangs.
- **Loop guard:** same failure twice → stop and change approach (new hypothesis, smaller step, or do it yourself); third failure → ask the owner.

## Zero hallucination
- No claim without evidence: a `file:line`, command output or test result. If it is not verified, say "unknown" or ask the owner.
- Never report a number (timings, counts, test totals) that was not measured in this session.
- Review every worker change with `git diff`, line by line, before accepting it. Reject and re-brief (or revert) output that invents APIs, files, settings, constants or results, edits files outside the brief, or changes tests to make them pass.
- Run `pytest netseer/tests` after every accepted change; a task is not done while any test fails.
- Check library usage against the installed version (`.venv`), not memory.

## dump.md: idea inbox
- The owner writes new ideas under `## Inbox`.
- Whenever Claude reads it: compare each idea with the related parts of `docs/` (CONCEPTS, PROTOTYPE-BRIEF, RAD-PLAN incl. its decisions to confirm, WRITEUP) and give the owner a review per idea: **new / conflicts with <doc §> / duplicate of <doc §> / already done (<commit or progress line>)**, the docs it would change, risks, and a recommendation.
- Execute only after the owner's go-ahead. Then move the idea to `## Reviewed` as `[YYYY-MM-DD] idea → verdict → commit`.
- If an idea conflicts with CONCEPTS.md, CONCEPTS.md wins until the owner decides.

## How to work
- Build **one brief §10 step (or one change request) at a time**: plan → brief workers → review → tests pass → pass its **Check**. Stop at the end of each cycle (C1–C4) for the owner's demo and go-ahead.
- **After every finished task:** update the related `docs/` files (CONCEPTS/BRIEF when behaviour or spec changed, WRITEUP when the explanation changed, RAD-PLAN Build record/decisions and WRITEUP §8 numbers as needed, progress.md always: one change-log line), then commit and `git push origin main` (https://github.com/notassa/netseer), then summarise what changed.
- **Don't change** the risk constants, database schema, feature list or page set on your own. If something looks wrong, explain why and propose an edit to `docs/CONCEPTS.md` first.
- Prefer small, readable modules matching the paths in CONCEPTS A2. Type hints, docstrings on public functions, no dead code.
- Never commit secrets, API keys, pcaps, eve.json, databases or `.venv`; see `.gitignore`.
- Commit messages: imperative summary line (e.g. `Add offline ingest with mergecap`), optional body, and the Co-Authored-By attribution line your environment specifies.

## sudo: you can't type the password
For anything that needs root (apt installs, `suricata-update`, files under `/etc`, systemd units, sudoers, `ufw`, Ollama install), **don't run it yourself** and never let a worker do it. Print the exact commands as one block for the owner to run in the VS Code terminal, wait for "done", then verify the result yourself with read-only commands.

## Environment
- Ubuntu Server 24.04, user `netseer`, host 192.168.100.24 (LAN). Repo at `~/FYP2_netseer`.
- Python venv: `~/FYP2_netseer/.venv` (`. .venv/bin/activate`).
- App: `uvicorn netseer.src.api.main:app --host 0.0.0.0 --port 8000`, run from the repo root. Never run the app as root.
- Ollama on `localhost:11434`, model `llama3.2:3b`. CPU only (i5-9600T), about 1.5 min per explanation.
- NICs: `eno1` = LAN, `enxec1ac300527e` = switch mirror port (see `docs/PROTOTYPE-BRIEF.md` §3a).
- opencode v2.3.2 (`~/.opencode/bin/opencode`), DeepSeek credentials stored.

## Code conventions
- Package root `netseer/`: `src/api`, `src/engine`, `src/database` (+ `pcaps/`, `eves/`), `ai`, `web/templates`, `web/static`, `config`, `tests`, `eval`, `cli.py`.
- SQLite via the stdlib `sqlite3` (WAL mode). FastAPI + Jinja2 + vanilla JS + Chart.js (vendored, offline). No frontend build step.
- Tests: `pytest netseer/tests`. The scorer must reproduce the CONCEPTS A5.6 worked example exactly (health = 47).

## Hand-back for the report (written on the Windows machine)
- Screenshots go to `docs/screenshots/` with the names in brief §12 (`01-login.png` … `13-network-live.png`).
- Record in `docs/WRITEUP.md` §8: per-cycle status (Completed / In progress / Planned) for report Table 4.12, and demo numbers for Table 4.13 (capture size, raw alerts, groups, incidents, reduction %, processing time, LLM seconds per explanation, verified explanations, tests passed).
