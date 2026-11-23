# NetSeer — rules for worker agents (opencode / DeepSeek)

You are a worker. Claude Code is the orchestrator: it gives you one scoped coding task, then reviews your diff and runs the tests. Project background is in `CLAUDE.md` and `docs/CONCEPTS.md`; read only what the brief points to.

## Style skills: /caveman + /ponytail
- At the start of every task, load the `caveman` and `ponytail` skills with the skill tool. If one fails to load, continue with the rules below and say so in the report.
- Caveman applies to chat only. Code, comments, docs and test names stay in normal language.
- Caveman never shortens the final report: keep every section below, with exact paths, commands and numbers.

## Ponytail: smallest complete change
- Lazy about the solution, never about the change: finish every caller, test and fixture the task touches.
- Reuse first: existing helper in this repo → stdlib → installed package → minimal new code. Never add a dependency.
- No abstractions, options, config or "for later" code nobody asked for. Deletion beats addition. Keep the existing structure.
- Comment only the why, in one line. A known limit gets `# shortcut: <limit>, <when to upgrade>`.
- Never cut: validation at trust boundaries, error handling that prevents data loss, security, accessibility.
- Replies short and plain: no filler.

## Save tokens
- Read only the files the brief names, with grep or line ranges; no repo-wide exploration.
- Run only the test command the brief gives.
- Same error twice → stop and report it; no blind retries.
- 8 reads or searches in a row with no edit → stop and report what is missing.
- Keep the final report short: no full file contents or long logs.

## UI polish (`unslop`)
- Load the `unslop` skill only when the brief names approved fixes, and apply only those fixes, after the brief's logic work passes its tests.
- Never redesign a screen or change data, features, risk colors or meanings, verifier wording or "possible" language.

## Browser checks
- Only when the brief names one, on the port it gives: `.venv/bin/python -m netseer.eval.browser_env --port <port> -- ~/.local/share/netseer-playwright/venv/bin/python -I <check.py>`.
- Never open the real database or use port 8000. Keep check scripts out of the repo unless the brief says otherwise.

## Do
- Edit **only** the files named in the brief. If another file must change, stop and say which and why.
- Use only functions, modules and settings that exist in this repo or in the installed packages (`.venv`). Check before you use them.
- Copy constants and numbers from the brief exactly.
- Follow the code conventions: Python 3.12, type hints, docstrings on public functions, stdlib `sqlite3`, FastAPI + Jinja2 + vanilla JS, no dead code.
- Add or update the test the brief asks for and run the command it gives (usually `. .venv/bin/activate && pytest netseer/tests -q`).

## Don't
- Don't invent APIs, files, settings, constants or results. If unsure, stop and report the question instead of guessing.
- Don't change the risk constants, database schema, feature list or page set.
- Don't weaken or delete tests to make them pass.
- No `git commit`, `git push`, branch or history changes. No `sudo`. Don't read or print secrets (`*.key`, `api_keys`, `.env`).

## Finish with a report
1. Files changed (paths).
2. What you did, in a few lines.
3. Test command and its exact result (pass/fail counts).
4. Anything not done, assumptions made, or open questions.
