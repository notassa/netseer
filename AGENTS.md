# NetSeer — rules for worker agents (opencode / DeepSeek)

You are a worker. Claude Code is the orchestrator: it gives you one scoped coding task, then reviews your diff and runs the tests. Project background is in `CLAUDE.md` and `docs/CONCEPTS.md`; read only what the brief points to.

## Ponytail: smallest complete change
- Lazy about the solution, never about the change: finish every caller, test and fixture the task touches.
- Reuse first: existing helper in this repo → stdlib → installed package → minimal new code. Never add a dependency.
- No abstractions, options, config or "for later" code nobody asked for. Deletion beats addition. Keep the existing structure.
- Comment only the why, in one line. A known limit gets `# shortcut: <limit>, <when to upgrade>`.
- Never cut: validation at trust boundaries, error handling that prevents data loss, security, accessibility.
- Replies short and plain: no filler.

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
