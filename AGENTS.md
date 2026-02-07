# AGENTS.md

## Tooling Convention

- Use `uv` directly for Python environment and package tasks; do **not** use `uv pip` or `uv venv`.

## Project Structure

```
src/fastmail_cli/
  __init__.py        # Exports main()
  __main__.py        # python -m fastmail_cli
  cli.py             # Entry point — promotes FASTMAIL_API_TOKEN env var, calls jmapc.main()
  jmapc.py           # All CLI commands, argparse setup, JMAP client logic
```

- **Entry point:** `fastmail-cli <command> [args]` (defined in pyproject.toml `[project.scripts]`)
- **Single runtime dependency:** `jmapc>=0.2.23`

## Running

```bash
uv run fastmail-cli help                         # list commands
uv run fastmail-cli describe email.query         # show command options
uv run fastmail-cli session.get                  # test auth (needs JMAP_API_TOKEN)
```

## Output Format

Every command returns a JSON envelope:

```json
{
  "ok": true,
  "command": "email.query",
  "args": { "host": "...", "api_token": "**REDACTED**", ... },
  "meta": { "timestamp": "...", "account_id": "...", ... },
  "data": { ... }
}
```

On failure, `"data"` is replaced by `"error"`.

## Security

- **Never log or output API tokens.** The `envelope()` function redacts `api_token` from output automatically via `_sanitize_args()`.
- Prefer environment variables (`JMAP_API_TOKEN`, `FASTMAIL_API_TOKEN`) over `--api-token` CLI flag — CLI args are visible in process listings.
- If adding new sensitive fields to connection options, add the key name to `_REDACTED_KEYS` in `jmapc.py`.
- The CLI is read-only by default. `email.draft` / `email.draft-reply` create drafts but never send. `pipeline.run` uses an allowlist of safe JMAP methods.

## Testing

No automated test suite exists yet. Verify changes manually:

```bash
uv run fastmail-cli help
uv run fastmail-cli session.get 2>&1 | python -m json.tool
```
