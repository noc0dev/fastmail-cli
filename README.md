<p align="center">
  <img src="https://raw.githubusercontent.com/noc0dev/fastmail-cli/main/assets/mascot.png" alt="Fastmail CLI mascot" width="300">
</p>

<h1 align="center">fastmail-cli</h1>

<p align="center">
  <strong>Read-only email access for AI agents via JMAP, and draft responses.</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/fastmail-cli/"><img src="https://img.shields.io/pypi/v/fastmail-cli" alt="PyPI version"></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
</p>

---

## Demo

<p align="left">
  <img src="https://raw.githubusercontent.com/noc0dev/fastmail-cli/main/assets/demo.gif" alt="Demo">
</p>

---

## Installation

```bash
uv add fastmail-cli
```

Or run without installing:

```bash
uvx fastmail-cli help
```

## Setup

```bash
export FASTMAIL_API_TOKEN="fmu1-..."  # from Fastmail Settings → Integrations
```

## Usage

```bash
# Read
fastmail-cli email.query --limit 5                    # recent emails
fastmail-cli email.query --filter '{"from":"alice"}'  # search
fastmail-cli email.get --ids '["M123"]'               # full email by ID
fastmail-cli mailbox.query                            # list mailboxes
fastmail-cli thread.get --ids '["T456"]'              # get thread

# Draft (safe for AI agents - human reviews before sending)
fastmail-cli email.draft --to "bob@x.com" --subject "Hi" --body "..."
fastmail-cli email.draft-reply --id "M123" --body "Thanks!"
fastmail-cli email.draft-reply --id "M123" --body @reply.txt --reply-all

# Advanced
fastmail-cli email.changes --since-state "abc123"     # poll for changes
fastmail-cli searchsnippet.get --email-ids '["M1"]' --filter '{"text":"foo"}'
fastmail-cli describe email.query                     # show command options
```

All output is JSON with `ok`, `command`, `meta`, and `data`/`error` fields.

## Required Reading

- [Getting Claude Code to do my emails](https://harper.blog/2025/12/03/claude-code-email-productivity-mcp-agents/)
- [jmap-mcp](https://github.com/obra/jmap-mcp)

## License

Apache 2.0
