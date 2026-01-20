<p align="center">
  <img src="https://raw.githubusercontent.com/noc0dev/fastmail-cli/main/assets/mascot.png" alt="Fastmail CLI mascot" width="300">
</p>

<h1 align="center">fastmail-cli</h1>

<p align="center">
  <strong>Read-only email access for AI agents via JMAP.</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/fastmail-cli/"><img src="https://badge.fury.io/py/fastmail-cli.svg" alt="PyPI version"></a>
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
export FASTMAIL_READONLY_API_TOKEN="fmu1-..."  # from Fastmail Settings → Integrations
```

## Usage

```bash
fastmail-cli help                              # list commands
fastmail-cli email.query --limit 5             # recent emails
fastmail-cli email.get --ids '["M123"]'        # get by ID
fastmail-cli mailbox.query                     # list mailboxes
```

All output is JSON with `ok`, `command`, `meta`, and `data`/`error` fields.

## Required Reading

- [Claude Code Email Productivity: MCP Agents](https://harper.blog/2025/12/03/claude-code-email-productivity-mcp-agents/)
- [jmap-mcp](https://github.com/obra/jmap-mcp)

## License

Apache 2.0
