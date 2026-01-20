<p align="center">
  <img src="asset/mascot.png" alt="Fastmail JMAP CLI" width="300">
</p>

# Fastmail JMAP CLI

Read-only CLI for agents to access Fastmail via JMAP.

## Setup

```bash
uv sync
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
