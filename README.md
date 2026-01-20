<p align="center">
  <img src="asset/mascot.png" alt="Fastmail CLI mascot" width="300">
</p>

# Fastmail CLI

[![PyPI version](https://badge.fury.io/py/fastmail-cli.svg)](https://pypi.org/project/fastmail-cli/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Read-only CLI for agents to access Fastmail via JMAP.

## Installation

```bash
uv add fastmail-cli
# or
pip install fastmail-cli
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

## License

Apache 2.0
