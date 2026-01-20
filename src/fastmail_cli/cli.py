#!/usr/bin/env python3
"""
fastmail-cli: thin wrapper around jmapc-cli with Fastmail defaults.
"""
import os
import sys

DEFAULT_HOST = "api.fastmail.com"
DEFAULT_TOKEN_ENV = "FASTMAIL_API_TOKEN"
LEGACY_TOKEN_ENV = "FASTMAIL_READONLY_API_TOKEN"


def main(argv=None) -> int:
    # Set default host if not provided
    os.environ.setdefault("JMAP_HOST", DEFAULT_HOST)
    # Promote FASTMAIL_API_TOKEN to JMAP_API_TOKEN if not already set
    # Fall back to legacy FASTMAIL_READONLY_API_TOKEN for backwards compatibility
    if "JMAP_API_TOKEN" not in os.environ:
        if DEFAULT_TOKEN_ENV in os.environ:
            os.environ["JMAP_API_TOKEN"] = os.environ[DEFAULT_TOKEN_ENV]
        elif LEGACY_TOKEN_ENV in os.environ:
            os.environ["JMAP_API_TOKEN"] = os.environ[LEGACY_TOKEN_ENV]
    from .jmapc import main as jmap_main
    return jmap_main(argv)


if __name__ == "__main__":
    sys.exit(main())
