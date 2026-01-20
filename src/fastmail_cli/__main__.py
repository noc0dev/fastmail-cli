"""Enable running as: python -m fastmail_cli"""

from .cli import main
import sys

if __name__ == "__main__":
    sys.exit(main())
