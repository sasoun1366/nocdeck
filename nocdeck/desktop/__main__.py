"""`python -m nocdeck.desktop` — the same window, without the executable."""

import sys

from . import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
