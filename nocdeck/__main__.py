"""`python -m nocdeck …` — the same entry point as the console script."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
