"""Frozen-build entry point for the desktop window.

The window is optional everywhere else in the tool, which is exactly why it gets its
own executable: a monitoring box with no Qt installed still gets the full command line
and the web dashboard, and a person who wants the window downloads the window.
"""

import sys

from nocdeck.desktop import main

if __name__ == "__main__":
    # `sys.argv[1:]`, not nothing: a frozen window that ignores its own flags opens a
    # blank window and waits at an event loop instead of doing what it was asked —
    # which is exactly what the release smoke test is looking for.
    raise SystemExit(main(sys.argv[1:]))
