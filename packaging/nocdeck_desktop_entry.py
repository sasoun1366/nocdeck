"""Frozen-build entry point for the desktop window.

The window is optional everywhere else in the tool, which is exactly why it gets its
own executable: a monitoring box with no Qt installed still gets the full command line
and the web dashboard, and a person who wants the window downloads the window.
"""

from nocdeck.desktop import main

if __name__ == "__main__":
    raise SystemExit(main())
