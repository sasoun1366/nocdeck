"""The desktop window (PyQt6). Optional: everything else works without it.

`pip install PyQt6` is the only extra, and the rest of the tool never imports it —
`nocdeck serve`, `nocdeck watch` and `nocdeck demo` all run on the standard library
alone. This package exists so the same dashboard can also be a window: one engine,
two front doors.
"""

from __future__ import annotations

from typing import Optional, Sequence

__all__ = ["available", "main", "parse_args", "why_not", "TABS"]

#: The tabs the window has, in order — re-exported so `cli.py` can check a `--tab`
#: before it starts Qt at all.
TABS = ("fleet", "device", "events", "alerts", "settings")


def available() -> bool:
    """Is PyQt6 installed *and* able to start? A missing `libEGL` counts as missing."""
    try:
        import PyQt6.QtWidgets  # noqa: F401
    except Exception:                                     # noqa: BLE001
        return False
    return True


def why_not() -> str:
    """The reason, in one line, so `nocdeck desktop` can say something useful."""
    try:
        import PyQt6.QtWidgets  # noqa: F401
    except Exception as exc:                              # noqa: BLE001
        return str(exc)
    return ""


def main(argv: Optional[Sequence[str]] = None) -> int:
    from .desktop import main as run

    return run(argv)


def parse_args(argv: Optional[Sequence[str]] = None):
    from .desktop import parse_args as read

    return read(argv)
