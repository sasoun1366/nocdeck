# PyInstaller spec: the nocdeck command line as a single executable.
#
# Build:  pyinstaller packaging/nocdeck-cli.spec
# Output: dist/nocdeck.exe (Windows) / dist/nocdeck (Linux, macOS)
#
# A console build on purpose: this is the thing you run over ssh, in a cron job, and in
# a terminal at 3 a.m. Qt is excluded entirely, so the download stays small.

import sys
from pathlib import Path

SPEC_DIR = Path(SPECPATH)  # noqa: F821 - injected by PyInstaller
REPO_ROOT = SPEC_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

analysis = Analysis(
    [str(SPEC_DIR / "nocdeck_cli_entry.py")],
    pathex=[str(REPO_ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "PyQt6", "unittest", "pydoc_data", "lib2to3"],
    noarchive=False,
)
pyz = PYZ(analysis.pure)

exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="nocdeck",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
