# PyInstaller spec: the desktop window as a single executable with no console.
#
# Build:  pyinstaller packaging/nocdeck-desktop.spec
# Output: dist/nocdeck-desktop.exe (Windows) / dist/nocdeck-desktop (Linux, macOS)
#
# `console=False` because a monitoring window is double-clicked, not run from a shell.
# The Qt modules a dashboard never imports are excluded: it takes the download from
# ~70 MB to something a person on a hotel wi-fi will actually wait for.

import sys
from pathlib import Path

SPEC_DIR = Path(SPECPATH)  # noqa: F821 - injected by PyInstaller
REPO_ROOT = SPEC_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

analysis = Analysis(
    [str(SPEC_DIR / "nocdeck_desktop_entry.py")],
    pathex=[str(REPO_ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=["nocdeck.desktop.desktop", "nocdeck.desktop.widgets"],
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        "tkinter", "unittest",
        "PyQt6.QtNetwork", "PyQt6.QtQml", "PyQt6.QtQuick", "PyQt6.QtQuickWidgets",
        "PyQt6.QtMultimedia", "PyQt6.QtMultimediaWidgets", "PyQt6.QtWebEngineCore",
        "PyQt6.QtWebEngineWidgets", "PyQt6.QtWebChannel", "PyQt6.QtWebSockets",
        "PyQt6.QtSql", "PyQt6.QtTest", "PyQt6.QtBluetooth", "PyQt6.QtNfc",
        "PyQt6.QtPositioning", "PyQt6.QtSerialPort", "PyQt6.QtSensors",
        "PyQt6.QtCharts", "PyQt6.QtDataVisualization", "PyQt6.QtPdf",
        "PyQt6.QtPdfWidgets", "PyQt6.QtDesigner", "PyQt6.QtHelp", "PyQt6.QtOpenGL",
    ],
    noarchive=False,
)
pyz = PYZ(analysis.pure)

exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="nocdeck-desktop",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,          # no black window behind the dashboard
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
