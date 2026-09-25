"""Small painted things: a status dot, a sparkline, a gauge bar, a tile.

Qt gives you tables and trees for free; what it does not give you is a picture of
what the numbers have been doing. These four widgets draw that picture with
QPainter, so the desktop window needs no charting library and no network — the
same reason the web dashboard draws its own SVG.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import QBrush, QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget

#: One palette for both surfaces — the web dashboard's CSS reads from the same names.
INK = "#0d1117"
PANEL = "#161b22"
LINE = "#232b36"
TEXT = "#d7e2ee"
DIM = "#8b9bb0"
UP = "#3ddc84"
DEGRADED = "#ffb648"
DOWN = "#ff5f56"
UNKNOWN = "#5c7186"
BLUE = "#4aa8ff"

STATUS_COLOUR = {"up": UP, "degraded": DEGRADED, "down": DOWN, "unknown": UNKNOWN}


def status_colour(status: str) -> str:
    return STATUS_COLOUR.get(status, UNKNOWN)


class Dot(QWidget):
    """A filled circle whose colour is a state. Slightly wider than it is tall so it
    reads as a bullet next to a name."""

    def __init__(self, status: str = "unknown", size: int = 10, parent=None):
        super().__init__(parent)
        self.status = status
        self.size = size
        self.setFixedSize(size + 4, size)

    def set_status(self, status: str) -> None:
        if status != self.status:
            self.status = status
            self.update()

    def paintEvent(self, _event) -> None:            # noqa: N802 — Qt's spelling
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor(status_colour(self.status))))
        painter.drawEllipse(QRectF(2.0, 0.0, float(self.size), float(self.size)))


class Sparkline(QWidget):
    """A line over time. Threshold lines are drawn in, because a line with no
    horizon tells you nothing."""

    def __init__(self, colour: str = BLUE, height: int = 44, warn: Optional[float] = None,
                 crit: Optional[float] = None, fill: bool = True, parent=None):
        super().__init__(parent)
        self.points: List[float] = []
        self.colour = colour
        self.warn = warn
        self.crit = crit
        self.fill = fill
        self.setMinimumHeight(height)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_points(self, points: Sequence[float]) -> None:
        self.points = [float(value) for value in points if isinstance(value, (int, float))]
        self.update()

    def paintEvent(self, _event) -> None:            # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        area = QRectF(0.5, 0.5, self.width() - 1.0, self.height() - 1.0)
        if not self.points:
            painter.setPen(QPen(QColor(DIM)))
            painter.drawText(area, Qt.AlignmentFlag.AlignCenter, "no history yet")
            return

        low, high = min(self.points), max(self.points)
        for line, colour in ((self.crit, DOWN), (self.warn, DEGRADED)):
            if line is None:
                continue
            low, high = min(low, line), max(high, line)
        span = (high - low) or 1.0
        low -= span * 0.08
        high += span * 0.08
        span = high - low

        def place(index: int) -> QPointF:
            x = area.left() + area.width() * (index / max(1, len(self.points) - 1))
            y = area.bottom() - area.height() * ((self.points[index] - low) / span)
            return QPointF(x, y)

        for line, colour in ((self.crit, DOWN), (self.warn, DEGRADED)):
            if line is None:
                continue
            y = area.bottom() - area.height() * ((line - low) / span)
            pen = QPen(QColor(colour))
            pen.setStyle(Qt.PenStyle.DashLine)
            pen.setWidthF(1.0)
            painter.setPen(pen)
            painter.drawLine(QPointF(area.left(), y), QPointF(area.right(), y))

        path = QPainterPath(place(0))
        for index in range(1, len(self.points)):
            path.lineTo(place(index))
        if self.fill and len(self.points) > 1:
            under = QPainterPath(path)
            under.lineTo(QPointF(area.right(), area.bottom()))
            under.lineTo(QPointF(area.left(), area.bottom()))
            under.closeSubpath()
            gradient = QLinearGradient(0.0, area.top(), 0.0, area.bottom())
            top = QColor(self.colour)
            top.setAlpha(70)
            bottom = QColor(self.colour)
            bottom.setAlpha(0)
            gradient.setColorAt(0.0, top)
            gradient.setColorAt(1.0, bottom)
            painter.fillPath(under, QBrush(gradient))

        pen = QPen(QColor(self.colour))
        pen.setWidthF(1.6)
        painter.setPen(pen)
        painter.drawPath(path)

        newest = self.points[-1]
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor(self.colour)))
        painter.drawEllipse(place(len(self.points) - 1), 2.4, 2.4)
        painter.setPen(QPen(QColor(DIM)))
        painter.setFont(QFont(painter.font().family(), 7))
        painter.drawText(area.adjusted(2.0, 0.0, -2.0, 0.0),
                         Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignRight,
                         ("%.4g" % newest))


class Bar(QFrame):
    """A usage bar with a warning line marked on it — the same gauge the web page
    draws, in a form you can put in a table cell."""

    def __init__(self, warn: float = 70.0, crit: float = 90.0, low_is_bad: bool = False,
                 width: int = 120, parent=None):
        super().__init__(parent)
        self.value: Optional[float] = None
        self.warn = warn
        self.crit = crit
        self.low_is_bad = low_is_bad
        self.setFixedSize(width, 12)

    def set_value(self, value: Optional[float]) -> None:
        self.value = value
        self.setToolTip("%s / warn %g / crit %g" % (
            "—" if value is None else "%.4g" % value, self.warn, self.crit))
        self.update()

    def paintEvent(self, _event) -> None:            # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        track = QRectF(0.5, 2.5, self.width() - 1.0, self.height() - 5.0)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor(LINE)))
        painter.drawRoundedRect(track, 3.0, 3.0)
        if self.value is None:
            return
        ceiling = max(self.crit, self.warn, float(self.value), 1.0)
        fraction = max(0.0, min(1.0, float(self.value) / ceiling))
        if self.low_is_bad:
            colour = DOWN if self.value <= self.crit else (
                DEGRADED if self.value <= self.warn else UP)
        else:
            colour = DOWN if self.value >= self.crit else (
                DEGRADED if self.value >= self.warn else UP)
        filled = QRectF(track.left(), track.top(), max(3.0, track.width() * fraction),
                        track.height())
        painter.setBrush(QBrush(QColor(colour)))
        painter.drawRoundedRect(filled, 3.0, 3.0)


class Tile(QFrame):
    """One number, a label, and a quieter line saying what it means."""

    def __init__(self, label: str, note: str = "", colour: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("tile")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(1)
        self.value = QLabel("—")
        self.value.setObjectName("tileValue")
        if colour:
            self.value.setStyleSheet("color: %s;" % colour)
        self.label = QLabel(label)
        self.label.setObjectName("tileLabel")
        note_label = QLabel(note)
        note_label.setObjectName("tileNote")
        layout.addWidget(self.value)
        layout.addWidget(self.label)
        layout.addWidget(note_label)

    def set_value(self, text: str, colour: str = "") -> None:
        self.value.setText(str(text))
        if colour:
            self.value.setStyleSheet("color: %s;" % colour)


class MetricRow(QWidget):
    """`CPU  [====      ]  42 %` — a label, a bar and a number, on one line."""

    def __init__(self, label: str, warn: float = 70.0, crit: float = 90.0,
                 low_is_bad: bool = False, unit: str = "%", parent=None):
        super().__init__(parent)
        self.unit = unit
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 1, 0, 1)
        row.setSpacing(8)
        self.name = QLabel(label)
        self.name.setMinimumWidth(90)
        self.name.setObjectName("metricName")
        self.bar = Bar(warn=warn, crit=crit, low_is_bad=low_is_bad)
        self.number = QLabel("—")
        self.number.setMinimumWidth(64)
        self.number.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.number.setObjectName("mono")
        row.addWidget(self.name)
        row.addWidget(self.bar, 1)
        row.addWidget(self.number)

    def set_value(self, value: Optional[float]) -> None:
        self.bar.set_value(value)
        if value is None:
            self.number.setText("—")
            return
        text = ("%.2f" % value).rstrip("0").rstrip(".")
        self.number.setText(text + ((" " + self.unit) if self.unit else ""))
        colour = UP
        if self.bar.low_is_bad:
            colour = DOWN if value <= self.bar.crit else (
                DEGRADED if value <= self.bar.warn else UP)
        else:
            colour = DOWN if value >= self.bar.crit else (
                DEGRADED if value >= self.bar.warn else UP)
        self.number.setStyleSheet("color: %s;" % colour)


class Badge(QLabel):
    """A small coloured word: up, degraded, down, unknown."""

    def __init__(self, status: str = "unknown", parent=None):
        super().__init__(parent)
        self.setObjectName("badge")
        self.set_status(status)

    def set_status(self, status: str) -> None:
        self.setText(status)
        colour = status_colour(status)
        self.setStyleSheet("color:%s; border:1px solid %s; border-radius:8px; padding:0 6px;"
                           % (colour, colour))


def formats(values: Dict[str, Optional[float]]) -> Dict[str, str]:
    """Turn raw metric numbers into the strings a person reads."""
    out: Dict[str, str] = {}
    for key, value in values.items():
        if value is None:
            out[key] = "—"
        elif key in ("optical", "optical_dbm"):
            out[key] = "%.1f dBm" % value
        elif key in ("voltage",):
            out[key] = "%.1f V" % value
        elif key in ("power",):
            out[key] = "%.0f W" % value
        elif key in ("fan",):
            out[key] = "%.0f rpm" % value
        elif key == "temperature":
            out[key] = "%.1f °C" % value
        elif key in ("runtime", "runtime_min"):
            out[key] = "%.0f min" % value
        else:
            out[key] = "%.1f" % value
    return out
