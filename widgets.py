"""Reusable UI widgets."""

from __future__ import annotations

from PySide6.QtCore import Qt, QSize
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from database import Email


class Card(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(16, 16, 16, 16)
        self._layout.setSpacing(10)

    def add_widget(self, widget: QWidget) -> None:
        self._layout.addWidget(widget)

    def add_layout(self, layout) -> None:
        self._layout.addLayout(layout)


class StatCard(QFrame):
    def __init__(
        self,
        title: str,
        value: str = "0",
        compact: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("statCard")
        layout = QVBoxLayout(self)
        if compact:
            layout.setContentsMargins(10, 6, 10, 6)
            layout.setSpacing(2)
            self.setMinimumWidth(88)
        else:
            layout.setContentsMargins(14, 12, 14, 12)
            layout.setSpacing(6)
        self._title = QLabel(title)
        self._title.setObjectName("statTitle")
        self._value = QLabel(value)
        self._value.setObjectName("statValue")
        layout.addWidget(self._title)
        layout.addWidget(self._value)

    def set_value(self, value: str) -> None:
        self._value.setText(value)


class VerdictBadge(QLabel):
    BASE_STYLE = (
        "font-size: 22px; font-weight: 800; letter-spacing: 2px; "
        "border-radius: 10px; padding: 12px;"
    )

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setMinimumHeight(56)
        self._verdict: str | None = None
        self._dark = False
        self.set_verdict(None)

    def set_dark_mode(self, dark: bool) -> None:
        self._dark = dark
        self.set_verdict(self._verdict)

    def set_verdict(self, verdict: str | None) -> None:
        self._verdict = verdict
        if verdict is None:
            self.setText("NOT ANALYZED")
            if self._dark:
                bg, fg, border = "#374151", "#9ca3af", "#4b5563"
            else:
                bg, fg, border = "#f1f5f9", "#64748b", "#e2e8f0"
            self.setStyleSheet(
                f"{self.BASE_STYLE} background: {bg}; color: {fg}; border: 1px solid {border};"
            )
        elif verdict.lower() == "phishing":
            self.setText("PHISHING")
            if self._dark:
                bg, fg, border = "#7f1d1d", "#fca5a5", "#991b1b"
            else:
                bg, fg, border = "#fee2e2", "#dc2626", "#fecaca"
            self.setStyleSheet(
                f"{self.BASE_STYLE} background: {bg}; color: {fg}; border: 1px solid {border};"
            )
        elif verdict.lower() == "legitimate":
            self.setText("LEGITIMATE")
            if self._dark:
                bg, fg, border = "#14532d", "#86efac", "#166534"
            else:
                bg, fg, border = "#dcfce7", "#16a34a", "#bbf7d0"
            self.setStyleSheet(
                f"{self.BASE_STYLE} background: {bg}; color: {fg}; border: 1px solid {border};"
            )
        else:
            self.setText(verdict.upper())
            if self._dark:
                bg, fg, border = "#78350f", "#fcd34d", "#92400e"
            else:
                bg, fg, border = "#fef3c7", "#d97706", "#fde68a"
            self.setStyleSheet(
                f"{self.BASE_STYLE} background: {bg}; color: {fg}; border: 1px solid {border};"
            )


class ConfidenceBar(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._label = QLabel("Confidence: —")
        self._label.setStyleSheet("font-weight: 600;")
        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setTextVisible(True)
        self._bar.setFormat("%p%")
        layout.addWidget(self._label)
        layout.addWidget(self._bar)

    def set_confidence(self, score: float | None, verdict: str | None = None) -> None:
        if score is None:
            self._label.setText("Confidence: —")
            self._bar.setValue(0)
            return
        pct = int(round(score * 100))
        label = verdict or "Confidence"
        self._label.setText(f"{label}: {pct}%")
        self._bar.setValue(pct)


class AgentCard(QFrame):
    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("agentCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        # Header Row: Title + small Verdict badge
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        self._title_label = QLabel(title)
        self._title_label.setObjectName("agentTitle")

        self._verdict_badge = QLabel("—")
        self._verdict_badge.setObjectName("agentVerdict")
        self._verdict_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        header_layout.addWidget(self._title_label)
        header_layout.addStretch()
        header_layout.addWidget(self._verdict_badge)
        layout.addLayout(header_layout)

        # Content fields
        self._confidence = QLabel("Confidence: —")
        self._confidence.setObjectName("agentConfidence")

        self._reason = QLabel("—")
        self._reason.setWordWrap(True)
        self._reason.setObjectName("agentReason")

        layout.addWidget(self._confidence)
        layout.addWidget(self._reason)

    def set_data(self, verdict: str | None, confidence: float | None, reason: str | None) -> None:
        if not verdict:
            self._verdict_badge.setText("PENDING")
            self._verdict_badge.setProperty("verdict", "unknown")
            self._confidence.setText("Confidence: —")
        else:
            self._verdict_badge.setText(verdict.upper())
            self._verdict_badge.setProperty("verdict", verdict.lower())
            if confidence is not None:
                self._confidence.setText(f"Confidence: {confidence:.0%}")
            else:
                self._confidence.setText("Confidence: —")
        self._reason.setText(reason or "—")
        self._verdict_badge.style().unpolish(self._verdict_badge)
        self._verdict_badge.style().polish(self._verdict_badge)


def status_color(email: Email) -> str:
    if not email.is_analyzed:
        return "#94a3b8"
    if email.final_verdict and email.final_verdict.lower() == "phishing":
        return "#dc2626"
    if email.final_verdict and email.final_verdict.lower() == "legitimate":
        return "#16a34a"
    return "#d97706"


def status_text(email: Email) -> str:
    if not email.is_analyzed:
        return "Not analyzed"
    return email.final_verdict or "Unknown"


class EmailListItem(QWidget):
    ITEM_HEIGHT = 92
    ITEM_HEIGHT_WITH_PROGRESS = 112

    def __init__(self, email: Email, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.email_id = email.id
        self._email_index = email.email_index
        self._status_text = status_text(email)
        self._showing_progress = False
        self.setMinimumHeight(self.ITEM_HEIGHT)
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed,
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(6)

        row = QHBoxLayout()
        row.setSpacing(10)

        dot = QLabel("●")
        self._dot = dot
        dot.setStyleSheet(f"color: {status_color(email)}; font-size: 15px;")
        dot.setFixedWidth(18)
        dot.setAlignment(Qt.AlignmentFlag.AlignTop)

        info = QVBoxLayout()
        info.setSpacing(4)
        subject = QLabel(email.subject)
        subject.setObjectName("emailSubject")
        subject.setWordWrap(True)
        subject.setMinimumHeight(30)

        sender = QLabel("From: " + (email.metadata.splitlines()[0] if email.metadata else "Unknown sender"))
        sender.setObjectName("emailSender")
        sender.setWordWrap(True)

        self._meta = QLabel(f"#{email.email_index}  ·  {self._status_text}")
        self._meta.setObjectName("emailMeta")
        self._meta.setMinimumHeight(18)
        info.addWidget(subject)
        info.addWidget(sender)
        info.addWidget(self._meta)

        row.addWidget(dot)
        row.addLayout(info, 1)
        layout.addLayout(row)

        self._progress = QProgressBar()
        self._progress.setVisible(False)
        self._progress.setTextVisible(True)
        self._progress.setMaximumHeight(8)
        self._progress.setObjectName("analysisProgress")
        layout.addWidget(self._progress)

    def update_status(self, email: Email) -> None:
        self._status_text = status_text(email)
        if not self._showing_progress:
            self._meta.setText(f"#{self._email_index}  ·  {self._status_text}")
        self._dot.setStyleSheet(f"color: {status_color(email)}; font-size: 15px;")

    def set_analysis_state(self, state: str | None) -> None:
        showing = state is not None
        if showing:
            self._progress.setVisible(True)
            self._progress.setRange(0, 0)
            if state == "analyzing":
                self._progress.setFormat("Analyzing…")
                self._meta.setText(f"#{self._email_index}  ·  Analyzing…")
            else:
                self._progress.setFormat("Queued…")
                self._meta.setText(f"#{self._email_index}  ·  Queued…")
        else:
            self._progress.setVisible(False)
            self._meta.setText(f"#{self._email_index}  ·  {self._status_text}")

        if showing != self._showing_progress:
            self._showing_progress = showing
            self.setMinimumHeight(
                self.ITEM_HEIGHT_WITH_PROGRESS if showing else self.ITEM_HEIGHT
            )
            self.updateGeometry()

    def sizeHint(self) -> QSize:
        height = self.ITEM_HEIGHT_WITH_PROGRESS if self._showing_progress else self.ITEM_HEIGHT
        return QSize(0, height)

    def minimumSizeHint(self) -> QSize:
        return self.sizeHint()
