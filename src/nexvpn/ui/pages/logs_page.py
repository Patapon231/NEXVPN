"""Logs viewer screen with live streaming, level filter, search, and safe copy."""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QClipboard, QFont, QGuiApplication
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from nexvpn.ui.i18n import tr
from nexvpn.utils.logger import InMemoryLogHandler, LogEntry


class _LogBridge(QObject):
    """Thread-safe Qt signal bridge from background logging threads to GUI thread."""

    entry_received = Signal(object)


class LogsPage(QWidget):
    """Real-time diagnostic log viewer with level filtering and clipboard export."""

    def __init__(
        self,
        log_handler: InMemoryLogHandler,
        lang: str = "ru",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._handler = log_handler
        self._lang = lang
        self._bridge = _LogBridge(self)
        self._bridge.entry_received.connect(self._on_new_entry)

        self._build_ui()
        self._handler.add_listener(self._bridge.entry_received.emit)
        self.refresh_logs()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(14)

        header = QHBoxLayout()
        self.title_lbl = QLabel(tr("logs.title", self._lang))
        self.title_lbl.setObjectName("PageTitle")
        header.addWidget(self.title_lbl)
        header.addStretch(1)

        self.level_combo = QComboBox()
        self.level_combo.addItem("Все уровни", "ALL")
        self.level_combo.addItem("INFO", "INFO")
        self.level_combo.addItem("WARNING", "WARNING")
        self.level_combo.addItem("ERROR", "ERROR")
        self.level_combo.currentIndexChanged.connect(self.refresh_logs)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Фильтр по тексту...")
        self.search_edit.setMinimumWidth(210)
        self.search_edit.textChanged.connect(self.refresh_logs)

        self.copy_btn = QPushButton(tr("logs.copy", self._lang))
        self.copy_btn.clicked.connect(self._copy_logs)

        self.clear_btn = QPushButton(tr("logs.clear", self._lang))
        self.clear_btn.clicked.connect(self._clear_logs)

        header.addWidget(self.level_combo)
        header.addWidget(self.search_edit)
        header.addWidget(self.copy_btn)
        header.addWidget(self.clear_btn)
        root.addLayout(header)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        mono = QFont("Consolas", 10)
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self.log_view.setFont(mono)
        self.log_view.setMaximumBlockCount(2000)
        root.addWidget(self.log_view, stretch=1)

    def _matches_current_filter(self, entry: LogEntry) -> bool:
        lvl = str(self.level_combo.currentData() or "ALL")
        if lvl != "ALL" and entry.level != lvl:
            return False
        q = self.search_edit.text().strip().lower()
        if q and q not in entry.message.lower() and q not in entry.source.lower():
            return False
        return True

    def _on_new_entry(self, entry: object) -> None:
        if isinstance(entry, LogEntry) and self._matches_current_filter(entry):
            self.log_view.appendPlainText(entry.format_line())

    def refresh_logs(self) -> None:
        lvl = str(self.level_combo.currentData() or "ALL")
        q = self.search_edit.text().strip()
        entries = self._handler.get_entries(level_filter=lvl, search_query=q)
        self.log_view.setPlainText("\n".join(e.format_line() for e in entries))
        scrollbar = self.log_view.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def _copy_logs(self) -> None:
        clipboard: QClipboard = QGuiApplication.clipboard()
        clipboard.setText(self.log_view.toPlainText())

    def _clear_logs(self) -> None:
        self._handler.clear()
        self.log_view.clear()

    def set_language(self, lang: str) -> None:
        self._lang = lang
        self.title_lbl.setText(tr("logs.title", lang))
        self.copy_btn.setText(tr("logs.copy", lang))
        self.clear_btn.setText(tr("logs.clear", lang))

    def detach_listener(self) -> None:
        self._handler.remove_listener(self._bridge.entry_received.emit)
