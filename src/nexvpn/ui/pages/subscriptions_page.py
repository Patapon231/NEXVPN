"""Full Subscriptions screen with non-blocking network updates, file import, rename, auto-update, and delete."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from nexvpn.database.repository import DatabaseRepository
from nexvpn.subscription.manager import SubscriptionError, SubscriptionManager
from nexvpn.subscription.models import SubscriptionRecord
from nexvpn.ui.i18n import tr
from nexvpn.ui.theme import Palette
from nexvpn.ui.widgets.cards import CardFrame


class _SubWorker(QThread):
    """Background worker executing remote subscription network operations off the GUI thread."""

    finished_ok = Signal(str, list)
    failed = Signal(str)

    def __init__(
        self,
        manager: SubscriptionManager,
        action: str,
        url: str = "",
        name: str = "",
        auto_update: bool = True,
        interval_min: int = 360,
        sub_id: int | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.manager = manager
        self.action = action
        self.url = url
        self.name = name
        self.auto_update = auto_update
        self.interval_min = interval_min
        self.sub_id = sub_id

    def run(self) -> None:
        try:
            if self.action == "add_url":
                sub, warnings = self.manager.add_subscription_from_url(
                    url=self.url,
                    name=self.name,
                    auto_update=self.auto_update,
                    update_interval_min=self.interval_min,
                )
                self.finished_ok.emit(
                    f"Подписка «{sub.name}» добавлена ({sub.server_count} серверов).",
                    warnings,
                )
            elif self.action == "refresh_one" and self.sub_id is not None:
                sub, warnings = self.manager.refresh_subscription(self.sub_id)
                self.finished_ok.emit(
                    f"Подписка «{sub.name}» обновлена ({sub.server_count} серверов).",
                    warnings,
                )
            elif self.action == "refresh_all":
                subs = [s for s in self.manager.repo.list_subscriptions() if s.source_type == "url"]
                if not subs:
                    self.finished_ok.emit("Нет URL-подписок для обновления.", [])
                    return
                ok_cnt = 0
                errs: list[str] = []
                for s in subs:
                    try:
                        self.manager.refresh_subscription(s.id)
                        ok_cnt += 1
                    except SubscriptionError as exc:
                        errs.append(f"{s.name}: {exc}")
                msg = f"Обновлено подписок: {ok_cnt} из {len(subs)}."
                self.finished_ok.emit(msg, errs)
        except SubscriptionError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:
            self.failed.emit(f"Непредвиденная ошибка: {exc}")


class _AddSubscriptionDialog(QDialog):
    """Modal dialog for adding a subscription URL with optional name and auto-update interval."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Добавить подписку по URL")
        self.setMinimumWidth(460)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(14)

        form = QFormLayout()
        form.setSpacing(12)

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Необязательно (определится автоматически)")

        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://...")

        self.auto_chk = QCheckBox("Автоматически обновлять подписку")
        self.auto_chk.setChecked(True)

        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(15, 10080)
        self.interval_spin.setSingleStep(30)
        self.interval_spin.setValue(360)
        self.interval_spin.setSuffix(" мин")

        form.addRow("Название:", self.name_edit)
        form.addRow("HTTPS URL:", self.url_edit)
        form.addRow("", self.auto_chk)
        form.addRow("Интервал:", self.interval_spin)
        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


def _format_masked_source(sub: SubscriptionRecord) -> str:
    if sub.source_type == "file" or not sub.url:
        return "Локальный файл"
    parts = urlsplit(sub.url)
    host = parts.hostname or "remote"
    return f"{parts.scheme}://{host}/•••"


def _format_timestamp(iso_str: str | None) -> str:
    if not iso_str:
        return "Никогда"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00")).astimezone()
        return dt.strftime("%d.%m.%Y %H:%M")
    except ValueError:
        return iso_str


class SubscriptionsPage(QWidget):
    """Full subscription management view."""

    subscriptions_changed = Signal()

    def __init__(
        self,
        repo: DatabaseRepository | None = None,
        manager: SubscriptionManager | None = None,
        lang: str = "ru",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._repo = repo
        self._manager = manager
        self._lang = lang
        self._worker: _SubWorker | None = None

        self._build_ui()
        self.reload_subscriptions()

    def bind_services(self, repo: DatabaseRepository, manager: SubscriptionManager) -> None:
        self._repo = repo
        self._manager = manager
        self.reload_subscriptions()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)

        header = QHBoxLayout()
        self.title_lbl = QLabel(tr("subs.title", self._lang))
        self.title_lbl.setObjectName("PageTitle")
        header.addWidget(self.title_lbl)
        header.addStretch(1)

        self.add_url_btn = QPushButton(tr("subs.add_url", self._lang))
        self.add_url_btn.setObjectName("PrimaryButton")
        self.add_url_btn.clicked.connect(self._on_add_url_clicked)

        self.import_file_btn = QPushButton(tr("subs.import_file", self._lang))
        self.import_file_btn.clicked.connect(self._on_import_file_clicked)

        self.update_all_btn = QPushButton(tr("subs.update_all", self._lang))
        self.update_all_btn.clicked.connect(self._on_update_all_clicked)

        header.addWidget(self.add_url_btn)
        header.addWidget(self.import_file_btn)
        header.addWidget(self.update_all_btn)
        root.addLayout(header)

        self.status_lbl = QLabel("")
        self.status_lbl.setObjectName("MutedLabel")
        self.status_lbl.hide()
        root.addWidget(self.status_lbl)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.list_container = QWidget()
        self.list_layout = QVBoxLayout(self.list_container)
        self.list_layout.setContentsMargins(0, 0, 4, 0)
        self.list_layout.setSpacing(10)
        self.scroll.setWidget(self.list_container)
        root.addWidget(self.scroll, stretch=1)

    def _set_busy(self, busy: bool, status_text: str = "") -> None:
        self.add_url_btn.setEnabled(not busy)
        self.import_file_btn.setEnabled(not busy)
        self.update_all_btn.setEnabled(not busy)
        if status_text:
            self.status_lbl.setText(status_text)
            self.status_lbl.setStyleSheet(f"color: {Palette.ACCENT}; font-size: 12px;")
            self.status_lbl.show()
        elif not busy:
            self.status_lbl.hide()

    def reload_subscriptions(self) -> None:
        while self.list_layout.count():
            item = self.list_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

        if self._repo is None:
            return

        subs = self._repo.list_subscriptions()
        if not subs:
            empty_card = CardFrame()
            el = QVBoxLayout(empty_card)
            el.setContentsMargins(22, 22, 22, 22)
            lbl = QLabel(
                "Подписки ещё не добавлены. Нажмите «Добавить по URL» или «Импорт из файла»."
            )
            lbl.setObjectName("MutedLabel")
            el.addWidget(lbl)
            self.list_layout.addWidget(empty_card)
            self.list_layout.addStretch(1)
            return

        for sub in subs:
            self.list_layout.addWidget(self._create_sub_card(sub))
        self.list_layout.addStretch(1)

    def _create_sub_card(self, sub: SubscriptionRecord) -> QWidget:
        card = CardFrame()
        row = QHBoxLayout(card)
        row.setContentsMargins(18, 14, 18, 14)
        row.setSpacing(14)

        info_col = QVBoxLayout()
        info_col.setSpacing(4)

        name_lbl = QLabel(sub.name)
        name_lbl.setObjectName("SectionTitle")

        meta_str = (
            f"{_format_masked_source(sub)}   •   "
            f"Серверов: {sub.server_count}   •   "
            f"Обновлено: {_format_timestamp(sub.last_updated_at)}"
        )
        meta_lbl = QLabel(meta_str)
        meta_lbl.setObjectName("MutedLabel")

        info_col.addWidget(name_lbl)
        info_col.addWidget(meta_lbl)
        row.addLayout(info_col, stretch=1)

        if sub.source_type == "url":
            auto_chk = QCheckBox(f"Авто ({sub.update_interval_min}м)")
            auto_chk.setChecked(sub.auto_update)
            auto_chk.toggled.connect(
                lambda checked, sid=sub.id: self._toggle_auto_update(sid, checked)
            )
            row.addWidget(auto_chk)

            refresh_btn = QPushButton("Обновить")
            refresh_btn.clicked.connect(lambda _c=False, sid=sub.id: self._refresh_single(sid))
            row.addWidget(refresh_btn)

        rename_btn = QPushButton("Переименовать")
        rename_btn.clicked.connect(
            lambda _c=False, sid=sub.id, cur=sub.name: self._rename_sub(sid, cur)
        )
        row.addWidget(rename_btn)

        del_btn = QPushButton("Удалить")
        del_btn.setObjectName("DangerButton")
        del_btn.clicked.connect(
            lambda _c=False, sid=sub.id, cur=sub.name: self._delete_sub(sid, cur)
        )
        row.addWidget(del_btn)

        return card

    def _on_add_url_clicked(self) -> None:
        if self._manager is None or (self._worker and self._worker.isRunning()):
            return
        dlg = _AddSubscriptionDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        url = dlg.url_edit.text().strip()
        if not url:
            return
        self._set_busy(True, "Загрузка и проверка подписки...")
        self._worker = _SubWorker(
            manager=self._manager,
            action="add_url",
            url=url,
            name=dlg.name_edit.text().strip(),
            auto_update=dlg.auto_chk.isChecked(),
            interval_min=dlg.interval_spin.value(),
            parent=self,
        )
        self._worker.finished_ok.connect(self._on_worker_ok)
        self._worker.failed.connect(self._on_worker_failed)
        self._worker.start()

    def _on_import_file_clicked(self) -> None:
        if self._manager is None:
            return
        file_str, _ = QFileDialog.getOpenFileName(
            self,
            "Импорт файла подписки или URI",
            "",
            "Файлы конфигураций (*.txt *.sub *.conf *);;Все файлы (*)",
        )
        if not file_str:
            return
        try:
            sub, warnings = self._manager.import_from_file(Path(file_str))
            self.reload_subscriptions()
            self.subscriptions_changed.emit()
            msg = f"Импортирована подписка «{sub.name}» ({sub.server_count} серверов)."
            if warnings:
                msg += f"\nПропущено некорректных строк: {len(warnings)}"
            self.status_lbl.setText(msg)
            self.status_lbl.setStyleSheet(f"color: {Palette.SUCCESS}; font-size: 12px;")
            self.status_lbl.show()
        except SubscriptionError as exc:
            QMessageBox.warning(self, "Ошибка импорта", str(exc))

    def _refresh_single(self, sub_id: int) -> None:
        if self._manager is None or (self._worker and self._worker.isRunning()):
            return
        self._set_busy(True, "Обновление подписки...")
        self._worker = _SubWorker(
            manager=self._manager,
            action="refresh_one",
            sub_id=sub_id,
            parent=self,
        )
        self._worker.finished_ok.connect(self._on_worker_ok)
        self._worker.failed.connect(self._on_worker_failed)
        self._worker.start()

    def _on_update_all_clicked(self) -> None:
        if self._manager is None or (self._worker and self._worker.isRunning()):
            return
        self._set_busy(True, "Обновление всех подписок...")
        self._worker = _SubWorker(
            manager=self._manager,
            action="refresh_all",
            parent=self,
        )
        self._worker.finished_ok.connect(self._on_worker_ok)
        self._worker.failed.connect(self._on_worker_failed)
        self._worker.start()

    def _on_worker_ok(self, message: str, warnings: list[str]) -> None:
        self._set_busy(False)
        if warnings:
            message = f"{message} (предупреждений: {len(warnings)})"
        self.status_lbl.setText(message)
        self.status_lbl.setStyleSheet(f"color: {Palette.SUCCESS}; font-size: 12px;")
        self.status_lbl.show()
        self.reload_subscriptions()
        self.subscriptions_changed.emit()

    def _on_worker_failed(self, error_msg: str) -> None:
        self._set_busy(False)
        self.status_lbl.setText(error_msg)
        self.status_lbl.setStyleSheet(f"color: {Palette.ERROR}; font-size: 12px;")
        self.status_lbl.show()
        QMessageBox.warning(self, "Ошибка подписки", error_msg)

    def _toggle_auto_update(self, sub_id: int, enabled: bool) -> None:
        if self._repo is not None:
            self._repo.set_subscription_auto_update(sub_id, enabled)

    def _rename_sub(self, sub_id: int, current_name: str) -> None:
        if self._repo is None:
            return
        new_name, ok = QInputDialog.getText(
            self, "Переименовать подписку", "Новое название:", text=current_name
        )
        if ok and new_name.strip():
            self._repo.rename_subscription(sub_id, new_name.strip())
            self.reload_subscriptions()
            self.subscriptions_changed.emit()

    def _delete_sub(self, sub_id: int, name: str) -> None:
        if self._repo is None:
            return
        ans = QMessageBox.question(
            self,
            "Удаление подписки",
            f"Удалить подписку «{name}» и связанные с ней серверы?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if ans == QMessageBox.StandardButton.Yes:
            self._repo.delete_subscription(sub_id)
            self.reload_subscriptions()
            self.subscriptions_changed.emit()

    def set_language(self, lang: str) -> None:
        self._lang = lang
        self.title_lbl.setText(tr("subs.title", lang))
        self.add_url_btn.setText(tr("subs.add_url", lang))
        self.import_file_btn.setText(tr("subs.import_file", lang))
        self.update_all_btn.setText(tr("subs.update_all", lang))
