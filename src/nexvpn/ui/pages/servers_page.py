"""Full Servers management screen: search, sort, favorites, real TCP ping, select, rename, delete, URI import."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from nexvpn.connection.latency import BatchLatencyWorker
from nexvpn.database.repository import DatabaseRepository
from nexvpn.subscription.manager import SubscriptionError, SubscriptionManager
from nexvpn.subscription.models import ServerRecord
from nexvpn.ui.i18n import tr
from nexvpn.ui.theme import Palette
from nexvpn.ui.widgets.cards import CardFrame


class _ImportUriDialog(QDialog):
    """Dialog to paste one or multiple proxy URIs directly."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Импорт URI конфигураций")
        self.setMinimumSize(500, 290)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        hint = QLabel(
            "Вставьте один или несколько URI (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC) "
            "или Base64-блок:"
        )
        hint.setWordWrap(True)
        hint.setObjectName("MutedLabel")
        layout.addWidget(hint)

        self.text_edit = QPlainTextEdit()
        self.text_edit.setPlaceholderText("vless://...\ntrojan://...\nss://...")
        layout.addWidget(self.text_edit, stretch=1)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


def _format_latency_badge(ms: int | None) -> tuple[str, str]:
    if ms is None:
        return "—", Palette.MUTED
    if ms < 0:
        return "Timeout", Palette.ERROR
    if ms < 150:
        return f"{ms} ms", Palette.SUCCESS
    if ms < 350:
        return f"{ms} ms", Palette.WARNING
    return f"{ms} ms", Palette.ERROR


class ServersPage(QWidget):
    """Full server list view with search, sort, favorites, latency check, and CRUD."""

    server_selected = Signal(int)
    servers_modified = Signal()

    def __init__(
        self,
        repo: DatabaseRepository | None = None,
        sub_manager: SubscriptionManager | None = None,
        lang: str = "ru",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._repo = repo
        self._sub_manager = sub_manager
        self._lang = lang
        self._ping_worker: BatchLatencyWorker | None = None
        self._latency_labels: dict[int, QLabel] = {}

        self._build_ui()
        self.reload_servers()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(14)

        # Header row
        header = QHBoxLayout()
        self.title_lbl = QLabel(tr("servers.title", self._lang))
        self.title_lbl.setObjectName("PageTitle")
        header.addWidget(self.title_lbl)
        header.addStretch(1)

        self.import_uri_btn = QPushButton(tr("servers.import_uri", self._lang))
        self.import_uri_btn.setObjectName("PrimaryButton")
        self.import_uri_btn.clicked.connect(self._on_import_uri)

        self.ping_all_btn = QPushButton(tr("servers.ping_all", self._lang))
        self.ping_all_btn.clicked.connect(self._on_ping_all)

        header.addWidget(self.import_uri_btn)
        header.addWidget(self.ping_all_btn)
        root.addLayout(header)

        # Filter & Sort toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText(tr("servers.search", self._lang))
        self.search_edit.textChanged.connect(self.reload_servers)

        self.sort_combo = QComboBox()
        self.sort_combo.addItem("По умолчанию", "default")
        self.sort_combo.addItem(tr("servers.sort_latency", self._lang), "latency")
        self.sort_combo.addItem(tr("servers.sort_name", self._lang), "name")
        self.sort_combo.addItem(tr("servers.sort_protocol", self._lang), "protocol")
        self.sort_combo.currentIndexChanged.connect(self.reload_servers)

        self.fav_only_chk = QCheckBox(tr("servers.only_fav", self._lang))
        self.fav_only_chk.toggled.connect(self.reload_servers)

        toolbar.addWidget(self.search_edit, stretch=1)
        toolbar.addWidget(self.sort_combo)
        toolbar.addWidget(self.fav_only_chk)
        root.addLayout(toolbar)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.list_container = QWidget()
        self.list_layout = QVBoxLayout(self.list_container)
        self.list_layout.setContentsMargins(0, 0, 4, 0)
        self.list_layout.setSpacing(9)
        self.scroll.setWidget(self.list_container)
        root.addWidget(self.scroll, stretch=1)

    def _get_filtered_sorted_servers(self) -> list[ServerRecord]:
        if self._repo is None:
            return []
        servers = self._repo.list_servers()
        query = self.search_edit.text().strip().lower()
        if query:
            servers = [
                s
                for s in servers
                if query in s.display_name.lower()
                or query in s.host.lower()
                or query in s.protocol.lower()
            ]
        if self.fav_only_chk.isChecked():
            servers = [s for s in servers if s.is_favorite]

        sort_key = str(self.sort_combo.currentData() or "default")
        if sort_key == "name":
            servers.sort(key=lambda s: (not s.is_favorite, s.display_name.lower()))
        elif sort_key == "latency":
            servers.sort(
                key=lambda s: (
                    not s.is_favorite,
                    s.latency_ms if (s.latency_ms is not None and s.latency_ms > 0) else 999_999,
                    s.display_name.lower(),
                )
            )
        elif sort_key == "protocol":
            servers.sort(key=lambda s: (not s.is_favorite, s.protocol.lower(), s.display_name.lower()))
        return servers

    def reload_servers(self) -> None:
        self._latency_labels.clear()
        while self.list_layout.count():
            item = self.list_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

        if self._repo is None:
            return

        selected_raw = self._repo.get_setting("selected_server_id", "")
        selected_id = int(selected_raw) if selected_raw.isdigit() else -1
        servers = self._get_filtered_sorted_servers()

        if not servers:
            empty_card = CardFrame()
            el = QVBoxLayout(empty_card)
            el.setContentsMargins(22, 22, 22, 22)
            lbl = QLabel("Серверы не найдены. Добавьте подписку или нажмите «Добавить URI».")
            lbl.setObjectName("MutedLabel")
            el.addWidget(lbl)
            self.list_layout.addWidget(empty_card)
            self.list_layout.addStretch(1)
            return

        for srv in servers:
            self.list_layout.addWidget(self._create_server_card(srv, srv.id == selected_id))
        self.list_layout.addStretch(1)

    def _create_server_card(self, srv: ServerRecord, is_selected: bool) -> QWidget:
        card = CardFrame(selected=is_selected)
        row = QHBoxLayout(card)
        row.setContentsMargins(16, 12, 16, 12)
        row.setSpacing(12)

        # Favorite star button
        fav_btn = QPushButton("★" if srv.is_favorite else "☆")
        fav_btn.setFixedSize(34, 34)
        fav_color = Palette.WARNING if srv.is_favorite else Palette.MUTED
        fav_btn.setStyleSheet(
            f"QPushButton {{ color: {fav_color}; font-size: 16px; padding: 0px; }}"
        )
        fav_btn.setToolTip("Избранное")
        fav_btn.clicked.connect(
            lambda _c=False, sid=srv.id, nxt=not srv.is_favorite: self._toggle_fav(sid, nxt)
        )
        row.addWidget(fav_btn)

        # Server title + protocol/transport tags
        info_col = QVBoxLayout()
        info_col.setSpacing(3)

        name_lbl = QLabel(srv.display_name)
        name_lbl.setObjectName("SectionTitle")

        badges: list[str] = [srv.protocol_summary, srv.endpoint_label]
        if srv.node.additional_outbounds:
            badges.append(f"{len(srv.node.additional_outbounds) + 1} узлов")

        meta_lbl = QLabel("  •  ".join(badges))
        meta_lbl.setObjectName("MutedLabel")

        info_col.addWidget(name_lbl)
        info_col.addWidget(meta_lbl)
        row.addLayout(info_col, stretch=1)

        # Latency display
        lat_txt, lat_color = _format_latency_badge(srv.latency_ms)
        lat_lbl = QLabel(lat_txt)
        lat_lbl.setMinimumWidth(72)
        lat_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        lat_lbl.setStyleSheet(f"color: {lat_color}; font-weight: 600; font-size: 13px;")
        self._latency_labels[srv.id] = lat_lbl
        row.addWidget(lat_lbl)

        # Action buttons
        ping_btn = QPushButton("Пинг")
        ping_btn.clicked.connect(lambda _c=False, s=srv: self._ping_single(s))
        row.addWidget(ping_btn)

        sel_btn = QPushButton("Выбран" if is_selected else "Выбрать")
        if is_selected:
            sel_btn.setObjectName("PrimaryButton")
            sel_btn.setEnabled(False)
        else:
            sel_btn.clicked.connect(lambda _c=False, sid=srv.id: self._select_server(sid))
        row.addWidget(sel_btn)

        ren_btn = QPushButton("✎")
        ren_btn.setFixedWidth(36)
        ren_btn.setToolTip("Переименовать сервер")
        ren_btn.clicked.connect(
            lambda _c=False, sid=srv.id, cur=srv.display_name: self._rename_server(sid, cur)
        )
        row.addWidget(ren_btn)

        del_btn = QPushButton("✕")
        del_btn.setObjectName("DangerButton")
        del_btn.setFixedWidth(36)
        del_btn.setToolTip("Удалить сервер")
        del_btn.clicked.connect(
            lambda _c=False, sid=srv.id, cur=srv.display_name: self._delete_server(sid, cur)
        )
        row.addWidget(del_btn)

        return card

    def _select_server(self, server_id: int) -> None:
        if self._repo is None:
            return
        self._repo.set_setting("selected_server_id", str(server_id))
        self.reload_servers()
        self.server_selected.emit(server_id)

    def _toggle_fav(self, server_id: int, is_fav: bool) -> None:
        if self._repo is None:
            return
        self._repo.toggle_server_favorite(server_id, is_fav)
        self.reload_servers()

    def _rename_server(self, server_id: int, current_name: str) -> None:
        if self._repo is None:
            return
        new_name, ok = QInputDialog.getText(
            self, "Переименовать сервер", "Пользовательское название:", text=current_name
        )
        if ok:
            self._repo.rename_server(server_id, new_name.strip() or None)
            self.reload_servers()
            self.servers_modified.emit()

    def _delete_server(self, server_id: int, name: str) -> None:
        if self._repo is None:
            return
        ans = QMessageBox.question(
            self,
            "Удаление сервера",
            f"Удалить сервер «{name}»?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if ans == QMessageBox.StandardButton.Yes:
            self._repo.delete_server(server_id)
            self.reload_servers()
            self.servers_modified.emit()

    def _on_import_uri(self) -> None:
        if self._sub_manager is None:
            return
        dlg = _ImportUriDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        raw = dlg.text_edit.toPlainText().strip()
        if not raw:
            return
        try:
            nodes, warnings = self._sub_manager.import_raw_text(raw)
            self.reload_servers()
            self.servers_modified.emit()
            if warnings:
                QMessageBox.information(
                    self,
                    "Импорт завершён",
                    f"Добавлено серверов: {len(nodes)}\nПропущено строк: {len(warnings)}",
                )
        except SubscriptionError as exc:
            QMessageBox.warning(self, "Ошибка импорта URI", str(exc))

    def _ping_single(self, srv: ServerRecord) -> None:
        self._start_ping_batch([srv])

    def _on_ping_all(self) -> None:
        servers = self._get_filtered_sorted_servers()
        if servers:
            self._start_ping_batch(servers)

    def start_ping_for_server_id(self, server_id: int) -> None:
        if self._repo is None:
            return
        srv = self._repo.get_server(server_id)
        if srv is not None:
            self._start_ping_batch([srv])

    def _start_ping_batch(self, targets: list[ServerRecord]) -> None:
        if self._ping_worker is not None and self._ping_worker.isRunning():
            return
        self.ping_all_btn.setEnabled(False)
        for t in targets:
            lbl = self._latency_labels.get(t.id)
            if lbl is not None:
                lbl.setText("...")
                lbl.setStyleSheet(f"color: {Palette.ACCENT}; font-weight: 600;")

        worker = BatchLatencyWorker(targets, timeout=3.0, parent=self)
        worker.result_ready.connect(self._on_ping_result)
        worker.all_finished.connect(self._on_ping_batch_done)
        self._ping_worker = worker
        worker.start()

    def _on_ping_result(self, server_id: int, latency_ms: int) -> None:
        if self._repo is not None:
            self._repo.update_server_latency(server_id, latency_ms)
        lbl = self._latency_labels.get(server_id)
        if lbl is not None:
            txt, color = _format_latency_badge(latency_ms)
            lbl.setText(txt)
            lbl.setStyleSheet(f"color: {color}; font-weight: 600; font-size: 13px;")
        self.servers_modified.emit()

    def _on_ping_batch_done(self) -> None:
        self.ping_all_btn.setEnabled(True)
        if self.sort_combo.currentData() == "latency":
            self.reload_servers()

    def stop_background_tasks(self) -> None:
        if self._ping_worker is not None and self._ping_worker.isRunning():
            self._ping_worker.cancel()
            self._ping_worker.wait(2000)

    def set_language(self, lang: str) -> None:
        self._lang = lang
        self.title_lbl.setText(tr("servers.title", lang))
        self.import_uri_btn.setText(tr("servers.import_uri", lang))
        self.ping_all_btn.setText(tr("servers.ping_all", lang))
        self.search_edit.setPlaceholderText(tr("servers.search", lang))
        self.fav_only_chk.setText(tr("servers.only_fav", lang))
