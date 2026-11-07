"""Full Settings & Diagnostics screen: mode, DNS, ports, TUN, autostart, autoconnect, language, history."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from nexvpn.connection.states import ConnectionMode, format_bytes
from nexvpn.database.repository import DatabaseRepository
from nexvpn.services.autostart import set_autostart_enabled
from nexvpn.services.tun_service import is_running_as_admin
from nexvpn.ui.i18n import tr
from nexvpn.ui.theme import Palette
from nexvpn.ui.widgets.cards import CardFrame
from nexvpn.utils.paths import AppPaths


class SettingsPage(QWidget):
    """Comprehensive configuration and diagnostic screen."""

    settings_saved = Signal()
    language_changed = Signal(str)

    def __init__(
        self,
        repo: DatabaseRepository | None = None,
        paths: AppPaths | None = None,
        lang: str = "ru",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._repo = repo
        self._paths = paths
        self._lang = lang

        self._build_ui()
        self.load_from_repo()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 24, 28, 24)
        outer.setSpacing(14)

        header = QHBoxLayout()
        self.title_lbl = QLabel(tr("settings.title", self._lang))
        self.title_lbl.setObjectName("PageTitle")
        header.addWidget(self.title_lbl)
        header.addStretch(1)

        self.save_btn = QPushButton(tr("settings.save", self._lang))
        self.save_btn.setObjectName("PrimaryButton")
        self.save_btn.clicked.connect(self._save_settings)
        header.addWidget(self.save_btn)
        outer.addLayout(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        col = QVBoxLayout(content)
        col.setContentsMargins(0, 0, 6, 0)
        col.setSpacing(14)
        scroll.setWidget(content)
        outer.addWidget(scroll, stretch=1)

        # 1. Connection & Network Card
        net_card = CardFrame()
        net_layout = QVBoxLayout(net_card)
        net_layout.setContentsMargins(20, 16, 20, 16)
        net_layout.setSpacing(12)

        net_hdr = QLabel("Сеть, прокси и DNS")
        net_hdr.setObjectName("SectionTitle")
        net_layout.addWidget(net_hdr)

        net_form = QFormLayout()
        net_form.setSpacing(10)

        self.mode_combo = QComboBox()
        self.mode_combo.addItem("System Proxy (SOCKS5 + HTTP)", ConnectionMode.SYSTEM_PROXY.value)
        self.mode_combo.addItem("TUN Mode (Виртуальный адаптер Wintun)", ConnectionMode.TUN.value)

        self.port_spin = QSpinBox()
        self.port_spin.setRange(1024, 65535)
        self.port_spin.setValue(10808)

        self.dns_remote_edit = QLineEdit()
        self.dns_remote_edit.setPlaceholderText("https://1.1.1.1/dns-query")

        self.dns_direct_edit = QLineEdit()
        self.dns_direct_edit.setPlaceholderText("1.1.1.1 или local")

        self.proxy_consent_chk = QCheckBox(
            "Разрешить автоматическую настройку системного прокси Windows в режиме System Proxy"
        )
        self.bypass_lan_chk = QCheckBox("Направлять локальный трафик (LAN / 192.168.* / 10.*) напрямую")

        self.tun_stack_combo = QComboBox()
        self.tun_stack_combo.addItem("System (Рекомендуется)", "system")
        self.tun_stack_combo.addItem("gVisor", "gvisor")
        self.tun_stack_combo.addItem("Mixed (System TCP + gVisor UDP)", "mixed")

        self.tun_strict_chk = QCheckBox("Строгая маршрутизация TUN (strict_route)")

        net_form.addRow("Режим подключения:", self.mode_combo)
        net_form.addRow("Локальный порт прокси:", self.port_spin)
        net_form.addRow("Удалённый DNS (через VPN):", self.dns_remote_edit)
        net_form.addRow("Прямой Bootstrap DNS:", self.dns_direct_edit)
        net_form.addRow("Стек TUN:", self.tun_stack_combo)
        net_form.addRow("", self.tun_strict_chk)
        net_form.addRow("", self.proxy_consent_chk)
        net_form.addRow("", self.bypass_lan_chk)
        net_layout.addLayout(net_form)
        col.addWidget(net_card)

        # 2. Application & Automation Card
        app_card = CardFrame()
        app_layout = QVBoxLayout(app_card)
        app_layout.setContentsMargins(20, 16, 20, 16)
        app_layout.setSpacing(12)

        app_hdr = QLabel("Приложение и автоматизация")
        app_hdr.setObjectName("SectionTitle")
        app_layout.addWidget(app_hdr)

        app_form = QFormLayout()
        app_form.setSpacing(10)

        self.lang_combo = QComboBox()
        self.lang_combo.addItem("Русский", "ru")
        self.lang_combo.addItem("English", "en")

        self.autostart_chk = QCheckBox("Запускать NEXVPN при входе в Windows")
        self.autoconnect_chk = QCheckBox("Автоматически подключаться к выбранному серверу при запуске")
        self.auto_subs_chk = QCheckBox("Автоматически обновлять URL-подписки по расписанию")

        app_form.addRow("Язык интерфейса:", self.lang_combo)
        app_form.addRow("", self.autostart_chk)
        app_form.addRow("", self.autoconnect_chk)
        app_form.addRow("", self.auto_subs_chk)
        app_layout.addLayout(app_form)
        col.addWidget(app_card)

        # 3. Diagnostics & Connection History Card
        diag_card = CardFrame()
        diag_layout = QVBoxLayout(diag_card)
        diag_layout.setContentsMargins(20, 16, 20, 16)
        diag_layout.setSpacing(8)

        diag_hdr = QLabel("Диагностика системы и история сессий")
        diag_hdr.setObjectName("SectionTitle")
        diag_layout.addWidget(diag_hdr)

        admin_txt = "Да (TUN доступен)" if is_running_as_admin() else "Обычный пользователь (System Proxy без UAC; для TUN нужен запуск от Администратора)"
        admin_color = Palette.SUCCESS if is_running_as_admin() else Palette.WARNING
        self.priv_lbl = QLabel(f"Права администратора: {admin_txt}")
        self.priv_lbl.setStyleSheet(f"color: {admin_color}; font-size: 12px;")
        diag_layout.addWidget(self.priv_lbl)

        if self._paths is not None:
            paths_lbl = QLabel(
                f"Портативный каталог: {self._paths.root_dir}\n"
                f"База данных: {self._paths.db_file}\n"
                f"Журнал: {self._paths.log_file}"
            )
            paths_lbl.setObjectName("MutedLabel")
            diag_layout.addWidget(paths_lbl)

        self.history_lbl = QLabel("История подключений пуста.")
        self.history_lbl.setObjectName("MutedLabel")
        self.history_lbl.setWordWrap(True)
        diag_layout.addWidget(self.history_lbl)

        col.addWidget(diag_card)
        col.addStretch(1)

    def load_from_repo(self) -> None:
        if self._repo is None:
            return
        s = self._repo.get_all_settings()

        mode_idx = self.mode_combo.findData(s.get("connection_mode", "system_proxy"))
        if mode_idx >= 0:
            self.mode_combo.setCurrentIndex(mode_idx)

        port_str = s.get("local_mixed_port", "10808")
        self.port_spin.setValue(int(port_str) if port_str.isdigit() else 10808)

        self.dns_remote_edit.setText(s.get("dns_remote", "https://1.1.1.1/dns-query"))
        self.dns_direct_edit.setText(s.get("dns_direct", "1.1.1.1"))

        stack_idx = self.tun_stack_combo.findData(s.get("tun_stack", "system"))
        if stack_idx >= 0:
            self.tun_stack_combo.setCurrentIndex(stack_idx)

        self.tun_strict_chk.setChecked(s.get("tun_strict_route", "1") == "1")
        self.proxy_consent_chk.setChecked(s.get("system_proxy_consent", "1") == "1")
        self.bypass_lan_chk.setChecked(s.get("bypass_lan", "1") == "1")
        self.autostart_chk.setChecked(s.get("autostart", "0") == "1")
        self.autoconnect_chk.setChecked(s.get("autoconnect", "0") == "1")
        self.auto_subs_chk.setChecked(s.get("auto_update_subs", "1") == "1")

        lang_idx = self.lang_combo.findData(s.get("language", "ru"))
        if lang_idx >= 0:
            self.lang_combo.setCurrentIndex(lang_idx)

        self.refresh_diagnostics()

    def refresh_diagnostics(self) -> None:
        if self._repo is None:
            return
        history = self._repo.list_connection_history(limit=5)
        if not history:
            self.history_lbl.setText("Последние сессии: нет записей.")
            return
        lines = ["Последние сессии:"]
        for h in history:
            traffic = f"↑{format_bytes(h.bytes_up)} ↓{format_bytes(h.bytes_down)}"
            err_suffix = f" ({h.error_message})" if h.error_message else ""
            lines.append(
                f"• [{h.started_at}] {h.server_name} ({h.protocol.upper()}, {h.mode}) — {h.status} {traffic}{err_suffix}"
            )
        self.history_lbl.setText("\n".join(lines))

    def _save_settings(self) -> None:
        if self._repo is None:
            return

        dns_remote = self.dns_remote_edit.text().strip() or "https://1.1.1.1/dns-query"
        dns_direct = self.dns_direct_edit.text().strip() or "1.1.1.1"
        new_lang = str(self.lang_combo.currentData() or "ru")
        autostart_val = self.autostart_chk.isChecked()

        self._repo.set_setting("connection_mode", str(self.mode_combo.currentData()))
        self._repo.set_setting("local_mixed_port", str(self.port_spin.value()))
        self._repo.set_setting("dns_remote", dns_remote)
        self._repo.set_setting("dns_direct", dns_direct)
        self._repo.set_setting("tun_stack", str(self.tun_stack_combo.currentData()))
        self._repo.set_setting("tun_strict_route", "1" if self.tun_strict_chk.isChecked() else "0")
        self._repo.set_setting("system_proxy_consent", "1" if self.proxy_consent_chk.isChecked() else "0")
        self._repo.set_setting("bypass_lan", "1" if self.bypass_lan_chk.isChecked() else "0")
        self._repo.set_setting("autostart", "1" if autostart_val else "0")
        self._repo.set_setting("autoconnect", "1" if self.autoconnect_chk.isChecked() else "0")
        self._repo.set_setting("auto_update_subs", "1" if self.auto_subs_chk.isChecked() else "0")
        self._repo.set_setting("language", new_lang)

        set_autostart_enabled(autostart_val)

        if new_lang != self._lang:
            self._lang = new_lang
            self.language_changed.emit(new_lang)

        self.settings_saved.emit()
        QMessageBox.information(self, "NEXVPN", "Настройки успешно сохранены.")

    def set_language(self, lang: str) -> None:
        self._lang = lang
        self.title_lbl.setText(tr("settings.title", lang))
        self.save_btn.setText(tr("settings.save", lang))
