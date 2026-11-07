# NEXVPN Desktop

**NEXVPN** — современный самостоятельный портативный VPN-клиент для Windows (10/11 x64), построенный на **Python 3.12+**, **PySide6** и сетевом ядре **sing-box** (`v1.14.4`).

---

## Ключевые возможности

- **Управление подписками:**
  - Добавление подписок по защищённому `https://` URL с проверкой TLS-сертификатов и защитой от небезопасных перенаправлений (downgrade / SSRF).
  - Импорт списков конфигураций из локальных файлов и прямой ввод отдельных URI.
  - Поддержка контейнеров JSON (массивы и одиночные профили Xray / Happ), Base64, URL-safe Base64 и обычных текстовых списков URI.
  - Атомарное обновление подписок (предыдущие рабочие серверы сохраняются при сетевых ошибках или некорректном ответе; пользовательские названия и избранное не сбрасываются).
  - Ручное и автоматическое обновление по настраиваемому интервалу.
- **Поддерживаемые протоколы:**
  - **VLESS** (TCP, XTLS Vision, XHTTP / SplitHTTP + TLS, Reality + uTLS, WebSocket, gRPC, HTTP/2, HTTPUpgrade, кластерная балансировка, IPv6)
  - **VMess** (Base64 JSON v2rayN и URI-формат; TCP, WS, gRPC, HTTPUpgrade, XHTTP, TLS)
  - **Trojan** (TLS, Reality, WS, gRPC, HTTPUpgrade, XHTTP)
  - **Shadowsocks** (SIP002, SS-2022 `2022-blake3-*`, AEAD `aes-*-gcm` / `chacha20-ietf-poly1305`, Legacy Base64, плагины `obfs-local` / `v2ray-plugin`)
  - **Hysteria2** (`hysteria2://` и `hy2://`, QUIC, обфускация Salamander, лимиты пропускной способности)
  - **TUIC** (`tuic://` v5, QUIC, BBR / Cubic / NewReno, Native / QUIC UDP relay)
- **Два независимых режима работы:**
  1. **System Proxy (приоритетный режим без прав администратора):** локальный `mixed` inbound (`SOCKS5` + `HTTP/HTTPS CONNECT`) в `sing-box`, автоматическая настройка системного прокси Windows через WinINET API (`InternetSetOptionW`) и реестр `HKCU`, обнаружение блокировок групповыми политиками (`GPO`), сохранение предыдущих настроек прокси/PAC и гарантированное восстановление при отключении или после аварийного сбоя.
  2. **TUN Mode:** виртуальный сетевой интерфейс `NEXVPN-TUN` (`Wintun`), автоматическая маршрутизация (`auto_route`, `strict_route`), перехват DNS (`hijack-dns`), проверка прав администратора, автоматическое разрешение конфликтов подсетей и очистка маршрутов/DNS-кэша при отключении. *Примечание: режим TUN использует механизмы маршрутизации `sing-box`; поведение утечек зависит от правил брандмауэра и политик конкретной системы Windows.*
- **Реальная диагностика и телеметрия:**
  - Состояния `DISCONNECTED`, `CONNECTING`, `CONNECTED`, `RECONNECTING`, `DISCONNECTING`, `ERROR` — переход в `CONNECTED` выполняется только после реальной проверки готовности локального прокси (SOCKS5-рукопожатие) или интерфейса TUN и доступности узла.
  - Реальное измерение задержки (TCP SYN/SYN-ACK RTT и HTTP 204 roundtrip через локальный прокси).
  - Реальная скорость загрузки и отправки в реальном времени через локальный контроллер `sing-box` Clash API (`127.0.0.1` со случайным Bearer-токеном).
- **Безопасность хранения и логирования:**
  - Чувствительные данные в SQLite (URL подписок, параметры и ключи серверов) шифруются штатным механизмом **Windows DPAPI** (`CryptProtectData`), привязанным к учётной записи пользователя Windows.
  - Временные рабочие конфигурации `sing-box` создаются в `data/runtime/` с ограниченными правами доступа Windows ACL (`icacls`, только текущий пользователь и SYSTEM/Администраторы) и затираются нулями при остановке ядра.
  - Централизованный фильтр логов автоматически маскирует токены подписок, прокси-URI, пароли и UUID.

---

## Архитектура проекта

```text
NEXVPN/
├── main.py                      # Точка входа приложения
├── build_portable.py            # Скрипт сборки Portable-версии (PyInstaller)
├── core/
│   ├── sing-box.exe             # Основное сетевое ядро sing-box v1.14.4
│   ├── xray.exe                 # Модуль Xray-core для нативного транспорта XHTTP
│   ├── LICENSE.sing-box         # Лицензия GPLv3 ядра sing-box
│   └── LICENSE.xray             # Лицензия MPL-2.0 модуля Xray-core
├── assets/
│   ├── fonts/InterVariable.ttf  # Шрифт Inter (OFL-1.1)
│   └── icon.ico                 # Иконка NEXVPN
├── data/                        # SQLite БД (nexvpn.db) и защищённая папка runtime/
├── logs/                        # Ротируемые очищенные журналы (nexvpn.log)
├── src/nexvpn/
│   ├── ui/                      # 1. UI Layer (PySide6, тема, виджеты, 5 экранов)
│   ├── core/                    # 2. Core Layer (поиск ядра, генератор конфигов 1.14+, QProcess)
│   ├── subscription/            # 3. Subscription Layer (модели, парсеры 6 протоколов, менеджер)
│   ├── connection/              # 4. Connection Layer (конечный автомат, реальный пинг)
│   ├── database/                # 5. Database Layer (SQLite, миграции, Windows DPAPI)
│   ├── services/                # 6. Services Layer (System Proxy, TUN, трафик, автозапуск)
│   └── utils/                   # 7. Utilities Layer (пути Portable, ACL, фильтр логов, порты, мьютекс)
└── tests/                       # Модульные и сквозные интеграционные тесты (pytest + pytest-qt)
```

---

## Использование Portable-сборки (без установки Python)

Готовая Portable-сборка располагается в `dist/NEXVPN/` (а также упакована в архив `dist/NEXVPN-Portable-win64.zip`):

```text
NEXVPN/
    NEXVPN.exe
    core/
        sing-box.exe
    data/
    logs/
```

1. Распакуйте архив `NEXVPN-Portable-win64.zip` в любую удобную папку с правами записи для вашего пользователя.
2. Запустите `NEXVPN.exe` (для режима **System Proxy** права администратора не требуются; для режима **TUN** запустите `NEXVPN.exe` от имени администратора).
3. Перейдите во вкладку **Подписки** → **Добавить по URL** (или **Импорт из файла**), либо во вкладку **Серверы** → **Добавить URI**.
4. Выберите сервер и нажмите центральную кнопку **Подключиться** на главной панели.

---

## Разработка, тестирование и самостоятельная сборка

### 1. Установка окружения
```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```
Убедитесь, что официальный бинарный файл `sing-box.exe` (`v1.14+` для `windows-amd64`) находится в `core/sing-box.exe`.

### 2. Запуск из исходного кода
```powershell
.\.venv\Scripts\python.exe main.py
```

### 3. Запуск полного набора тестов
```powershell
.\.venv\Scripts\pytest.exe
```

### 4. Сборка Portable EXE
```powershell
.\.venv\Scripts\python.exe build_portable.py
```

---

## Лицензии и сторонние компоненты

Проект распространяется под лицензией **GNU GPL v3.0 or later** (см. `LICENSE`). Полный перечень используемых открытых компонентов, уведомлений об авторских правах и ссылок на исходный код (`sing-box`, `Wintun`, `PySide6 / Qt 6`, `HTTPX`, `Inter`) приведён в `THIRD_PARTY_NOTICES.md` и `core/LICENSE.sing-box`.
