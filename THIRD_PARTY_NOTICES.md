# Third-Party Software Notices and Licenses

NEXVPN Desktop incorporates or interacts with the following open-source software components. Full license texts and upstream source code links are provided below in compliance with their respective licenses.

---

## 1. sing-box (Standalone Network Core)
- **Project:** SagerNet/sing-box
- **Role in NEXVPN:** Executed as an independent standalone CLI process (`core/sing-box.exe`) for proxy and TUN networking.
- **License:** GNU General Public License v3.0 or later (GPL-3.0-or-later)
- **Upstream Source Code:** https://github.com/SagerNet/sing-box
- **Release Tag Used:** https://github.com/SagerNet/sing-box/releases
- **License File:** Included in `core/LICENSE.sing-box` and `LICENSE`.
- **Source Code Notice:** `core/sing-box.exe` is an unmodified official upstream binary build distributed by the SagerNet project. Its complete corresponding source code is publicly available from the official GitHub repository linked above.

---

## 1b. Xray-core (Standalone XHTTP Transport Companion)
- **Project:** XTLS/Xray-core
- **Role in NEXVPN:** Executed as an independent standalone CLI process (`core/xray.exe`) providing native XHTTP (`splithttp`) transport bridged locally into `sing-box`.
- **License:** Mozilla Public License 2.0 (MPL-2.0)
- **Upstream Source Code:** https://github.com/XTLS/Xray-core
- **Release Tag Used:** https://github.com/XTLS/Xray-core/releases
- **License File:** Included in `core/LICENSE.xray`.
- **Source Code Notice:** `core/xray.exe` is an unmodified official upstream binary build distributed by the XTLS project under MPL-2.0.

---

## 2. Wintun (Embedded / Used by sing-box TUN on Windows)
- **Project:** WireGuard Wintun
- **License:** GPL-2.0 (driver) / MIT (wintun.dll userspace library)
- **Upstream Website & Source:** https://www.wintun.net/ | https://git.zx2c4.com/wintun/

---

## 3. PySide6 / Qt for Python
- **Project:** Qt for Python (PySide6)
- **License:** GNU Lesser General Public License v3.0 (LGPL-3.0)
- **Upstream Website & Source:** https://www.qt.io/qt-for-python | https://code.qt.io/cgit/pyside/pyside-setup.git/
- **LGPL Notice:** PySide6 and Qt dynamic libraries (`*.dll` / `*.pyd`) are dynamically linked and packaged unmodified, allowing users to inspect or replace the LGPL libraries in the portable directory.

---

## 4. HTTPX & Socksio
- **Projects:** encode/httpx, sethmlarson/socksio
- **License:** BSD 3-Clause License
- **Upstream Source:** https://github.com/encode/httpx | https://github.com/sethmlarson/socksio

---

## 5. Python Runtime
- **Project:** Python Software Foundation (CPython)
- **License:** PSF License Agreement (PSF-2.0)
- **Upstream Website:** https://www.python.org/

---

## 6. Inter Typeface
- **Project:** Inter by Rasmus Andersson
- **License:** SIL Open Font License 1.1 (OFL-1.1)
- **Upstream Source:** https://github.com/rsms/inter
