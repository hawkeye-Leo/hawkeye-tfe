# Hawkeye TFE

**Dual-stream (double-buffer) transparent file encryption** — a Windows minifilter research driver.

Each protected `.txt` file gets two views: **Plaintext** for applications and cache-manager I/O, **Shadow** for encrypted bytes on disk. The filter transforms at the boundary; stop the driver and only ciphertext remains.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
![Platform: Windows 10/11 x64](https://img.shields.io/badge/Platform-Windows%2010%2F11%20x64-0078D4)

[Releases](https://github.com/hawkeye-Leo/hawkeye-tfe/releases/latest)

## Authorized use only

Use only on systems you own or are authorized to test. Research and learning only — not for production data protection.

On-disk encrypt/decrypt uses **XOR** (`HawkCipher.c`) to keep the implementation simple and easy to study.

## Requirements

- **OS:** Windows 10 or Windows 11, x64
- **Privileges:** Administrator (driver install and start)
- **Build:** Visual Studio 2019 or later with **Windows Driver Kit (WDK)** 10
- **Load:** test-signed driver (`CN=HawkeyeTfe Test`) or your own signing pipeline — not WHQL

Test-signed builds require **test signing mode** (`bcdedit /set testsigning on`) and trusting the test certificate. Secure Boot and Memory Integrity (HVCI) may still block loading on some machines.

## Quick start

1. Build **Debug** or **Release** | **x64** in Visual Studio (`HawkeyeTfe.sln`).  
   Post-build **signs** the driver automatically and copies **`HawkeyeTfe.sys`** and **`HawkeyeTfe_Test.cer`** into `scripts\` (same folder as `install.bat`). No manual `sign_driver.ps1` unless you build outside Visual Studio.

2. On the target machine (admin, **once before first load**):

   **Enable test signing** (reboot required):

   ```text
   bcdedit /set testsigning on
   shutdown /r /t 0
   ```

   Right-click `HawkeyeTfe_Test.cer` → **Install Certificate** → **Local Machine** (admin) → **Trusted Root Certification Authorities**.  
   Repeat once → **Trusted Publishers**.

3. Install and start:

   ```text
   scripts\install.bat
   scripts\start.bat
   ```

   `install.bat` reads **`HawkeyeTfe.sys` from its own directory** and copies it to `%SystemRoot%\System32\drivers\`.  
   On first load the driver creates `C:\test_files` automatically.

4. Under `C:\test_files`, create or edit **`.txt` files**.  
   **Current scope:** only `.txt` under the protected path is transformed (`HawkIsProtectedTxtFile`).  
   **Verified editors:** Windows Notepad and Notepad++ — open, edit, and save work transparently; on-disk bytes stay encrypted.

5. Stop or remove:

   ```text
   scripts\stop.bat
   scripts\uninstall.bat
   ```

**Release zip layout:** ship `scripts\` with `HawkeyeTfe.sys`, the four `.bat` files, and `HawkeyeTfe_Test.cer` together — no Visual Studio required on the target machine.

## Verification

**Encrypt an existing plaintext file:** copy a `.txt` into `C:\test_files` while the driver is running, open it in Notepad or Notepad++, and save once (even unchanged). The on-disk copy becomes ciphertext; with the driver stopped you can confirm the raw bytes are no longer plain text.

After you have a protected `.txt` under `C:\test_files`:

1. With the driver **running** — open it in Notepad or Notepad++: you see **plaintext**.
2. Run `scripts\stop.bat` — open the same file again (or view raw bytes with a hex editor): you see **ciphertext** on disk.
3. Run `scripts\start.bat` — the file reads as **plaintext** again.

Plaintext while loaded, ciphertext while stopped — that closed loop means transparent encrypt/decrypt is working.

## Architecture (high level)

Each protected file uses a **dual-stream (double-buffer) model**:

| Stream | `FILE_OBJECT` | Role |
| --- | --- | --- |
| **Plaintext** | `PlaintextFileObject` | Filter-synthesized view for apps; bound to `HAWK_SCB`, cache-manager I/O on plaintext |
| **Shadow** | `ShadowFileObject` | Real lower-stack open; on-disk bytes are ciphertext |

Create opens both. **Read/write** on the Plaintext stream are transformed at the filter boundary (decrypt on read, encrypt on write). **Flush** and other metadata I/O are forwarded to the Shadow handle without transform.

## Current scope

What works today — everything else is untested or unchanged:

| Item | Today |
| --- | --- |
| Protected path | `C:\test_files` only (`HAWK_DEFAULT_PROTECT_PATH`; change in `HawkeyeTfe.h` and rebuild) |
| File type | `.txt` under that path |
| Editors | Notepad, Notepad++ |

Other extensions, applications, and paths are not transformed. Back up `.txt` files before trying new tools or build experiments — the driver sits on the cache-manager path.

## Support

Email [hawkeye18485@gmail.com](mailto:hawkeye18485@gmail.com). For driver load failures, include Windows build, signing mode, and `sc query HawkeyeTfe` output.

To report a security vulnerability, see [`SECURITY.md`](SECURITY.md) — do not open a public issue.

## License

GPL-3.0-or-later. See [`LICENSE`](LICENSE). The minifilter driver in this repository is licensed under the same terms.

---

**[Hawkeye Lab](https://hawkeye-leo.github.io/hawkeye/lab/)** — the author's commercial **game anti-cheat** research console (Windows kernel–level detection and analysis). Hawkeye TFE is unrelated open research (file encryption); if your focus is **game security and cheat detection**, see Lab instead.
