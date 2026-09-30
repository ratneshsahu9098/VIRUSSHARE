# Changelog

All notable changes to virusShare are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-09-29

First complete release.

### Added

- UDP broadcast discovery with 10 s expiry, lost-device detection and manual
  **Connect to IP…** fallback.
- Pairing with 6-digit codes (SHA-256 of certificate fingerprints), trust
  store with revocation from the device panel.
- TLS-encrypted transfers (ECDSA P-256, per-session or whole-session toggle),
  streaming SHA-256 verification on both ends.
- Pause / resume / cancel with chunk-aligned resume from `.etherpartial`
  files across pauses, drops and restarts; conflict dialog with
  skip / replace / keep-both / cancel and apply-to-all.
- Bounded reconnect, send-side concurrency slots, CANCEL propagation.
- SQLite transfer history with search and pruning.
- PySide6 GUI: device list, transfer queue with animated progress bars,
  drag & drop to send, in-window toasts, empty states, light/dark/system
  themes, pairing/conflict/settings/history dialogs, system tray with
  minimize-to-tray and balloon notifications.
- End-to-end tests over real loopback (pair, transfer, resume, unicode
  paths, conflicts, late receivers).
- PyInstaller packaging: single-file windowed exe with branded icon and
  Windows version resource; `build_windows.bat` runs the test suite before
  building.
- `--version` CLI flag; Help → About shows Qt/Python/data locations.
- Sender/Receiver mode selection: a start screen with **Send Files** /
  **Receive Files** cards; a sender screen (live receiver list with single
  selection, Manual IP dialog, drop zone + Add Files/Add Folder staging,
  Send button gated on device + files); a receiver screen (machine name,
  IP, link speed, save location with Change Location, waiting status).

### Changed

- Renamed the application to **virusShare**: window/tray titles, exe name,
  log file, `%APPDATA%\virusShare` data dir and the HKCU Run autostart key.
  Existing installs migrate automatically — the old data directory is
  renamed once on startup and the legacy autostart entry is removed.

### Security

- Traversal-proof path handling (absolute paths, `..`, UNC, drive letters,
  reserved names, alternate data streams, symlink escapes all rejected).
- Certificate fingerprint pinning: trust does not silently survive a
  certificate rotation — the device must be paired again.
