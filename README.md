# virusShare

Peer-to-peer LAN file transfer for Windows. Devices find each other with UDP
broadcast, pair with a one-time code, and move files over an encrypted TCP
connection — no server, no cloud, no accounts.

**Status: complete.** Full application (protocol, discovery, transfer engine,
security, history, PySide6 GUI, system tray, PyInstaller packaging) with
**334 passing unit tests** (1 privilege-dependent skip).

```
Python 3.10+   |   Windows-first (%APPDATA%)   |   PySide6 GUI   |   MIT-style deps
```

---

## Table of contents

1. [Quick start](#1-quick-start)
2. [Features](#2-features)
3. [Repository layout](#3-repository-layout)
4. [Architecture](#4-architecture)
5. [The wire protocol](#5-the-wire-protocol)
6. [Message catalog](#6-message-catalog)
7. [Handshake, pairing and encryption](#7-handshake-pairing-and-encryption)
8. [Transfer flow, resume and conflicts](#8-transfer-flow-resume-and-conflicts)
9. [Path security](#9-path-security)
10. [Discovery](#10-discovery)
11. [The GUI](#11-the-gui)
12. [Settings](#12-settings)
13. [Data locations](#13-data-locations)
14. [Testing](#14-testing)
15. [Packaging](#15-packaging)
16. [Troubleshooting](#16-troubleshooting)
17. [Known limitations](#17-known-limitations)

---

## 1. Quick start

### Run from source

```powershell
pip install -r requirements.txt
python app.py
```

Useful flags:

| Flag | Effect |
|---|---|
| `--minimized` | start hidden (to tray, if available) |
| `--verbose` | DEBUG console logging |
| `--transfer-port N` / `--discovery-port N` | override defaults (54322 / 54321) |
| `--no-discovery` | disable UDP broadcast discovery (paste IP manually) |
| `--version` | print `virusShare 1.0.0` and exit |

### Test

```powershell
python -m pytest -q          # 334 passed, 1 skipped
```

### Build a Windows executable

```powershell
build_windows.bat
# -> dist\virusShare.exe   (single file, no console window)
```

### Send a file between two PCs

1. Start virusShare on both machines (same LAN, Private network profile).
2. On the sending PC pick **SEND FILES**; on the receiving PC pick
   **RECEIVE FILES** (it shows the machine name, IP, link speed and save
   location while waiting).
3. On the sender the peer appears in the receiver list within a couple of
   seconds — select it, add files (**Add Files / Add Folder** or drag & drop
   onto the drop zone) and press **Send Files →**. No peer found? **Manual
   IP…** connects by `IP` or `IP:port` directly.
4. The receiver gets a connection request showing a **6-digit pairing code**
   (identical on both screens) → Approve once. The device is then trusted.
5. The transfer shows up in the queue with speed, progress and ETA; on
   completion the file is opened in Explorer.

---

## 2. Features

- **Auto-discovery** — UDP broadcast beacons (port 54321) with 10 s expiry and
  lost-device detection; manual IP connect always available.
- **Pairing + trust store** — first connection shows a 6-digit code verified
  via cross-signed certificate fingerprints; trusted devices reconnect
  automatically; trust can be revoked from the device panel.
- **TLS-encrypted transfers** — ephemeral TLS session over the TCP channel
  with self-signed ECDSA P-256 certificates; whole-session or per-file
  encryption toggle.
- **Integrity** — streaming SHA-256 per file; the receiver re-hashes while
  writing and only commits the file when the hash matches.
- **Pause / resume / cancel** — chunk-aligned resume from `.etherpartial`
  files across pauses, connection drops and app restarts.
- **Conflict handling** — never overwrites silently; Skip / Replace / Keep
  both / Cancel, with *apply to all*.
- **Reliability** — bounded reconnect with exponential-ish backoff
  (`reconnect_attempts`), send-side concurrency limit, CANCEL propagation.
- **History** — SQLite log of every session (peer, direction, bytes, status,
  duration) with search and pruning.
- **GUI** — PySide6: Send/Receive mode start screen, receiver list with
  drag & drop file staging, device list, transfer queue, animated progress
  bars with speed/ETA, in-window toasts, empty states, light/dark/system
  themes, notifications.
- **System tray** — minimize-to-tray, tray menu (Open / Send / Quit), tray
  notifications on completion.
- **Safe by default** — traversal-proof path handling (see
  [§9](#9-path-security)).

---

## 3. Repository layout

```
virusShare/                  repository root (run pytest here)
├── app.py                   entry point: wiring, CLI args, shutdown
├── conftest.py              sys.path + QT_QPA_PLATFORM=offscreen
├── models.py                TransferSession / TransferFile / TransferStatus
├── core/
│   ├── constants.py         ports, magic bytes, message ids, defaults, paths
│   ├── config.py            Settings (validation, atomic save, unknown keys)
│   └── security.py          Identity, TrustStore, pairing codes, fingerprints
├── network/
│   ├── protocol.py          framing, Message, payload codecs, recv helpers
│   ├── session.py           ConnectionSession + client/server handshake
│   ├── tcp_server.py        TransferServer (threads, handler, TLS)
│   ├── tcp_client.py        TransferClient (connect, TLS, FILE_DATA loop)
│   └── discovery.py         DiscoveryService (UDP announce/collect/expire)
├── transfer/
│   ├── sender.py            push_files, manifest, chunk loop, TransferControls
│   ├── receiver.py          handle_incoming, conflicts, checksum commit
│   ├── manager.py           TransferManager (threads, slots, reconnect, events)
│   ├── resume.py            .etherpartial + sidecar JSON lifecycle
│   ├── checksum.py          streaming SHA-256 helpers
│   └── path_security.py     sanitize_filename / resolve_destination
├── database/history.py      HistoryDB (SQLite, WAL, RLock)
├── gui/                     PySide6 (no __init__.py — namespace packages)
│   ├── main_window.py       window, page stack, menus, wiring, drag & drop
│   ├── role_screen.py       start screen: Send / Receive mode cards
│   ├── sender_screen.py     receiver list, manual IP, drop zone, Send button
│   ├── receiver_screen.py   identity, save location, waiting status
│   ├── bridge.py            ThreadBridge (worker→GUI signals, futures)
│   ├── device_panel.py      discovered/trusted device list + empty state
│   ├── transfer_queue.py    queue table + animated progress delegate
│   ├── animations.py        fade/pulse/row-insert/flash helpers + TickDriver
│   ├── widgets.py           EmptyState / Toast / ToastManager
│   ├── pairing_dialog.py    connection approval (pairing code)
│   ├── conflict_dialog.py   skip/replace/keep-both/cancel (+ apply to all)
│   ├── settings_dialog.py   settings editor
│   ├── history_dialog.py    history browser
│   ├── tray.py              AppTray (guarded by isSystemTrayAvailable)
│   ├── styles.py            light/dark/system QSS + palette
│   └── icons.py             programmatic icons (no binary assets)
├── assets/                  virusShare.ico + version_info.txt (generated)
├── scripts/make_release_assets.py  icon/version-resource generator
├── utils/                   logger, network info, Windows helpers, formatting
├── tests/                   15 test modules, 334 tests
├── virusShare.spec       PyInstaller build description
├── build_windows.bat        install deps → test → build
├── requirements.txt         PySide6, psutil, cryptography, pyinstaller
└── _exp.py                  protocol framing experiment (throwaway)
```

---

## 4. Architecture

```
                GUI thread                          worker threads
        ┌───────────────────────┐          ┌────────────────────────────┐
        │ MainWindow            │          │ TransferManager            │
        │  DevicePanel          │ signals  │  ├ send thread (per session)│
        │  TransferQueue        │◄─────────┤  ├ receive thread           │
        │  dialogs              │  futures │  └ slot pool (concurrency)  │
        │  ThreadBridge ────────┼─────────►│    approval/conflict waits  │
        │  AppTray              │          ├ DiscoveryService threads    │
        └───────────┬───────────┘          │  ├ announcer  └ listener    │
                    │                      ├ TransferServer accept loop  │
        SQLite ◄────┼ ────► %APPDATA%      └ TransferClient threads      │
        HistoryDB   │      settings/trust/partial files                  │
                    └──────── app.py shutdown coordinator ◄──────────────┘
```

Threading rules:

- All widgets are touched only on the GUI thread; worker code communicates
  exclusively through `ThreadBridge` signals (Qt queued connections).
- Blocking prompts (approval, conflict) run in the worker as **futures** on
  `ThreadBridge`: the worker emits a signal, the GUI thread shows a dialog and
  resolves the future — with a timeout fallback (approval → reject, conflict →
  skip) so a dead UI can never hang a transfer.
- `TransferManager` owns lifecycle: FIFO concurrency slots, pause/resume/cancel
  controls, reconnect loop, exactly-once `finished` events, `shutdown()` join.

---

## 5. The wire protocol

Fixed 16-byte header, big-endian (`network/protocol.py`):

```
 0      1      2      3      4              8              12
 +------+------+------+------+--------------+--------------+
 | magic        | ver  | type | sequence     | flags        |
 | "ETHR" (4B)  | u8   | u8   | u16          | u16          |
 +------+------+------+------+--------------+--------------+
 | payload_len (u32)                                        |
 +----------------------------------------------------------+
 | payload …                              (payload_len B)   |
 +----------------------------------------------------------+

struct "!4sBBHII"  → 16 bytes header + payload
magic = b"ETHR", version = 1, max payload = 32 MiB
```

- `sequence` increments per direction for request/response matching.
- Payloads are JSON (UTF-8) for control messages, raw bytes for `FILE_CHUNK`
  / `FILE_DATA`.
- `recv_message(sock)` reads header+payload atomically (`_recv_exact`);
  incomplete frames raise `IncompleteMessage`, bad magic/version raise
  `ProtocolError`.
- Filesystem paths on the wire always use **forward slashes**; `file_id` is
  the normalized relative path.

---

## 6. Message catalog

| Type | id | Payload |
|---|---|---|
| `DISCOVERY` | 0x01 | DeviceInfo (JSON) |
| `DISCOVERY_RESPONSE` | 0x02 | DeviceInfo (JSON) |
| `SESSION_CHALLENGE` | 0x10 | device, cert, nonce, sig |
| `CONNECT_REQUEST` | 0x11 | device, cert, nonce, sig |
| `CONNECT_RESPONSE` | 0x12 | accepted, device, paired, reason |
| `PAIR_CONFIRM` | 0x13 | code |
| `FILE_LIST` | 0x20 | `[FileInfo]` manifest |
| `FILE_REQUEST` | 0x21 | file_id, offset, (name, size, path, mtime, chunk_size on first request) |
| `FILE_RESUME` | 0x22 | file_id, offset |
| `FILE_CHUNK` | 0x23 | `file_id`\|`chunk_index`\|`data` |
| `FILE_DATA` | 0x24 | `file_id`\|`data` (legacy/unframed stream) |
| `FILE_COMPLETE` | 0x25 | file_id, success, checksum |
| `FILE_CANCEL` | 0x26 | file_id |
| `CHECKSUM_REQUEST` | 0x30 | file_id, algorithm |
| `CHECKSUM_RESPONSE` | 0x31 | file_id, checksum |
| `ERROR` | 0x40 | code, message |
| `DISCONNECT` | 0x41 | — |

Error codes: `0x01` protocol, `0x02` not found, `0x03` permission,
`0x04` checksum, `0x05` cancelled, `0x06` timeout, `0x07` busy,
`0x08` rejected (used to cancel an in-flight manifest).

---

## 7. Handshake, pairing and encryption

```
server ──SESSION_CHALLENGE {device, cert, nonce, sig}──► client
client ──CONNECT_REQUEST   {device, cert, nonce, sig}──► server
server ──CONNECT_RESPONSE  {accepted, device, paired, reason}──► client
   │   [untrusted] ──PAIR_CONFIRM {code}──  (6-digit, both sides confirm)
   └── [trusted]   data channel starts immediately
```

- Both sides present a self-signed **ECDSA P-256** certificate
  (`Identity`, 20-year validity) and sign a challenge bundle
  (`virusShare/client/v1` / `…/server/v1` contexts) to prove key
  possession — a passive interceptor cannot spoof identity.
- The **pairing code** is `SHA-256(sorted cert fingerprints)` truncated to
  digits; it is compared against the code rendered in the dialogs. Matching →
  `TrustStore` records `device_id → cert fingerprint`.
- Later connections must present the **same fingerprint**, otherwise the
  session is rejected and the device must be paired again (certificate
  rotation ⇒ visible re-pair, not silent trust).
- After handshake, file payload runs inside TLS (when `enable_encryption`);
  with TLS disabled the protocol is plaintext — shown as such in the UI.
- Rejection reasons surface verbatim to the initiator
  (`"<name> rejected the connection"`).

---

## 8. Transfer flow, resume and conflicts

```
sender                                     receiver
  │ FILE_LIST (manifest)  ─────────────────►│
  │                              conflict? ─┤  skip/replace/keep-both/cancel
  │◄────── FILE_LIST (accepted subset) ─────┤   (or ERROR 0x08 → cancel all)
  │                                         │
  │ FILE_REQUEST {file_id, offset, meta} ──►│   offset = resume point
  │◄──── FILE_RESUME {file_id, offset} ─────┤   (chunk-aligned; 0 = new)
  │ FILE_CHUNK {index, data}* ─────────────►│   streams to .etherpartial
  │◄────── FILE_COMPLETE {checksum} ────────┤   receiver hashes while writing
  │ FILE_COMPLETE {ok, checksum} ──────────►│   hash must match → os.replace
  │ … repeat per file …                     │
  │ DISCONNECT ◄───────────────────────────►│
```

- **Partials:** `<name>.etherpartial` + `<name>.etherpartial.json` sidecar
  (`file_id`, size, mtime, chunk size, sha-so-far). On reconnect the receiver
  asks for the stored offset; the sender re-verifies size/mtime — mismatch
  restarts from 0.
- **Commit rules:** rename via `os.replace` only after SHA-256 matches the
  sender's digest; partials are **kept** on cancel/disconnect (resumable) but
  zeroed on protocol violation.
- **Conflict default = Skip.** Files that don't exist are written directly.
- **Reconnect:** permanent errors (rejected, security violation) are not
  retried; transient drops retry up to `reconnect_attempts` times with backoff
  `RECONNECT_BACKOFF × attempt`, then the session fails visibly.

---

## 9. Path security

`transfer/path_security.py` — applied to every manifest entry and every
destination write:

- reject absolute paths, drive letters, UNC (`\\server\share`), `..`
  segments, alternate data streams (`file.txt:stream`), reserved device names
  (`CON`, `NUL`, `PRN`…), control characters, names > 200 chars, relpaths
  > 400 chars;
- resolve the final destination against the receive root and re-check that
  it stays inside it (**symlink/`..` escape → reject**, tested with a real
  symlink);
- the receiver never trusts `path` from the wire for the actual write — only
  the sanitized `relpath` joined under `save_received_files_to`.

---

## 10. Discovery

- Every instance broadcasts `DISCOVERY` (DeviceInfo JSON) to
  `255.255.255.255:54321` every 2 s (`BROADCAST_INTERVAL`) and answers
  `DISCOVERY_RESPONSE` to direct probes.
- Received beacons are merged into a device table with `last_seen`;
  `device_timeout` (10 s) raises `on_device_lost` → panel removal.
- Device id is stable per machine (registry machine GUID on Windows,
  `get_stable_device_id()`); display name is editable at runtime via
  `update_device_info(device_name=…)` (renames do **not** change device id).
- Socket lifecycle is race-safe: loops snapshot the socket and re-check for
  `None` so `stop()` can never hit `sendto` on a closed socket.

---

## 11. The GUI

The app opens on a **role screen**; each mode is a page in the window's
stack, so tray, close and toasts keep working everywhere:

```
┌ virusShare ──────────────────────────────── [—][□][×] ┐
│                virusShare                             │
│     Peer-to-peer file transfer, no cloud.             │
│           Which side are you on today?                │
│   ┌────────────────────┐   ┌────────────────────┐     │
│   │      📤 SEND FILES │   │   📥 RECEIVE FILES │     │
│   │ pick a PC, send…   │   │ wait for a sender… │     │
│   └────────────────────┘   └────────────────────┘     │
│                                     ⚙ Settings        │
└───────────────────────────────────────────────────────┘
```

- **Role screen** — two large cards (Send / Receive) plus a Settings link;
  menu and status bar stay hidden until a transfer flow reaches the
  workspace.
- **Sender screen** — live receiver list (auto-refreshes from discovery,
  exclusive single selection), **Manual IP…** dialog, drag & drop **drop
  zone** + Add Files/Add Folder, staged-file list with count and Clear, and
  a **Send Files →** button gated on *device + files*; Back returns to the
  role screen. Sending lands on the workspace (queue).
- **Receiver screen** — machine name, primary IP, link speed
  (`Ethernet • 1 Gbps`), save location with **Change Location**, and a
  waiting-for-connection status; Back returns to the role screen.
- **Workspace (home)** — the classic split view:

```
┌ virusShare ──────────────────────────────────────── [—][□][×] ┐
│ File  Edit  Transfer  Help                                      │
├───────────────┬─────────────────────────────────────────────────┤
│ Devices       │ Transfer queue                                  │
│               │ ┌──────┬────────┬──────┬────────┬─────────────┐ │
│ ● LAPTOP-7    │ │Peer  │File    │Dir   │Progress│Status       │ │
│ ○ DESKTOP-2   │ │…      │…       │…     │ 42 %   │ sending     │ │
│               │ └──────┴────────┴──────┴────────┴─────────────┘ │
│ [Send files]  │  [Pause] [Resume] [Cancel] [Open location] …    │
└───────────────┴─────────────────────────────────────────────────┘
```

- **Device panel** — devices discovered (or pasted manually), trust badge;
  **Send files…** button and right-click menu (send, remove trust). Revoking
  trust only removes trust, never the device entry. Empty panel shows a
  centered "Searching for devices…" hint; newly discovered devices flash in.
- **Manual connect** — **File → Connect to IP…** (workspace) or the sender
  screen's **Manual IP…** button sends to `IP` or `IP:port` directly, for
  networks where UDP broadcast discovery is blocked.
- **Drag & drop** — on the sender screen, files land in the staged list;
  on the workspace, dropping files/folders starts a transfer to the
  selected device (status bar warns if none is selected).
- **Transfer queue** — one row per session, animated progress bar under the
  file name (smoothly interpolated, shimmer while active), aggregate progress,
  status from `TransferStatus`, contextual buttons (pause/resume/cancel/open/
  clear finished); empty queue shows a centered hint.
- **Toasts** — transient in-window notices (transfer complete, trust changes)
  anchored bottom-right; minimized → tray balloon instead.
- **Pairing dialog** — shows peer, IP, fingerprint and the 6-digit code with
  Approve/Reject; also used for auto-accept decisions of trusted devices.
- **Conflict dialog** — per-file details (size vs existing) + Apply-to-all.
- **Settings dialog** — destinations, concurrency, chunk size, encryption,
  approval mode, theme, notifications, autostart; validated through
  `Settings` before save.
- **History dialog** — searchable session log (peer/file filter, clear all).
- **Tray** — when a system tray exists: close button minimizes to tray while
  transfers run (confirmed otherwise), tray menu, balloon notifications; all
  guarded by `isSystemTrayAvailable()` so headless/CI hosts log and continue.

---

## 12. Settings

Stored as JSON in `%APPDATA%\virusShare\settings.json`
(`core/config.py` — defaults merged, values validated, unknown keys
preserved, atomic write):

| Key | Default | Notes |
|---|---|---|
| `save_received_files_to` | `~/Downloads/virusShare` | receive root |
| `enable_encryption` | `true` | TLS session |
| `require_connection_approval` | `true` | prompt untrusted peers |
| `auto_accept_trusted` | `false` | skip prompt for trusted devices |
| `max_concurrent_transfers` | `3` | send-side slot pool |
| `reconnect_attempts` | `3` | 0–10; transient drops only |
| `chunk_size` | `1048576` | 64 KiB–8 MiB, 64 KiB aligned |
| `verify_checksums` | `true` | streaming SHA-256 |
| `transfer_port` / `discovery_port` | `54322` / `54321` | 1–65535 |
| `buffer_size` | `65536` | socket read buffer |
| `theme` | `system` | `light` \| `dark` \| `system` |
| `language` | `en` | |
| `minimize_to_tray` | `true` | |
| `show_notifications` | `true` | |
| `start_with_windows` | `false` | HKCU Run key |
| `preferred_network_adapter` | `auto` | broadcast source selection |
| `trusted_devices` | `[]` | mirror of trust store |

---

## 13. Data locations

```
%APPDATA%\virusShare\
├── settings.json          settings
├── identity.pem           long-lived ECDSA key (keep private!)
├── trust.json             device_id → certificate fingerprint
├── history.db             SQLite (WAL)
└── logs\virusShare.log rotating log

%USERPROFILE%\Downloads\virusShare\    default receive folder
<receive root>\*.etherpartial(.json)      resumable partials, cleaned on commit
```

On first launch the folders, identity and defaults are created automatically.

---

## 14. Testing

```powershell
python -m pytest -q          # 334 passed, 1 skipped (~55 s)
```

| Module | Focus |
|---|---|
| `test_protocol.py` | framing, header codec, payload round-trips |
| `test_network.py` | TCP server/client, handshake accept/reject, TLS |
| `test_transfer.py` | sender/receiver end-to-end, checksums, cancellation |
| `test_resume.py` | partial lifecycle: prepare/resume/restart/mismatch |
| `test_security.py` | pairing codes, trust store, path traversal, manifest abuse |
| `test_manager.py` | concurrency slots, pause/resume/cancel, reconnect, events |
| `test_discovery.py` | announce/collect/expire/stop-race |
| `test_history.py` | SQLite record/search/prune/corrupt-JSON resilience |
| `test_models.py` | domain model totals, status transitions |
| `test_config.py` | validation, atomic save, unknown keys, data-dir migration |
| `test_utils.py` | formatting, network helpers, Windows helpers |
| `test_gui.py` | offscreen Qt: window, panels, dialogs, bridge, tray, animations |
| `test_role_flow.py` | offscreen Qt: role/sender/receiver screens, navigation |
| `test_release.py` | icon, version resource, `--version`, about text |
| `test_e2e.py` | real-loopback end-to-end: pair, transfer, resume, conflicts |

Notes:

- `conftest.py` forces `QT_QPA_PLATFORM=offscreen` before any Qt import, so
  the GUI tests run headless (CI-friendly).
- Network tests use loopback with **monkeypatched peers** where a
  connect-to-dead-port test would be flaky (this host drops SYNs to closed
  ephemeral ports instead of refusing).
- The single skip is a symlink-escape test that needs privileges to create
  real symlinks on some systems.

---

## 15. Packaging

```powershell
build_windows.bat
```

runs `pip install -r requirements.txt` → `pytest -q` (refuses to package a
broken build) → `python -m PyInstaller --clean --noconfirm virusShare.spec`
→ `dist\virusShare.exe`.

- Single-file, **windowed** (no console), no UPX, branded `virusShare.ico`
  icon and Windows version resource (Product/FileDescription/`virusShare.exe`)
  generated by `scripts/make_release_assets.py`.
- The spec excludes unused heavy Qt modules (WebEngine, Quick/Qml, Charts,
  Multimedia, …) to keep the bundle small; verified to boot headless
  (server binds, discovery starts, log written).

---

## 16. Troubleshooting

| Symptom | Fix |
|---|---|
| Peer not listed | same LAN + *Private* profile; allow Python/virusShare in Firewall for UDP 54321 + TCP 54322; or **File → Connect to IP…**; check `preferred_network_adapter` |
| "rejected the connection" | peer has *Require approval* and you're not trusted, or its certificate changed (re-pair); check your own approval dialog |
| Transfer stalls after network change | reconnect runs up to `reconnect_attempts`; resume continues from the partial automatically |
| Port already in use | Settings → ports, or launch with `--transfer-port`/`--discovery-port` |
| No tray icon | host has no system tray (RDP/CI) — app continues normally, see log |
| Corrupt settings | settings file is backed up and defaults restored on parse failure |
| Checksum failure | partial is discarded (0 bytes) and the file re-sent; see log for the file id |

Logs: `%APPDATA%\virusShare\logs\virusShare.log` (add `--verbose` for
console DEBUG).

---

## 17. Known limitations

- Windows-first: registry machine id, HKCU autostart, `%APPDATA%` paths;
  other platforms run but without those conveniences.
- IPv4 only; broadcast discovery needs a non-public (Private) network
  profile for Windows Firewall to allow it by default.
- One transfer session per peer connection; multiple files per session.
- Directory listings in history are session-level (no per-file history rows).
- No code signing / branded icon in the built exe yet.
# VIRUSSHARE
