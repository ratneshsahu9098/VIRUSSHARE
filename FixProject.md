# FixProject.md — virusShare bug/fix backlog

Audit date: 2026-09-29. Three deep reviews (network+transfer / GUI / core+utils)
plus hands-on reproduction of the top claims.

**Baseline:** `python -m pytest -q` → **336 passed, 1 skipped** (~52 s).
**Current (2026-09-29):** Phase 1 + H7 + Phase 2 (H1–H9) + Phase 3 GUI
(M1–M14) → **378 passed, 1 skipped** (~56 s), 42 net regression tests
added (43 written; M2 replaced the old once-per-device contract test).

Legend — verification status of each finding:

- `[run]` = reproduced by executing code in this session
- `[code]` = confirmed by reading the cited lines myself
- `[report]` = from the automated audit, not independently re-verified

Severity: **CRITICAL** (broken core flow / security), **HIGH** (data loss,
wrong target, crash), **MEDIUM** (wrong UX/state, latent race), **LOW** (hygiene,
polish).

---

## Phase 0 — repo hygiene (5 min)

- [ ] **L1** No `.gitignore` — next `git add .` would commit `dist/`, `build/`,
      `__pycache__/`, `.pytest_cache/`, `*.log`, `_exp.py`. `[code]`
      → create `.gitignore`: `__pycache__/`, `dist/`, `build/`, `.pytest_cache/`,
      `*.log`, `_exp.py`, `*.tmp`.
- [ ] **L2** Only `README.md` is tracked; all source untracked (README also has
      an uncommitted fix: known-limitations line). `[code]`
      → commit remaining source after Phase 1 lands (or now, if preferred).
- [ ] **L3** `_exp.py` throwaway file in repo root. `[code]` → delete or gitignore.

---

## Fixed

### 2026-09-29 — Phase 1: C1–C4 (CRITICAL) ✅

Reproduce-first: 4 regression tests written and confirmed failing before the
fixes. Full suite **340 passed, 1 skipped** (336 baseline + 4).
`dist\virusShare.exe` rebuilt; `python app.py --version` and exe `--version`
both print `virusShare 1.0.0`, exit 0.

- [x] **C1** — `gui/bridge.py:_wait` popped the future *before* waiting, so a
  GUI answer landing after the emit (the normal queued-signal case) found
  `future is None` and was discarded → every approval/conflict dialog fell
  back to its default after the full 300 s timeout. Fixed: look the future
  up, wait on it, pop in a `finally` (`_resolve`'s `not done()` guard makes
  late/duplicate resolves a no-op). *Test:*
  `test_bridge_queued_prompt_roundtrip` — worker emits, GUI resolves later,
  worker returns the click in < 2 s instead of the default after 3 s. `[run]`
- [x] **C2** — `gui/bridge.py:make_approval_callback` returned `True` whenever
  the setting was on, with no trust check; combined with
  `network/session.py:312` (callback only fires for **untrusted** peers) this
  auto-paired unknown LAN devices and re-pinned fingerprints → MitM.
  Fixed: new `trust_store` parameter (wired in `app.py`), auto-accept only
  when `trust_store.is_trusted(device_id, peer_fp)`; everything else prompts.
  ⚠️ **Follow-up:** since the session only asks about untrusted peers, the
  "accept trusted devices without asking" checkbox is now inert-but-safe —
  the label claims behavior the flow cannot trigger (UX pass candidate).
  *Test:* `test_auto_accept_only_for_trusted_peers` (trusted fp → auto, no
  prompt; stranger → prompted). `[code]`
- [x] **C3** — `core/security.py:206` derived the displayed short code from
  `digest[:4]` (16 bits): every code was `0xxxxx`, `% 1_000_000` a no-op,
  only 65 536 possible codes for the human comparison the UI instructs.
  Fixed: `int(digest[:16], 16) % 1_000_000` (64-bit prefix → uniform 6
  digits); wire `canonical` unchanged. *Test:*
  `test_pairing_short_code_uses_full_entropy` — 64 samples, max > 65535, no
  permanent leading zero. `[code]`
- [x] **C4** — `gui/device_panel.py:remove_device`: `takeItem` on the current
  row slides the current-row marker onto a neighbour → after removing the
  selected peer, `selected()` returned the next device and the send button
  stayed enabled → transfer could target the **wrong machine**. Fixed: if the
  removed row was current, `setCurrentItem(None)` (the existing
  `currentItemChanged` hook disables the send button). *Test:*
  `test_removing_selected_device_clears_selection`. `[run]`

### 2026-09-29 — H7 (HIGH): trusted badge from self-asserted UDP id ✅

The list's "Trusted" badge was set in `app.py`'s discovery callback from
`trust_store.is_trusted(device_id)` alone — any LAN host broadcasting a known
`device_id` earned the badge, contradicting `security.py:218-221` (device_id is
never proof of identity). Fixed: discovery only refreshes the list; the badge
now comes exclusively from fingerprint-verified sources.

- [x] `app.py:make_device_found_handler` — discovery packets never touch the
  badge (plain pass-through emit).
- [x] `bridge.deviceTrusted = Signal(str, bool)` — new verification signal.
- [x] `app.py:make_session_handler` — server side emits it when
  `conn_session.result.trusted` (fp matched the store at handshake,
  `session.py:302/362`); `TransferManager(on_peer_trusted=...)` does the same
  on the sender side after `client.connect` (`session.py:492`).
- [x] `MainWindow` — `deviceTrusted → devices.set_trusted` (badge/tooltip);
  trust **revocation** in `_toggle_trust` now also emits the signal so the
  app-side discovery record is cleared (a revoked peer could otherwise
  resurrect its badge on re-find).
- ⚠️ Note: `sender_screen` rows still refresh only on re-emit — badge updates
  after verification land in `DevicePanel` only (safe direction: under-trust,
  never over-trust). Sender-row refresh on trust change stays in **M3**.
- *Tests:* `test_discovery_packet_never_earns_trusted_badge`,
  `test_device_trusted_signal_updates_badge`,
  `test_session_handler_marks_fp_verified_peer`,
  `test_send_reports_fp_verified_peer` (all RED pre-fix).

**H7 sign-off (2026-09-29):** 344 passed, 1 skipped · 4 regression tests
(reproduce-first) · no swallowed exceptions (new catches all log) · exe
rebuilt + `--version` smoke (source + exe, exit 0).

### 2026-09-29 — Phase 2: H1–H9 (HIGH) ✅

Reproduce-first throughout: all 14 new tests (9 Group A, 5 Group B) confirmed
RED before the fixes, with these exact reasons — H3 network: `DID NOT RAISE
RuntimeError` (Windows `SO_REUSEADDR` let a second server double-bind); H3
subprocess: uncaught `RuntimeError: Cannot bind…` traceback, rc 1 not 2;
H6: `ImportError: acquire_instance_lock`, `subprocess.TimeoutExpired`
(second instance started the full GUI), `RuntimeError: window blew up`
propagating out of `main()` (server/history leaked); H1/H2/H4/H5/H8/H9:
receiver discarded checksum-less file, crashed session left ACTIVE, settings
never reached the manager, corrupt trust store silently wiped, case-colliding
manifest entries double-committed, mid-transfer file overwritten at commit.

**Group A:**

- [x] **H1** — `transfer/receiver.py:_finalize`: empty declared checksum is the
  sender's verification opt-out → accept by size (per decision Q1); a
  *mismatched* non-empty checksum still discards. *Test:*
  `test_receiver_accepts_when_sender_disables_checksums`.
- [x] **H2** — `app.py:make_session_handler`: any handler exception (malformed
  `FILE_LIST`, `file_id.decode`, bugs) now logs + produces
  `ReceiveReport(error=…)` and `finally: manager.finish_receive(...)` → no
  session stuck ACTIVE, history row always written. Unused top-level
  `handle_incoming` import removed. *Test:*
  `test_session_handler_finishes_receive_on_crash`.
- [x] **H4** — `transfer/manager.py:apply_settings(settings)` (receive_dir,
  chunk_size, verify, encryption, max_concurrent, reconnect_attempts under the
  lock); called from `main_window._change_receive_location` **and**
  `show_settings` — "Change Location" now actually redirects incoming files.
  *Tests:* `test_settings_changes_reach_transfer_manager`,
  `test_receive_location_change_updates_manager`,
  `test_apply_settings_updates_receive_dir_and_tunables`.
- [x] **H5** — `core/security.py:TrustStore`: unreadable/corrupt store is
  renamed `*.corrupt-<ts>` + `log.error` before starting empty (trust is never
  silently wiped); `save()` now `flush()` + `os.fsync()` before `os.replace`.
  *Tests:* `test_corrupt_trust_store_is_backed_up_not_wiped`,
  `test_trust_store_save_fsyncs_before_replace`.
- [x] **H8** — `receiver.py:_accept_manifest`: seen-set keyed by
  `os.path.normcase(relpath)` → `a.txt` + `A.txt` no longer share one
  `.etherpartial` and double-commit. *Test:*
  `test_case_differing_manifest_entries_are_deduplicated`.
- [x] **H9** — `receiver.py`: dest `(mtime_ns, size)` captured per file at
  plan time; before `resume.commit()` a `_dest_changed` re-check escalates to
  the conflict callback if the destination appeared/changed **during** the
  transfer (REPLACE/KEEP_BOTH proceed; SKIP/CANCEL keep the partial and fail
  the file instead of overwriting). *Test:*
  `test_file_created_during_transfer_is_not_overwritten`.

**Group B:**

- [x] **H3** — `app.py`: `server.start()` failure now caught as
  `(OSError, RuntimeError)` → clean log + exit 2 (no traceback);
  `network/tcp_server.py`: `SO_REUSEADDR` set only off Windows so a second
  instance cannot silently double-bind a taken port. *Tests:*
  `test_second_server_on_same_port_raises`,
  `test_app_exits_cleanly_when_transfer_port_is_taken`.
- [x] **H6** (decision Q4: block 2nd launch + message) — `app.py`:
  `acquire_instance_lock()` (`QLockFile` at `%APPDATA%\virusShare\virusShare.lock`,
  taken right after `setup_logging`, before any settings/identity/history is
  touched → no identity-creation race); second instance prints
  "virusShare is already running…" and shows an info dialog
  (`VIRUSSHARE_NO_DIALOG=1` test hook) → exit 1; stale locks from dead
  processes auto-reclaim. Post-bind startup (discovery/window/tray/exec) is
  wrapped `try/except Exception → log.exception("startup failed") + rc 1
  finally: shutdown()` — accept loop, discovery, manager and SQLite are
  released on any startup failure. *Tests:*
  `test_instance_lock_blocks_second_holder`,
  `test_second_instance_bows_out`,
  `test_startup_failure_after_bind_shuts_everything_down`.

**Phase 2 sign-off (2026-09-29):** 358 passed, 1 skipped (344 + 14 new) ·
all 14 regression tests reproduce-first (confirmed RED) · no swallowed
exceptions (new catches all log) · `dist\virusShare.exe` rebuilt + `--version`
smoke (source + exe, exit 0) · this file updated.

### 2026-09-29 — Phase 3 GUI: M1–M14 (MEDIUM) ✅

Reproduce-first: 21 tests written and confirmed RED first (exact reasons in
the per-item notes). Two contract tests updated where the fix intentionally
changes behavior (M2 discovery, M12 status bar). Decisions: **Q2** Esc/X on
the conflict dialog = *Skip*; **Q3** back-navigation = *Menu "Mode…" + tray*.

- [x] **M1** — `conflict_dialog.ask`: rejected (Esc/X) maps to `"skip"` (the
  default button/timeout) instead of `"cancel"`; explicit "Cancel transfer"
  still cancels. *Tests:* `test_conflict_dialog_reject_maps_to_skip`
  (RED `- skip + cancel`), `..._explicit_cancel_still_cancels`,
  `..._apply_all_survives_accept`.
- [x] **M2** — `discovery._handle_packet`: `deviceFound` re-fires on **every**
  beacon (REQUEST and RESPONSE branches), not only on first sighting; cleared
  lists (View→Refresh, manual-connect clear) repopulate within one broadcast
  interval instead of ~10-12 s. *Test:* `test_found_refires_on_each_beacon`
  (RED: no re-emit) — replaced `test_found_fires_once_per_device`.
- [x] **M3** — `sender_screen.DeviceRow`: labels stored (`_name/_meta/_status/
  _icon`) + `refresh()`; `upsert_device` repaints existing rows (name/IP/
  status/trust). *Test:* `test_sender_row_refreshes_on_device_update`
  (RED: `AttributeError: _name`).
- [x] **M4** — `SenderScreen.remove_device` calls `_update_send_button()` when
  the removed device was selected. *Test:*
  `test_sender_remove_device_disables_send_button` (RED: button stayed on).
- [x] **M5** — `_on_row_selected` sets `set_selected(True)` on the clicked row
  → `#devrow[selected]` highlight works for user clicks. *Test:*
  `test_sender_click_highlights_selected_row` (RED: property `None`).
- [x] **M6** — `_handle_drop`: drops on role/receiver pages switch to the
  sender screen and collect the paths there (a dropped file is a send
  intent) instead of dispatching invisibly to the hidden workspace;
  home/workspace behavior unchanged. *Tests:*
  `test_drop_on_role_screen_opens_sender_with_paths`,
  `test_drop_on_receiver_screen_opens_sender_with_paths` (RED: page unchanged).
- [x] **M7** (Q3) — File menu gains **"Mode…"** → `show_role_screen`; tray
  gains `modeRequested` signal + "Switch mode" action (wired in `app.py`).
  *Tests:* `test_mode_menu_action_returns_to_role_screen`,
  `test_tray_offers_switch_mode_action` (RED: no such action).
- [x] **M8** — Conflict/Approval/History/Settings/ManualConnect dialogs set
  `WA_DeleteOnClose` (verified: Qt deletes them before `exec()` returns, so
  only Python attrs may be read afterwards — `ManualConnectDialog` now
  pre-captures the peer in `_validate_accept` and exposes `result_info`;
  `ConflictDialog.ask` reads only Python attrs). *Test:*
  `test_dialogs_declare_delete_on_close` (RED: `ConflictDialog lacks
  WA_DeleteOnClose`).
- [x] **M9** — `animations.flash_item_background`: `_tick`/`_reset` guard with
  `shiboken6.isValid(item)` and stop the animation when the item was deleted
  (clear/takeItem during a flash no longer raises `RuntimeError` every
  frame). *Test:* `test_flash_ticks_are_safe_after_item_deletion`
  (RED: excepthook captured `RuntimeError: Internal C++ object already
  deleted`).
- [x] **M10** — `SettingsDialog._save` restructured: stage → validate (any
  `SettingsError` restores originals, logs, warns, dialog stays open);
  persist (`save()` failure restores + logs + warns); compute
  `restart_needed` (ports + encryption); mkdir best-effort (logged);
  registry autostart **only after** the file is on disk (logged on failure);
  `show_settings` shows "Settings saved — restart virusShare…" when
  `restart_needed`. *Tests:*
  `test_settings_dialog_reports_invalid_value_and_stays_open` (RED: dropped
  silently), `test_settings_dialog_autostart_only_after_successful_save`
  (RED: `OSError` escaped + registry touched first),
  `test_settings_dialog_flags_network_restart` (RED: no `restart_needed`),
  `test_show_settings_mentions_restart_for_port_change` (RED: message had no
  restart hint).
- [x] **M11** — `TransferQueue._cleared_ids`: `clear_finished` marks removed
  terminal ids (capped 256); `upsert_session` ignores later terminal updates
  for them (history recording in `_on_session_finished` unaffected); a
  session that goes active again is un-marked. *Test:*
  `test_cleared_finished_row_stays_cleared` (RED: row resurrected).
- [x] **M12** — `_goto` no longer hides the status bar off home → status
  messages (settings saved, save location updated, sending…) are visible on
  every page. Contract test updated: `test_window_starts_on_role_screen`
  now asserts the bar is visible; new *Test:*
  `test_status_bar_stays_visible_off_home` (RED: `hidden on
  show_role_screen`).
- [x] **M13** — `closeEvent`: X/ESC (`NoButton`) on the "hide to tray?" prompt
  aborts the close instead of falling through to the quit confirmation;
  explicit No still asks "Quit anyway?". *Test:*
  `test_close_dismiss_first_dialog_stops_quit` (RED: `2 == 1` dialogs).
- [x] **M14** — `TransferQueue._can_open_folder(status)` (COMPLETED, FAILED,
  **CANCELLED**) shared by the Open-folder button and the context menu;
  cancelled transfers with partials can open their folder. *Test:*
  `test_open_folder_available_for_cancelled` (RED: button disabled).

**Phase 3 GUI sign-off (2026-09-29):** 378 passed, 1 skipped (358 + 20 net) ·
21 regression tests reproduce-first (all confirmed RED) + 1 contract test
updated for intended behavior changes (M12) · no swallowed exceptions (new
catches all log) · `dist\virusShare.exe` rebuilt + `--version` smoke (source +
exe, exit 0) · this file updated.

---

## Phase 2 — HIGH

~~All of H1–H9 fixed and moved to **Fixed** above (2026-09-29).~~ See
"Phase 2: H1–H9" in the Fixed section for per-item details and tests.

---

## Phase 3 — MEDIUM

### GUI

~~M1–M14 fixed and moved to **Fixed** above (2026-09-29).~~ See
"Phase 3 GUI: M1–M14" for per-item details and tests.

### Engine / core (M15–M36 — open)

| ID | Where | Problem |
|---|---|---|
| M15 | `sender.py:367` × `receiver.py:366` | Sender reads to EOF with no cap at declared `size`; a file growing during send → receiver `ProtocolError` → **whole batch** aborts, retried 3× |
| M16 | `receiver.py:120-123` | Sender-initiated cancel/disconnect → `aborted` path returns report but `completed = True` set on the normal path → peer-cancel reported **COMPLETED** |
| M17 | `sender.py:209-210` | `all(r.success for r in active)` with everything skipped → `all([])` is True → session **COMPLETED with 0 bytes** |
| M18 | `manager.py:344-352` | `cancel()` mutates status without the lock and without checking `_finalized` → can flip COMPLETED→CANCELLED after history was written; unlocked reads at `:322,333,344` |
| M19 | `app.py:200` × `bridge.py:46, 93-94` | `conflict_override` is one shared attribute reset per connection → concurrent receives clear/inherit each other's "apply to all" (can auto-`replace` without prompting) |
| M20 | `bridge.py:26-27` (300 s) vs `constants.py:40` (180 s) | Prompt windows outlive socket timeouts — dialog still open while peer already gave up |
| M21 | `manager.py:275` | `report.error` only carries session-level errors → file-level `"Checksum mismatch"` etc. surface as generic `"transfer failed"` |
| M22 | `receiver.py:429-433` | Socket errors in the chunk loop (incl. `session.expect` at :348) reported as `"disk error: ..."` |
| M23 | `tcp_server.py:146, 176-177` | Raw conn detached by `wrap_socket` before being tracked → `stop()` can't close a peer stuck in the approval dialog; `_handle_connection` never re-checks `_running` → files can arrive after stop; `:125` join-timeout then `clear()` hides survivors; accept thread never joined |
| M24 | `manager.py:507-510` | `shutdown()` clears `_sessions/_threads` even when `wait_all` expired → later `wait_all()` returns True immediately; hung workers invisible |
| M25 | `tcp_client.py:50-51` | No `try/finally` around handshake → malformed-field exceptions (`KeyError` from `_unb64(data["cert"])`, `protocol.py:334`) leak the raw socket |
| M26 | `history.py` | `prune()` never called (unbounded growth); write on UI thread with `timeout=15.0` → up to 15 s freeze; corrupt DB bricks startup (`HistoryDB()` unguarded at `app.py:193`); `close()` skips `conn.close()` if `commit()` raises |
| M27 | `app.py:266-273` | Shutdown runs twice (`closeEvent` → `on_shutdown` → then `finally`); `manager.shutdown(8.0)` blocks the GUI thread; manager stopped **before** server → accepts new peers while shutting down; `history.close()` runs while `sessionFinished` still queued → those rows are lost |
| M28 | `config.py:104-107` | Transient read failure (AV lock) → defaults in memory → next `set/save` permanently overwrites the real settings file |
| M29 | `constants.py:137-145` | Legacy data-dir migration: any rename failure is swallowed, next `mkdir` makes `new.exists()` true forever → old identity/trust/history orphaned silently |
| M30 | `app.py:115-118` | `--transfer-port 80` → raw `SettingsError` traceback; `--transfer-port 0` ignored by truthiness check |
| M31 | `protocol.py:493-500` / `utils/network.py:90-97` | On a no-default-route LAN, fallback announces `127.0.0.1` to peers |
| M32 | `logger.py:50-53` | Peer-supplied device names with `\n` can forge log records (names flow into `log.info/exception`) |
| M33 | `models.py:137-158` | `add_file` can mutate `total_size` mid-transfer; `get_progress()` unclamped → >100 %, negative ETA for any consumer that doesn't clamp |
| M34 | `security.py:241-242, 264` | Trust records not schema-validated → `record.get(...)` raises `AttributeError` inside handshake if the JSON value is a string/list |
| M35 | `discovery.py:164, 197` | `join(2.0)` vs 2.0 s broadcast sleep → thread likely not joined; `start/stop` restart can accumulate duplicate broadcast threads |
| M36 | `main_window.py` dialogs | Approval dialogs stack modally (one nested `exec()` per concurrent peer) |

---

## Phase 4 — LOW

| ID | Where | Problem |
|---|---|---|
| L4 | `virusShare.spec:24` | `ensure_assets(_ROOT)` passes a path as `force: bool` → truthy → every build rewrites version file + icon `[code]` |
| L5 | `build_windows.bat:42` | `%discovery%` never set → literal printed in help text |
| L6 | `utils/windows.py:119` | `executable` param of `set_autostart` is dead code |
| L7 | `config.py:38,45` | `buffer_size` / `preferred_network_adapter` validated but never read |
| L8 | `logger.py:55-57` | RotatingFileHandler not multi-process safe (two instances lose records) |
| L9 | `utils/network.py:143-150` | Malformed netmask → `ValueError` escapes `broadcast_targets` (discovery's own copy is guarded) |
| L10 | `security.py:123-126` | `os.chmod 0600` is a no-op for real ACLs on Windows; brief 0666 window on POSIX; partial `identity.pem` → app refuses to start with no auto-repair |
| L11 | `history.py:273` | `%`/`_` in search act as wildcards (parameterized — no injection — but no `ESCAPE`) |
| L12 | `make_release_assets.py:30, 99` | Non-numeric version (`1.0.0-beta`) crashes at spec-exec time; version file write not atomic |
| L13 | `animations.py:235-238` | `TickDriver._tick` swallows all exceptions → delegate bugs invisible |
| L14 | `history_dialog.py:53, 101-103` | DB read error → modal QMessageBox **per keystroke** |
| L15 | `main_window.py:461-463` | Theme change re-styles only MainWindow subtree → parentless tray `QMenu` keeps old theme |
| L16 | `transfer_queue.py:361` × `animations.py:173-174` | `remove_session` drops row animation without `stop()` → animates wrong (shifted) row indices |
| L17 | `constants.py` migration + legacy autostart | Working as intended; covered by tests (`test_config.py`, `test_utils.py`) — listed here only so it isn't "cleaned up" by accident |
| L18 | `session.py:153-158` | No send lock / no "poisoned after timeout" flag — latent only (single-threaded ownership today) |
| L19 | `app.py` tray path | Hide-to-tray answered "Yes" while `tray.available` is False → window hidden, no tray, unreachable app |
| L20 | `discovery.py` / `app.py:124` | `device_id` from `uuid.getnode()` (MAC) — randomized MACs on Windows can orphan all trust records |

---

## Suggested execution order

1. ~~**Phase 1 (C1-C4)**~~ — **done 2026-09-29** (see Fixed).
2. ~~**Phase 2 (H1-H9)**~~ — **done 2026-09-29** (see Fixed; 14 new regression
   tests, suite at 358 passed / 1 skipped).
3. **Phase 3** — ~~GUI (M1-M14)~~ **done 2026-09-29** (suite at 378 passed /
   1 skipped); engine (M15-M36) still open — one PR, full suite green.
4. **Phase 4** — opportunistic, batch with any touching PR.

## Definition of done (each PR)

- [ ] `python -m pytest -q` → all green (baseline 336 passed, 1 skipped; each
      fix adds its regression test → count must grow)
- [ ] New regression test for every CRITICAL/HIGH fix (reproduce-first: assert
      the failure, then fix)
- [ ] No new bare `except` / swallowed exceptions
- [ ] Rebuild `dist\virusShare.exe` after any `app.py`/`gui`/`core` change
      (`Get-Process virusShare | Stop-Process -Force` first) and smoke:
      `python app.py --version`, exe `--version` exit 0
- [ ] Update this file: move fixed items to a "Fixed" section with date + PR

### Phase 1 sign-off (2026-09-29)

- [x] Full suite green: **340 passed, 1 skipped** (baseline 336 + 4 new)
- [x] 4 regression tests, reproduce-first (all confirmed RED pre-fix)
- [x] No new bare `except` / swallowed exceptions
- [x] `dist\virusShare.exe` rebuilt; smoke `python app.py --version` +
      exe `--version` → `virusShare 1.0.0`, both exit 0
- [x] This file updated (C1–C4 moved to Fixed)

## Open questions (decided — all answered)

1. ~~**H1**: should the receiver trust an empty checksum…~~ **Answered
   2026-09-29: skip verification (availability)** — empty declared checksum =
   sender opt-out, receiver accepts by size; mismatched checksum still fails.
2. ~~**M1**: Esc on conflict dialog → "skip" or "cancel"?~~ **Answered
   2026-09-29: Skip** — matches default button + timeout; explicit
   "Cancel transfer" button still cancels.
3. ~~**M7**: how to return to role/sender/receiver from home?~~ **Answered
   2026-09-29: Menu action "Mode…"** (File menu) + tray "Switch mode".
4. ~~**H6**: single-instance guard…~~ **Answered 2026-09-29: block second
   launch + message** — `QLockFile`, "already running" notice + dialog,
   exit 1 (stale locks from dead processes auto-reclaim).
