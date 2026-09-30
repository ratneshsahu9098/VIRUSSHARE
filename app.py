#!/usr/bin/env python3
"""virusShare - application entry point.

Wires together settings, identity, discovery, the transfer server/client,
the history database and the Qt GUI.  Runs headless until ``app.exec()``.

Usage::

    python app.py               # normal start
    python app.py --minimized   # start hidden in the tray
    python app.py --verbose     # DEBUG logging to console as well
"""

from __future__ import annotations

import argparse
import logging
import os
import platform
import sys
from pathlib import Path
from typing import List, Optional

from core.constants import (
    APP_NAME,
    APP_VERSION,
    TRANSFER_PORT,
    DISCOVERY_PORT,
    ensure_dirs,
    get_app_data_dir,
)

log = logging.getLogger(__name__)


def acquire_instance_lock(lock_path: Optional[Path] = None):
    """Take the per-user single-instance lock (H6).

    Returns the held ``QLockFile`` or ``None`` when another live instance
    already owns it.  A lock left behind by a dead process is reclaimed by
    ``QLockFile`` itself (it validates the owning PID), so a crash never
    blocks the next start.
    """
    from PySide6.QtCore import QLockFile

    if lock_path is None:
        lock_path = get_app_data_dir() / "virusShare.lock"
    lock = QLockFile(str(lock_path))
    if not lock.tryLock(0):
        return None
    return lock


def _report_already_running() -> None:
    """Tell the user a second instance is already up (H6)."""
    message = f"{APP_NAME} is already running. Check the system tray."
    try:
        print(message, flush=True)
    except Exception:  # noqa: BLE001
        log.debug("stdout unavailable for already-running notice", exc_info=True)
    log.info("second instance detected, exiting")
    if os.environ.get("VIRUSSHARE_NO_DIALOG") == "1":
        return
    try:
        from PySide6.QtWidgets import QApplication, QMessageBox

        qapp = QApplication.instance() or QApplication(sys.argv[:1])
        QMessageBox.information(None, APP_NAME, message)
    except Exception:  # noqa: BLE001
        log.exception("already-running dialog failed")


class _VersionAction(argparse.Action):
    """Like argparse's ``version`` action but tolerant of broken streams.

    A windowed exe started without a console has ``sys.stdout is None``;
    the stock action then crashes with AttributeError.  Write/flush can also
    raise on an invalid handle (no console) or a dead pipe.  Best effort
    output, always exit 0.
    """

    def __init__(self, option_strings, dest, version="", **kwargs):
        super().__init__(
            option_strings, dest, nargs=0, default=argparse.SUPPRESS, **kwargs
        )
        self.version_text = version

    def __call__(self, parser, namespace, values, option_string=None):
        stream = sys.stdout or sys.stderr
        if stream is not None:
            try:
                stream.write(self.version_text + "\n")
                stream.flush()
            except (OSError, ValueError):
                pass  # broken/closed/invalid stream - version output is best effort
        parser.exit(0)


def _port_arg(value: str) -> int:
    """argparse type for the port flags (M30).

    Rejects junk and the out-of-range values Settings would refuse, as a
    clean usage error instead of an uncaught SettingsError traceback.
    """
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(
            f"port must be an integer, got {value!r}"
        ) from None
    if not 1024 <= port <= 65535:
        raise argparse.ArgumentTypeError(
            f"port must be between 1024 and 65535, got {port}"
        )
    return port


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="virusShare", description=APP_NAME)
    parser.add_argument(
        "--version",
        action=_VersionAction,
        version=f"{APP_NAME} {APP_VERSION}",
        help="print the version and exit",
    )
    parser.add_argument(
        "--minimized",
        action="store_true",
        help="start hidden in the system tray",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="debug logging to console"
    )
    parser.add_argument(
        "--transfer-port",
        type=_port_arg,
        default=None,
        help=f"TCP transfer port (default {TRANSFER_PORT})",
    )
    parser.add_argument(
        "--discovery-port",
        type=_port_arg,
        default=None,
        help=f"UDP discovery port (default {DISCOVERY_PORT})",
    )
    parser.add_argument(
        "--no-discovery",
        action="store_true",
        help="do not announce/listen for LAN peers (manual IP only)",
    )
    return parser.parse_args(argv)


def make_device_found_handler(bridge: "ThreadBridge"):
    """Build the discovery callback used by :func:`main`.

    Discovery packets are unauthenticated: a self-asserted ``device_id`` must
    never light the "Trusted" badge — otherwise any LAN host can spoof a known
    peer (H7).  The badge is set only by a fingerprint-verified handshake
    (``bridge.deviceTrusted``) or an explicit toggle in the device list.
    """

    def on_device_found(device) -> None:
        bridge.deviceFound.emit(device)

    return on_device_found


def make_session_handler(manager, bridge: "ThreadBridge", conflict=None):
    """Build the transfer-server session callback used by :func:`main`.

    Each incoming session gets its own conflict callback (unless one is
    injected), so an "apply to all" answer stays scoped to the session that
    asked for it (M19).
    """
    from gui.bridge import make_conflict_callback

    from transfer.receiver import ReceiveReport, handle_incoming

    def session_handler(conn_session) -> None:
        session_conflict = (
            conflict if conflict is not None else make_conflict_callback(bridge)
        )
        result = getattr(conn_session, "result", None)
        if result is not None and getattr(result, "trusted", False):
            # The peer's certificate fingerprint matched the trust store
            # during the handshake (session.py) — only now is the badge honest.
            bridge.deviceTrusted.emit(result.device.device_id, True)
        model = manager.begin_receive(conn_session.peer_device)
        report = None
        try:
            ctx = manager.receive_context(
                model, conflict_callback=session_conflict
            )
            report = handle_incoming(conn_session, ctx)
        except Exception as exc:  # noqa: BLE001 - H2: a malformed message or
            # protocol bug must not skip finish_receive, or the session stays
            # ACTIVE forever with no history row.
            log.exception(
                "receive session crashed for %s",
                getattr(conn_session, "peer_device", None),
            )
            report = ReceiveReport(error=f"receive session crashed: {exc}")
        finally:
            manager.finish_receive(model, report)

    return session_handler


def make_shutdown(
    *,
    bridge,
    manager,
    server,
    history,
    get_discovery,
    get_window=None,
    process_events=None,
):
    """Build the application shutdown callback used by :func:`main`.

    Kept as a factory so tests can pin the teardown behaviour (M27):
    idempotence, accept-loop-first ordering, the GUI event pump while
    workers wind down, and the history flush before the DB is closed.
    """
    state = {"done": False}

    def shutdown() -> None:
        if state["done"]:
            return
        state["done"] = True
        log.info("shutting down…")
        bridge.cancel_all_prompts()
        try:
            server.stop()
        except Exception:  # noqa: BLE001
            log.exception("server stop failed")
        try:
            discovery = get_discovery()
        except Exception:  # noqa: BLE001
            discovery = None
            log.exception("discovery lookup failed")
        if discovery is not None:
            try:
                discovery.stop()
            except Exception:  # noqa: BLE001
                log.exception("discovery stop failed")
        try:
            manager.shutdown(timeout=8.0, on_wait=process_events)
        except Exception:  # noqa: BLE001
            log.exception("manager shutdown failed")
        if process_events is not None:
            try:
                process_events()
            except Exception:  # noqa: BLE001
                log.exception("shutdown event pump failed")
        if get_window is not None:
            try:
                window = get_window()
            except Exception:  # noqa: BLE001
                window = None
                log.exception("window lookup failed")
            if window is not None:
                try:
                    window.flush_history()
                except Exception:  # noqa: BLE001
                    log.exception("history flush failed")
        try:
            history.close()
        except Exception:  # noqa: BLE001
            log.exception("history close failed")

    return shutdown


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    ensure_dirs()
    from utils.windows import remove_legacy_autostart

    remove_legacy_autostart()
    from utils.logger import setup_logging

    setup_logging(level=logging.DEBUG if args.verbose else logging.INFO, console=args.verbose)

    # Single instance: before any state (settings/identity/history) is
    # touched, so two racing launches cannot both create identity files.
    instance_lock = acquire_instance_lock()
    if instance_lock is None:
        _report_already_running()
        return 1

    from core.config import get_settings
    from core.security import TrustStore, load_identity
    from core.constants import get_identity_path, get_trust_store_path
    from network.protocol import DeviceInfo, get_local_ip
    from network.discovery import DiscoveryService, get_stable_device_id
    from network.tcp_server import TransferServer

    settings = get_settings()
    if args.transfer_port is not None:
        settings.set("transfer_port", args.transfer_port, save=False)
    if args.discovery_port is not None:
        settings.set("discovery_port", args.discovery_port, save=False)
    transfer_port = int(settings.get("transfer_port", TRANSFER_PORT))
    discovery_port = int(settings.get("discovery_port", DISCOVERY_PORT))

    identity = load_identity(get_identity_path())
    trust_store = TrustStore(get_trust_store_path())
    device_id = get_stable_device_id()
    device_name = platform.node() or "PC"

    def local_device() -> DeviceInfo:
        caps = ["file_transfer", "resume", "checksum", "pairing"]
        try:
            import cryptography  # noqa: F401

            if settings.get("enable_encryption", True):
                caps.append("encryption")
        except ImportError:
            pass
        return DeviceInfo(
            name=device_name,
            ip=get_local_ip(),
            port=transfer_port,
            device_id=device_id,
            os_version=platform.platform(),
            app_version=APP_VERSION,
            capabilities=caps,
        )

    # ------------------------------------------------------------------ #
    # Qt
    # ------------------------------------------------------------------ #
    from PySide6.QtWidgets import QApplication

    from gui.bridge import (
        ThreadBridge,
        make_approval_callback,
    )
    from gui.icons import app_icon
    from gui.main_window import MainWindow
    from gui.styles import apply_theme
    from gui.tray import AppTray

    qapp = QApplication.instance() or QApplication(sys.argv[:1])
    qapp.setApplicationName(APP_NAME)
    qapp.setApplicationVersion(APP_VERSION)
    qapp.setOrganizationName(APP_NAME)
    qapp.setWindowIcon(app_icon(64))
    qapp.setQuitOnLastWindowClosed(True)
    apply_theme(qapp, str(settings.get("theme", "system")))

    bridge = ThreadBridge()

    def auto_accept() -> bool:
        return bool(settings.get("auto_accept_trusted", False))

    approval = make_approval_callback(bridge, auto_accept, trust_store=trust_store)

    # ------------------------------------------------------------------ #
    # transfer manager + history
    # ------------------------------------------------------------------ #
    from database.history import HistoryDB
    from transfer.manager import TransferManager

    manager = TransferManager(
        identity=identity,
        trust_store=trust_store,
        device_provider=local_device,
        approve_callback=approval,
        settings=settings.as_dict(),
        on_update=bridge.sessionUpdate.emit,
        on_finished=bridge.sessionFinished.emit,
        on_peer_trusted=lambda device_id: bridge.deviceTrusted.emit(
            device_id, True
        ),
    )
    history = HistoryDB()

    # ------------------------------------------------------------------ #
    # incoming connections
    # ------------------------------------------------------------------ #
    session_handler = make_session_handler(manager, bridge)

    server = TransferServer(
        device_provider=local_device,
        identity=identity,
        trust_store=trust_store,
        host="",
        port=transfer_port,
        encryption=bool(settings.get("enable_encryption", True)),
        require_approval=bool(
            settings.get("require_connection_approval", True)
        ),
        approve_callback=approval,
        session_handler=session_handler,
    )
    try:
        server.start()
    except (OSError, RuntimeError) as exc:
        log.error("cannot bind transfer port %s: %s", transfer_port, exc)
        return 2

    # ------------------------------------------------------------------ #
    # discovery / window / tray - any failure after bind must still
    # release the server, manager, history and the instance lock (H6)
    # ------------------------------------------------------------------ #
    discovery = None
    window = None

    shutdown = make_shutdown(
        bridge=bridge,
        manager=manager,
        server=server,
        history=history,
        get_discovery=lambda: discovery,
        get_window=lambda: window,
        process_events=qapp.processEvents,
    )

    try:
        if not args.no_discovery:
            discovery = DiscoveryService(
                device_name=device_name,
                device_id=device_id,
                port=discovery_port,
                transfer_port=transfer_port,
                on_device_found=make_device_found_handler(bridge),
                on_device_lost=bridge.deviceLost.emit,
            )
            try:
                discovery.start()
            except RuntimeError as exc:
                log.warning("discovery disabled: %s", exc)
                discovery = None

            def on_device_trusted(device_id: str, trusted: bool) -> None:
                # Keep discovery's record in sync: a re-found peer keeps a badge
                # earned by a verified handshake; a revoked one does not resurrect.
                if discovery is not None:
                    try:
                        discovery.set_trusted(device_id, trusted)
                    except Exception:  # noqa: BLE001
                        log.exception(
                            "discovery trust sync failed for %s", device_id
                        )

            bridge.deviceTrusted.connect(on_device_trusted)

        # ------------------------------------------------------------------ #
        # window + tray
        # ------------------------------------------------------------------ #
        window = MainWindow(
            settings=settings,
            manager=manager,
            history=history,
            bridge=bridge,
            trust_store=trust_store,
            on_shutdown=shutdown,
            start_on_role_screen=True,
        )

        tray = AppTray(None)
        window.tray = tray
        if tray.available:
            tray.toggleWindow.connect(window.toggle_visibility)
            tray.sendRequested.connect(window.send_files)
            tray.modeRequested.connect(window.show_role_screen)
            tray.historyRequested.connect(window.show_history)
            tray.settingsRequested.connect(window.show_settings)
            tray.quitRequested.connect(window.request_quit)

        if args.minimized and tray.available:
            window.start_minimized()
        else:
            window.show()

        log.info(
            "%s %s ready (device=%s, tcp=%d, udp=%d, encryption=%s)",
            APP_NAME,
            APP_VERSION,
            device_name,
            transfer_port,
            discovery_port,
            settings.get("enable_encryption"),
        )

        code = qapp.exec()
        return int(code)
    except Exception:
        log.exception("startup failed")
        return 1
    finally:
        shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
