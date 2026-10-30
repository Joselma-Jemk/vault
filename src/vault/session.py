"""Verrouillage à la session Windows (Win+L) : écoute le message WM_WTSSESSION_CHANGE.

Sans effet hors Windows.
"""

from __future__ import annotations

import ctypes
import sys
from collections.abc import Callable

from PySide6.QtCore import QAbstractNativeEventFilter

WM_WTSSESSION_CHANGE = 0x02B1
WTS_SESSION_LOCK = 0x7
NOTIFY_FOR_THIS_SESSION = 0
WINDOWS_MSG_TYPE = b"windows_generic_MSG"


def is_session_lock_message(address: int) -> bool:
    """Lit une structure MSG Windows à cette adresse et dit si c'est un verrouillage de session."""
    from ctypes import wintypes

    msg = wintypes.MSG.from_address(address)
    return msg.message == WM_WTSSESSION_CHANGE and msg.wParam == WTS_SESSION_LOCK


class SessionLockFilter(QAbstractNativeEventFilter):
    def __init__(self, on_lock: Callable[[], None]) -> None:
        super().__init__()
        self._on_lock = on_lock

    def nativeEventFilter(self, eventType, message):  # noqa: N802 (nom imposé par Qt)
        if sys.platform == "win32":
            try:
                if bytes(eventType) == WINDOWS_MSG_TYPE and is_session_lock_message(int(message)):
                    self._on_lock()
            except (TypeError, ValueError, OSError):
                pass  # message illisible : on laisse Qt le traiter, sans jamais planter la boucle d'événements
        return False, 0


def register_session_notifications(hwnd: int) -> bool:
    """Demande à Windows de prévenir la fenêtre quand la session est verrouillée. Renvoie False si impossible."""
    if sys.platform != "win32":
        return False
    from ctypes import wintypes

    try:
        wtsapi32 = ctypes.WinDLL("wtsapi32")
        ok = wtsapi32.WTSRegisterSessionNotification(wintypes.HWND(hwnd), NOTIFY_FOR_THIS_SESSION)
    except (OSError, AttributeError):
        return False
    return bool(ok)
