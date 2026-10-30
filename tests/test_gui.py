"""Interface Qt hors écran : recherche, copie, effacement du presse-papiers, journal."""

import sys
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from vault import audit, session
from vault.app import ICON_PATH, AuditDialog, MainWindow, app_icon
from vault.ipc import BrokerServer
from vault.store import VaultStore

SECRET = "tok_SECRET_VALUE_12345"


@pytest.fixture
def window(qapp: QApplication, tmp_path: Path, monkeypatch) -> MainWindow:
    monkeypatch.setenv("VAULT_HOME", str(tmp_path))
    store = VaultStore.create(tmp_path / "vault.enc", "bon-mot-de-passe")
    store.set("GH_TOKEN", SECRET)
    store.set("OPENAI_KEY", "sk-autre")
    store.set("NPM_TOKEN", "npm-autre")
    win = MainWindow(store, BrokerServer())
    yield win
    win.close()


def _visible_names(win: MainWindow) -> list[str]:
    return [
        win._table.item(r, 0).text()
        for r in range(win._table.rowCount())
        if not win._table.isRowHidden(r)
    ]


def test_search_filters_rows_case_insensitively(window: MainWindow) -> None:
    window._search.setText("token")
    assert _visible_names(window) == ["GH_TOKEN", "NPM_TOKEN"]
    window._search.setText("")
    assert len(_visible_names(window)) == 3


def test_copy_puts_value_on_clipboard_then_clears_it(window: MainWindow, qapp: QApplication) -> None:
    window._table.selectRow(0)  # GH_TOKEN, première ligne triée
    window._copy()
    clipboard = QApplication.clipboard()
    assert clipboard.text() == SECRET

    window._clear_clipboard()
    assert clipboard.text() != SECRET


def test_clear_keeps_clipboard_if_user_copied_something_else(window: MainWindow, qapp: QApplication) -> None:
    window._table.selectRow(0)
    window._copy()
    QApplication.clipboard().setText("texte de l'utilisateur")
    window._clear_clipboard()
    assert QApplication.clipboard().text() == "texte de l'utilisateur"


def test_audit_dialog_lists_entries_without_values(window: MainWindow, tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    audit.append(path, {"ts": "t1", "action": "run", "name": "GH_TOKEN", "target": "echo",
                        "decision": "approuvé", "result": "code 0"})
    dialog = AuditDialog(window, path)
    table = dialog.findChildren(type(window._table))[0]
    assert table.rowCount() == 1
    dump = "".join(table.item(0, c).text() for c in range(table.columnCount()))
    assert "GH_TOKEN" in dump and SECRET not in dump


def test_app_icon_is_the_packaged_logo(qapp: QApplication) -> None:
    assert ICON_PATH.exists()
    assert ICON_PATH.with_suffix(".ico").exists()  # utilisé par la compilation Nuitka pour l'exécutable
    icon = app_icon()
    assert not icon.isNull()
    assert not icon.pixmap(32, 32).isNull()


@pytest.mark.skipif(sys.platform != "win32", reason="message de session Windows uniquement")
def test_session_lock_message_is_detected() -> None:
    import ctypes
    from ctypes import wintypes

    msg = wintypes.MSG()
    msg.message = session.WM_WTSSESSION_CHANGE
    msg.wParam = session.WTS_SESSION_LOCK
    assert session.is_session_lock_message(ctypes.addressof(msg))

    msg.wParam = 0x8  # session déverrouillée : ne doit pas verrouiller
    assert not session.is_session_lock_message(ctypes.addressof(msg))
