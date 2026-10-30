"""Interface Qt : déverrouillage, gestion des entrées, approbation des demandes de Claude."""

from __future__ import annotations

import sys
import time
from pathlib import Path

from PySide6.QtCore import QEvent, QObject, Qt, QTimer
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QStyle,
    QSystemTrayIcon,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from vault import audit, autostart
from vault.broker import DENY, ONCE, SESSION, TEMP_GRANT_SECONDS, Broker
from vault.crypto import WrongPassword
from vault.ipc import BrokerServer
from vault.paths import audit_file, vault_file
from vault.policy import (
    CLIPBOARD_CLEAR_MS,
    IDLE_LOCK_SECONDS,
    should_lock,
    unlock_delay_seconds,
)
from vault.session import SessionLockFilter, register_session_notifications
from vault.store import MIN_PASSWORD_LENGTH, VaultError, VaultStore, validate_name

ICON_PATH = Path(__file__).parent / "assets" / "vault.png"
APPROVAL_TIMEOUT_MS = 60_000
TICK_MS = 5_000
ACTIVITY_EVENTS = {
    QEvent.Type.MouseMove,
    QEvent.Type.MouseButtonPress,
    QEvent.Type.KeyPress,
    QEvent.Type.Wheel,
}


def app_icon() -> QIcon:
    """Icône de l'application. Repli sur une icône du système si le fichier est introuvable."""
    if ICON_PATH.exists():
        return QIcon(str(ICON_PATH))
    return QApplication.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)


# --- dialogues ---------------------------------------------------------------


def ask_approval(parent: QWidget | None, summary: str) -> str:
    """Fenêtre d'approbation. Refus par défaut, refus automatique après 60 s."""
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Question)
    box.setWindowTitle("Vault : demande d'accès")
    box.setTextFormat(Qt.TextFormat.PlainText)  # la commande s'affiche telle quelle, sans HTML
    box.setText("Claude demande à utiliser un secret :")
    box.setInformativeText(
        f"{summary}\n\nRefus automatique dans 60 secondes."
        f"\n« Autoriser {TEMP_GRANT_SECONDS // 60} min » : cette même commande ne redemandera rien "
        "jusqu'au verrouillage ou à l'expiration."
    )
    box.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint)
    once = box.addButton("Autoriser une fois", QMessageBox.ButtonRole.AcceptRole)
    session = box.addButton(f"Autoriser {TEMP_GRANT_SECONDS // 60} min", QMessageBox.ButtonRole.AcceptRole)
    deny = box.addButton("Refuser", QMessageBox.ButtonRole.RejectRole)
    box.setDefaultButton(deny)
    timer = QTimer(box)
    timer.setSingleShot(True)
    timer.timeout.connect(deny.click)
    timer.start(APPROVAL_TIMEOUT_MS)
    box.exec()
    timer.stop()
    clicked = box.clickedButton()
    if clicked is once:
        return ONCE
    if clicked is session:
        return SESSION
    return DENY


def ask_new_password(parent: QWidget | None, title: str = "Choisis un mot de passe maître") -> str | None:
    """Mot de passe saisi deux fois, longueur minimale vérifiée."""
    while True:
        first, ok = QInputDialog.getText(parent, "Vault", f"{title} :", QLineEdit.EchoMode.Password)
        if not ok:
            return None
        if len(first) < MIN_PASSWORD_LENGTH:
            QMessageBox.warning(parent, "Vault", f"{MIN_PASSWORD_LENGTH} caractères minimum.")
            continue
        second, ok = QInputDialog.getText(
            parent, "Vault", "Confirme le mot de passe :", QLineEdit.EchoMode.Password
        )
        if not ok:
            return None
        if first != second:
            QMessageBox.warning(parent, "Vault", "Les deux mots de passe ne correspondent pas.")
            continue
        return first


def unlock(parent: QWidget | None) -> VaultStore | None:
    """Ouvre le coffre existant ou en crée un. Renvoie None si l'utilisateur abandonne."""
    path = vault_file()
    if not VaultStore.exists(path):
        password = ask_new_password(parent)
        if password is None:
            return None
        return VaultStore.create(path, password)

    failures = 0
    while True:
        password, ok = QInputDialog.getText(
            parent, "Vault", "Mot de passe maître :", QLineEdit.EchoMode.Password
        )
        if not ok:
            return None
        try:
            return VaultStore.open(path, password)
        except (WrongPassword, VaultError, ValueError, OSError):
            failures += 1
            wait = unlock_delay_seconds(failures)
            message = "Mot de passe incorrect ou fichier illisible."
            if wait:
                message += f"\nNouvelle tentative possible dans {wait} s."
            QMessageBox.warning(parent, "Vault", message)
            if wait:
                time.sleep(wait)


def change_password_dialog(parent: QWidget, store: VaultStore) -> None:
    current, ok = QInputDialog.getText(
        parent, "Vault", "Mot de passe maître actuel :", QLineEdit.EchoMode.Password
    )
    if not ok:
        return
    new = ask_new_password(parent, "Nouveau mot de passe maître")
    if new is None:
        return
    try:
        store.change_password(current, new)
    except (VaultError, OSError) as exc:
        QMessageBox.warning(parent, "Vault", str(exc))
        return
    QMessageBox.information(parent, "Vault", "Mot de passe maître changé.")


class AuditDialog(QDialog):
    """Journal des demandes, du plus récent au plus ancien. Aucune valeur n'y figure."""

    HEADERS = ["Date", "Action", "Nom", "Cible", "Décision", "Résultat"]
    KEYS = ["ts", "action", "name", "target", "decision", "result"]

    def __init__(self, parent: QWidget, path) -> None:
        super().__init__(parent)
        self.setWindowTitle("Vault : journal des demandes")
        self.resize(900, 440)
        table = QTableWidget(0, len(self.HEADERS))
        table.setHorizontalHeaderLabels(self.HEADERS)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        rows = audit.read_recent(path)
        table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, key in enumerate(self.KEYS):
                table.setItem(r, c, QTableWidgetItem(str(row.get(key, "-"))))
        close = QPushButton("Fermer")
        close.clicked.connect(self.accept)
        layout = QVBoxLayout(self)
        layout.addWidget(table)
        layout.addWidget(close, alignment=Qt.AlignmentFlag.AlignRight)


# --- verrouillage automatique ----------------------------------------------------


class AutoLocker(QObject):
    """Verrouille après une période d'inactivité, ou après une mise en veille."""

    def __init__(self, on_lock, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._on_lock = on_lock
        self._last_activity = time.time()
        self._last_tick = time.time()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(TICK_MS)

    def eventFilter(self, obj, event) -> bool:  # noqa: N802 (nom imposé par Qt)
        if event.type() in ACTIVITY_EVENTS:
            self._last_activity = time.time()
        return False

    def reset(self) -> None:
        """Compte une demande traitée comme une activité, et évite de prendre une commande longue pour une veille."""
        self._last_activity = time.time()
        self._last_tick = self._last_activity

    def _tick(self) -> None:
        now = time.time()
        if should_lock(self._last_activity, self._last_tick, now, IDLE_LOCK_SECONDS):
            # Le minuteur est suspendu pendant le déverrouillage (boucle modale), puis repris.
            self._timer.stop()
            try:
                self._on_lock()
            finally:
                self._last_activity = time.time()
                self._last_tick = self._last_activity
                self._timer.start(TICK_MS)
            return
        self._last_tick = now


# --- fenêtre principale --------------------------------------------------------


class MainWindow(QMainWindow):
    def __init__(self, store: VaultStore, server: BrokerServer) -> None:
        super().__init__()
        self.setWindowTitle("Vault")
        self.resize(780, 440)
        self._store = store
        self._server = server
        self._last_copied: str | None = None
        self._clear_timer: QTimer | None = None

        self._search = QLineEdit()
        self._search.setPlaceholderText("Rechercher une entrée…")
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self._apply_filter)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Nom", "Créé", "Modifié", "Dernier usage"])
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.doubleClicked.connect(lambda _index: self._copy())

        add = QPushButton("Ajouter")
        edit = QPushButton("Modifier la valeur")
        copy = QPushButton("Copier")
        delete = QPushButton("Supprimer")
        lock = QPushButton("Verrouiller")
        add.clicked.connect(self._add)
        edit.clicked.connect(self._edit)
        copy.clicked.connect(self._copy)
        delete.clicked.connect(self._delete)
        lock.clicked.connect(self.lock)

        buttons = QHBoxLayout()
        for button in (add, edit, copy, delete):
            buttons.addWidget(button)
        buttons.addStretch()
        buttons.addWidget(lock)

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.addWidget(self._search)
        layout.addWidget(self._table)
        layout.addLayout(buttons)
        self.setCentralWidget(central)

        self._build_menus()
        self._build_tray()
        self.statusBar().showMessage("Coffre déverrouillé. Claude peut lister et utiliser les entrées.")
        self._refresh()

    # --- menus et barre des tâches ------------------------------------------------

    def _build_menus(self) -> None:
        tools = self.menuBar().addMenu("Outils")
        tools.addAction(_action(self, "Changer le mot de passe maître…", self._change_password))
        tools.addAction(_action(self, "Journal des demandes…", self._show_audit))
        tools.addSeparator()
        if sys.platform == "win32":
            self._autostart = QAction("Lancer au démarrage de Windows", self)
            self._autostart.setCheckable(True)
            self._autostart.setChecked(autostart.is_enabled())
            self._autostart.toggled.connect(self._toggle_autostart)
            tools.addAction(self._autostart)
        tools.addAction(_action(self, "Verrouiller", self.lock))

    def _build_tray(self) -> None:
        self._tray: QSystemTrayIcon | None = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self._tray = QSystemTrayIcon(app_icon(), self)
        menu = QMenu(self)
        menu.addAction(_action(self, "Ouvrir", self.show_window))
        menu.addAction(_action(self, "Verrouiller", self.lock))
        menu.addSeparator()
        menu.addAction(_action(self, "Quitter", lambda: QApplication.quit()))
        self._tray.setContextMenu(menu)
        self._tray.setToolTip("Vault")
        self._tray.activated.connect(self._on_tray_activated)
        self._tray.show()

    def _on_tray_activated(self, reason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self.show_window()

    def show_window(self) -> None:
        self.show()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, event) -> None:  # noqa: N802 (nom imposé par Qt)
        if self._tray is not None:
            self.hide()  # reste dans la barre des tâches : le coffre reste déverrouillé
            event.ignore()
            return
        super().closeEvent(event)

    # --- liste -------------------------------------------------------------------

    def _refresh(self) -> None:
        rows = self._store.list_metadata()
        self._table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            values = [row["name"], row["created"], row["updated"], row["last_used"] or "-"]
            for c, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self._table.setItem(r, c, item)
        self._apply_filter(self._search.text())

    def _apply_filter(self, text: str) -> None:
        needle = text.strip().lower()
        for r in range(self._table.rowCount()):
            item = self._table.item(r, 0)
            self._table.setRowHidden(r, needle not in item.text().lower())

    def _selected_name(self) -> str | None:
        row = self._table.currentRow()
        if row < 0:
            return None
        return self._table.item(row, 0).text()

    # --- actions -----------------------------------------------------------------

    def _add(self) -> None:
        name, ok = QInputDialog.getText(self, "Vault", "Nom de l'entrée (ex. GH_TOKEN) :")
        if not ok:
            return
        value, ok = QInputDialog.getText(
            self, "Vault", "Valeur (masquée) :", QLineEdit.EchoMode.Password
        )
        if not ok:
            return
        self._save(name, value)

    def _edit(self) -> None:
        name = self._selected_name()
        if name is None:
            return
        value, ok = QInputDialog.getText(
            self, "Vault", f"Nouvelle valeur pour {name} (masquée) :", QLineEdit.EchoMode.Password
        )
        if ok:
            self._save(name, value)

    def _copy(self) -> None:
        name = self._selected_name()
        if name is None:
            self.statusBar().showMessage("Sélectionne une entrée à copier.")
            return
        value = self._store.get_value(name)
        QApplication.clipboard().setText(value)
        self._last_copied = value
        if self._clear_timer is not None:
            self._clear_timer.stop()
        self._clear_timer = QTimer(self)
        self._clear_timer.setSingleShot(True)
        self._clear_timer.timeout.connect(self._clear_clipboard)
        self._clear_timer.start(CLIPBOARD_CLEAR_MS)
        seconds = CLIPBOARD_CLEAR_MS // 1000
        self.statusBar().showMessage(f"« {name} » copié. Effacé du presse-papiers dans {seconds} s.")

    def _clear_clipboard(self) -> None:
        """Vide le presse-papiers, seulement s'il contient encore la valeur copiée."""
        clipboard = QApplication.clipboard()
        if self._last_copied is not None and clipboard.text() == self._last_copied:
            clipboard.clear()
        self._last_copied = None
        self._clear_timer = None

    def _delete(self) -> None:
        name = self._selected_name()
        if name is None:
            return
        answer = QMessageBox.question(self, "Vault", f"Supprimer définitivement « {name} » ?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            self._store.delete(name)
        except VaultError as exc:
            QMessageBox.warning(self, "Vault", str(exc))
        self._refresh()

    def _save(self, name: str, value: str) -> None:
        try:
            validate_name(name)
            self._store.set(name, value)
        except VaultError as exc:
            QMessageBox.warning(self, "Vault", str(exc))
            return
        self._refresh()

    def _change_password(self) -> None:
        change_password_dialog(self, self._store)

    def _show_audit(self) -> None:
        AuditDialog(self, audit_file()).exec()

    def _toggle_autostart(self, checked: bool) -> None:
        try:
            autostart.set_enabled(checked)
        except OSError as exc:
            QMessageBox.warning(self, "Vault", f"Impossible de modifier le démarrage : {exc}")
            self._autostart.setChecked(not checked)

    def lock(self) -> None:
        """Verrouille : débranche le courtier, efface le presse-papiers, demande le mot de passe."""
        self._server.set_broker(None)
        self._clear_clipboard()
        self.hide()
        store = unlock(None)
        if store is None:
            QApplication.quit()
            return
        self._store = store
        attach(self._server, store, self)
        self._refresh()
        self.show_window()


def _action(parent: QWidget, text: str, slot) -> QAction:
    action = QAction(text, parent)
    action.triggered.connect(slot)
    return action


# --- câblage --------------------------------------------------------------------


def attach(server: BrokerServer, store: VaultStore, window: QWidget) -> None:
    """Branche le courtier sur le canal local, avec l'approbation affichée dans cette fenêtre."""
    broker = Broker(store, approve=lambda summary: ask_approval(window, summary), audit_path=audit_file())
    server.set_broker(broker)


def main() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("Vault")
    app.setWindowIcon(app_icon())
    server = BrokerServer()
    try:
        server.start()
    except RuntimeError:
        # Typiquement : Vault est déjà ouvert (le canal local est pris). Sans ce message, rien ne s'afficherait.
        QMessageBox.critical(
            None,
            "Vault",
            "Vault est déjà ouvert, ou son canal local est occupé.\n"
            "Cherche l'icône dans la barre des tâches, ou ferme l'autre instance.",
        )
        return 1

    store = unlock(None)
    if store is None:
        server.stop()
        return 0

    window = MainWindow(store, server)
    attach(server, store, window)
    locker = AutoLocker(window.lock, window)
    server.handled.connect(locker.reset)
    app.installEventFilter(locker)
    session_filter = SessionLockFilter(lambda: QTimer.singleShot(0, window.lock))
    app.installNativeEventFilter(session_filter)
    window.show()
    register_session_notifications(int(window.winId()))
    code = app.exec()
    server.stop()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
