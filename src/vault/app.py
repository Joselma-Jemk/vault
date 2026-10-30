"""Interface Qt : déverrouillage, liste des entrées, et approbation des demandes de Claude."""

from __future__ import annotations

import sys

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from vault.broker import Broker
from vault.crypto import WrongPassword
from vault.ipc import BrokerServer
from vault.paths import audit_file, vault_file
from vault.store import VaultError, VaultStore, validate_name

APPROVAL_TIMEOUT_MS = 60_000
MIN_PASSWORD_LENGTH = 8


# --- dialogues ---------------------------------------------------------------


def ask_approval(parent: QWidget | None, summary: str) -> bool:
    """Fenêtre d'approbation : refus par défaut, refus automatique après 60 s."""
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Question)
    box.setWindowTitle("Vault : demande d'accès")
    box.setText("Claude demande à utiliser un secret :")
    box.setInformativeText(f"{summary}\n\nRefus automatique dans 60 secondes.")
    allow = box.addButton("Autoriser", QMessageBox.ButtonRole.AcceptRole)
    deny = box.addButton("Refuser", QMessageBox.ButtonRole.RejectRole)
    box.setDefaultButton(deny)
    timer = QTimer(box)
    timer.setSingleShot(True)
    timer.timeout.connect(deny.click)
    timer.start(APPROVAL_TIMEOUT_MS)
    box.exec()
    timer.stop()
    return box.clickedButton() is allow


def ask_new_password(parent: QWidget | None) -> str | None:
    """Création du coffre : mot de passe saisi deux fois."""
    while True:
        first, ok = QInputDialog.getText(
            parent, "Vault", "Choisis un mot de passe maître :", QLineEdit.EchoMode.Password
        )
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

    while True:
        password, ok = QInputDialog.getText(
            parent, "Vault", "Mot de passe maître :", QLineEdit.EchoMode.Password
        )
        if not ok:
            return None
        try:
            return VaultStore.open(path, password)
        except (WrongPassword, ValueError, OSError):  # mot de passe faux ou fichier illisible
            QMessageBox.warning(parent, "Vault", "Mot de passe incorrect ou fichier illisible.")


# --- fenêtre principale --------------------------------------------------------


class MainWindow(QMainWindow):
    def __init__(self, store: VaultStore, server: BrokerServer) -> None:
        super().__init__()
        self.setWindowTitle("Vault")
        self.resize(760, 420)
        self._store = store
        self._server = server

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Nom", "Créé", "Modifié", "Dernier usage"])
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        add = QPushButton("Ajouter")
        edit = QPushButton("Modifier la valeur")
        delete = QPushButton("Supprimer")
        lock = QPushButton("Verrouiller")
        add.clicked.connect(self._add)
        edit.clicked.connect(self._edit)
        delete.clicked.connect(self._delete)
        lock.clicked.connect(self._lock)

        buttons = QHBoxLayout()
        for button in (add, edit, delete):
            buttons.addWidget(button)
        buttons.addStretch()
        buttons.addWidget(lock)

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.addWidget(self._table)
        layout.addLayout(buttons)
        self.setCentralWidget(central)
        self.statusBar().showMessage("Coffre déverrouillé. Claude peut lister et utiliser les entrées.")
        self._refresh()

    # --- actions ---------------------------------------------------------------

    def _refresh(self) -> None:
        rows = self._store.list_metadata()
        self._table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            values = [row["name"], row["created"], row["updated"], row["last_used"] or "-"]
            for c, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self._table.setItem(r, c, item)

    def _selected_name(self) -> str | None:
        row = self._table.currentRow()
        if row < 0:
            return None
        return self._table.item(row, 0).text()

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

    def _delete(self) -> None:
        name = self._selected_name()
        if name is None:
            return
        answer = QMessageBox.question(
            self, "Vault", f"Supprimer définitivement « {name} » ?"
        )
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

    def _lock(self) -> None:
        self._server.set_broker(None)
        self.hide()
        store = unlock(None)
        if store is None:
            QApplication.quit()
            return
        self._store = store
        attach(self._server, store, self)
        self._refresh()
        self.show()


# --- câblage --------------------------------------------------------------------


def attach(server: BrokerServer, store: VaultStore, window: QWidget) -> None:
    """Branche le courtier sur le canal local, avec l'approbation affichée dans cette fenêtre."""
    broker = Broker(store, approve=lambda summary: ask_approval(window, summary), audit_path=audit_file())
    server.set_broker(broker)


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Vault")
    server = BrokerServer()
    server.start()

    store = unlock(None)
    if store is None:
        server.stop()
        return 0

    window = MainWindow(store, server)
    attach(server, store, window)
    window.show()
    code = app.exec()
    server.stop()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
