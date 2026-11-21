"""Interface Qt : déverrouillage, gestion des entrées, approbation des demandes de Claude."""

from __future__ import annotations

import os
import secrets
import sys
import time
from datetime import date
from importlib import resources
from pathlib import Path

from PySide6.QtCore import QEvent, QObject, Qt, QTimer
from PySide6.QtGui import QAction, QColor, QIcon, QKeySequence, QPixmap, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
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
from vault.backup import read_backup, write_backup
from vault.broker import DENY, ONCE, SESSION, TEMP_GRANT_SECONDS, TRUST_SECONDS, Broker
from vault.crypto import WrongPassword
from vault.envfile import parse_env
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


def app_icon() -> QIcon | None:
    """Logo lu dans le paquet, y compris dans l'exécutable compilé. None si introuvable.

    Dans ce cas on ne pose aucune icône : Windows affiche alors celle qui est intégrée à l'exécutable.
    Une icône générique du système serait pire qu'aucune.
    """
    data = _logo_bytes()
    if data is None:
        return None
    pixmap = QPixmap()
    if not pixmap.loadFromData(data):
        return None
    return QIcon(pixmap)


def _logo_bytes() -> bytes | None:
    try:
        return resources.files("vault").joinpath("assets").joinpath("vault.png").read_bytes()
    except (OSError, ModuleNotFoundError, TypeError):
        pass
    if ICON_PATH.exists():  # lancement depuis les sources, sans passer par le paquet
        return ICON_PATH.read_bytes()
    return None


# --- dialogues ---------------------------------------------------------------


ICONS_FOLDER = "assets", "icons"


def _is_dark_scheme() -> bool:
    app = QApplication.instance()
    return app is not None and app.styleHints().colorScheme() == Qt.ColorScheme.Dark


def themed_icon(name: str) -> QIcon:
    """Icône PyPlayer adaptée au thème : blanche sur fond sombre, sombre sur fond clair. Vide si introuvable."""
    folder = "light" if _is_dark_scheme() else "dark"
    try:
        data = resources.files("vault").joinpath(*ICONS_FOLDER).joinpath(folder).joinpath(f"{name}.png").read_bytes()
    except (OSError, ModuleNotFoundError, TypeError):
        return QIcon()
    pixmap = QPixmap()
    return QIcon(pixmap) if pixmap.loadFromData(data) else QIcon()


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


class EntriesDialog(QDialog):
    """Choix des entrées autorisées pour un projet : une case par entrée, jamais de valeur."""

    def __init__(self, parent: QWidget, store: VaultStore, folder: str, chosen: list[str]) -> None:
        super().__init__(parent)
        self.setWindowTitle("Vault : droits du projet")
        self.resize(460, 380)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"Entrées que Claude peut utiliser dans :\n{folder}\n(et ses sous-dossiers)"))
        self._list = QListWidget()
        for row in store.list_metadata():
            name = str(row["name"])
            label = name + ("  (en attente : valeur à renseigner)" if row.get("pending") else "")
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, name)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if name in chosen else Qt.CheckState.Unchecked)
            self._list.addItem(item)
        layout.addWidget(self._list)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def selected(self) -> list[str]:
        names = []
        for index in range(self._list.count()):
            item = self._list.item(index)
            if item.checkState() == Qt.CheckState.Checked:
                names.append(str(item.data(Qt.ItemDataRole.UserRole)))
        return names


class ProjectsDialog(QDialog):
    """Dossiers enregistrés et entrées autorisées. Claude ne peut ni les créer ni les modifier."""

    def __init__(self, parent: QWidget, store: VaultStore) -> None:
        super().__init__(parent)
        self._store = store
        self.setWindowTitle("Vault : projets")
        self.resize(640, 420)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(
            "Un projet = un dossier. Claude peut utiliser, depuis ce dossier et ses sous-dossiers, "
            "uniquement les entrées cochées."
        ))
        self._list = QListWidget()
        layout.addWidget(self._list)
        row = QHBoxLayout()
        add = QPushButton("Ajouter un dossier…")
        edit = QPushButton("Modifier les droits…")
        remove = QPushButton("Retirer le projet")
        close = QPushButton("Fermer")
        add.clicked.connect(self._add)
        edit.clicked.connect(self._edit)
        remove.clicked.connect(self._remove)
        close.clicked.connect(self.accept)
        for button in (add, edit, remove):
            row.addWidget(button)
        row.addStretch()
        row.addWidget(close)
        layout.addLayout(row)
        self._reload()

    def _reload(self) -> None:
        self._list.clear()
        for project in self._store.list_projects():
            entries = ", ".join(project["entries"]) or "aucune entrée"
            item = QListWidgetItem(f"{project['path']}\n    {entries}")
            item.setData(Qt.ItemDataRole.UserRole, project["path"])
            self._list.addItem(item)

    def _current_path(self) -> str | None:
        item = self._list.currentItem()
        return None if item is None else str(item.data(Qt.ItemDataRole.UserRole))

    def _current_entries(self, path: str) -> list[str]:
        for project in self._store.list_projects():
            if project["path"] == path:
                return list(project["entries"])
        return []

    def _add(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Dossier du projet")
        if not folder:
            return
        self._choose_entries(folder, [])

    def _edit(self) -> None:
        path = self._current_path()
        if path is None:
            return
        self._choose_entries(path, self._current_entries(path))

    def _choose_entries(self, folder: str, chosen: list[str]) -> None:
        dialog = EntriesDialog(self, self._store, folder, chosen)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self._store.set_project(folder, dialog.selected())
        except VaultError as exc:
            QMessageBox.warning(self, "Vault", str(exc))
            return
        self._reload()

    def _remove(self) -> None:
        path = self._current_path()
        if path is None:
            return
        answer = QMessageBox.question(
            self, "Vault", f"Retirer ce projet ? Les entrées ne sont pas supprimées.\n\n{path}"
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._store.delete_project(path)
        self._reload()


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

        self._pending_only = False
        self._tag_filter = ""
        self._pending_button = QPushButton("En attente")
        self._pending_button.setCheckable(True)
        self._pending_button.toggled.connect(self._toggle_pending_filter)
        self._tag_combo = QComboBox()
        self._tag_combo.addItem("Toutes les étiquettes", "")
        self._tag_combo.currentIndexChanged.connect(self._tag_changed)

        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["Nom", "Étiquettes", "Expire", "Modifié", "Dernier usage"])
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_row_menu)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.doubleClicked.connect(lambda _index: self._edit())
        # Raccourcis : seulement quand le tableau a le focus, pour ne pas gêner la saisie ailleurs.
        for keys, slot in (
            ("Return", self._edit),
            ("Enter", self._edit),
            ("Ctrl+C", self._copy),
            ("Delete", self._delete),
        ):
            shortcut = QShortcut(QKeySequence(keys), self._table)
            shortcut.setContext(Qt.ShortcutContext.WidgetShortcut)
            shortcut.activated.connect(slot)
        find = QShortcut(QKeySequence("Ctrl+F"), self)
        find.activated.connect(self._search.setFocus)

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
        # Icônes du jeu PyPlayer, adaptées au thème. Copier et Verrouiller n'ont pas d'équivalent : texte seul.
        self._themed_buttons = [(add, "add"), (edit, "metadata"), (delete, "remove")]
        self._refresh_icons()
        style_hints = QApplication.styleHints()
        style_hints.colorSchemeChanged.connect(lambda _scheme: self._refresh_icons())

        buttons = QHBoxLayout()
        for button in (add, edit, copy, delete):
            buttons.addWidget(button)
        buttons.addStretch()
        buttons.addWidget(lock)

        central = QWidget()
        layout = QVBoxLayout(central)
        search_row = QHBoxLayout()
        search_row.addWidget(self._search, 1)
        search_row.addWidget(self._tag_combo)
        search_row.addWidget(self._pending_button)
        layout.addLayout(search_row)
        layout.addWidget(self._table)
        layout.addLayout(buttons)
        self.setCentralWidget(central)

        self._build_menus()
        self._build_tray()
        self.statusBar().showMessage("Coffre déverrouillé. Claude peut lister et utiliser les entrées.")
        self._refresh()
        # Rappel des clés qui expirent : au démarrage, puis toutes les 6 heures.
        self._expiry_timer = QTimer(self)
        self._expiry_timer.timeout.connect(self._check_expiry)
        self._expiry_timer.start(6 * 3600 * 1000)
        self._check_expiry()

    # --- menus et barre des tâches ------------------------------------------------

    def _build_menus(self) -> None:
        tools = self.menuBar().addMenu("Outils")
        tools.addAction(_action(self, "Projets (dossiers autorisés)…", self._projects))
        tools.addAction(_action(self, "Importer un fichier .env…", self._import_env))
        tools.addAction(_action(self, "Générer une valeur aléatoire (copiée)", self._generate_value))
        tools.addSeparator()
        tools.addAction(_action(self, "Sauvegarder le coffre (chiffré)…", self._backup))
        tools.addAction(_action(self, "Restaurer une sauvegarde…", self._restore))
        tools.addSeparator()
        tools.addAction(_action(self, "Changer le mot de passe maître…", self._change_password))
        tools.addAction(_action(self, "Journal des demandes…", self._show_audit))
        tools.addSeparator()
        self._trust = QAction("Mode confiance : 1 h sans demande pour les projets", self)
        self._trust.setCheckable(True)
        self._trust.toggled.connect(self._toggle_trust)
        tools.addAction(self._trust)
        self._trust_timer = QTimer(self)
        self._trust_timer.setSingleShot(True)
        self._trust_timer.timeout.connect(self._trust_expired)
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
        icon = app_icon() or QApplication.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
        self._tray = QSystemTrayIcon(icon, self)  # la zone de notification exige une icône : repli seulement ici
        menu = QMenu(self)
        menu.addAction(_action(self, "Ouvrir", self.show_window))
        self._recent_menu = QMenu("Copier une entrée récente", menu)
        self._recent_menu.aboutToShow.connect(self._fill_recent_menu)
        menu.addMenu(self._recent_menu)
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
        today = date.today()
        expiring = dict(self._store.expiring_within(7, today))
        for r, row in enumerate(rows):
            name = row["name"]
            pending = bool(row.get("pending"))
            usage = "à renseigner" if pending else (row["last_used"] or "-")
            expiry = self._store.expiry_of(name) or "-"
            values = [name, ", ".join(self._store.tags_of(name)) or "-", expiry, row["updated"], usage]
            for c, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if pending:
                    item.setForeground(QColor("#c77700"))
                elif name in expiring and c == 2:
                    item.setForeground(QColor("#c0392b"))  # expirée ou proche de l'expiration
                self._table.setItem(r, c, item)
        self._refresh_tag_choices()
        self._apply_filter(self._search.text())

    def _refresh_tag_choices(self) -> None:
        current = self._tag_filter
        self._tag_combo.blockSignals(True)
        self._tag_combo.clear()
        self._tag_combo.addItem("Toutes les étiquettes", "")
        for tag in self._store.all_tags():
            self._tag_combo.addItem(tag, tag)
        index = self._tag_combo.findData(current)
        self._tag_combo.setCurrentIndex(max(index, 0))
        self._tag_combo.blockSignals(False)

    def _apply_filter(self, text: str) -> None:
        needle = text.strip().lower()
        for r in range(self._table.rowCount()):
            name = self._table.item(r, 0).text()
            hidden = needle not in name.lower()
            if self._pending_only and not self._store.is_pending(name):
                hidden = True
            if self._tag_filter and self._tag_filter not in self._store.tags_of(name):
                hidden = True
            self._table.setRowHidden(r, hidden)

    def _toggle_pending_filter(self, checked: bool) -> None:
        self._pending_only = checked
        self._apply_filter(self._search.text())

    def _tag_changed(self, _index: int) -> None:
        self._tag_filter = self._tag_combo.currentData() or ""
        self._apply_filter(self._search.text())

    def _show_row_menu(self, position) -> None:
        row = self._table.rowAt(position.y())
        if row < 0:
            return
        self._table.selectRow(row)
        menu = QMenu(self)
        menu.addAction(_action(self, "Copier la valeur", self._copy))
        menu.addAction(_action(self, "Copier la référence NOM=vault:NOM", self._copy_reference))
        menu.addAction(_action(self, "Modifier la valeur", self._edit))
        menu.addAction(_action(self, "Date d'expiration…", self._set_expiry))
        menu.addAction(_action(self, "Étiquettes…", self._set_tags))
        menu.addSeparator()
        menu.addAction(_action(self, "Supprimer", self._delete))
        menu.exec(self._table.viewport().mapToGlobal(position))

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
        if self._store.is_pending(name):
            self.statusBar().showMessage(f"« {name} » est en attente : renseigne sa valeur d'abord (Modifier la valeur).")
            return
        self._copy_text(self._store.get_value(name), f"« {name} » copié.")

    def _copy_text(self, value: str, message: str) -> None:
        """Copie une valeur sensible, effacée du presse-papiers après un délai."""
        QApplication.clipboard().setText(value)
        self._last_copied = value
        if self._clear_timer is not None:
            self._clear_timer.stop()
        self._clear_timer = QTimer(self)
        self._clear_timer.setSingleShot(True)
        self._clear_timer.timeout.connect(self._clear_clipboard)
        self._clear_timer.start(CLIPBOARD_CLEAR_MS)
        seconds = CLIPBOARD_CLEAR_MS // 1000
        self.statusBar().showMessage(f"{message} Effacé du presse-papiers dans {seconds} s.")

    def _copy_reference(self) -> None:
        """Copie `NOM=vault:NOM` : aucune valeur, donc pas de nettoyage du presse-papiers."""
        name = self._selected_name()
        if name is None:
            self.statusBar().showMessage("Sélectionne une entrée.")
            return
        reference = f"{name}=vault:{name}"
        QApplication.clipboard().setText(reference)
        self.statusBar().showMessage(f"Référence « {reference} » copiée : colle-la dans .env.vault.")

    def _generate_value(self) -> None:
        """Génère une clé aléatoire forte et la copie. Rien n'est enregistré : l'utilisateur la colle où il veut."""
        self._copy_text(secrets.token_urlsafe(32), "Valeur générée (43 caractères).")

    def _set_expiry(self) -> None:
        name = self._selected_name()
        if name is None:
            return
        current = self._store.expiry_of(name) or ""
        text, ok = QInputDialog.getText(
            self, "Vault", f"Date d'expiration de {name} (AAAA-MM-JJ, vide pour aucune) :", text=current
        )
        if not ok:
            return
        try:
            self._store.set_expiry(name, text.strip())
        except VaultError as exc:
            QMessageBox.warning(self, "Vault", str(exc))
            return
        self._refresh()
        self._check_expiry()

    def _set_tags(self) -> None:
        name = self._selected_name()
        if name is None:
            return
        current = ", ".join(self._store.tags_of(name))
        text, ok = QInputDialog.getText(
            self, "Vault", f"Étiquettes de {name}, séparées par des virgules :", text=current
        )
        if not ok:
            return
        try:
            self._store.set_tags(name, text.split(","))
        except VaultError as exc:
            QMessageBox.warning(self, "Vault", str(exc))
            return
        self._refresh()

    def _check_expiry(self) -> None:
        """Signale les clés expirées ou qui expirent dans 7 jours : barre d'état et zone de notification."""
        soon = self._store.expiring_within(7, date.today())
        if not soon:
            return
        expired = [name for name, text in soon if date.fromisoformat(text) < date.today()]
        parts = [f"{name} ({text})" for name, text in soon]
        message = "Clés à renouveler : " + ", ".join(parts)
        self.statusBar().showMessage(message)
        title = "Vault : clé expirée" if expired else "Vault : clé qui expire bientôt"
        self.notify(title, ", ".join(parts))

    def notify(self, title: str, message: str) -> None:
        """Notification dans la zone de l'horloge, quand l'interface n'est pas au premier plan."""
        if self._tray is not None:
            self._tray.showMessage(title, message, QSystemTrayIcon.MessageIcon.Information, 8000)

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

    def _projects(self) -> None:
        ProjectsDialog(self, self._store).exec()
        self._refresh()

    def _fill_recent_menu(self) -> None:
        self._recent_menu.clear()
        recent = [
            row for row in self._store.list_metadata() if row["last_used"] and not row.get("pending")
        ]
        recent.sort(key=lambda row: row["last_used"], reverse=True)
        if not recent:
            empty = self._recent_menu.addAction("Aucune entrée récente")
            empty.setEnabled(False)
            return
        for row in recent[:5]:
            name = row["name"]
            self._recent_menu.addAction(_action(self, name, lambda n=name: self._copy_by_name(n)))

    def _copy_by_name(self, name: str) -> None:
        if self._store.is_pending(name):
            self.statusBar().showMessage(f"« {name} » est en attente : renseigne sa valeur d'abord.")
            return
        self._copy_text(self._store.get_value(name), f"« {name} » copié.")

    def _import_env(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Fichier .env à importer", "", "Fichiers .env (.env*);;Tous (*)")
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as handle:
                pairs, ignored = parse_env(handle.read())
        except (OSError, UnicodeDecodeError) as exc:
            QMessageBox.warning(self, "Vault", f"Fichier illisible : {exc}")
            return
        new: list[str] = []
        present: list[str] = []
        invalid: list[str] = []
        for name, _value in pairs:
            try:
                validate_name(name)
            except VaultError:
                invalid.append(name)
                continue
            (present if name in self._store else new).append(name)
        if not new:
            QMessageBox.information(self, "Vault", "Rien à importer : toutes les variables sont déjà dans le coffre.")
            return
        # Seuls les noms s'affichent ici : aucune valeur n'est montrée.
        summary = f"Variables à importer ({len(new)}) : {', '.join(new)}"
        if present:
            summary += f"\n\nDéjà présentes, non modifiées ({len(present)}) : {', '.join(present)}"
        if invalid or ignored:
            summary += f"\n\nIgnorées : {', '.join(invalid + ignored)}"
        answer = QMessageBox.question(
            self,
            "Vault : importer un .env",
            summary + "\n\nImporter ?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        values = dict(pairs)
        imported = 0
        for name in new:
            try:
                self._store.set(name, values[name])
                imported += 1
            except VaultError as exc:
                QMessageBox.warning(self, "Vault", f"« {name} » ignorée : {exc}")
        self._refresh()
        self.statusBar().showMessage(f"{imported} variable(s) importée(s).")
        keep = QMessageBox.question(
            self,
            "Vault",
            "Supprimer le fichier .env en clair ? Ses valeurs sont maintenant dans le coffre.\n\n"
            f"{path}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if keep == QMessageBox.StandardButton.Yes:
            try:
                os.remove(path)
                self.statusBar().showMessage("Fichier .env supprimé après import.")
            except OSError as exc:
                QMessageBox.warning(self, "Vault", f"Suppression impossible : {exc}")

    def _backup(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Enregistrer la sauvegarde", "vault-sauvegarde.vbak", "Sauvegarde Vault (*.vbak)")
        if not path:
            return
        password = ask_new_password(self, "Mot de passe de la sauvegarde (différent de celui du coffre)")
        if password is None:
            return
        try:
            write_backup(self._store, Path(path), password)
        except (OSError, VaultError) as exc:
            QMessageBox.warning(self, "Vault", f"Sauvegarde impossible : {exc}")
            return
        self.statusBar().showMessage(f"Sauvegarde écrite : {path}")

    def _restore(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Sauvegarde à restaurer", "", "Sauvegarde Vault (*.vbak)")
        if not path:
            return
        password, ok = QInputDialog.getText(
            self, "Vault", "Mot de passe de la sauvegarde :", QLineEdit.EchoMode.Password
        )
        if not ok:
            return
        try:
            payload = read_backup(Path(path), password)
            report = self._store.import_payload(payload)
        except VaultError as exc:
            QMessageBox.warning(self, "Vault", str(exc))
            return
        self._refresh()
        QMessageBox.information(
            self,
            "Vault",
            f"Restauré : {len(report['added'])} entrée(s) ajoutée(s).\n"
            f"Ignorées (déjà présentes ou invalides) : {len(report['skipped'])}.\n"
            "Les entrées existantes ne sont jamais écrasées.",
        )

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

    def _refresh_icons(self) -> None:
        for button, name in self._themed_buttons:
            button.setIcon(themed_icon(name))

    def _set_trust_checked(self, checked: bool) -> None:
        self._trust.blockSignals(True)
        self._trust.setChecked(checked)
        self._trust.blockSignals(False)

    def _toggle_trust(self, checked: bool) -> None:
        broker = self._server.broker
        if not checked:
            if broker is not None:
                broker.disable_trust()
            self._trust_timer.stop()
            self.statusBar().showMessage("Mode confiance désactivé.")
            return
        answer = QMessageBox.question(
            self,
            "Vault : mode confiance",
            "Pendant 1 heure, Claude pourra lancer « vault exec » dans les projets enregistrés sans te demander.\n\n"
            "Restent soumis à approbation : les entrées hors projet, « vault run » et la copie.\n"
            "Le mode s'arrête à la fin de l'heure ou au verrouillage.\n\nActiver ?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes or broker is None:
            self._set_trust_checked(False)
            return
        broker.enable_trust(TRUST_SECONDS)
        self._trust_timer.start(TRUST_SECONDS * 1000)
        self.statusBar().showMessage("Mode confiance actif pendant 1 h (vault exec dans les projets).")

    def _trust_expired(self) -> None:
        self._set_trust_checked(False)
        self.statusBar().showMessage("Mode confiance terminé : les demandes redeviennent soumises à approbation.")

    def lock(self) -> None:
        """Verrouille : débranche le courtier, efface le presse-papiers, demande le mot de passe."""
        self._trust_timer.stop()
        self._set_trust_checked(False)
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
    broker = Broker(store, approve=lambda summary: _approve_with_notice(window, summary), audit_path=audit_file())
    server.set_broker(broker)


def _approve_with_notice(window: QWidget, summary: str) -> str:
    """Prévient dans la zone de notification (utile si la fenêtre est cachée), puis demande l'approbation."""
    if isinstance(window, MainWindow):
        window.notify("Vault : Claude demande un accès", summary.splitlines()[0] if summary else "")
    return ask_approval(window, summary)


def main() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("Vault")
    icon = app_icon()
    if icon is not None:
        app.setWindowIcon(icon)
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
