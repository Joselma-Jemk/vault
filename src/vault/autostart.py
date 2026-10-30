"""Lancement de Vault à l'ouverture de session Windows (clé HKCU ... \\Run, sans droits administrateur)."""

from __future__ import annotations

import os
import sys

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "Vault"


def _is_compiled() -> bool:
    """Vrai dans un binaire (Nuitka définit `__compiled__`, PyInstaller définit `sys.frozen`)."""
    return "__compiled__" in globals() or bool(getattr(sys, "frozen", False))


def launch_command() -> str:
    """Commande inscrite au démarrage. Sans argument, Vault ouvre l'interface."""
    if _is_compiled():
        # En onefile, `sys.executable` pointe vers un dossier temporaire : le vrai binaire est argv[0].
        return f'"{os.path.abspath(sys.argv[0])}"'
    executable = sys.executable
    windowed = os.path.join(os.path.dirname(executable), "pythonw.exe")
    if os.path.basename(executable).lower() == "python.exe" and os.path.exists(windowed):
        executable = windowed  # pas de fenêtre de console au démarrage
    return f'"{executable}" -m vault'


def is_enabled() -> bool:
    if sys.platform != "win32":
        return False
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            value, _ = winreg.QueryValueEx(key, VALUE_NAME)
    except FileNotFoundError:
        return False
    return value == launch_command()


def set_enabled(enabled: bool) -> None:
    if sys.platform != "win32":
        raise OSError("Lancement automatique disponible uniquement sous Windows")
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_SZ, launch_command())
            return
        try:
            winreg.DeleteValue(key, VALUE_NAME)
        except FileNotFoundError:
            pass
