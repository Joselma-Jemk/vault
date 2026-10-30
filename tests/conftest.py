"""Réglages communs aux tests."""

import os

# Pas d'écran requis : Qt tourne hors écran (CI, serveurs, terminaux sans bureau).
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402

from vault import crypto  # noqa: E402


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    """Coût scrypt réduit pour que la suite reste rapide. Le coût réel est vérifié dans test_security."""
    monkeypatch.setattr(crypto, "SCRYPT_N", 2**10)


@pytest.fixture(scope="session")
def qapp():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])
