"""Chiffrement et stockage : rien en clair sur le disque, mauvais mot de passe refusé."""

import json
from pathlib import Path

import pytest

from vault import crypto
from vault.store import VaultError, VaultStore, validate_name

SECRET = "tok_SECRET_VALUE_12345"


def test_round_trip_and_no_plaintext_on_disk(tmp_path: Path) -> None:
    path = tmp_path / "vault.enc"
    store = VaultStore.create(path, "motdepasse-long")
    store.set("GH_TOKEN", SECRET)

    assert SECRET.encode() not in path.read_bytes()

    reopened = VaultStore.open(path, "motdepasse-long")
    assert reopened.get_value("GH_TOKEN") == SECRET


def test_wrong_password_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "vault.enc"
    VaultStore.create(path, "bon-mot-de-passe").set("A", "1")
    with pytest.raises(crypto.WrongPassword):
        VaultStore.open(path, "mauvais-mot-de-passe")


def test_tampered_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "vault.enc"
    VaultStore.create(path, "bon-mot-de-passe").set("A", "1")
    blob = json.loads(path.read_text(encoding="utf-8"))
    blob["ct"] = blob["ct"][:-4] + ("AAAA" if not blob["ct"].endswith("AAAA") else "BBBB")
    path.write_text(json.dumps(blob), encoding="utf-8")
    with pytest.raises(crypto.WrongPassword):
        VaultStore.open(path, "bon-mot-de-passe")


def test_metadata_has_dates_and_no_values(tmp_path: Path) -> None:
    store = VaultStore.create(tmp_path / "vault.enc", "bon-mot-de-passe")
    store.set("A_KEY", SECRET)
    store.mark_used("A_KEY")
    rows = store.list_metadata()
    assert rows[0]["name"] == "A_KEY"
    assert rows[0]["created"] and rows[0]["updated"] and rows[0]["last_used"]
    assert SECRET not in json.dumps(rows)


def test_update_keeps_creation_date(tmp_path: Path) -> None:
    store = VaultStore.create(tmp_path / "vault.enc", "bon-mot-de-passe")
    store.set("A", "1")
    created = store.list_metadata()[0]["created"]
    store.set("A", "2")
    assert store.list_metadata()[0]["created"] == created


def test_delete_and_missing_entries(tmp_path: Path) -> None:
    store = VaultStore.create(tmp_path / "vault.enc", "bon-mot-de-passe")
    store.set("A", "1")
    store.delete("A")
    assert "A" not in store
    with pytest.raises(VaultError):
        store.delete("A")


@pytest.mark.parametrize("name", ["", "1ABC", "A-B", "A" * 65, "A B"])
def test_invalid_names_are_rejected(name: str) -> None:
    with pytest.raises(VaultError):
        validate_name(name)


def test_create_refuses_to_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "vault.enc"
    VaultStore.create(path, "bon-mot-de-passe")
    with pytest.raises(VaultError):
        VaultStore.create(path, "autre-mot-de-passe")
