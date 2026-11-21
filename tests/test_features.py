"""Expiration, étiquettes, sauvegarde chiffrée, import de .env."""

from datetime import date
from pathlib import Path

import pytest

from vault.backup import read_backup, write_backup
from vault.envfile import parse_env
from vault.store import VaultError, VaultStore

PASSWORD = "bon-mot-de-passe"
BACKUP_PASSWORD = "sauvegarde-tres-solide"
GH = "ghp_FEATURE_SECRET_1"


@pytest.fixture
def store(tmp_path: Path) -> VaultStore:
    s = VaultStore.create(tmp_path / "vault.enc", PASSWORD)
    s.set("GH_TOKEN", GH)
    s.set("OPENAI_KEY", "sk-valeur")
    return s


def test_expiry_is_stored_and_listed_when_close(store: VaultStore) -> None:
    store.set_expiry("GH_TOKEN", "2026-11-25")
    store.set_expiry("OPENAI_KEY", "2030-01-01")
    soon = store.expiring_within(7, date(2026, 11, 21))
    assert soon == [("GH_TOKEN", "2026-11-25")]


def test_already_expired_is_listed_first(store: VaultStore) -> None:
    store.set_expiry("OPENAI_KEY", "2026-11-01")
    store.set_expiry("GH_TOKEN", "2026-11-20")
    assert [name for name, _ in store.expiring_within(7, date(2026, 11, 21))] == ["OPENAI_KEY", "GH_TOKEN"]


def test_bad_expiry_date_is_refused(store: VaultStore) -> None:
    with pytest.raises(VaultError):
        store.set_expiry("GH_TOKEN", "31/12/2026")


def test_clearing_expiry(store: VaultStore) -> None:
    store.set_expiry("GH_TOKEN", "2026-11-25")
    store.set_expiry("GH_TOKEN", "")
    assert store.expiry_of("GH_TOKEN") is None


def test_tags_are_saved_and_listed(store: VaultStore, tmp_path: Path) -> None:
    store.set_tags("GH_TOKEN", ["github", " ci ", "github"])
    store.set_tags("OPENAI_KEY", ["ia"])
    reopened = VaultStore.open(tmp_path / "vault.enc", PASSWORD)
    assert reopened.tags_of("GH_TOKEN") == ["ci", "github"]
    assert reopened.all_tags() == ["ci", "github", "ia"]


def test_delete_removes_expiry_and_tags(store: VaultStore) -> None:
    store.set_expiry("GH_TOKEN", "2026-11-25")
    store.set_tags("GH_TOKEN", ["github"])
    store.delete("GH_TOKEN")
    assert store.expiry_of("GH_TOKEN") is None
    assert store.all_tags() == []


def test_backup_roundtrip_is_encrypted(store: VaultStore, tmp_path: Path) -> None:
    store.set_expiry("GH_TOKEN", "2026-11-25")
    store.set_tags("GH_TOKEN", ["github"])
    target = tmp_path / "backup.vbak"
    write_backup(store, target, BACKUP_PASSWORD)
    raw = target.read_text(encoding="utf-8")
    assert GH not in raw
    assert "GH_TOKEN" not in raw
    payload = read_backup(target, BACKUP_PASSWORD)
    assert payload["entries"]["GH_TOKEN"]["value"] == GH
    assert payload["expiries"] == {"GH_TOKEN": "2026-11-25"}


def test_backup_wrong_password_is_refused(store: VaultStore, tmp_path: Path) -> None:
    target = tmp_path / "backup.vbak"
    write_backup(store, target, BACKUP_PASSWORD)
    with pytest.raises(VaultError):
        read_backup(target, "mauvais-mot-de-passe")


def test_backup_refuses_weak_password(store: VaultStore, tmp_path: Path) -> None:
    with pytest.raises(VaultError):
        write_backup(store, tmp_path / "b.vbak", "court")


def test_backup_refuses_a_plain_vault_file(store: VaultStore, tmp_path: Path) -> None:
    with pytest.raises(VaultError):
        read_backup(tmp_path / "vault.enc", PASSWORD)


def test_import_adds_missing_and_never_overwrites(store: VaultStore, tmp_path: Path) -> None:
    store.set_expiry("GH_TOKEN", "2026-11-25")
    target = tmp_path / "backup.vbak"
    write_backup(store, target, BACKUP_PASSWORD)

    fresh = VaultStore.create(tmp_path / "other.enc", PASSWORD)
    fresh.set("GH_TOKEN", "valeur-differente-gardee")
    report = fresh.import_payload(read_backup(target, BACKUP_PASSWORD))
    assert report["added"] == ["OPENAI_KEY"]
    assert report["skipped"] == ["GH_TOKEN"]
    assert fresh.get_value("GH_TOKEN") == "valeur-differente-gardee"
    assert fresh.get_value("OPENAI_KEY") == "sk-valeur"


def test_import_ignores_malformed_payload(tmp_path: Path) -> None:
    fresh = VaultStore.create(tmp_path / "x.enc", PASSWORD)
    report = fresh.import_payload({"entries": {"bad name": {"value": "x"}, "OK": {"nope": 1}}})
    assert report == {"added": [], "skipped": ["OK", "bad name"]}


def test_parse_env_reads_plain_values_and_skips_references() -> None:
    text = """
# commentaire
export GITHUB_TOKEN="ghp_abc"
DATABASE_URL='postgres://x'
PORT=8080
EMPTY=
REF=vault:GH_TOKEN
not a line
"""
    pairs, ignored = parse_env(text)
    assert pairs == [("GITHUB_TOKEN", "ghp_abc"), ("DATABASE_URL", "postgres://x"), ("PORT", "8080")]
    assert ignored == []


def test_parse_env_reports_duplicates() -> None:
    pairs, ignored = parse_env("A=1\nA=2\n")
    assert pairs == [("A", "1")]
    assert ignored == ["A"]

