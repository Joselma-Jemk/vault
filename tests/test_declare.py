"""Entrées en attente : Claude déclare un nom, l'utilisateur renseigne la valeur plus tard."""

from pathlib import Path

import pytest

from vault import broker as broker_module
from vault import cli
from vault.broker import ONCE, Broker
from vault.store import VaultError, VaultStore


@pytest.fixture
def store(tmp_path: Path) -> VaultStore:
    s = VaultStore.create(tmp_path / "vault.enc", "bon-mot-de-passe")
    s.set("GH_TOKEN", "ghp_DEJA_RENSEIGNEE")
    return s


@pytest.fixture
def project_dir(tmp_path: Path) -> Path:
    root = tmp_path / "monprojet"
    root.mkdir()
    return root


def make_broker(store: VaultStore, tmp_path: Path):
    asked: list[str] = []

    def approve(summary: str):
        asked.append(summary)
        return ONCE

    return Broker(store, approve, tmp_path / "audit.jsonl"), asked


def test_declare_creates_pending_entry_without_value(store: VaultStore) -> None:
    assert store.declare("OPENAI_KEY") is True
    assert store.is_pending("OPENAI_KEY")
    assert "OPENAI_KEY" in store
    row = next(r for r in store.list_metadata() if r["name"] == "OPENAI_KEY")
    assert row["pending"] is True


def test_declare_existing_entry_changes_nothing(store: VaultStore) -> None:
    assert store.declare("GH_TOKEN") is False
    assert store.get_value("GH_TOKEN") == "ghp_DEJA_RENSEIGNEE"
    assert not store.is_pending("GH_TOKEN")


def test_declare_refuses_invalid_name(store: VaultStore) -> None:
    with pytest.raises(VaultError):
        store.declare("1-mauvais nom")


def test_user_fills_pending_entry_with_set(store: VaultStore, tmp_path: Path) -> None:
    store.declare("OPENAI_KEY")
    store.set("OPENAI_KEY", "sk-valeur-saisie-par-utilisateur")
    assert not store.is_pending("OPENAI_KEY")
    assert store.get_value("OPENAI_KEY") == "sk-valeur-saisie-par-utilisateur"


def test_pending_state_survives_reopening(store: VaultStore, tmp_path: Path) -> None:
    store.declare("OPENAI_KEY")
    reopened = VaultStore.open(tmp_path / "vault.enc", "bon-mot-de-passe")
    assert reopened.is_pending("OPENAI_KEY")


def test_broker_declare_needs_no_approval_and_is_audited(store: VaultStore, tmp_path: Path) -> None:
    broker, asked = make_broker(store, tmp_path)
    reply = broker.handle({"action": "declare", "names": ["OPENAI_KEY", "GH_TOKEN"]})
    assert reply["ok"] is True
    assert reply["data"] == {"created": ["OPENAI_KEY"], "existing": ["GH_TOKEN"]}
    assert asked == []
    audit_lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "declare" in audit_lines
    assert "ghp_DEJA_RENSEIGNEE" not in audit_lines


def test_broker_declare_rejects_bad_input(store: VaultStore, tmp_path: Path) -> None:
    broker, _ = make_broker(store, tmp_path)
    assert broker.handle({"action": "declare", "names": []})["ok"] is False
    assert broker.handle({"action": "declare", "names": ["mauvais nom"]})["ok"] is False
    assert broker.handle({"action": "declare"})["ok"] is False


def test_exec_refuses_pending_entry_before_asking_approval(
    store: VaultStore, tmp_path: Path, project_dir: Path, monkeypatch
) -> None:
    store.declare("OPENAI_KEY")
    store.set_project(str(project_dir), ["OPENAI_KEY"])
    ran: list[bool] = []
    monkeypatch.setattr(broker_module.subprocess, "run", lambda *a, **k: ran.append(True))
    broker, asked = make_broker(store, tmp_path)
    reply = broker.handle(
        {
            "action": "exec",
            "project": str(project_dir),
            "mapping": {"OPENAI_API_KEY": "OPENAI_KEY"},
            "argv": ["python", "app.py"],
        }
    )
    assert reply["ok"] is False
    assert "en attente" in reply["error"]
    assert asked == []
    assert ran == []


def test_declare_does_not_grant_project_rights(store: VaultStore, project_dir: Path) -> None:
    store.set_project(str(project_dir), ["GH_TOKEN"])
    store.declare("OPENAI_KEY")
    listed = store.list_projects()[0]["entries"]
    assert listed == ["GH_TOKEN"]


def test_cli_parses_declare_with_several_names() -> None:
    args = cli.build_parser().parse_args(["declare", "OPENAI_KEY", "STRIPE_KEY"])
    assert args.subcommand == "declare"
    assert args.names == ["OPENAI_KEY", "STRIPE_KEY"]


def test_cli_declare_requires_a_name() -> None:
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["declare"])
