"""Projets et sous-projets : droits hérités, références .env, exécution avec plusieurs secrets."""

import subprocess
from pathlib import Path

import pytest

from vault import broker as broker_module
from vault import cli
from vault.broker import ONCE, Broker
from vault.store import VaultError, VaultStore

GH = "ghp_SECRET_TOKEN_12345"
DB = "postgres://SECRET_DB_99"


@pytest.fixture
def store(tmp_path: Path) -> VaultStore:
    s = VaultStore.create(tmp_path / "vault.enc", "bon-mot-de-passe")
    s.set("GH_TOKEN", GH)
    s.set("PROD_DB", DB)
    s.set("OPENAI_KEY", "sk-autre-valeur")
    return s


@pytest.fixture
def tree(tmp_path: Path) -> dict[str, Path]:
    root = tmp_path / "monprojet"
    child = root / "backend"
    other = tmp_path / "ailleurs"
    child.mkdir(parents=True)
    other.mkdir()
    return {"root": root, "child": child, "other": other}


def make_broker(store: VaultStore, tmp_path: Path, answer=ONCE):
    asked: list[str] = []

    def approve(summary: str):
        asked.append(summary)
        return answer

    return Broker(store, approve, tmp_path / "audit.jsonl"), asked


@pytest.fixture
def run_stub(monkeypatch):
    seen: dict = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(argv, 0, stdout=f"sortie {GH} {DB}\n", stderr="")

    monkeypatch.setattr(broker_module.subprocess, "run", fake_run)
    return seen


# --- droits des projets ------------------------------------------------------------


def test_project_roundtrip_through_encrypted_file(store: VaultStore, tree, tmp_path: Path) -> None:
    store.set_project(str(tree["root"]), ["GH_TOKEN"])
    reopened = VaultStore.open(tmp_path / "vault.enc", "bon-mot-de-passe")
    assert reopened.effective_entries(next(iter(reopened.list_projects()))["path"]) == {"GH_TOKEN"}


def test_project_cannot_allow_unknown_entry(store: VaultStore, tree) -> None:
    with pytest.raises(VaultError):
        store.set_project(str(tree["root"]), ["INCONNUE"])


def test_subproject_never_gains_rights_over_parent(store: VaultStore, tree) -> None:
    store.set_project(str(tree["root"]), ["GH_TOKEN"])
    store.set_project(str(tree["child"]), ["GH_TOKEN", "PROD_DB"])  # PROD_DB n'est pas dans le parent
    assert store.effective_entries(_key(tree["child"])) == {"GH_TOKEN"}


def test_subproject_keeps_its_own_narrower_rights(store: VaultStore, tree) -> None:
    store.set_project(str(tree["root"]), ["GH_TOKEN", "PROD_DB"])
    store.set_project(str(tree["child"]), ["PROD_DB"])
    assert store.effective_entries(_key(tree["child"])) == {"PROD_DB"}


def test_directory_without_project_is_refused(store: VaultStore, tree) -> None:
    store.set_project(str(tree["root"]), ["GH_TOKEN"])
    with pytest.raises(VaultError):
        store.resolve_project(str(tree["other"]))


def test_nearest_registered_parent_is_used(store: VaultStore, tree) -> None:
    store.set_project(str(tree["root"]), ["GH_TOKEN"])
    store.set_project(str(tree["child"]), ["PROD_DB"])
    assert store.resolve_project(str(tree["child"] / "src")) == _key(tree["child"])


def _key(path: Path) -> str:
    from vault.store import normalize_dir

    return normalize_dir(str(path))


# --- broker : exec ----------------------------------------------------------------------


def test_exec_injects_all_references_with_one_approval(store, tree, tmp_path, run_stub) -> None:
    store.set_project(str(tree["root"]), ["GH_TOKEN", "PROD_DB"])
    broker, asked = make_broker(store, tmp_path)
    reply = broker.handle(
        {
            "action": "exec",
            "project": str(tree["root"]),
            "mapping": {"GITHUB_TOKEN": "GH_TOKEN", "DATABASE_URL": "PROD_DB"},
            "argv": ["python", "app.py"],
        }
    )
    assert reply["ok"] is True
    assert len(asked) == 1
    assert "GITHUB_TOKEN ← GH_TOKEN" in asked[0] and "DATABASE_URL ← PROD_DB" in asked[0]
    assert run_stub["env"]["GITHUB_TOKEN"] == GH and run_stub["env"]["DATABASE_URL"] == DB


def test_exec_masks_every_value_in_output(store, tree, tmp_path, run_stub) -> None:
    store.set_project(str(tree["root"]), ["GH_TOKEN", "PROD_DB"])
    broker, _ = make_broker(store, tmp_path)
    reply = broker.handle(
        {
            "action": "exec",
            "project": str(tree["root"]),
            "mapping": {"A": "GH_TOKEN", "B": "PROD_DB"},
            "argv": ["x"],
        }
    )
    assert GH not in reply["stdout"] and DB not in reply["stdout"]
    assert reply["stdout"].count("***") == 2


def test_exec_refuses_entry_outside_project_without_prompt(store, tree, tmp_path, run_stub) -> None:
    store.set_project(str(tree["root"]), ["GH_TOKEN"])
    broker, asked = make_broker(store, tmp_path)
    reply = broker.handle(
        {"action": "exec", "project": str(tree["root"]), "mapping": {"X": "PROD_DB"}, "argv": ["x"]}
    )
    assert reply["ok"] is False
    assert asked == []
    assert "n'est pas autorisée" in reply["error"]


def test_exec_refuses_unregistered_directory(store, tree, tmp_path, run_stub) -> None:
    store.set_project(str(tree["root"]), ["GH_TOKEN"])
    broker, asked = make_broker(store, tmp_path)
    reply = broker.handle(
        {"action": "exec", "project": str(tree["other"]), "mapping": {"X": "GH_TOKEN"}, "argv": ["x"]}
    )
    assert reply["ok"] is False and asked == []


def test_exec_grant_is_bound_to_project_and_mapping(store, tree, tmp_path, run_stub) -> None:
    from vault.broker import SESSION

    store.set_project(str(tree["root"]), ["GH_TOKEN"])
    broker, asked = make_broker(store, tmp_path, answer=SESSION)
    request = {"action": "exec", "project": str(tree["root"]), "mapping": {"X": "GH_TOKEN"}, "argv": ["x"]}
    broker.handle(request)
    broker.handle(request)  # même projet, même liste : pas de nouvelle demande
    broker.handle({**request, "mapping": {"Y": "GH_TOKEN"}})  # autre variable : nouvelle demande
    assert len(asked) == 2


# --- fichier de références --------------------------------------------------------------


def test_reference_file_accepts_references_and_comments() -> None:
    text = "# commentaire\nexport GITHUB_TOKEN=vault:GH_TOKEN  # jeton\n\nDATABASE_URL=vault:PROD_DB\n"
    assert cli.parse_references(text) == {"GITHUB_TOKEN": "GH_TOKEN", "DATABASE_URL": "PROD_DB"}


def test_reference_file_refuses_plain_values() -> None:
    with pytest.raises(ValueError, match="jamais une valeur en clair"):
        cli.parse_references("APP_ENV=production\n")


def test_reference_file_refuses_duplicates() -> None:
    with pytest.raises(ValueError, match="déjà définie"):
        cli.parse_references("A=vault:GH_TOKEN\nA=vault:PROD_DB\n")
