"""Export .env et ajout de projet par l'IA : approbation normale, libre en mode confiance, avec des garde-fous."""

from pathlib import Path

import pytest

from vault.broker import DENY, ONCE, Broker
from vault.store import VaultStore

KEY = "AKIA_TEST_SECRET_1"
HARD = 'va"leur avec espace #et\nretour'


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def store(tmp_path: Path) -> VaultStore:
    s = VaultStore.create(tmp_path / "vault.enc", "bon-mot-de-passe")
    s.set("R2_KEY", KEY)
    s.set("HARD", HARD)
    s.set("OTHER", "autre")
    s.declare("PENDING")
    return s


@pytest.fixture
def project(tmp_path: Path, store: VaultStore) -> Path:
    root = tmp_path / "monprojet"
    root.mkdir()
    store.set_project(str(root), ["R2_KEY", "HARD", "PENDING"])
    return root


def make(store: VaultStore, tmp_path: Path, answer=ONCE):
    asked: list[str] = []

    def approve(summary: str):
        asked.append(summary)
        return answer

    return Broker(store, approve, tmp_path / "audit.jsonl", clock=Clock()), asked


# --- export .env ---------------------------------------------------------------------


def test_export_writes_values_only_to_the_file(store, project, tmp_path) -> None:
    broker, asked = make(store, tmp_path)
    reply = broker.handle({"action": "export_env", "project": str(project), "mapping": {"R2_KEY": "R2_KEY"}})
    assert reply["ok"] is True
    assert (project / ".env").read_text(encoding="utf-8") == f"R2_KEY={KEY}\n"
    assert KEY not in str(reply)  # la réponse ne contient jamais la valeur
    assert KEY not in asked[0]  # ni la fenêtre d'approbation
    assert "EN CLAIR" in asked[0]
    assert KEY not in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")


def test_export_without_names_takes_every_allowed_entry_but_not_pending(store, project, tmp_path) -> None:
    broker, _ = make(store, tmp_path)
    reply = broker.handle({"action": "export_env", "project": str(project)})
    assert reply["ok"] is True
    assert reply["data"]["variables"] == ["HARD", "R2_KEY"]


def test_export_can_rename_variables(store, project, tmp_path) -> None:
    broker, _ = make(store, tmp_path)
    broker.handle({"action": "export_env", "project": str(project), "mapping": {"S3_KEY": "R2_KEY"}})
    assert (project / ".env").read_text(encoding="utf-8") == f"S3_KEY={KEY}\n"


def test_export_quotes_awkward_values(store, project, tmp_path) -> None:
    broker, _ = make(store, tmp_path)
    broker.handle({"action": "export_env", "project": str(project), "mapping": {"HARD": "HARD"}})
    line = (project / ".env").read_text(encoding="utf-8")
    assert line == 'HARD="va\\"leur avec espace #et\\nretour"\n'


def test_export_refused_by_user_writes_nothing(store, project, tmp_path) -> None:
    broker, _ = make(store, tmp_path, answer=DENY)
    reply = broker.handle({"action": "export_env", "project": str(project)})
    assert reply["ok"] is False
    assert not (project / ".env").exists()


def test_export_refuses_entry_outside_the_project(store, project, tmp_path) -> None:
    broker, asked = make(store, tmp_path)
    reply = broker.handle({"action": "export_env", "project": str(project), "mapping": {"OTHER": "OTHER"}})
    assert reply["ok"] is False
    assert asked == []


def test_export_refuses_pending_entry(store, project, tmp_path) -> None:
    broker, _ = make(store, tmp_path)
    reply = broker.handle({"action": "export_env", "project": str(project), "mapping": {"PENDING": "PENDING"}})
    assert reply["ok"] is False
    assert "attente" in reply["error"]


def test_export_needs_a_registered_project(store, tmp_path) -> None:
    free = tmp_path / "libre"
    free.mkdir()
    broker, _ = make(store, tmp_path)
    assert broker.handle({"action": "export_env", "project": str(free)})["ok"] is False


def test_export_never_overwrites_without_flag(store, project, tmp_path) -> None:
    (project / ".env").write_text("A=garde-moi\n", encoding="utf-8")
    broker, _ = make(store, tmp_path)
    reply = broker.handle({"action": "export_env", "project": str(project), "mapping": {"R2_KEY": "R2_KEY"}})
    assert reply["ok"] is False
    assert (project / ".env").read_text(encoding="utf-8") == "A=garde-moi\n"
    again = broker.handle(
        {"action": "export_env", "project": str(project), "mapping": {"R2_KEY": "R2_KEY"}, "overwrite": True}
    )
    assert again["ok"] is True


@pytest.mark.parametrize("target", ["../dehors.env", "..\\dehors.env", "sous/../../dehors.env"])
def test_export_cannot_escape_the_project(store, project, tmp_path, target) -> None:
    broker, asked = make(store, tmp_path)
    reply = broker.handle({"action": "export_env", "project": str(project), "file": target})
    assert reply["ok"] is False
    assert asked == []
    assert not (tmp_path / "dehors.env").exists()


def test_export_in_a_subfolder_of_the_project(store, project, tmp_path) -> None:
    (project / "config").mkdir()
    broker, _ = make(store, tmp_path)
    reply = broker.handle(
        {"action": "export_env", "project": str(project), "file": "config/app.env", "mapping": {"R2_KEY": "R2_KEY"}}
    )
    assert reply["ok"] is True
    assert (project / "config" / "app.env").exists()


def test_export_warns_when_git_does_not_ignore_it(store, project, tmp_path) -> None:
    (project / ".git").mkdir()
    broker, _ = make(store, tmp_path)
    reply = broker.handle({"action": "export_env", "project": str(project), "mapping": {"R2_KEY": "R2_KEY"}})
    assert "gitignore" in reply["data"]["warning"]
    (project / ".env").unlink()
    (project / ".gitignore").write_text(".env\n", encoding="utf-8")
    ok = broker.handle({"action": "export_env", "project": str(project), "mapping": {"R2_KEY": "R2_KEY"}})
    assert "warning" not in ok["data"]


def test_trust_makes_export_silent_but_not_run(store, project, tmp_path) -> None:
    broker, asked = make(store, tmp_path)
    broker.enable_trust()
    reply = broker.handle({"action": "export_env", "project": str(project), "mapping": {"R2_KEY": "R2_KEY"}})
    assert reply["ok"] is True
    assert asked == []
    run = broker.handle({"action": "run", "name": "R2_KEY", "env_var": "X", "argv": ["python", "-c", "pass"]})
    assert run["ok"] is True
    assert len(asked) == 1, "run doit toujours demander l'approbation, même en mode confiance"


# --- ajout de projet ------------------------------------------------------------------


def test_project_add_asks_then_registers(store, tmp_path) -> None:
    folder = tmp_path / "nouveau"
    folder.mkdir()
    broker, asked = make(store, tmp_path)
    reply = broker.handle({"action": "project_add", "directory": str(folder), "names": ["R2_KEY"]})
    assert reply["ok"] is True
    assert len(asked) == 1 and "R2_KEY" in asked[0]
    assert store.effective_entries(store.resolve_project(str(folder))) == {"R2_KEY"}


def test_project_add_refused_registers_nothing(store, tmp_path) -> None:
    folder = tmp_path / "nouveau"
    folder.mkdir()
    broker, _ = make(store, tmp_path, answer=DENY)
    assert broker.handle({"action": "project_add", "directory": str(folder), "names": ["R2_KEY"]})["ok"] is False
    assert store.list_projects() == []


def test_project_add_is_silent_in_trust_mode(store, tmp_path) -> None:
    folder = tmp_path / "nouveau"
    folder.mkdir()
    broker, asked = make(store, tmp_path)
    broker.enable_trust()
    assert broker.handle({"action": "project_add", "directory": str(folder), "all": True})["ok"] is True
    assert asked == []
    assert store.effective_entries(store.resolve_project(str(folder))) == {"R2_KEY", "HARD", "OTHER", "PENDING"}


def test_project_add_merges_and_never_removes_rights(store, project, tmp_path) -> None:
    broker, _ = make(store, tmp_path)
    broker.handle({"action": "project_add", "directory": str(project), "names": ["OTHER"]})
    assert store.effective_entries(store.resolve_project(str(project))) == {"R2_KEY", "HARD", "PENDING", "OTHER"}


def test_project_add_refuses_unknown_entry_and_missing_folder(store, tmp_path) -> None:
    folder = tmp_path / "nouveau"
    folder.mkdir()
    broker, asked = make(store, tmp_path)
    assert broker.handle({"action": "project_add", "directory": str(folder), "names": ["NOPE"]})["ok"] is False
    assert broker.handle({"action": "project_add", "directory": str(tmp_path / "absent"), "names": ["R2_KEY"]})["ok"] is False
    assert asked == []


def test_project_add_refuses_home_drive_root_and_parents(store, tmp_path) -> None:
    broker, asked = make(store, tmp_path)
    broker.enable_trust()
    home = Path.home()
    for folder in (home, home.parent, Path(home.anchor)):
        reply = broker.handle({"action": "project_add", "directory": str(folder), "all": True})
        assert reply["ok"] is False, folder
    assert store.list_projects() == []
    assert asked == []
