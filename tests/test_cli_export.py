"""CLI export-env et project-add : branchées sur un vrai courtier, sans canal local."""

from pathlib import Path

import pytest

from vault import cli
from vault.broker import ONCE, Broker
from vault.store import VaultStore


@pytest.fixture
def wired(tmp_path: Path, monkeypatch):
    store = VaultStore.create(tmp_path / "vault.enc", "bon-mot-de-passe")
    store.set("R2_KEY", "valeur-r2-secrete")
    store.set("S3", "valeur-s3-secrete")
    broker = Broker(store, lambda summary: ONCE, tmp_path / "audit.jsonl")
    monkeypatch.setattr(cli, "_request", broker.handle)
    project = tmp_path / "app"
    project.mkdir()
    monkeypatch.chdir(project)
    return store, project


def test_project_add_then_export_with_rename(wired, capsys) -> None:
    store, project = wired
    assert cli.main(["project-add", "R2_KEY", "S3"]) == 0
    assert cli.main(["export-env", "ACCESS=R2_KEY", "S3"]) == 0
    assert (project / ".env").read_text(encoding="utf-8") == "ACCESS=valeur-r2-secrete\nS3=valeur-s3-secrete\n"
    out = capsys.readouterr().out
    assert "valeur-r2-secrete" not in out and "valeur-s3-secrete" not in out
    assert "ACCESS" in out


def test_project_add_all_and_default_export(wired) -> None:
    _, project = wired
    assert cli.main(["project-add", "--all"]) == 0
    assert cli.main(["export-env", "--file", "prod.env"]) == 0
    assert (project / "prod.env").read_text(encoding="utf-8").count("\n") == 2


def test_project_add_needs_names_or_all(wired, capsys) -> None:
    assert cli.main(["project-add"]) == 1
    assert "--all" in capsys.readouterr().err


def test_export_env_refuses_second_write_without_overwrite(wired, capsys) -> None:
    cli.main(["project-add", "R2_KEY"])
    assert cli.main(["export-env"]) == 0
    assert cli.main(["export-env"]) == 1
    assert "overwrite" in capsys.readouterr().err
    assert cli.main(["export-env", "--overwrite"]) == 0
