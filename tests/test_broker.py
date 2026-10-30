"""Courtier : approbation, masquage, injection, journal sans valeur."""

import base64
import json
import subprocess
from pathlib import Path

import pytest

from vault import broker as broker_module
from vault.broker import Broker
from vault.store import VaultStore

SECRET = "ghp_SECRET_VALUE_12345"


@pytest.fixture
def store(tmp_path: Path) -> VaultStore:
    s = VaultStore.create(tmp_path / "vault.enc", "bon-mot-de-passe")
    s.set("GH_TOKEN", SECRET)
    return s


def make_broker(store: VaultStore, tmp_path: Path, approved: bool) -> tuple[Broker, list[str]]:
    asked: list[str] = []

    def approve(summary: str) -> bool:
        asked.append(summary)
        return approved

    return Broker(store, approve, tmp_path / "audit.jsonl"), asked


def audit_text(tmp_path: Path) -> str:
    path = tmp_path / "audit.jsonl"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def test_list_never_asks_and_never_leaks_value(store: VaultStore, tmp_path: Path) -> None:
    broker, asked = make_broker(store, tmp_path, approved=False)
    reply = broker.handle({"action": "list"})
    assert reply["ok"] is True
    assert asked == []
    assert SECRET not in json.dumps(reply)


def test_gh_secret_refused_runs_nothing(store: VaultStore, tmp_path: Path, monkeypatch) -> None:
    calls: list = []
    monkeypatch.setattr(broker_module.subprocess, "run", lambda *a, **k: calls.append(a))
    monkeypatch.setattr(broker_module.shutil, "which", lambda _: "gh")
    broker, asked = make_broker(store, tmp_path, approved=False)

    reply = broker.handle({"action": "gh_secret", "name": "GH_TOKEN", "repo": "a/b"})

    assert reply["ok"] is False
    assert len(asked) == 1
    assert calls == []
    assert "refusé" in audit_text(tmp_path)


def test_gh_secret_sends_value_on_stdin_not_argv(store: VaultStore, tmp_path: Path, monkeypatch) -> None:
    seen: dict = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["input"] = kwargs.get("input")
        return subprocess.CompletedProcess(argv, 0, stdout="ok\n", stderr="")

    monkeypatch.setattr(broker_module.subprocess, "run", fake_run)
    monkeypatch.setattr(broker_module.shutil, "which", lambda _: "gh")
    broker, _ = make_broker(store, tmp_path, approved=True)

    reply = broker.handle({"action": "gh_secret", "name": "GH_TOKEN", "repo": "a/b"})

    assert reply["ok"] is True
    assert seen["input"] == SECRET
    assert SECRET not in " ".join(seen["argv"])
    assert seen["argv"][-2:] == ["--repo", "a/b"]
    assert SECRET not in audit_text(tmp_path)


def test_gh_secret_rejects_bad_repo(store: VaultStore, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(broker_module.shutil, "which", lambda _: "gh")
    broker, asked = make_broker(store, tmp_path, approved=True)
    reply = broker.handle({"action": "gh_secret", "name": "GH_TOKEN", "repo": "a/b; rm -rf"})
    assert reply["ok"] is False
    assert asked == []


def test_run_injects_env_and_masks_output(store: VaultStore, tmp_path: Path, monkeypatch) -> None:
    b64 = base64.b64encode(SECRET.encode()).decode()

    def fake_run(argv, **kwargs):
        assert kwargs["env"]["MY_TOKEN"] == SECRET
        out = f"valeur={SECRET} b64={b64}\n"
        return subprocess.CompletedProcess(argv, 3, stdout=out, stderr=SECRET)

    monkeypatch.setattr(broker_module.subprocess, "run", fake_run)
    broker, _ = make_broker(store, tmp_path, approved=True)

    reply = broker.handle(
        {"action": "run", "name": "GH_TOKEN", "env_var": "MY_TOKEN", "argv": ["python", "x.py"]}
    )

    assert reply["returncode"] == 3
    assert reply["ok"] is False
    assert SECRET not in reply["stdout"] and b64 not in reply["stdout"]
    assert SECRET not in reply["stderr"]
    assert "***" in reply["stdout"]


@pytest.mark.parametrize(
    "request_",
    [
        {"action": "run", "name": "GH_TOKEN", "env_var": "1BAD", "argv": ["x"]},
        {"action": "run", "name": "GH_TOKEN", "env_var": "OK", "argv": []},
        {"action": "run", "name": "GH_TOKEN", "env_var": "OK", "argv": "pas une liste"},
        {"action": "run", "name": "INCONNU", "env_var": "OK", "argv": ["x"]},
        {"action": "inconnue"},
    ],
)
def test_invalid_requests_are_rejected(store: VaultStore, tmp_path: Path, request_) -> None:
    broker, asked = make_broker(store, tmp_path, approved=True)
    reply = broker.handle(request_)
    assert reply["ok"] is False
    assert asked == []


def test_audit_records_decision_without_value(store: VaultStore, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        broker_module.subprocess,
        "run",
        lambda argv, **k: subprocess.CompletedProcess(argv, 0, stdout="", stderr=""),
    )
    broker, _ = make_broker(store, tmp_path, approved=True)
    broker.handle({"action": "run", "name": "GH_TOKEN", "env_var": "T", "argv": ["echo"]})
    text = audit_text(tmp_path)
    assert '"decision": "approuvé"' in text
    assert SECRET not in text
