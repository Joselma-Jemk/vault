"""Mode confiance : une heure sans demande pour `vault exec` dans les projets, jamais pour `run`."""

import subprocess
from pathlib import Path

import pytest

from vault import broker as broker_module
from vault.broker import ONCE, TRUST_LABEL, TRUST_SECONDS, Broker
from vault.store import VaultStore

GH = "ghp_TRUST_SECRET_1"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def store(tmp_path: Path) -> VaultStore:
    s = VaultStore.create(tmp_path / "vault.enc", "bon-mot-de-passe")
    s.set("GH_TOKEN", GH)
    s.set("OTHER", "autre-valeur")
    return s


@pytest.fixture
def project(tmp_path: Path, store: VaultStore) -> Path:
    root = tmp_path / "monprojet"
    root.mkdir()
    store.set_project(str(root), ["GH_TOKEN"])
    return root


@pytest.fixture
def run_stub(monkeypatch):
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="ok\n", stderr="")

    monkeypatch.setattr(broker_module.subprocess, "run", fake_run)
    return calls


def make_broker(store: VaultStore, tmp_path: Path, clock: Clock):
    asked: list[str] = []

    def approve(summary: str):
        asked.append(summary)
        return ONCE

    return Broker(store, approve, tmp_path / "audit.jsonl", clock=clock), asked


def exec_request(project: Path) -> dict:
    return {
        "action": "exec",
        "project": str(project),
        "mapping": {"GITHUB_TOKEN": "GH_TOKEN"},
        "argv": ["python", "app.py"],
    }


def test_trust_runs_exec_in_project_without_asking(store, project, tmp_path, run_stub) -> None:
    clock = Clock()
    broker, asked = make_broker(store, tmp_path, clock)
    broker.enable_trust()
    reply = broker.handle(exec_request(project))
    assert reply["ok"] is True
    assert asked == []
    assert len(run_stub) == 1
    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert TRUST_LABEL in audit_text
    assert GH not in audit_text


def test_trust_expires_after_one_hour(store, project, tmp_path, run_stub) -> None:
    clock = Clock()
    broker, asked = make_broker(store, tmp_path, clock)
    broker.enable_trust()
    clock.now += TRUST_SECONDS + 1
    assert broker.trust_remaining() == 0
    broker.handle(exec_request(project))
    assert len(asked) == 1


def test_trust_never_covers_run(store, project, tmp_path, run_stub) -> None:
    clock = Clock()
    broker, asked = make_broker(store, tmp_path, clock)
    broker.enable_trust()
    broker.handle({"action": "run", "name": "GH_TOKEN", "env_var": "GH_TOKEN", "argv": ["gh", "api", "user"]})
    assert len(asked) == 1


def test_disable_trust_asks_again(store, project, tmp_path, run_stub) -> None:
    clock = Clock()
    broker, asked = make_broker(store, tmp_path, clock)
    broker.enable_trust()
    broker.disable_trust()
    broker.handle(exec_request(project))
    assert len(asked) == 1


def test_trust_does_not_extend_project_rights(store, project, tmp_path, run_stub) -> None:
    clock = Clock()
    broker, asked = make_broker(store, tmp_path, clock)
    broker.enable_trust()
    reply = broker.handle(
        {
            "action": "exec",
            "project": str(project),
            "mapping": {"X": "OTHER"},
            "argv": ["python", "app.py"],
        }
    )
    assert reply["ok"] is False
    assert asked == []
    assert run_stub == []


def test_trust_remaining_counts_down(store, tmp_path) -> None:
    clock = Clock()
    broker, _ = make_broker(store, tmp_path, clock)
    broker.enable_trust(100)
    clock.now += 40
    assert broker.trust_remaining() == pytest.approx(60)
