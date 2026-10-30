"""Durcissement : KDF, changement de mot de passe, journal, verrouillage, approbations temporaires."""

import base64
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vault import audit, autostart, crypto, policy
from vault.broker import (
    DENY,
    ONCE,
    REFUSAL_COOLDOWN_SECONDS,
    SESSION,
    TEMP_GRANT_SECONDS,
    Broker,
)
from vault.store import MAX_VALUE_LENGTH, VaultError, VaultStore

SECRET = "tok_SECRET_VALUE_12345"


# --- chiffrement -------------------------------------------------------------------


def test_encrypt_writes_scrypt_parameters_in_clear() -> None:
    blob = crypto.encrypt(b"x", "bon-mot-de-passe")
    assert blob["v"] == crypto.FORMAT_VERSION
    assert (blob["n"], blob["r"], blob["p"]) == (crypto.SCRYPT_N, crypto.SCRYPT_R, crypto.SCRYPT_P)


def test_default_kdf_cost_is_strong() -> None:
    # Le fixture autouse réduit SCRYPT_N pour la suite : on vérifie la valeur de référence dans le source.
    source = Path(crypto.__file__).read_text(encoding="utf-8")
    assert "SCRYPT_N = 2**17" in source


def test_tampered_scrypt_parameter_is_refused() -> None:
    blob = crypto.encrypt(b"secret", "bon-mot-de-passe")
    blob["n"] = blob["n"] * 2  # même valide, mais différent de ce qui a chiffré
    with pytest.raises(crypto.WrongPassword):
        crypto.decrypt(blob, "bon-mot-de-passe")


def test_out_of_bounds_parameter_is_refused() -> None:
    blob = crypto.encrypt(b"secret", "bon-mot-de-passe")
    blob["n"] = 2**30
    with pytest.raises(crypto.WrongPassword):
        crypto.decrypt(blob, "bon-mot-de-passe")


def test_unknown_version_is_refused() -> None:
    blob = crypto.encrypt(b"secret", "bon-mot-de-passe")
    blob["v"] = 99
    with pytest.raises(crypto.WrongPassword):
        crypto.decrypt(blob, "bon-mot-de-passe")


def test_legacy_v1_file_still_opens() -> None:
    """Un coffre créé avec le format v1 (paramètres fixes) reste lisible."""
    password, plaintext = "ancien-mot-de-passe", b'{"entries": {}}'
    salt, nonce = b"s" * 16, b"n" * 12
    key = crypto.derive_key(password, salt, 2**15, 8, 1)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, b"vault-v1")
    b64 = lambda data: base64.b64encode(data).decode("ascii")  # noqa: E731
    blob = {"v": 1, "salt": b64(salt), "nonce": b64(nonce), "ct": b64(ciphertext)}
    assert crypto.decrypt(blob, password) == plaintext


# --- coffre : mot de passe maître, bornes, écriture ----------------------------


def test_change_password_requires_current(tmp_path: Path) -> None:
    store = VaultStore.create(tmp_path / "vault.enc", "ancien-mot-de-passe")
    with pytest.raises(VaultError):
        store.change_password("mauvais-mot-de-passe", "nouveau-mot-de-passe")


def test_change_password_reencrypts_with_new_password(tmp_path: Path) -> None:
    path = tmp_path / "vault.enc"
    store = VaultStore.create(path, "ancien-mot-de-passe")
    store.set("A", SECRET)
    store.change_password("ancien-mot-de-passe", "nouveau-mot-de-passe")

    assert VaultStore.open(path, "nouveau-mot-de-passe").get_value("A") == SECRET
    with pytest.raises(crypto.WrongPassword):
        VaultStore.open(path, "ancien-mot-de-passe")


def test_change_password_rejects_short_password(tmp_path: Path) -> None:
    store = VaultStore.create(tmp_path / "vault.enc", "ancien-mot-de-passe")
    with pytest.raises(VaultError):
        store.change_password("ancien-mot-de-passe", "court")


def test_failed_write_keeps_previous_password(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "vault.enc"
    store = VaultStore.create(path, "ancien-mot-de-passe")
    store.set("A", "1")

    def broken_save() -> None:
        raise OSError("disque plein")

    monkeypatch.setattr(store, "save", broken_save)
    with pytest.raises(OSError):
        store.change_password("ancien-mot-de-passe", "nouveau-mot-de-passe")
    monkeypatch.undo()
    assert VaultStore.open(path, "ancien-mot-de-passe").get_value("A") == "1"


def test_value_size_limit_and_empty_value(tmp_path: Path) -> None:
    store = VaultStore.create(tmp_path / "vault.enc", "bon-mot-de-passe")
    with pytest.raises(VaultError):
        store.set("A", "x" * (MAX_VALUE_LENGTH + 1))
    with pytest.raises(VaultError):
        store.set("A", "")


def test_no_temporary_file_left_after_save(tmp_path: Path) -> None:
    store = VaultStore.create(tmp_path / "vault.enc", "bon-mot-de-passe")
    store.set("A", "1")
    assert not (tmp_path / "vault.enc.tmp").exists()


# --- journal ------------------------------------------------------------------------


def test_audit_read_recent_is_newest_first_and_skips_garbage(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    audit.append(path, {"action": "list", "n": 1})
    with path.open("a", encoding="utf-8") as handle:
        handle.write("ligne cassée\n")
    audit.append(path, {"action": "run", "n": 2})
    rows = audit.read_recent(path)
    assert [row["n"] for row in rows] == [2, 1]


def test_audit_read_missing_file_is_empty(tmp_path: Path) -> None:
    assert audit.read_recent(tmp_path / "absent.jsonl") == []


# --- règles de verrouillage -----------------------------------------------------------


def test_should_lock_after_idle_time() -> None:
    assert not policy.should_lock(last_activity=0, last_tick=299, now=299)
    assert policy.should_lock(last_activity=0, last_tick=300, now=300)


def test_should_lock_after_sleep_gap() -> None:
    # Aucun battement pendant une minute : la machine a dormi, même si l'activité est récente.
    assert policy.should_lock(last_activity=950, last_tick=900, now=1000)


@pytest.mark.parametrize(
    "failures, expected",
    [(0, 0), (1, 0), (2, 0), (3, 1), (4, 2), (5, 4), (10, 30)],
)
def test_unlock_delay_grows_then_caps(failures: int, expected: int) -> None:
    assert policy.unlock_delay_seconds(failures) == expected


# --- approbations temporaires et refus répétés ------------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def make_broker(store: VaultStore, tmp_path: Path, answers: list, clock: Clock):
    asked: list[str] = []

    def approve(summary: str):
        asked.append(summary)
        return answers.pop(0) if answers else DENY

    return Broker(store, approve, tmp_path / "audit.jsonl", clock=clock), asked


def run_request(name: str = "GH_TOKEN", argv=("echo", "ok")) -> dict:
    return {"action": "run", "name": name, "env_var": "T", "argv": list(argv)}


@pytest.fixture
def run_stub(monkeypatch):
    import subprocess

    from vault import broker as broker_module

    monkeypatch.setattr(
        broker_module.subprocess,
        "run",
        lambda argv, **k: subprocess.CompletedProcess(argv, 0, stdout="", stderr=""),
    )


def test_once_asks_every_time(tmp_path: Path, run_stub) -> None:
    store = VaultStore.create(tmp_path / "vault.enc", "bon-mot-de-passe")
    store.set("GH_TOKEN", SECRET)
    broker, asked = make_broker(store, tmp_path, [ONCE, ONCE], Clock())
    broker.handle(run_request())
    broker.handle(run_request())
    assert len(asked) == 2


def test_temporary_grant_skips_prompt_then_expires(tmp_path: Path, run_stub) -> None:
    store = VaultStore.create(tmp_path / "vault.enc", "bon-mot-de-passe")
    store.set("GH_TOKEN", SECRET)
    clock = Clock()
    broker, asked = make_broker(store, tmp_path, [SESSION], clock)

    assert broker.handle(run_request())["ok"] is True
    clock.now += TEMP_GRANT_SECONDS - 1
    assert broker.handle(run_request())["ok"] is True
    assert len(asked) == 1

    clock.now += 2  # le délai est écoulé : une nouvelle approbation est demandée
    broker.handle(run_request())
    assert len(asked) == 2


def test_temporary_grant_is_bound_to_exact_command(tmp_path: Path, run_stub) -> None:
    store = VaultStore.create(tmp_path / "vault.enc", "bon-mot-de-passe")
    store.set("GH_TOKEN", SECRET)
    broker, asked = make_broker(store, tmp_path, [SESSION, ONCE], Clock())
    broker.handle(run_request(argv=("echo", "ok")))
    broker.handle(run_request(argv=("echo", "autre")))
    assert len(asked) == 2


def test_consecutive_refusals_trigger_cooldown(tmp_path: Path, run_stub) -> None:
    store = VaultStore.create(tmp_path / "vault.enc", "bon-mot-de-passe")
    store.set("GH_TOKEN", SECRET)
    clock = Clock()
    broker, asked = make_broker(store, tmp_path, [], clock)  # tout est refusé

    for _ in range(5):
        broker.handle(run_request())
    assert len(asked) == 5

    assert broker.handle(run_request())["ok"] is False
    assert len(asked) == 5  # plus rien n'est affiché pendant le délai

    clock.now += REFUSAL_COOLDOWN_SECONDS
    broker.handle(run_request())
    assert len(asked) == 6


def test_approval_resets_refusal_counter(tmp_path: Path, run_stub) -> None:
    store = VaultStore.create(tmp_path / "vault.enc", "bon-mot-de-passe")
    store.set("GH_TOKEN", SECRET)
    answers = [DENY, DENY, DENY, DENY, ONCE, DENY, DENY, DENY, DENY]
    expected = len(answers)
    broker, asked = make_broker(store, tmp_path, answers, Clock())
    for _ in range(expected):
        broker.handle(run_request())
    assert len(asked) == expected  # jamais de délai : un accord remet le compteur à zéro


# --- lancement au démarrage ----------------------------------------------------------


def test_launch_command_uses_real_binary_path_when_compiled(monkeypatch) -> None:
    monkeypatch.setattr(autostart, "__compiled__", True, raising=False)
    monkeypatch.setattr(sys, "argv", [r"C:\Apps\Vault\vault-gui.exe"])
    monkeypatch.setattr(sys, "executable", r"C:\Temp\onefile_123\python.exe")  # dossier temporaire Nuitka
    command = autostart.launch_command()
    assert "onefile_123" not in command
    assert command.endswith('vault-gui.exe"')


def test_launch_command_runs_gui_without_arguments(monkeypatch) -> None:
    monkeypatch.setattr(sys, "executable", r"C:\Outils\monenv\Scripts\vault.exe")
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert autostart.launch_command() == r'"C:\Outils\monenv\Scripts\vault.exe" -m vault'
