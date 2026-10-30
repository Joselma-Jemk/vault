"""Cohérence de la publication : une seule version, et un installateur qui vise les bons fichiers."""

import tomllib
from pathlib import Path

import vault

ROOT = Path(__file__).resolve().parent.parent


def test_pyproject_version_matches_package_version() -> None:
    """Le workflow refuse un tag qui ne correspond pas à pyproject.toml : les deux versions doivent suivre."""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["version"] == vault.__version__


def test_installer_ships_both_binaries_and_the_logo() -> None:
    script = (ROOT / "packaging" / "vault.iss").read_text(encoding="utf-8")
    assert 'DestName: "vault-gui.exe"' in script
    assert 'DestName: "vault.exe"' in script
    assert "SetupIconFile=..\\src\\vault\\assets\\vault.ico" in script


def test_installer_never_touches_user_data() -> None:
    """Le coffre vit dans %APPDATA%\\Vault : l'installateur ne doit ni le copier ni le supprimer."""
    script = (ROOT / "packaging" / "vault.iss").read_text(encoding="utf-8")
    assert "UninstallDelete" not in script
    assert "{userappdata}" not in script and "{localappdata}" not in script


def test_installer_name_matches_what_the_workflow_expects() -> None:
    script = (ROOT / "packaging" / "vault.iss").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "OutputBaseFilename=vault-{#AppVersion}-windows-setup" in script
    assert "vault-$version-windows-setup.exe" in workflow
