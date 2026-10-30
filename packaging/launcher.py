"""Script d'entrée pour la compilation Nuitka : même comportement que `python -m vault`."""

from vault.__main__ import run

if __name__ == "__main__":
    raise SystemExit(run())
