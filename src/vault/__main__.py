"""Point d'entrée : `python -m vault` lance l'interface ; `vault ...` lance la CLI."""

import sys


def run(argv: list[str] | None = None) -> int:
    """Sans argument, ouvre l'interface. Avec des arguments, exécute la commande de la CLI."""
    args = sys.argv[1:] if argv is None else argv
    if args:
        from vault.cli import main as cli_main

        return cli_main(args)
    from vault.app import main as gui_main

    return gui_main()


if __name__ == "__main__":
    raise SystemExit(run())
