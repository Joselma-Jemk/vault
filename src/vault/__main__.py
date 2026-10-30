"""Point d'entrée : `python -m vault` lance l'interface ; `vault ...` lance la CLI."""

import sys

from vault.app import main as gui_main
from vault.cli import main as cli_main

if __name__ == "__main__":
    if len(sys.argv) > 1:
        raise SystemExit(cli_main(sys.argv[1:]))
    raise SystemExit(gui_main())
