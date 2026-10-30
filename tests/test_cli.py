"""CLI : la sous-commande `gui` ouvre l'interface, sans passer par le canal local."""

import vault.app
from vault import cli


def test_gui_subcommand_is_declared() -> None:
    args = cli.build_parser().parse_args(["gui"])
    assert args.subcommand == "gui"


def test_gui_subcommand_launches_gui_and_returns_its_code(monkeypatch) -> None:
    monkeypatch.setattr(vault.app, "main", lambda: 7)
    monkeypatch.setattr(cli, "send_request", lambda _: (_ for _ in ()).throw(AssertionError("canal non attendu")))
    assert cli.main(["gui"]) == 7
