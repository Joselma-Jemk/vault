"""CLI : commandes déléguées à l'application, sauf `gui`. Aucune ne renvoie une valeur."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from vault.ipc import ServerUnavailable, send_request


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vault", description="Coffre de secrets (sans affichage des valeurs)")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    sub.add_parser("list", help="Liste les noms et les dates (jamais les valeurs)")
    sub.add_parser("gui", help="Ouvre l'interface graphique du coffre")

    gh = sub.add_parser("gh-secret", help="Pose un secret GitHub Actions avec une valeur du coffre")
    gh.add_argument("name", help="Nom de l'entrée dans le coffre")
    gh.add_argument("--repo", required=True, help="Dépôt cible, au format proprietaire/depot")

    run = sub.add_parser("run", help="Lance une commande avec une valeur dans une variable d'environnement")
    run.add_argument("name", help="Nom de l'entrée dans le coffre")
    run.add_argument("env_var", help="Variable d'environnement qui recevra la valeur")
    run.add_argument("argv", nargs=argparse.REMAINDER, help="Commande à lancer, après --")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.subcommand == "gui":
            # Qt n'est importé que pour cette commande : les autres restent instantanées.
            from vault.app import main as gui_main

            return gui_main()
        if args.subcommand == "list":
            return _list()
        if args.subcommand == "gh-secret":
            return _gh_secret(args.name, args.repo)
        return _run(args.name, args.env_var, args.argv)
    except ServerUnavailable as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 1


def _request(payload: dict) -> dict:
    return send_request(payload)


def _list() -> int:
    reply = _request({"action": "list"})
    if not reply.get("ok"):
        return _fail(reply)
    rows = reply["data"]
    if not rows:
        print("Coffre vide.")
        return 0
    print(f"{'NOM':<32} {'CRÉÉ':<22} {'MODIFIÉ':<22} DERNIER USAGE")
    for row in rows:
        print(
            f"{row['name']:<32} {row['created']:<22} {row['updated']:<22} {row['last_used'] or '-'}"
        )
    return 0


def _gh_secret(name: str, repo: str) -> int:
    reply = _request({"action": "gh_secret", "name": name, "repo": repo})
    return _emit(reply)


def _run(name: str, env_var: str, command: list[str]) -> int:
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("Erreur : indique la commande après --", file=sys.stderr)
        return 1
    reply = _request({"action": "run", "name": name, "env_var": env_var, "argv": command})
    code = _emit(reply)
    return code


def _emit(reply: dict) -> int:
    if "stdout" in reply and reply["stdout"]:
        sys.stdout.write(reply["stdout"])
    if "stderr" in reply and reply["stderr"]:
        sys.stderr.write(reply["stderr"])
    if not reply.get("ok") and "error" in reply:
        return _fail(reply)
    return 0 if reply.get("ok") else int(reply.get("returncode") or 1)


def _fail(reply: dict) -> int:
    print(f"Erreur : {reply.get('error', 'échec')}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
