# Vault

<p align="center"><img src="src/vault/assets/vault.png" alt="Vault logo" width="128"></p>

A local secrets vault for Windows. A Qt desktop app stores your API keys and tokens. A command
line tool lets you (or an AI agent) **use** them without ever seeing their values.

> Français : see [README.fr.md](README.fr.md).

## Principles

- The desktop app is the only place where a value is decrypted for display or copy.
- The CLI has no command that prints a value. It sends a request to the open application.
- Every use of a secret asks you for approval, showing the exact command. Refusal is the default,
  and the request is refused automatically after 60 seconds.
- You can allow the same exact command for 10 minutes, to avoid being asked repeatedly.
- Values are masked (`***`) in the output of launched commands, in raw and base64 form.
- The audit log records who asked for what, when, and the decision. It never records values.

Read [THREAT_MODEL.md](THREAT_MODEL.md) for what Vault does and does not protect.

## Features

- Create a vault with a master password, change it later.
- Add, edit, copy, delete and search entries. Copies are cleared from the clipboard after 15 seconds.
- Automatic lock after 5 minutes of inactivity, after a Windows sleep, and when you lock Windows.
- Tray icon, and optional start with Windows.
- Journal viewer inside the application.
- Delay after repeated wrong master passwords.

## Installation

**Installer (recommended).** Download `vault-<version>-windows-setup.exe` from the
[Releases](https://github.com/Joselma-Jemk/vault/releases) page and run it. It installs for the current
user, without administrator rights, and adds the `vault` command to your `PATH` (you can untick this).
Uninstalling never deletes your vault (`%APPDATA%\Vault`).

**Portable.** Unzip `vault-<version>-windows-portable.zip` anywhere: it contains `vault-gui.exe` (the
application) and `vault.exe` (the command line).

Check a download with `sha256sum -c SHA256SUMS` (the file is attached to each release).

**From source.** Requires Python 3.13 or newer, on Windows.

```bash
python -m pip install -e ".[dev]"
```

The binaries are not code-signed yet, so Windows SmartScreen may warn on first launch.

## Usage

1. Open the application: `vault gui` (or `vault-gui`, or `python -m vault`).
   The first launch creates the vault and asks for a master password (8 characters minimum).
   Keep the application open: the CLI only works while it is open and unlocked.
2. Add an entry with **Ajouter** (name, then value).
3. From a terminal:

```bash
vault list
vault gh-secret GH_TOKEN --repo owner/repo
vault run GH_TOKEN GH_TOKEN -- gh api user
```

`vault run NAME ENV_VAR -- command` starts `command` with the value in the environment variable
`ENV_VAR`. The value never appears in the command line.

## Storage

- `%APPDATA%\Vault\vault.enc`: all entries, encrypted with AES-256-GCM. The key is derived from the
  master password with scrypt. Set `VAULT_HOME` to choose another folder.
- `%APPDATA%\Vault\audit.jsonl`: the audit log, without values.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check src tests --select E,F,W,I --ignore E501
```

The tests run without a screen.

## Limits

- Windows only.
- A program running as your user, while the vault is unlocked, can reach the broker and the
  application memory. See [THREAT_MODEL.md](THREAT_MODEL.md).
- Masking covers standard output and standard error only. Read each approval dialog carefully.
- Keep your own backups of `vault.enc`.

## Contributing and security

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md): report vulnerabilities privately.

## Contact

contact@joselma.online

## License

MIT. See [LICENSE](LICENSE).
