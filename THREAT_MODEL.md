# Threat model

This document describes what Vault protects, against whom, and what it does **not** protect.
Read it before storing a production credential in Vault.

## Assets

- **Secret values** (API keys, tokens). They exist in clear only in the memory of the unlocked
  application, and briefly in the environment of a command that Vault launches.
- **The master password**, which is held in memory while the vault is unlocked.
- **The audit log**, which is not secret but reveals which secrets are used and when.

## Components and trust

- The **Qt application** is the only place where a value is decrypted for display or copy.
- The **CLI** (`vault`) never receives a value. It sends a request to the application over a local
  named pipe that only the current Windows user can connect to.
- The **broker** runs inside the application. It asks a human for every use of a secret, except
  for an explicit, time-limited grant (see below).

## Adversaries considered

1. **Another process or user on the same machine that tries to read the vault file.**
   The file is encrypted with AES-256-GCM. The key is derived from the master password with
   scrypt (N = 2^17, r = 8, p = 1). Without the password, the file is not readable.
2. **A program or agent that asks for a secret without the user's knowledge.**
   Each use shows the exact command and the secret name in a dialog. Refusal is the default
   answer, and the dialog times out after 60 seconds.
3. **A program that tries to get a secret through the CLI output.**
   The CLI has no command that prints a value. Output of launched commands is masked, in raw and
   base64 form.
4. **Someone who stole the disk or copies the vault file.**
   They face an offline brute-force attack against scrypt. The strength depends entirely on the
   master password.
5. **Someone at the keyboard after the user walked away.**
   The vault locks after 5 minutes without input, after a Windows sleep, and when the Windows
   session is locked (Win+L).
6. **An agent that spams approval requests.**
   After 5 consecutive refusals, further requests are refused without being displayed for 2 minutes.
7. **Tampering with the vault file.**
   The scrypt parameters are written in the file and bound to the encrypted data. Any change makes
   decryption fail. Writes are atomic and flushed to disk before replacing the previous file.
8. **Passing a secret through the command line.**
   Values are passed to commands through environment variables or standard input, never through
   arguments, so they do not appear in process listings or in the audit log.

## Protections in place

- AES-256-GCM with the parameters in the associated data (format v2). Format v1 files still open.
- scrypt key derivation with a cost that makes offline guessing slow.
- Master password change requires the current password.
- Minimum master password length of 8 characters, and 16 KiB maximum per value.
- Local IPC restricted to the current Windows user, with a size limit on messages.
- Approval for every use, with the exact command displayed as plain text (no HTML rendering).
- Optional grants of 10 minutes for an exact command. Grants are dropped when the vault locks.
- Clipboard copy is cleared after 15 seconds, but only if it still holds the copied value.
- Audit log in JSON lines, containing names, targets and decisions, never values.
- Delay after failed unlock attempts: free for the first 2, then doubling up to 30 seconds.
  This slows down guessing through the window. It does **not** slow down an offline attacker who
  has the file.

## What Vault does not protect

- **A program running as you while the vault is unlocked.** Any process of the same Windows user
  can read the application's memory or ask the broker. Vault protects against leaks and mistakes,
  not against code that already runs on your account.
- **A command that writes the secret somewhere other than standard output or standard error.**
  Masking only covers `stdout` and `stderr`. A command that writes the value to a file, a log, or
  the network will leak it. Read the approval dialog carefully before approving.
- **A weak master password.** The offline attack cost is only as high as the password is hard.
- **Memory forensics.** Python strings cannot be reliably erased from memory. Values and the master
  password may remain in memory after locking, until the garbage collector reuses the space.
- **Keyloggers and screen capture.** Typing the master password or a value into a dialog exposes it
  to anything that watches the keyboard or the screen.
- **Clipboard managers and other programs that read the clipboard during the 15 seconds.**
- **Backups and cloud sync of `%APPDATA%\Vault`.** A copy of `vault.enc` is safe only as long as the
  master password is strong.
- **Windows administrators and system-level malware.**

## Known limitations (version 0.1.x)

- Windows only. The named pipe, the autostart key and the session notifications are Windows-specific.
- The approval dialog is shown by the application. If the application is not running, nothing can
  be approved, and the CLI fails closed.
- No hardware key or OS keychain integration.
- The backup file of the vault is not created: keep your own backups of `vault.enc`.
- Dependencies (PySide6, cryptography) are not audited by this project.

## Reporting

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.
