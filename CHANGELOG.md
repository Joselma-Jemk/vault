# Changelog

## 0.1.0

First public version.

- Desktop interface (Qt): create and unlock the vault, add, edit, copy, delete and search entries.
- Command line: `vault list`, `vault gui`, `vault gh-secret`, `vault run`. No command prints a value.
- Approval dialog for each use, with a choice of once or a 10-minute grant for an exact command.
- Output masking (raw and base64), audit log without values, journal viewer in the interface.
- Automatic lock after 5 minutes of inactivity, after a Windows sleep, and when the session is locked.
- Master password change, with verification of the current password.
- Clipboard copy with automatic clearing after 15 seconds.
- Tray icon, optional launch at Windows startup.
- Logo, used as the window, tray and executable icon.
- Delay after repeated wrong master passwords.
- Refusals stop being displayed after 5 in a row, for 2 minutes.
- Encryption format v2: scrypt parameters stored and authenticated; format v1 files still open.
