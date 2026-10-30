# Changelog

## 0.1.2

- Build: the executables are now compiled as folders (Nuitka standalone) instead of single files. The single-file
  build was flagged by Windows Defender as a false positive (`Program:Win32/Contebrew.A!ml`), because it extracts a
  DLL into a temporary folder at each launch. The installer and the portable zip now ship the whole folders.

## 0.1.1

- Fix: the logo was not shown in the window and taskbar. The window now reads it from the package,
  including in the compiled executable, and no longer falls back to a generic Windows icon.
- Fix: a second instance of Vault could silently take over the local channel of the first one. It is now
  refused with a message.

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
- Windows installer (Inno Setup, per-user, no administrator rights) with the `vault` command added to the PATH,
  and a portable zip. Both ship `vault-gui.exe` (application) and `vault.exe` (command line). Uninstalling
  never deletes the vault.
- Delay after repeated wrong master passwords.
- Refusals stop being displayed after 5 in a row, for 2 minutes.
- Encryption format v2: scrypt parameters stored and authenticated; format v1 files still open.
