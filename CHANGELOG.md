# Changelog

## 0.2.3

- Correctif : `vault exec` et `vault run` ouvraient un terminal visible, au premier plan, à chaque commande lancée
  (l'interface n'a pas de console, donc Windows en créait une). La commande tourne maintenant sans fenêtre, sa sortie
  reste capturée et masquée comme avant.

## 0.2.2

- Outils → Projets : ajouter un dossier, modifier ses droits, retirer un projet, depuis l'interface.
- Sauvegarde chiffrée du coffre et restauration, avec un mot de passe propre à la sauvegarde.
- Import d'un fichier `.env` (noms affichés, jamais les valeurs), dates d'expiration avec rappel, étiquettes.
- Raccourcis clavier, menu des entrées récentes dans la zone de notification, générateur de valeur aléatoire,
  copie de `NOM=vault:NOM`, notification Windows à chaque demande d'accès.

## 0.2.1

- Interface : un double-clic sur une entrée ouvre la modification de la valeur (avant, il copiait).
- Interface : icônes du jeu PyPlayer sur Ajouter, Modifier et Supprimer, blanches sur fond sombre et sombres sur fond
  clair, qui suivent le thème Windows.
- Mode confiance (Outils → Mode confiance) : pendant 1 h, `vault exec` tourne sans demande dans les projets enregistrés.
  Désactivé par défaut, activé uniquement depuis l'interface, arrêté au verrouillage. `vault run` reste soumis à approbation.

## 0.2.0

- Projects: register a folder in the app with the entries it may use. Sub-projects can only reduce their parent's
  rights. Claude cannot register a project or change its rights.
- `vault exec` runs a command with every secret referenced in a `.env.vault` file (`KEY=vault:NAME`), after one approval.
  The file never holds values; a plain value makes the command fail.
- `vault declare NOM…` : crée des entrées **en attente**, sans valeur. Claude peut déclarer les clés qui manquent sans
  jamais voir de secret ; l'utilisateur renseigne la valeur dans l'interface. Les entrées en attente sont marquées dans
  `vault list` et dans l'interface, et `vault exec` / `vault run` les refusent.

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
