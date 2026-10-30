# Vault

Coffre de secrets local, pour Windows. Une interface Qt pour enregistrer les clés, une CLI pour que
Claude (ou toi) puisse les **utiliser sans jamais les voir**.

## Principe

- L'application Qt est le seul endroit où une valeur est déchiffrée et affichée (à la saisie).
- La CLI n'a aucune commande qui renvoie une valeur. Elle envoie une demande à l'application ouverte.
- Chaque utilisation d'une clé demande ton accord dans une fenêtre, avec la commande exacte. Refus par défaut, refus automatique après 60 s.
- La valeur est masquée (`***`) dans la sortie des commandes lancées, y compris en base64.
- Le journal (`audit.jsonl`) enregistre qui a demandé quoi, quand, et la décision. Jamais la valeur.

## Installation

```bash
python -m pip install -e ".[dev]"
```

## Utilisation

1. Lance l'interface : `vault-gui` (ou `python -m vault`). Crée le coffre au premier lancement, avec un mot de passe maître (8 caractères minimum). Laisse la fenêtre ouverte : la CLI n'utilise l'application qu'ouverte et déverrouillée.
2. Ajoute une entrée avec **Ajouter** (nom, puis valeur masquée).
3. Depuis un terminal :

```bash
vault list
vault gh-secret GH_TOKEN --repo proprietaire/depot
vault run GH_TOKEN MA_VARIABLE -- python script.py
```

## Stockage

- `%APPDATA%\Vault\vault.enc` : toutes les entrées, chiffrées en AES-256-GCM, clé dérivée du mot de passe maître par scrypt.
- `%APPDATA%\Vault\audit.jsonl` : journal sans valeurs.
- `VAULT_HOME` permet de changer ce dossier.

## Tests

```bash
python -m pytest
```

## Limites connues (v1)

- Le mot de passe maître ne se change pas encore depuis l'interface (il faudra recréer le coffre).
- Pas de verrouillage automatique par inactivité : utilise **Verrouiller**.
- Une entrée déjà envoyée à une commande (`vault run`) peut être affichée par cette commande si elle la sort telle quelle en dehors de la sortie standard (fichier écrit, réseau). Le masquage ne couvre que stdout et stderr.
- Un programme qui tourne avec ta session Windows et lit la mémoire de l'application peut récupérer une valeur déverrouillée. Le coffre protège contre les fuites et les erreurs, pas contre un attaquant déjà présent sur ta machine.
