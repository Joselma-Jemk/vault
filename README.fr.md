# Vault

Coffre de secrets local pour Windows. Une interface Qt pour enregistrer les clés et les jetons,
une CLI pour que toi ou un agent puissiez **les utiliser sans jamais voir leurs valeurs**.

> English: voir [README.md](README.md).

## Principe

- L'application Qt est le seul endroit où une valeur est déchiffrée pour être affichée ou copiée.
- La CLI n'a aucune commande qui affiche une valeur. Elle envoie une demande à l'application ouverte.
- Chaque utilisation d'un secret demande ton accord, avec la commande exacte affichée. Refus par défaut,
  refus automatique après 60 s.
- Tu peux autoriser la même commande exacte pendant 10 minutes, pour ne pas être sollicité en boucle.
- La valeur est masquée (`***`) dans la sortie des commandes lancées, en brut et en base64.
- Le journal (`audit.jsonl`) enregistre qui a demandé quoi, quand, et la décision. Jamais la valeur.

Ce que Vault protège et ce qu'il ne protège pas est décrit dans [THREAT_MODEL.md](THREAT_MODEL.md).

## Fonctions

- Créer le coffre avec un mot de passe maître, et le changer ensuite.
- Ajouter, modifier, copier, supprimer et rechercher des entrées. La copie est effacée du presse-papiers après 15 s.
- Verrouillage automatique après 5 min d'inactivité, après une mise en veille, et quand tu verrouilles Windows.
- Icône dans la barre des tâches, et lancement optionnel avec Windows.
- Journal des demandes consultable dans l'application.
- Délai après des mots de passe maîtres erronés répétés.

## Installation

Windows, Python 3.10 ou plus récent.

```bash
python -m pip install -e ".[dev]"
```

## Utilisation

1. Ouvre l'application : `vault gui` (ou `vault-gui`, ou `python -m vault`).
   Au premier lancement, le coffre est créé et te demande un mot de passe maître (8 caractères minimum).
   Laisse l'application ouverte : la CLI ne fonctionne que si elle est ouverte et déverrouillée.
2. Ajoute une entrée avec **Ajouter** (nom, puis valeur).
3. Depuis un terminal :

```bash
vault list
vault gh-secret GH_TOKEN --repo proprietaire/depot
vault run GH_TOKEN GH_TOKEN -- gh api user
```

`vault run NOM VARIABLE -- commande` lance `commande` avec la valeur dans la variable d'environnement
`VARIABLE`. La valeur n'apparaît jamais dans la ligne de commande.

## Stockage

- `%APPDATA%\Vault\vault.enc` : toutes les entrées, chiffrées en AES-256-GCM. La clé est dérivée du mot
  de passe maître par scrypt. `VAULT_HOME` permet de choisir un autre dossier.
- `%APPDATA%\Vault\audit.jsonl` : le journal, sans valeurs.

## Développement

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check src tests --select E,F,W,I --ignore E501
```

Les tests tournent sans écran.

## Limites

- Windows uniquement.
- Un programme qui tourne avec ton compte, pendant que le coffre est ouvert, peut atteindre le courtier
  et la mémoire de l'application. Voir [THREAT_MODEL.md](THREAT_MODEL.md).
- Le masquage ne couvre que la sortie standard et l'erreur standard. Lis bien chaque fenêtre d'approbation.
- Garde tes propres sauvegardes de `vault.enc`.

## Contribuer et sécurité

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md) : signale les failles en privé.

## Licence

MIT. Voir [LICENSE](LICENSE).
