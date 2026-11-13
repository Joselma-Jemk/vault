---
name: vault
description: Utiliser le coffre de secrets local Vault (clés API, jetons, mots de passe d'application) sans jamais lire ni afficher leur valeur. À utiliser dès qu'une commande, un script ou une application d'un projet a besoin d'une clé enregistrée dans Vault, ou quand l'utilisateur parle de Vault, de secrets, de .env, de jetons ou de clés API à injecter.
---

# Vault : utiliser un secret sans le voir

Vault garde les clés de l'utilisateur, chiffrées sur son disque, rangées par **projet** et par **sous-projet**.
Tu peux **utiliser** une clé dans une commande, mais tu ne dois **jamais voir** sa valeur.

## Règles absolues

- Ne lis, ne demande, n'affiche, ne copie et n'écris jamais la valeur d'un secret.
- Ne mets jamais une valeur dans une commande, un fichier, un message, un commentaire ou un journal.
- Ne lis jamais un fichier `.env` qui contient des valeurs en clair : les seuls fichiers acceptables sont les
  fichiers de références `vault:NOM` (voir plus bas).
- Ne crée jamais de `.env` avec de vraies valeurs. Si l'utilisateur veut un `.env` pour un projet, crée un fichier
  de références.
- Ne cherche pas à lire le fichier du coffre (`%APPDATA%\Vault\vault.enc`), la mémoire de Vault, ou le presse-papiers.
- Si l'utilisateur colle une clé dans le chat, n'espère pas l'utiliser : demande-lui de l'enregistrer dans Vault,
  puis utilise-la par son nom.
- Ne contourne jamais un refus, un verrouillage, un délai ou une règle de projet. Signale-le à l'utilisateur.

## Projets

Un projet est un dossier enregistré par l'utilisateur **dans l'interface Vault** (menu Outils → Projets), avec la liste
des entrées qu'il a le droit d'utiliser. Tu ne peux pas enregistrer un projet ni modifier ses droits.

- Un **sous-projet** (dossier à l'intérieur d'un projet enregistré) peut seulement **réduire** les droits de son parent,
  jamais les étendre.
- Si le dossier courant n'appartient à aucun projet enregistré, `vault exec` échoue. Dis à l'utilisateur de l'ajouter
  dans Vault, au lieu d'essayer un autre moyen.
- `vault list` montre les entrées existantes, pas les projets : pour savoir ce qui est autorisé ici, lance `vault exec`
  et lis le message d'erreur s'il y a lieu.

## Fichier de références : `.env.vault`

Un fichier de références décrit quelles variables reçoivent quels secrets. Il ne contient **aucune valeur** et peut
être versionné sans risque :

```
# .env.vault : références seulement
export GITHUB_TOKEN=vault:GH_TOKEN
DATABASE_URL=vault:PROD_DB
```

Une ligne qui n'est ni un commentaire ni une référence fait échouer la commande, pour éviter toute valeur en clair.

## Commandes

Lancer une commande avec tous les secrets d'un fichier de références, une seule approbation pour l'ensemble :

```bash
vault exec -- python app.py
vault exec --env .env.vault -- npm run deploy
```

Lancer une commande avec un seul secret :

```bash
vault run GH_TOKEN GH_TOKEN -- gh api user
```

Lister les noms et les dates (jamais les valeurs) :

```bash
vault list
```

Poser un secret GitHub Actions sur un dépôt, à partir d'une entrée du coffre :

```bash
vault gh-secret NOM_DE_LENTREE --repo proprietaire/depot
```

Ouvrir l'interface graphique (seulement si l'utilisateur le demande) :

```bash
vault gui
```

## Ce que tu dois savoir

- **Vault doit être ouvert et déverrouillé.** Sinon la commande échoue avec « l'application Vault n'est pas ouverte
  ou le coffre est verrouillé ». Dis à l'utilisateur d'ouvrir Vault et de le déverrouiller.
- **Chaque utilisation demande l'accord de l'utilisateur.** Une fenêtre affiche le projet, la commande exacte et la
  liste « variable ← entrée » (sans valeurs). Si elle est refusée, la réponse est « Refusé par l'utilisateur » :
  n'insiste pas et ne réessaie pas en boucle. Après 5 refus d'affilée, Vault cesse d'afficher les demandes pendant 2 minutes.
- **Les valeurs sont masquées.** Toute valeur qui sort dans la sortie devient `***`. Ne la décode pas, ne la
  reconstitue pas.
- **Code de sortie.** `1` signifie une erreur de Vault (application fermée, refus, entrée inconnue, projet non
  enregistré, fichier de références invalide). Sinon le code est celui de la commande lancée.
- **Noms** : lettres, chiffres et `_`, sans chiffre en premier, 64 caractères maximum.

## Limites à respecter

- Une commande qui écrit la valeur dans un fichier, un journal ou sur le réseau n'est pas protégée par le masquage.
  Ne lance jamais une commande qui fait cela avec un secret du coffre, et refuse-toi si l'utilisateur te le demande.
- Vault protège contre les fuites et les erreurs, pas contre un programme déjà lancé sous le compte de l'utilisateur.

## Procédure type

1. Vérifie qu'un fichier `.env.vault` existe dans le projet. Sinon, demande à l'utilisateur de le créer avec des références.
2. Lance `vault exec -- commande` depuis le dossier du projet.
3. Lis seulement la sortie de la commande, jamais une valeur. Si une erreur de Vault apparaît, traduis-la pour l'utilisateur.
