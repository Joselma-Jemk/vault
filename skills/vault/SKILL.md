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
- Ne lis pas, n'affiche pas et ne copie pas un fichier `.env` qui contient des valeurs en clair : donne-le à l'outil
  qui en a besoin (`--env-file`, `docker compose`, l'application), sans l'ouvrir. Pour tes propres commandes, préfère
  les fichiers de références `vault:NOM` et `vault exec` (voir plus bas).
- N'écris jamais toi-même un `.env` avec de vraies valeurs : la seule voie est `vault export-env` (voir plus bas).
- Ne cherche pas à lire le fichier du coffre (`%APPDATA%\Vault\vault.enc`), la mémoire de Vault, ou le presse-papiers.
- Si l'utilisateur colle une clé dans le chat, n'espère pas l'utiliser : demande-lui de l'enregistrer dans Vault,
  puis utilise-la par son nom.
- Ne contourne jamais un refus, un verrouillage, un délai ou une règle de projet. Signale-le à l'utilisateur.

## Projets

Un projet est un dossier enregistré dans Vault, avec la liste des entrées qu'il a le droit d'utiliser. L'utilisateur
le fait dans l'interface (menu Outils → Projets). Toi, tu peux le demander avec `vault project-add` (voir plus bas) :
une fenêtre lui demande son accord, sauf en mode confiance. Tu ne peux ni retirer un projet ni retirer des droits.

- Un **sous-projet** (dossier à l'intérieur d'un projet enregistré) peut seulement **réduire** les droits de son parent,
  jamais les étendre.
- Si le dossier courant n'appartient à aucun projet enregistré, `vault exec` échoue. Enregistre-le avec
  `vault project-add NOM1 NOM2` (dans ce dossier), ou dis à l'utilisateur de l'ajouter dans Vault.
- `vault list` montre les entrées existantes, pas les projets : pour savoir ce qui est autorisé ici, lance `vault exec`
  et lis le message d'erreur s'il y a lieu.
- Si `vault project-add` est refusé, dis à l'utilisateur quoi faire : ouvrir Vault, menu **Outils → Projets
  (dossiers autorisés)…**, **Ajouter un dossier…**, cocher les entrées nécessaires. Ne contourne pas le refus.
- Si une entrée nécessaire n'existe pas, déclare-la (`vault declare NOM`) puis demande à l'utilisateur de la renseigner.
  Il peut aussi importer un fichier `.env` complet dans Vault : menu **Outils → Importer un fichier .env…**. Tu ne dois
  jamais ouvrir ce fichier toi-même, car il contient des valeurs.
- Les sauvegardes (**Outils → Sauvegarder / Restaurer**), la date d'expiration et les étiquettes sont réservées à
  l'utilisateur. Tu ne manipules ni les fichiers de sauvegarde, ni leur mot de passe.


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

Déclarer une clé qui manque encore, pour que le code la référence :

```bash
vault declare OPENAI_KEY STRIPE_KEY
```

Enregistrer le dossier courant comme projet (`--all` pour tout le coffre, sinon les noms), puis écrire un `.env` :

```bash
vault project-add R2_DEV_ACCESS_KEY R2_DEV_SECRET_KEY
vault export-env                       # toutes les entrées du projet, dans .env
vault export-env R2_KEY S3_KEY=R2_KEY  # certaines, avec renommage VARIABLE=NOM
vault export-env --file config/app.env --overwrite
```

`export-env` écrit les valeurs **en clair** dans un fichier du dossier du projet (jamais ailleurs, jamais par-dessus un
fichier existant sans `--overwrite`). Les valeurs ne reviennent pas dans ta sortie. Ensuite, ne l'ouvre pas : passe-le à
l'outil qui en a besoin. Vérifie qu'il est dans `.gitignore` (Vault avertit sinon) et ne le versionne jamais. Les entrées
en attente sont refusées. Une fenêtre demande l'accord de l'utilisateur, sauf en mode confiance.

L'utilisateur peut activer un **mode confiance** d'une heure dans l'interface : `vault exec`, `vault export-env` et
`vault project-add` tournent alors sans demande. Tu ne peux pas l'activer, et il ne couvre ni `vault run`, ni
`vault gh-secret`. Le dossier personnel et les racines de disque ne peuvent jamais être un projet. Ne te base jamais sur
ce mode pour contourner un refus : si une commande est refusée, dis-le à l'utilisateur.

Une entrée déclarée est **en attente** : son nom existe, sa valeur non. Elle ne contient aucun secret, donc tu peux la
déclarer sans demander. Ensuite :

- Écris le code ou le fichier de références avec `OPENAI_API_KEY=vault:OPENAI_KEY`, comme pour une clé existante.
- Dis à l'utilisateur de renseigner la valeur dans Vault (« Modifier la valeur ») et de l'ajouter au projet.
- Tant qu'elle est en attente, `vault exec` et `vault run` refusent de la lancer et te l'indiquent. Ne contourne pas ce
  refus, et ne mets jamais de valeur à la place.

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
- **Mode confiance.** Voir plus haut : une heure, activé seulement par l'utilisateur, il ne couvre pas `vault run`
  ni `vault gh-secret`.
- **Chaque utilisation demande l'accord de l'utilisateur**, sauf en mode confiance. Une fenêtre affiche le projet, la commande exacte et la
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
- Une clé expirée ou proche de l'expiration est signalée à l'utilisateur par Vault. Ne tente pas de la deviner ni de la
  faire renouveler toi-même : dis-le-lui.

## Procédure type

1. Vérifie qu'un fichier `.env.vault` existe dans le projet. Sinon, demande à l'utilisateur de le créer avec des références.
2. Lance `vault exec -- commande` depuis le dossier du projet.
3. Lis seulement la sortie de la commande, jamais une valeur. Si une erreur de Vault apparaît, traduis-la pour l'utilisateur.
