---
name: vault
description: Utiliser le coffre de secrets local Vault (clés API, jetons) sans jamais lire ni afficher leur valeur. À utiliser dès qu'une commande a besoin d'une clé déjà enregistrée dans Vault, ou quand l'utilisateur parle de Vault, de secrets, de jetons ou de clés API à injecter dans une commande.
---

# Vault : utiliser un secret sans le voir

Vault garde les clés (API, jetons) de l'utilisateur, chiffrées sur son disque. Tu peux **utiliser** une clé
dans une commande, mais tu ne dois **jamais voir** sa valeur.

## Règles absolues

- Ne lis, ne demande, n'affiche, ne copie et n'écris jamais la valeur d'un secret.
- Ne mets jamais une valeur dans une commande, un fichier, un message, un commentaire ou un journal.
- Ne cherche pas à lire le fichier du coffre (`%APPDATA%\Vault\vault.enc`), la mémoire de Vault, ou le presse-papiers.
- Si l'utilisateur colle une clé dans le chat, n'espère pas l'utiliser : demande-lui de l'enregistrer dans Vault,
  puis utilise-la par son nom.
- Ne contourne jamais un refus, un verrouillage ou un délai. Signale-le à l'utilisateur.

## Commandes

Liste des noms et des dates (jamais les valeurs) :

```bash
vault list
```

Lancer une commande avec une clé dans une variable d'environnement. La valeur n'apparaît jamais dans la ligne de commande :

```bash
vault run NOM_DE_LENTREE NOM_DE_LA_VARIABLE -- commande arguments...
```

Exemple : utiliser le jeton GitHub `GH_TOKEN` pour appeler l'API :

```bash
vault run GH_TOKEN GH_TOKEN -- gh api user
```

Poser un secret GitHub Actions sur un dépôt, à partir d'une entrée du coffre :

```bash
vault gh-secret NOM_DE_LENTREE --repo proprietaire/depot
```

Ouvrir l'interface graphique (à faire seulement si l'utilisateur le demande) :

```bash
vault gui
```

## Ce que tu dois savoir

- **Vault doit être ouvert et déverrouillé.** Sinon la commande échoue avec « l'application Vault n'est pas ouverte
  ou le coffre est verrouillé ». Dis à l'utilisateur d'ouvrir Vault et de le déverrouiller. N'essaie pas autre chose.
- **Chaque utilisation demande l'accord de l'utilisateur.** Une fenêtre affiche la commande exacte. Si elle est refusée,
  la réponse est « Refusé par l'utilisateur » : n'insiste pas et ne réessaie pas en boucle. Après 5 refus d'affilée,
  Vault cesse d'afficher les demandes pendant 2 minutes.
- **Les valeurs sont masquées.** Si une sortie contient `***`, c'est la valeur masquée : ne la décode pas, ne la
  reconstitue pas.
- **Code de sortie.** `1` signifie une erreur de Vault (application fermée, refus, entrée inconnue). Pour `vault run`,
  sinon le code est celui de la commande lancée.
- **Le nom de l'entrée** se trouve avec `vault list`. Il ne contient que des lettres, des chiffres et `_`, sans chiffre en premier.
- **Le nom de la variable** suit les mêmes règles : lettres, chiffres et `_`.

## Limites à respecter

- Une commande qui écrit la valeur dans un fichier, un journal ou sur le réseau n'est pas protégée par le masquage.
  Ne lance jamais une commande qui fait cela avec une clé du coffre, et refuse-toi si l'utilisateur te le demande.
- Vault protège contre les fuites et les erreurs, pas contre un programme déjà lancé sous le compte de l'utilisateur.

## Procédure type

1. `vault list` pour vérifier que l'entrée existe. Si elle n'existe pas, dis-le à l'utilisateur.
2. `vault run ENTREE VARIABLE -- commande` avec la commande voulue.
3. Lis seulement la sortie de la commande, jamais la valeur. Si une erreur de Vault apparaît, traduis-la pour l'utilisateur.
