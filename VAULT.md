# Vault — Gestion des secrets RF Sandbox Go

## Principe

Les secrets (token API) sont chiffrés avec **AES-256-GCM** avant d'être stockés dans `config/config.json`.

- La clé est dans `config/.vault.key` (fichier gitignore, **ne jamais committer**)
- Les valeurs chiffrées ont le format : `enc:<base64(nonce||ciphertext)>`
- Le programme déchiffre transparemment au démarrage

## Commandes

```bash
# Première utilisation : générer la clé
vault init

# Chiffrer les champs sensibles dans config.json
vault seal

# Vérifier l'état
vault status

# Chiffrer/déchiffrer une valeur manuellement
vault encrypt "mon-token-api"
vault decrypt "enc:..."

# Afficher les champs en clair (à ne faire qu'en local)
vault unseal
```

## Déploiement sur clé USB

La clé `.vault.key` doit être présente dans `config/` à côté de l'exécutable.

**Ne jamais partager la clé par email ou la committer dans git.**

Partagez-la via un coffre-fort ou une variable d'environnement sécurisée :

```bat
set RF_VAULT_KEY=<valeur base64 de la clé>
```

## Fichiers sensibles (chiffrés par défaut)

- `api_token` — Token API Recorded Future Sandbox
