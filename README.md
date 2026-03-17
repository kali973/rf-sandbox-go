# RF Sandbox Analyser — Go Edition v2.1.0

Outil **100% Go** pour soumettre des fichiers/URLs à la **Recorded Future Sandbox API**,
analyser les résultats et générer deux types de rapports PDF :

- **Rapport technique complet** — toutes les données brutes (signatures, IOCs, réseau, processus, MITRE)
- **Rapport management IA** — synthèse en langage clair générée par moteur local llama.cpp (Mistral 7B / Qwen2.5-14B), destinée aux dirigeants (RSSI, DSI, COMEX)

---

## Architecture du projet

```
rf-sandbox-go/
├── cmd/
│   ├── main.go                    # Point d'entrée principal (CLI + UI)
│   ├── trainer/
│   │   └── main.go                # Entraîneur LoRA 100% Go (llama-finetune natif)
│   ├── vault/
│   │   └── main.go                # Gestion secrets (init/seal/unseal/status)
│   ├── audit/
│   │   └── main.go                # Rapport PDF audit sécurité
│   ├── audit-securite/
│   │   └── main.go                # Audit gosec/govulncheck/gitleaks
│   ├── setup-moteur/
│   │   └── main.go                # Télécharge llama.cpp + modèles GGUF
│   ├── bootstrap-post/
│   │   └── main.go                # Post-bootstrap (audit + setup moteur)
│   ├── compilateur/
│   │   └── main.go                # Compilateur Go natif
│   └── update-proxy/
│       └── main.go                # Détection/mise à jour proxy
├── internal/
│   ├── ai/
│   │   ├── ollama.go              # Client llama.cpp local (dual-engine)
│   │   ├── prompt.go              # Construction prompt enrichi + parsing JSON
│   │   ├── reporter.go            # Générateur PDF rapport management IA
│   │   ├── enrich.go              # Enrichissement MITRE ATT&CK + AbuseIPDB
│   │   ├── geoip.go               # Géolocalisation IP (ip-api.com)
│   │   ├── knowledge.go           # Base de connaissances SQLite (analyses passées)
│   │   ├── dataset.go             # Export analyses.db → JSONL (dataset LoRA)
│   │   ├── claude.go              # Moteur cloud alternatif (Claude API)
│   │   └── colors.go              # Helpers couleurs logs
│   ├── client/
│   │   └── client.go              # Client API RF Sandbox (tous les endpoints)
│   ├── models/
│   │   └── models.go              # Structures de données API + KernelEvents
│   ├── reporter/
│   │   └── reporter.go            # Générateur PDF rapport technique
│   └── auditpdf/
│       └── auditpdf.go            # Générateur PDF rapport audit sécurité
├── ui/
│   ├── ui.go                      # Serveur HTTP + handlers API + SSE logs
│   └── index.html                 # Interface web (SPA)
├── config/
│   ├── config.go                  # Chargement configuration
│   ├── config.json                # Token API, proxy, port UI, options sandbox
│   └── config.json.example        # Modèle de configuration
├── httpclient/
│   └── client.go                  # Client HTTP (NTLM, proxy, retry, timeout)
├── vault/
│   └── vault.go                   # Chiffrement AES-256 des secrets
├── scripts/
│   ├── bootstrap.bat              # Lanceur Windows (compile + installe)
│   ├── compilateur.ps1            # Compilation + déploiement clé USB automatique
│   ├── lancer.bat                 # Démarrage depuis clé USB
│   ├── setup_moteur.ps1           # Télécharge llama.cpp + modèles dans moteur/
│   ├── signer.ps1                 # Signature code PowerShell
│   ├── audit_securite.ps1         # Audit sécurité (gosec/govulncheck/gitleaks)
│   └── update_proxy.ps1           # Détection et mise à jour proxy
├── moteur/                        # Moteur IA local (NON versionné — voir .gitignore)
│   ├── llama-server.exe           # Binaire llama.cpp portable (CUDA + CPU)
│   ├── llama-finetune.exe         # Fine-tuning LoRA natif
│   ├── llama-quantize.exe         # Quantification modèles GGUF
│   ├── models/
│   │   ├── mistral-7b-instruct-v0.2.Q4_K_M.gguf
│   │   └── Qwen2.5-14B-Instruct-Q4_K_M.gguf
│   └── lora/                      # Modèles fine-tunés (générés par trainer.exe)
├── knowledge/                     # Base de connaissances (NON versionné)
│   ├── analyses.db                # SQLite : analyses mémorisées
│   └── training_dataset.jsonl     # Dataset d'entraînement généré
├── samples/
├── output/
├── audit/
├── go.mod
├── Makefile
└── README.md
```

---

## Prérequis

- **Go 1.21+** : https://go.dev/dl/
- **Windows** recommandé (scripts PowerShell, CUDA)
- GPU NVIDIA recommandé pour le moteur IA (CPU possible mais lent)
- Connexion Internet pour l'API RF Sandbox et le premier téléchargement du moteur IA

---

## Installation rapide (Windows)

### 1. Bootstrap — compilation + installation automatique

```bat
scripts\bootstrap.bat
```

**Si une clé USB est branchée** → détectée automatiquement (`Win32_LogicalDisk DriveType=2`).
Compile en `windows/amd64` et copie sur la clé :

```
E:\rf-sandbox-go\
├── rf-sandbox.exe       exécutable principal
├── vault.exe            gestion des secrets
├── setup-moteur.exe     télécharge le moteur IA (Go natif)
├── bootstrap-post.exe   audit + setup moteur (Go natif)
├── trainer.exe          fine-tuning LoRA Mistral 7B (Go natif, zéro Python)
├── config\              configuration (token chiffré, proxy)
├── moteur\              moteur IA complet (~12 Go, si présent localement)
├── samples\             fichiers batch exemples
└── lancer.bat           point d'entrée (double-clic)
```

**Sans clé USB** → compilation locale + lancement automatique de l'application.

### 2. Télécharger le moteur IA (une seule fois)

```bat
setup-moteur.exe
```

Télécharge dans `moteur\` :
- `llama-server.exe` + DLLs CUDA (~150 Mo)
- `llama-finetune.exe` et `llama-quantize.exe` (même build llama.cpp)
- `mistral-7b-instruct-v0.2.Q4_K_M.gguf` (~4,1 Go) — modèle principal
- `Qwen2.5-14B-Instruct-Q4_K_M.gguf` (~8,7 Go) — moteur de secours

Après téléchargement, **aucune connexion Internet n'est requise** pour les rapports IA.

### 3. Démarrer

```bat
rf-sandbox.exe -ui
REM ou double-clic :
lancer.bat
```

Ouvre l'interface web sur **http://localhost:8766**

---

## Compilation manuelle

```bash
go build -ldflags="-s -w" -o rf-sandbox.exe    ./cmd
go build -ldflags="-s -w" -o vault.exe          ./cmd/vault
go build -ldflags="-s -w" -o setup-moteur.exe   ./cmd/setup-moteur
go build -ldflags="-s -w" -o bootstrap-post.exe ./cmd/bootstrap-post
go build -ldflags="-s -w" -o trainer.exe         ./cmd/trainer
go build -ldflags="-s -w" -o audit.exe           ./cmd/audit

# Cross-compilation Windows depuis Linux/Mac
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o rf-sandbox.exe ./cmd

# Via Makefile
make build && make windows && make linux
```

---

## Interface web (http://localhost:8766)

### Soumission d'analyses

- **Fichier** : glisser-déposer ou sélecteur de fichier
- **URL** : soumission directe d'une URL malveillante
- **ID RF Sandbox** : récupérer une analyse existante par son identifiant
- **Queue** : soumissions multiples simultanées avec statuts en temps réel
- **Mode privé** : activé par défaut (analyses non partagées avec RF)

### Rapports PDF

- **Rapport technique** : données brutes complètes (toutes sections)
- **Rapport management IA** : synthèse dirigeants générée par IA locale

> **Isolation des sessions** : chaque dépôt crée une session isolée.
> Le rapport PDF n'utilise que la session du dernier dépôt, pas les précédents.
> Pour un rapport multi-fichiers consolidé : soumettre tous les fichiers en une seule queue.

### Toggles de configuration

| Toggle | Défaut | Description |
|---|---|---|
| 🔍 Enrichissement MITRE | ON | Résolution TTPs via MITRE ATT&CK |
| 🛡 AbuseIPDB | ON | Réputation des IPs contactées |
| 🌍 Géolocalisation | ON | GeoIP des serveurs C2 |
| 🧠 Base de connaissances — Mémorisation | ON | Sauvegarde chaque analyse dans SQLite |
| 🧠 Injecter le contexte dans le prompt | OFF | Injecte les analyses similaires passées dans le prompt |

### Logs en temps réel

Loupe flottante 🔍 : tous les logs du serveur via SSE (Server-Sent Events), colorés :
- Violet : GPU/CUDA, vault, entraînement LoRA
- Bleu : IA, enrichissements, knowledge
- Orange : avertissements
- Rouge : erreurs

---

## Base de connaissances (SQLite)

Chaque analyse avec rapport IA est automatiquement mémorisée dans `knowledge/analyses.db`.

### Ce qui est stocké par analyse

`filename`, `famille_presumee`, `classification`, `score`, `TTPs[]`, `IPs[]`, `domaines[]`,
`SHA256`, `resume_executif` (500 chars), `recommandations[]`, `confiance`

### Recherche de similarité (si injection activée)

| Signal | Points |
|---|---|
| Même famille malware | +40 |
| TTP en commun | +5 par TTP (max 30) |
| IP ou domaine en commun | +10 par IOC (max 30) |

Les analyses avec score ≥ 10 sont injectées dans le prompt comme contexte historique.
La correspondance se fait sur des **données invariantes** (TTPs, IOCs) — indépendant du contexte sandbox.

---

## Entraînement LoRA des modèles IA

Fine-tuning LoRA de Mistral 7B sur vos analyses réelles.
**100% Go, zéro Python, zéro PyTorch** — utilise `llama-finetune.exe` natif.

### Lancement (bouton 🧠 Entraîner les IA dans Configuration)

```
1. Export dataset : analyses.db → training_dataset.jsonl → training_dataset.txt
2. Détection GPU via nvidia-smi → profil LoRA optimal
3. Vérification llama-finetune.exe → extraction/téléchargement si absent
4. Fine-tuning LoRA sur Mistral 7B (moteur/models/)
5. Quantification Q4_K_M → moteur/lora/mistral-7b-forensic-fr-Q4_K_M.gguf
```

Logs en temps réel dans la loupe 🔍. Bouton réactivé automatiquement à la fin.

### Profils GPU auto-sélectionnés

| VRAM libre | r LoRA | Batch | Ctx | Durée estimée (100 exemples) |
|---|---|---|---|---|
| ≥ 20 Go (RTX 3090/4090) | 64 | 32 | 512 | ~15 min |
| ≥ 14 Go (RTX 3080Ti/4080) | 32 | 16 | 512 | ~30 min |
| ≥ 10 Go (RTX 3080/4070) | 16 | 8 | 256 | ~1h |
| ≥ 6 Go (RTX 3070/4060) | 8 | 4 | 256 | ~2h |
| CPU only | 4 | 1 | 64 | plusieurs heures |

### Résultat

Copier `moteur/lora/mistral-7b-forensic-fr-Q4_K_M.gguf` dans `moteur/models/`
pour l'utiliser comme modèle principal à la place de `mistral-7b-instruct-v0.2.Q4_K_M.gguf`.

---

## Architecture IA dual-engine

```
Prompt enrichi (~25–30k tokens)
        │
        ▼
┌─────────────────────┐
│  Mistral 7B Q4_K_M  │  tentative 1 (~12 min)
└─────────┬───────────┘
          ├─ JSON valide → rapport ✓
          └─ JSON invalide → fallback
                    │
                    ▼
        ┌───────────────────────────┐
        │  Qwen2.5-14B Q4_K_M       │  tentative 2 (~19 min)
        └─────────────┬─────────────┘
                      └─ JSON valide → rapport ✓
```

| Paramètre | Valeur |
|---|---|
| Context window | 32 768 tokens |
| Max tokens réponse | 8 192 tokens |
| Temperature | 0.1 (déterministe) |
| Repeat penalty | 1.1 |
| GPU layers | 99 (tout sur VRAM si disponible) |

---

## Endpoints API RF Sandbox utilisés

| Endpoint | Données |
|---|---|
| `POST /samples` | Soumission fichier/URL |
| `GET /samples/{id}/summary` | Scores, statuts, SHA256 |
| `GET /samples/{id}/overview.json` | IOCs, signatures, famille |
| `GET /samples/{id}/reports/static` | Analyse statique, YARA |
| `GET /samples/{id}/{task}/report_triage.json` | Processus, réseau, dumps |
| `GET /samples/{id}/{task}/files/{name}` | Fichiers déposés par le malware |
| `GET /samples/{id}/{task}/memory/{name}` | Dumps mémoire |
| `GET /samples/{id}/{task}/logs/onemon.json` | Événements kernel horodatés (JSONL) |
| `GET /samples/{id}/{task}/dump.pcap` | Traffic réseau brut |
| `GET /samples/{id}/{task}/dump.pcapng` | Traffic réseau + HTTPS déchiffré |

> `dump.Name` = chemin relatif pour l'URL API (ex: `NVIDIA.exe`, `extracted/payload.exe`).
> `dump.Path` = chemin absolu Windows — ne jamais utiliser dans les URLs.
> Fichiers `kind=memory` → endpoint `/memory/` ; autres → endpoint `/files/`.

---

## Rapports générés

### Rapport technique

Hashes, signatures, analyse statique, IOCs, réseau géolocalisé, processus+cmdlines,
MITRE ATT&CK avec liens officiels.

### Rapport management IA (15+ sections)

Classification (CRITIQUE/ELEVE/MOYEN/FAIBLE), état de compromission, chronologie d'attaque,
risque de propagation réseau, données exposées (base RGPD), analyse comportementale,
communications réseau, activité processus, techniques MITRE, attribution famille,
posture de réponse (Confinement→Éradication→Recouvrement), plan d'action priorisé,
obligations de notification.

---

## Configuration (config.json)

```json
{
  "api_token":       "votre_token_RF_sandbox",
  "proxy":           "",
  "ui_port":         "8766",
  "abuseipdb_key":   "",
  "claude_api_key":  "",
  "use_geoip":       false,
  "sandbox_timeout": 300,
  "sandbox_network": "internet"
}
```

> Tous les tokens sont chiffrés AES-256 via `vault.exe` — jamais stockés en clair.

---

## Sécurité

- Token API chiffré AES-256 via `vault.exe init / seal / unseal`
- Soumissions RF Sandbox en mode **privé** par défaut
- `config/.vault.key` et `config/config.json` exclus du dépôt (`.gitignore`)
- Moteur IA **100% local** — aucune donnée envoyée à un tiers
- Audit sécurité automatique à chaque compilation (gosec + govulncheck + gitleaks)
- Compilation **bloquée** si secrets détectés dans le code source

---

## Dépendances Go

| Package | Usage |
|---|---|
| `github.com/jung-kurt/gofpdf` | Génération PDF |
| `github.com/Azure/go-ntlmssp` | Authentification NTLM (proxy d'entreprise) |
| `github.com/joho/godotenv` | Chargement `.env` |
| `modernc.org/sqlite` | Base de connaissances SQLite (pur Go, sans CGO) |

---

*RF Sandbox Analyser Go Edition v2.1.0 — https://sandbox.recordedfuture.com/api/v0*
