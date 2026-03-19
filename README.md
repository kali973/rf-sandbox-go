# RF Sandbox Analyser — Go Edition v3.0.0

Outil **100% Go** pour soumettre des fichiers/URLs à la **Recorded Future Sandbox API**,
analyser les résultats et générer des rapports PDF professionnels de cybersécurité via
un moteur d'intelligence artificielle **entièrement local** (aucune donnée envoyée à un tiers).

---

## Vue d'ensemble

```
Fichier / URL malveillant
        │
        ▼
┌─────────────────────────────────────────────────────┐
│              RF Sandbox API                         │
│  Analyse dynamique multi-plateformes (1-3 min)      │
│  Windows 7/10, Linux — comportements, réseau, mémoire│
└──────────────────────┬──────────────────────────────┘
                       │  Signatures · IOCs · TTPs · Processus
                       ▼
┌─────────────────────────────────────────────────────┐
│         Enrichissement externe (parallèle)          │
│  MITRE ATT&CK API  ·  AbuseIPDB  ·  GeoIP          │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│          Pipeline IA local (llama.cpp)              │
│                                                     │
│  Mode CHAÎNÉ (si ≥ 2 modèles présents) :           │
│    M1 Cyber spécialiste → extraction technique      │
│    M2 Généraliste structuré → synthèse rapport      │
│                                                     │
│  Mode MONO-MODÈLE (fallback) :                      │
│    Meilleur modèle disponible → rapport complet     │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
         Rapport PDF professionnel (20+ sections)
         Rapport technique Go (données brutes)
```

---

## Table des matières

1. [Architecture du projet](#1-architecture-du-projet)
2. [Prérequis](#2-prérequis)
3. [Installation rapide](#3-installation-rapide)
4. [Interface web](#4-interface-web)
5. [Moteurs IA — catalogue complet](#5-moteurs-ia--catalogue-complet)
6. [Pipeline bi-modèle en chaîne](#6-pipeline-bi-modèle-en-chaîne)
7. [Rapports générés](#7-rapports-générés)
8. [Base de connaissances SQLite](#8-base-de-connaissances-sqlite)
9. [Entraînement IA — Foundation-Sec-8B](#9-entraînement-ia--foundation-sec-8b)
10. [Enrichissement externe](#10-enrichissement-externe)
11. [Audit de sécurité](#11-audit-de-sécurité)
12. [Vault — chiffrement des secrets](#12-vault--chiffrement-des-secrets)
13. [Compilation et déploiement](#13-compilation-et-déploiement)
14. [Configuration](#14-configuration)
15. [Endpoints RF Sandbox API](#15-endpoints-rf-sandbox-api)
16. [Dépendances Go](#16-dépendances-go)

---

## 1. Architecture du projet

```
rf-sandbox-go/
├── cmd/
│   ├── main.go                    # Point d'entrée principal (CLI + UI web)
│   ├── trainer/main.go            # Entraîneur LoRA 100% Go — Foundation-Sec-8B
│   ├── vault/main.go              # Gestion secrets (init / seal / unseal / status)
│   ├── audit/main.go              # Rapport PDF audit sécurité
│   ├── audit-securite/main.go     # Audit gosec / govulncheck / gitleaks
│   ├── setup-moteur/main.go       # Télécharge llama.cpp + modèles GGUF
│   ├── bootstrap-post/main.go     # Post-bootstrap (audit + setup moteur)
│   ├── compilateur/main.go        # Compilateur Go natif
│   └── update-proxy/main.go       # Détection / mise à jour proxy
├── internal/
│   ├── ai/
│   │   ├── ollama.go              # Client llama.cpp — catalogue, pipeline chaîné, auto-détection GPU
│   │   ├── prompt.go              # Prompts enrichis, extraction M1, synthèse M2, parsing JSON
│   │   ├── reporter.go            # Générateur PDF rapport management IA
│   │   ├── enrich.go              # MITRE ATT&CK API + AbuseIPDB + MalwareBazaar
│   │   ├── geoip.go               # Géolocalisation IP (ip-api.com)
│   │   ├── knowledge.go           # Base de connaissances SQLite (analyses + enrichissements)
│   │   ├── dataset.go             # Export analyses.db → JSONL Alpaca (dataset LoRA enrichi)
│   │   ├── claude.go              # Moteur cloud alternatif (Claude API, optionnel)
│   │   └── colors.go              # Helpers couleurs logs SSE
│   ├── client/client.go           # Client API RF Sandbox (tous les endpoints)
│   ├── models/models.go           # Structures de données API + KernelEvents
│   ├── reporter/reporter.go       # Générateur PDF rapport technique (gofpdf)
│   └── auditpdf/auditpdf.go       # Générateur PDF rapport audit sécurité
├── ui/
│   ├── ui.go                      # Serveur HTTP + handlers + SSE logs + pipeline IA
│   └── index.html                 # Interface web SPA (queue, logs temps réel, config)
├── config/
│   ├── config.go                  # Chargement configuration
│   ├── config.json                # Token API, proxy, port UI, options sandbox
│   └── config.json.example        # Modèle de configuration
├── httpclient/client.go           # Client HTTP (NTLM, proxy, retry, timeout)
├── vault/vault.go                 # Chiffrement AES-256 des secrets
├── scripts/
│   ├── bootstrap.bat              # Lanceur Windows (compile + installe)
│   ├── compilateur.ps1            # Compilation + déploiement clé USB automatique
│   ├── lancer.bat                 # Démarrage depuis clé USB
│   ├── setup_moteur.ps1           # Télécharge llama.cpp + modèles dans moteur/
│   ├── signer.ps1                 # Signature code PowerShell
│   ├── audit_securite.ps1         # Audit sécurité (gosec / govulncheck / gitleaks)
│   └── update_proxy.ps1           # Détection et mise à jour proxy
├── moteur/                        # Moteur IA local (NON versionné — .gitignore)
│   ├── llama-server.exe           # llama.cpp portable (CUDA + CPU fallback)
│   ├── llama-finetune.exe         # Fine-tuning LoRA natif (build b4109)
│   ├── llama-quantize.exe         # Quantification modèles GGUF
│   ├── models/                    # Fichiers GGUF (téléchargés via setup-moteur ou UI)
│   └── lora/                      # Modèles fine-tunés (sortie de trainer.exe)
├── knowledge/                     # Base de connaissances (NON versionné)
│   ├── analyses.db                # SQLite — analyses + MITRE + AbuseIPDB
│   └── training_dataset.jsonl     # Dataset d'entraînement exporté
├── reporting/                     # Rapports PDF archivés automatiquement
├── audit/                         # Rapports d'audit de sécurité
├── samples/                       # Fichiers batch exemples
├── go.mod / go.sum
├── Makefile
└── README.md
```

---

## 2. Prérequis

- **Go 1.21+** — https://go.dev/dl/
- **Windows** recommandé (scripts PowerShell, CUDA natif)
- GPU NVIDIA recommandé (CPU possible mais ~10× plus lent)
- Connexion Internet pour l'API RF Sandbox et le premier téléchargement des modèles
- Clé API **Recorded Future Sandbox** — https://sandbox.recordedfuture.com/

---

## 3. Installation rapide

### Windows — Bootstrap automatique

```bat
scripts\bootstrap.bat
```

Compile tous les binaires et les copie sur clé USB si détectée :

```
E:\rf-sandbox-go\
├── rf-sandbox.exe       exécutable principal
├── vault.exe            gestion des secrets
├── setup-moteur.exe     télécharge le moteur IA
├── bootstrap-post.exe   audit + setup moteur
├── trainer.exe          fine-tuning LoRA Foundation-Sec-8B
├── config\              configuration (token chiffré, proxy)
├── moteur\              moteur IA (~12 Go si présent localement)
└── lancer.bat           point d'entrée (double-clic)
```

### Télécharger le moteur IA (une seule fois)

```bat
setup-moteur.exe
```

Télécharge automatiquement dans `moteur\` :
- `llama-server.exe` + DLLs CUDA (~150 Mo)
- `mistral-7b-instruct-v0.2.Q4_K_M.gguf` (~4,1 Go) — modèle de base

Les modèles supplémentaires se téléchargent depuis **Configuration → Moteur IA**.

### Démarrer

```bat
rf-sandbox.exe -ui
REM ou double-clic :
lancer.bat
```

Interface web disponible sur **http://localhost:8766**

---

## 4. Interface web

### Pages

| Page | Fonction |
|---|---|
| **Analyse** | Soumission fichiers / URLs / IDs RF Sandbox |
| **File d'attente** | Suivi temps réel — phases, moteur actif, détails étape |
| **Résultats** | Scores, IOCs, signatures par analyse |
| **Rapports IA** | Historique des rapports PDF archivés |
| **Configuration** | Moteurs IA, enrichissements, base de connaissances, entraînement |
| **Logs** | Console SSE temps réel — colorisation par catégorie |
| **Audit sécurité** | gosec / govulncheck / gitleaks + rapport PDF |
| **Readme** | Cette documentation |

### File d'attente — suivi détaillé

Chaque fichier soumis traverse les phases suivantes :

| Phase | Icône | Label |
|---|---|---|
| pending | ⏳ | En attente |
| running | 🔬 | Analyse sandbox RF… |
| ai-report | 🤖 | Génération rapport IA… |
| done | ✅ | Terminé |
| error | ❌ | Erreur |

En phase `ai-report`, une **ligne de détail temps réel** (alimentée par le flux SSE)
indique l'étape exacte du moteur IA :

```
⚡ Préchauffage moteur IA…
⏳ Chargement modèle… 45s / 120s
🔬 M1 — Extraction technique (cyber spécialiste)…
✓ M1 terminé — passage au M2…
🤖 M2 — Chargement moteur synthèse…
📤 Envoi du prompt au moteur…
✓ Génération terminée — parsing JSON…
💾 Mémorisation dans la base…
📄 Génération PDF en cours…
✅ Rapport généré avec succès
```

Le badge moteur est visible dès le **préchauffage parallèle** (avant même le retour de RF) :
`🔬 Foundation-Sec-8B` · `💻 Granite 8B` · `🛡 Primus 8B` · `🤖 Qwen/Mistral`

### Toggles

| Toggle | Défaut | Description |
|---|---|---|
| 🔍 Enrichissement MITRE ATT&CK | ON | TTPs via API MITRE (sans clé) |
| 🛡 AbuseIPDB | ON | Réputation IPs (clé gratuite) |
| 🌍 Géolocalisation IP | OFF | GeoIP via ip-api.com |
| 🧠 Mémorisation analyses | ON | Sauvegarde dans analyses.db |
| 🧠 Injection contexte prompt | OFF | Analyses similaires passées dans le prompt |

### Soumission

- **Fichier** : drag & drop ou sélecteur — max 100 Mo
- **URL** : soumission directe d'une URL malveillante
- **ID** : récupérer une analyse RF existante
- **Mode privé** : ON par défaut
- **Lot** : plusieurs fichiers simultanés — un rapport PDF par fichier

---

## 5. Moteurs IA — catalogue complet

Tous les modèles s'exécutent **localement via llama.cpp** — port 18081, localhost uniquement.

### Catalogue

| Modèle | VRAM | Taille | Spécialité | Licence |
|---|---|---|---|---|
| **Foundation-Sec-8B** (Cisco) ⭐ | 6 Go | 4,9 Go | Cyber natif — CVEs, CTI, exploits. **Priorité max. Fine-tunable.** | Apache 2.0 |
| **Qwen 2.5 14B Instruct** | 10 Go | 8,7 Go | Généraliste — meilleur JSON structuré, contexte 32k | Apache 2.0 |
| **Primus 8B** (Trend Micro) | 6 Go | 4,0 Go | CTI/forensic — 10B+ tokens cybersécurité Trend Micro | Llama 3 |
| **Granite 8B Code** (IBM) | 6 Go | 4,9 Go | Analyse de code — scripts obfusqués (PS1, JS, VBA) | Apache 2.0 |
| **Mistral 7B Instruct v0.2** | 6 Go | 4,1 Go | Généraliste léger — fallback, bon rapport qualité/vitesse | Apache 2.0 |

### Sélection automatique

```
Foundation-Sec-8B  →  Qwen 2.5 14B  →  Primus 8B  →  Mistral 7B
```

Foundation-Sec-8B est prioritaire car c'est le seul LLM du catalogue entraîné
en *continued pre-training* sur un corpus cybersécurité curé (pas un simple fine-tuning).

### Préchauffage parallèle

Dès la soumission d'un fichier, `llama-server` démarre **en parallèle** de l'analyse
RF Sandbox. Quand RF retourne ses résultats (1-3 min), le modèle est déjà chargé
en VRAM — gain de 30-60 secondes.

### Paramètres d'inférence

| Paramètre | Valeur |
|---|---|
| Temperature | 0,1 (JSON déterministe) |
| Repeat penalty | 1,1 |
| GPU layers | 99 (tout sur VRAM si disponible) |
| Context window | 32 768 tokens (GPU ≥ 6 Go) |
| Max output | 8 192 – 16 384 tokens |

---

## 6. Pipeline bi-modèle en chaîne

Activé automatiquement quand ≥ 2 modèles **distincts** sont présents dans `moteur/models/`.

### Architecture

```
Données RF + MITRE + AbuseIPDB
        │
        ▼  Prompt focalisé (~6k chars)
┌─────────────────────────────────────┐
│  M1 — Spécialiste cyber             │
│  Foundation-Sec / Primus / Granite  │
│                                     │
│  Sortie (TechExtraction JSON) :     │
│  → famille, TTPs confirmés          │
│  → infrastructure C2                │
│  → vecteur d'infection              │
│  → propagation estimée              │
│  → IOCs réseaux, confiance          │
└────────────────┬────────────────────┘
                 │ JSON partiel
                 ▼  Prompt synthèse (~10k chars)
┌─────────────────────────────────────┐
│  M2 — Généraliste structuré         │
│  Qwen 2.5 14B / Mistral 7B          │
│                                     │
│  Sortie (ForensicReport JSON) :     │
│  → résumé exécutif COMEX            │
│  → recommandations actionnables     │
│  → timeline narrative               │
│  → JSON final validé                │
└────────────────┬────────────────────┘
                 │
                 ▼
          Rapport PDF complet
```

### Candidats par rôle

| Rôle | Priorité |
|---|---|
| M1 (extraction technique) | Foundation-Sec-8B → Primus 8B → Granite 8B |
| M2 (synthèse rapport) | Qwen 2.5 14B → Mistral 7B |

### Gains estimés vs mono-modèle

| Critère | Gain |
|---|---|
| Précision famille / TTPs | +25% |
| Qualité JSON structuré | +40% |
| Cohérence technique / business | +30% |
| Temps de génération | +60% (acceptable — RF prend 1-3 min) |

Si la chaîne échoue à n'importe quelle étape, repli silencieux sur le mono-modèle.

---

## 7. Rapports générés

Tous les rapports sont archivés dans `reporting/` et téléchargeables depuis la page Rapports IA.

### Rapport management IA (20+ sections)

| Section | Contenu |
|---|---|
| Classification | CRITIQUE / ÉLEVÉ / MOYEN / FAIBLE |
| État de compromission | CONFIRMÉ / PROBABLE / SUSPECTÉ |
| Résumé exécutif | 3-4 phrases pour la direction, sans jargon |
| Pourquoi c'est une menace réelle | Argumentation non-technique |
| Chronologie d'attaque | Timeline phase par phase (activation → C2 → exfiltration) |
| Risque de propagation réseau | Niveau + vecteurs + systèmes ciblés |
| Données exposées | Inventaire RGPD (identifiants AD, fichiers, données métier) |
| Analyse comportementale | Actions observées en sandbox |
| Communications réseau | Connexions C2, DNS, HTTP/S, empreintes JA3/TLS |
| Activité processus | Arbre processus, cmdlines suspectes, durées |
| Analyse statique | Structure fichier, obfuscation, packing, YARA |
| Configs malware extraites | C2 hardcodés, mutex, botnet ID, clés crypto |
| Techniques MITRE ATT&CK | ID + nom + tactique + détection + mitigations |
| IOCs critiques | Hashes, IPs, domaines avec score AbuseIPDB |
| Attribution | Famille présumée, confiance, indicateurs |
| Posture de réponse | Confinement → Éradication → Recouvrement |
| Plan d'action | CRITIQUE / ÉLEVÉ / MOYEN / FAIBLE avec délais |
| Obligations de notification | RGPD 72h, ANSSI (OIV/OSE), assurance cyber |
| Indicateurs de compromission | Résumé IOCs + Event IDs Windows à surveiller |
| Conclusion | Synthèse et urgence |

### Rapport technique Go (données brutes)

Disponible sans moteur IA. Contient : hashes, signatures avec scores et TTPs,
analyse statique complète, IOCs exhaustifs, réseau géolocalisé (AbuseIPDB + GeoIP),
empreintes TLS/JA3, arbre processus avec timelines, MITRE avec liens officiels,
chronologie d'attaque, risque de propagation, recommandations priorisées.

---

## 8. Base de connaissances SQLite

Chaque analyse avec rapport IA validé est mémorisée dans `knowledge/analyses.db`.

### Schéma

```sql
CREATE TABLE analyses (
    id              TEXT PRIMARY KEY,
    date            TEXT,
    filename        TEXT,
    famille         TEXT,
    classification  TEXT,             -- CRITIQUE | ELEVE | MOYEN | FAIBLE
    score           INTEGER,          -- 0-10
    ttps            TEXT,             -- JSON ["T1059", "T1071", ...]
    ips             TEXT,             -- JSON ["1.2.3.4", ...]
    domaines        TEXT,             -- JSON ["evil.com", ...]
    hashes          TEXT,             -- JSON ["abc123...", ...]
    resume          TEXT,             -- Résumé exécutif (500 chars max)
    recommandations TEXT,             -- JSON ["[CRITIQUE] Isoler...", ...]
    confiance       TEXT,             -- HAUTE | MOYENNE | FAIBLE
    mitre_details   TEXT DEFAULT '{}', -- {T1059: {nom, tactique, description, mitigations}}
    abuse_scores    TEXT DEFAULT '{}'  -- {1.2.3.4: {score, pays, ISP, categories}}
)
```

Les colonnes `mitre_details` et `abuse_scores` enrichissent le dataset d'entraînement
avec le contexte sémantique des données RF. Migration automatique pour les bases existantes.

### Recherche de similarité (injection contexte)

| Signal | Points |
|---|---|
| Même famille malware | +40 |
| TTP en commun | +5 par TTP (max 30) |
| IP ou domaine en commun | +10 par IOC (max 30) |

Les 3 analyses les plus proches sont injectées dans le prompt si l'option est activée.

---

## 9. Entraînement IA — Foundation-Sec-8B

Fine-tuning LoRA de Foundation-Sec-8B (Cisco, Apache 2.0) sur vos propres analyses.
**100% Go, zéro Python, zéro PyTorch** — utilise `llama-finetune.exe` natif.

### Pourquoi Foundation-Sec-8B uniquement

Foundation-Sec-8B est le **seul modèle fine-tunable** du projet :
- Architecture LLaMA 3.1 8B ouverte, non propriétaire
- Cisco a publié les poids FP16 (nécessaires pour le fine-tuning)
- Licence Apache 2.0 — redistribution et modification autorisées

Les autres modèles ne peuvent pas être fine-tunés localement :
- Qwen 14B / Mistral 7B — GGUF quantifié 4-bit (pas de poids FP16 utilisables)
- Primus 8B — modèle propriétaire Trend Micro (poids fusionnés non redistribuables)

### Pipeline

```
1. Export dataset
   analyses.db → training_dataset.jsonl (format Alpaca enrichi RF+MITRE+AbuseIPDB)
              → training_dataset.txt    (format LLaMA 3.1 Chat Template)

2. Détection matériel
   nvidia-smi → profil GPU (threads, batch, ctx)

3. Vérification binaires
   llama-finetune.exe (build b4109) / llama-quantize.exe

4. Fine-tuning LoRA
   Base  : Foundation-Sec-8B-Instruct-Q4_K_M.gguf
   Sortie: moteur/lora/Foundation-Sec-8B-forensic-fr-lora.bin

5. Quantification Q4_K_M
   Sortie: moteur/lora/Foundation-Sec-8B-forensic-fr-Q4_K_M.gguf
```

### Format d'entraînement — LLaMA 3.1 Chat Template

```
<|begin_of_text|>
<|start_header_id|>system<|end_header_id|>
Tu es un analyste senior CERT/CSIRT francophone...
<|eot_id|>
<|start_header_id|>user<|end_header_id|>
FICHIER: malware.exe | SCORE: 9/10
TECHNIQUES MITRE ATT&CK OBSERVEES:
  [T1059.001] PowerShell | Tactique: Execution | ...
REPUTATION IPs (AbuseIPDB):
  185.220.101.45 : MALVEILLANTE score=97/100 | Pays=NL | ...
<|eot_id|>
<|start_header_id|>assistant<|end_header_id|>
{"classification":"CRITIQUE","score_global":9,...}
<|eot_id|>
```

### Profils GPU

| VRAM libre | Threads | Batch | Ctx | Durée estimée / 100 exemples |
|---|---|---|---|---|
| ≥ 20 Go (RTX 3090/4090) | 8 | 32 | 512 | ~15 min |
| ≥ 14 Go (RTX 3080Ti/4080) | 8 | 16 | 512 | ~30 min |
| ≥ 10 Go (RTX 3080/4070) | 6 | 8 | 256 | ~1h |
| ≥ 6 Go (RTX 3070/4060) | 4 | 4 | 256 | ~2h |
| CPU only | N cores (max 8) | 1 | 64 | plusieurs heures |

### Résultat

Copier `moteur/lora/Foundation-Sec-8B-forensic-fr-Q4_K_M.gguf` dans `moteur/models/`
→ il sera sélectionné en priorité maximale dès le prochain redémarrage.

---

## 10. Enrichissement externe

Toutes les requêtes sont exécutées **en parallèle** pendant la construction du prompt.

### MITRE ATT&CK (sans clé)

Source : `cti-taxii.mitre.org` + `raw.githubusercontent.com/mitre/cti`

Pour chaque TTP identifié par RF Sandbox :
- Nom de la technique et sous-technique
- Tactique (Initial Access, Execution, Persistence, C2...)
- Description technique complète
- Méthodes de détection recommandées
- Mitigations disponibles
- Lien `attack.mitre.org/techniques/Txxx/`

### AbuseIPDB (clé gratuite — 1 000 req/jour)

Source : `api.abuseipdb.com/api/v2/check`

Pour chaque IP publique contactée :
- Score d'abus /100
- Nombre de signalements (fenêtre 90 jours)
- Pays et ISP d'hébergement
- Catégories (Port Scan, Hacking, Web Spam, DDoS...)
- Flag `estMalveillant` (score ≥ 25 ou ≥ 5 signalements)

### Géolocalisation IP (optionnel)

Source : `ip-api.com/json` (sans clé, 45 req/min)

- Pays, région, ville
- ISP et organisation déclarée
- Coordonnées GPS
- Détection automatique des IPs privées / loopback

### MalwareBazaar (abuse.ch)

Source : `mb-api.abuse.ch/api/v1/`

- Famille malware confirmée pour les hashes SHA256
- Tags (stealer, ransomware, RAT, loader...)
- Date de première soumission

---

## 11. Audit de sécurité

Exécuté automatiquement à chaque compilation. Disponible à la demande depuis l'interface web.

### Outils

| Outil | Rôle |
|---|---|
| **gosec** | Vulnérabilités dans le code source Go |
| **govulncheck** | CVE dans les dépendances (go.sum / go.mod) |
| **gitleaks** | Secrets dans le code source (tokens, clés, passwords) |
| **Moteur IA local** | Analyse des binaires et modèles IA dans `moteur/` |

### Niveaux

- `OK` — aucun problème
- `AVERTISSEMENT` — problèmes non-bloquants
- `CRITIQUE` — secrets détectés → **compilation bloquée**

### Rapport IA de l'audit

Depuis l'interface web, le rapport d'audit peut être soumis au moteur IA local
pour générer un PDF professionnel structuré avec impact business et remédiation.

---

## 12. Vault — chiffrement des secrets

```bat
vault.exe init      # Génère config/.vault.key (AES-256)
vault.exe seal      # Chiffre les champs sensibles dans config.json
vault.exe unseal    # Déchiffre en mémoire
vault.exe status    # État du vault et champs chiffrés
```

Champs auto-chiffrés : `api_token`, `abuseipdb_key`, `hf_token`

Ordre de recherche de la clé :
1. Variable d'env `RF_VAULT_KEY`
2. `config/.vault.key` à côté de l'exécutable
3. `config/.vault.key` dans le dossier de `config.json`
4. `config/.vault.key` dans le répertoire courant

---

## 13. Compilation et déploiement

### Commandes de base

```bash
go build -ldflags="-s -w" -o rf-sandbox.exe    ./cmd
go build -ldflags="-s -w" -o vault.exe          ./cmd/vault
go build -ldflags="-s -w" -o setup-moteur.exe   ./cmd/setup-moteur
go build -ldflags="-s -w" -o bootstrap-post.exe ./cmd/bootstrap-post
go build -ldflags="-s -w" -o trainer.exe         ./cmd/trainer
go build -ldflags="-s -w" -o audit.exe           ./cmd/audit
```

### Cross-compilation

```bash
# Windows depuis Linux/Mac
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o rf-sandbox.exe ./cmd

# Linux depuis Windows
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o rf-sandbox ./cmd
```

### Via Makefile

```bash
make build      # Plateforme courante
make windows    # Cross-compilation Windows
make linux      # Cross-compilation Linux
```

---

## 14. Configuration

```json
{
  "api_token":        "VAULT:xxx",
  "proxy":            "",
  "ui_port":          "8766",
  "abuseipdb_key":    "VAULT:xxx",
  "hf_token":         "VAULT:xxx",
  "claude_api_key":   "",
  "ai_model":         "",
  "use_geoip":        false,
  "sandbox_timeout":  300,
  "sandbox_network":  "internet"
}
```

| Champ | Description |
|---|---|
| `api_token` | Token API RF Sandbox (chiffré via vault) |
| `proxy` | Proxy HTTP/HTTPS d'entreprise (NTLM supporté) |
| `ui_port` | Port de l'interface web (défaut : 8766) |
| `abuseipdb_key` | Clé API AbuseIPDB (gratuit, 1 000 req/jour) |
| `hf_token` | Token Hugging Face (modèles gated uniquement) |
| `ai_model` | Nom GGUF à forcer (vide = sélection automatique) |
| `use_geoip` | Activer la géolocalisation IP |
| `sandbox_timeout` | Durée max d'attente analyse RF en secondes |
| `sandbox_network` | Mode réseau sandbox : `internet` / `drop` / `tor` |

---

## 15. Endpoints RF Sandbox API

| Endpoint | Données |
|---|---|
| `POST /samples` | Soumission fichier/URL |
| `GET /samples/{id}/summary` | Scores, statuts, SHA256, famille |
| `GET /samples/{id}/overview.json` | IOCs, signatures, TTPs |
| `GET /samples/{id}/reports/static` | Analyse statique, YARA, fichiers extraits |
| `GET /samples/{id}/{task}/report_triage.json` | Processus, réseau, dumps, configs |
| `GET /samples/{id}/{task}/files/{name}` | Fichiers déposés par le malware |
| `GET /samples/{id}/{task}/memory/{name}` | Dumps mémoire (configs, credentials) |
| `GET /samples/{id}/{task}/logs/onemon.json` | Événements kernel horodatés (JSONL) |
| `GET /samples/{id}/{task}/dump.pcap` | Traffic réseau brut |
| `GET /samples/{id}/{task}/dump.pcapng` | Traffic réseau + HTTPS déchiffré |

> `dump.Name` = chemin relatif pour l'URL API.
> `dump.Path` = chemin absolu Windows — ne jamais utiliser dans les URLs.
> Fichiers `kind=memory` → endpoint `/memory/` ; autres → endpoint `/files/`.

---

## 16. Dépendances Go

| Package | Version | Usage |
|---|---|---|
| `github.com/jung-kurt/gofpdf` | v1.16.2 | Génération PDF (rapport technique + audit) |
| `github.com/Azure/go-ntlmssp` | v0.0.0-... | Authentification NTLM proxy d'entreprise |
| `github.com/joho/godotenv` | v1.5.1 | Chargement `.env` |
| `modernc.org/sqlite` | v1.46.1 | Base de connaissances SQLite (pur Go, sans CGO) |

---

## Sécurité

- Tokens API chiffrés **AES-256** — jamais stockés en clair
- Soumissions RF Sandbox en mode **privé** par défaut
- `config/.vault.key` et `config/config.json` exclus du dépôt (`.gitignore`)
- Moteur IA **100% local** — aucune donnée envoyée à un tiers
- Audit sécurité automatique à chaque compilation
- Compilation **bloquée** si secrets détectés dans le code source
- llama-server : port 18081, interface loopback uniquement

---

*RF Sandbox Analyser Go Edition v3.0.0 — https://sandbox.recordedfuture.com/api/v0*
*CCM de Bercy — Ministère de l'Économie et des Finances*
