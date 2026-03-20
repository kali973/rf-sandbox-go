// Package ai fournit un client llama.cpp local pour la generation de rapports
// management par IA. Le binaire llama-server et le modele GGUF sont stockes dans
// le dossier moteur/ du projet — portable, aucune installation systeme requise.
//
// MOTEUR : llama.cpp (llama-server.exe) avec support CUDA natif (GPU NVIDIA)
// MODELE : Mistral 7B Q4_K_M (~4.1 Go) au format GGUF
// PORT   : 18081 (dedie, isole de tout autre service)
// API    : Compatible OpenAI — POST /v1/chat/completions
package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	llamaPort          = "18081"
	LlamaBaseURL       = "http://localhost:" + llamaPort
	DefaultModel       = "mistral-7b-instruct-v0.2.Q4_K_M.gguf"
	FallbackModel      = "Qwen2.5-14B-Instruct-Q4_K_M.gguf"       // moteur secondaire — meilleure gestion JSON structuré
	PrimusModel        = "Llama-Primus-8B-Q3_K_M.gguf"            // Trend Micro Primus 8B — spécialisé cybersécurité/CTI
	FoundationSecModel = "Foundation-Sec-8B-Instruct-Q4_K_M.gguf" // Cisco Foundation-Sec-8B — cybersécurité, fine-tunable
	GraniteCodeModel   = "granite-8b-code-instruct-Q4_K_M.gguf"   // IBM Granite 8B Code — analyse de code malveillant statique
	LlamaForensicModel = "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf" // Meta Llama 3.1 8B — base forensic fine-tunable (contexte 128k)
	startupTimeout     = 120 * time.Second
	httpTimeout        = 10 * time.Second // pour health checks uniquement
	genTimeout         = 0                // sans limite pour la génération IA (prompt ~20k tokens)

	// Llama.cpp release depuis GitHub — tag b8185 (2026-03-02)
	llamaCppWindowsMain = "https://github.com/ggml-org/llama.cpp/releases/download/b8185/llama-b8185-bin-win-cuda-cu12.4-x64.zip"
	llamaCppWindowsCPU  = "https://github.com/ggml-org/llama.cpp/releases/download/b8185/llama-b8185-bin-win-cpu-x64.zip"
	llamaCppLinux       = "https://github.com/ggml-org/llama.cpp/releases/download/b8185/llama-b8185-bin-ubuntu-x64.zip"

	// DLLs CUDA runtime (separees du binaire principal depuis b8000+)
	llamaCppWindowsCUDArt = "https://github.com/ggml-org/llama.cpp/releases/download/b8185/cudart-llama-bin-win-cuda-12.4-x64.zip"

	// Mistral 7B Q4_K_M — Hugging Face (gratuit, aucun compte requis)
	mistralGGUFURL = "https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF/resolve/main/mistral-7b-instruct-v0.2.Q4_K_M.gguf"

	// Qwen2.5 14B Instruct Q4_K_M — bartowski (fichier unique, ~8.7 Go)
	// Avantages : meilleure instruction following, JSON structuré plus fiable, contexte 32k
	// Source : https://huggingface.co/bartowski/Qwen2.5-14B-Instruct-GGUF
	qwenGGUFURL = "https://huggingface.co/bartowski/Qwen2.5-14B-Instruct-GGUF/resolve/main/Qwen2.5-14B-Instruct-Q4_K_M.gguf"

	// Trend Micro Primus 8B Q4_K_M — spécialisé cybersécurité/CTI
	// Trend Micro Primus 8B — GGUF communautaire par TensorBlock (public, sans token)
	// Source officielle SafeTensors : trendmicro-ailab/Llama-Primus-Merged
	// GGUF quantisé par TensorBlock : tensorblock/Llama-Primus-Merged-GGUF (Q4_K_M ~4.9 Go)
	primusRepoID   = "tensorblock/Llama-Primus-Merged-GGUF"
	primusGGUFFile = "Llama-Primus-Merged-Q3_K_M.gguf"
	primusGGUFURL  = "https://huggingface.co/" + primusRepoID + "/resolve/main/" + primusGGUFFile

	// Foundation-Sec-8B Instruct Q4_K_M — Cisco (Apache 2.0, publié avril 2025)
	// LLaMA 3.1 8B continued-pretrained sur corpus cybersécurité (CVEs, CTI, exploit write-ups)
	// Seul modèle du projet entraînable localement via Unsloth QLoRA sur le dataset analyses.db
	// Source : fdtn-ai/Foundation-Sec-8B-Instruct + mradermacher/Foundation-Sec-8B-Instruct-GGUF
	foundationSecGGUFURL = "https://huggingface.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF/resolve/main/Foundation-Sec-8B-Instruct.Q4_K_M.gguf"

	// Meta Llama 3.1 8B Instruct Q4_K_M — base forensic idéale pour fine-tuning
	// Contexte 128k tokens, architecture LLaMA 3.1 (même base que Foundation-Sec et ForensicLLM)
	// Licence : Llama 3.1 Community License (usage commercial autorisé)
	// Source : bartowski/Meta-Llama-3.1-8B-Instruct-GGUF
	llamaForensicGGUFURL = "https://huggingface.co/bartowski/Meta-Llama-3.1-8B-Instruct-GGUF/resolve/main/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf"

	// IBM Granite 8B Code Instruct Q4_K_M — IBM Research (Apache 2.0)
	// Spécialisé analyse de code — excellent pour décompilation, détection patterns malveillants,
	// analyse de scripts obfusqués (PowerShell, JavaScript, VBA). Complémentaire à Foundation-Sec.
	// IBM Granite URLs — bartowski/granite-8b-code-instruct-4k-GGUF → 404 (repo supprimé)
	// On essaie plusieurs sources dans EnsureGraniteCodeModel()
	graniteCodeGGUFURL       = "https://huggingface.co/ibm-granite/granite-8b-code-instruct-4k/resolve/main/granite-8b-code-instruct-4k-Q4_K_M.gguf"
	graniteCodeGGUFFallback1 = "https://huggingface.co/bartowski/ibm-granite-8b-code-instruct-4k-GGUF/resolve/main/ibm-granite-8b-code-instruct-4k-Q4_K_M.gguf"
	graniteCodeGGUFFallback2 = "https://huggingface.co/bartowski/ibm-granite-3.1-8b-instruct-GGUF/resolve/main/ibm-granite-3.1-8b-instruct-Q4_K_M.gguf"
)

// ─── Catalogue des modèles connus ────────────────────────────────────────────

// ModelInfo décrit un modèle GGUF disponible dans le catalogue.
type ModelInfo struct {
	Filename      string  // nom du fichier GGUF dans moteur/models/
	DisplayName   string  // nom affiché dans l'UI
	Description   string  // description courte
	VRAMMinGB     float64 // VRAM minimale recommandée en Go
	SizeGB        float64 // taille approximative du fichier en Go
	DownloadURL   string  // URL de téléchargement direct HuggingFace (vide = installation manuelle)
	SourceURL     string  // URL de la page HuggingFace du modèle (pour les instructions manuelles)
	Specialty     string  // domaine de spécialisation ("general", "cyber", "code"...)
	Gated         bool    // true = nécessite un token HuggingFace + acceptation de licence
	ManualInstall bool    // true = pas de téléchargement automatique (conversion GGUF requise)
	GatedNote     string  // instruction pour obtenir l'accès (affiché dans l'UI)
}

// KnownModels est le catalogue statique des modèles supportés par le projet.
// Clé = nom de fichier GGUF (identifiant stable).
var KnownModels = map[string]ModelInfo{
	DefaultModel: {
		Filename:    DefaultModel,
		DisplayName: "Mistral 7B Instruct v0.2",
		Description: "Modèle généraliste léger — bon rapport qualité/vitesse, JSON structuré correct",
		VRAMMinGB:   6,
		SizeGB:      4.1,
		DownloadURL: mistralGGUFURL,
		SourceURL:   "https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF",
		Specialty:   "general",
	},
	FallbackModel: {
		Filename:    FallbackModel,
		DisplayName: "Qwen 2.5 14B Instruct",
		Description: "Modèle généraliste plus puissant — meilleur JSON structuré, contexte 32k",
		VRAMMinGB:   10,
		SizeGB:      8.7,
		DownloadURL: qwenGGUFURL,
		SourceURL:   "https://huggingface.co/bartowski/Qwen2.5-14B-Instruct-GGUF",
		Specialty:   "general",
	},
	PrimusModel: {
		Filename:      PrimusModel,
		DisplayName:   "Trend Micro Primus 8B (cybersécurité)",
		Description:   "Spécialisé CTI/forensic — entraîné sur 10B+ tokens cybersécurité Trend Micro. Familles malware, TTPs MITRE, threat intelligence. GGUF Q3_K_M par TensorBlock.",
		VRAMMinGB:     6,
		SizeGB:        4.0,
		DownloadURL:   primusGGUFURL,
		SourceURL:     "https://huggingface.co/tensorblock/Llama-Primus-Merged-GGUF",
		Specialty:     "cyber",
		Gated:         false,
		ManualInstall: false,
		GatedNote:     "",
	},
	FoundationSecModel: {
		Filename:    FoundationSecModel,
		DisplayName: "Foundation-Sec-8B Instruct (Cisco)",
		Description: "LLaMA 3.1 8B continued-pretrained sur corpus cybersécurité par Cisco (CVEs, CTI, exploit write-ups, compliance). Licence Apache 2.0. Seul modèle fine-tunable localement avec le dataset analyses.db.",
		VRAMMinGB:   6,
		SizeGB:      4.92,
		DownloadURL: foundationSecGGUFURL,
		SourceURL:   "https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct",
		Specialty:   "cyber",
		Gated:       false,
	},
	GraniteCodeModel: {
		Filename:    GraniteCodeModel,
		DisplayName: "IBM Granite 8B Code Instruct",
		Description: "IBM Research — spécialisé analyse de code : décompilation, scripts obfusqués (PowerShell, JS, VBA), détection de patterns malveillants dans le code source. Complémentaire à Foundation-Sec pour l'étape d'extraction technique. Apache 2.0.",
		VRAMMinGB:   6,
		SizeGB:      4.9,
		DownloadURL: graniteCodeGGUFURL,
		SourceURL:   "https://huggingface.co/ibm-granite/granite-8b-code-instruct-4k",
		Specialty:   "code-analysis",
		Gated:       false,
	},
	LlamaForensicModel: {
		Filename:    LlamaForensicModel,
		DisplayName: "Meta Llama 3.1 8B Instruct (base forensic)",
		Description: "Meta Llama 3.1 8B — architecture identique à Foundation-Sec et ForensicLLM (LLaMA 3.1). Contexte 128k tokens. Base idéale pour fine-tuning forensic local via LoRA/QLoRA sur le dataset analyses.db. Excellent équilibre qualité/vitesse sur RTX 3060+. Llama 3.1 Community License.",
		VRAMMinGB:   6,
		SizeGB:      4.9,
		DownloadURL: llamaForensicGGUFURL,
		SourceURL:   "https://huggingface.co/bartowski/Meta-Llama-3.1-8B-Instruct-GGUF",
		Specialty:   "forensic",
		Gated:       false,
	},
}

// ListAvailableModels retourne la liste des modèles présents dans moteur/models/.
// Combine les modèles du catalogue KnownModels (avec métadonnées) et les fichiers
// GGUF inconnus détectés dans le répertoire (affichés sans métadonnées).
func ListAvailableModels() []ModelInfo {
	mDir := moteurDir()
	modelsDir := filepath.Join(mDir, "models")

	var result []ModelInfo
	seen := map[string]bool{}

	// 1. Modèles du catalogue présents sur disque
	for _, info := range KnownModels {
		if modelPresent(mDir, info.Filename) {
			result = append(result, info)
			seen[info.Filename] = true
		}
	}

	// 2. Fichiers GGUF inconnus dans moteur/models/ (ajoutés manuellement)
	entries, err := os.ReadDir(modelsDir)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(strings.ToLower(name), ".gguf") {
				continue
			}
			if seen[name] {
				continue
			}
			info, _ := e.Info()
			sizeGB := 0.0
			if info != nil {
				sizeGB = float64(info.Size()) / (1024 * 1024 * 1024)
			}
			result = append(result, ModelInfo{
				Filename:    name,
				DisplayName: name,
				Description: "Modèle GGUF détecté localement",
				SizeGB:      sizeGB,
				Specialty:   "custom",
			})
			seen[name] = true
		}
	}

	return result
}

// ModelDisplayName retourne le nom d'affichage d'un modèle depuis son nom de fichier.
// Fallback sur le nom de fichier si inconnu du catalogue.
func ModelDisplayName(filename string) string {
	if info, ok := KnownModels[filename]; ok {
		return info.DisplayName
	}
	return filename
}

// IsModelPresent indique si un modèle est disponible dans moteur/models/.
func IsModelPresent(filename string) bool {
	return modelPresent(moteurDir(), filename)
}

// ModelDownloadedBytes retourne la taille actuelle du fichier en cours de téléchargement.
// Utile pour afficher une barre de progression dans l'UI.
// Retourne 0 si le fichier n'existe pas encore.
func ModelDownloadedBytes(filename string) int64 {
	p := modelPath(moteurDir(), filename)
	info, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return info.Size()
}

// hfToken est le token Hugging Face pour les téléchargements de modèles gated.
// Défini une fois au démarrage via SetHFToken().
var hfToken string

// SetHFToken configure le token Hugging Face pour les téléchargements authentifiés.
// Requis pour les modèles "gated" comme Primus (accord de licence Llama 3.1 nécessaire).
func SetHFToken(token string) {
	hfToken = strings.TrimSpace(token)
}

// GetHFToken retourne le token HuggingFace configuré (masqué pour les logs).
func GetHFToken() string      { return hfToken }
func HFTokenConfigured() bool { return hfToken != "" }

type Client struct {
	baseURL string
	model   string
	logger  *log.Logger
	http    *http.Client // pour health checks (timeout court)
	httpGen *http.Client // pour génération IA (sans timeout)
}

func NewClient(model string, logger *log.Logger) *Client {
	if model == "" {
		model = DefaultModel
	}
	if logger == nil {
		logger = log.New(os.Stderr, "", log.LstdFlags)
	}
	return &Client{
		baseURL: LlamaBaseURL,
		model:   model,
		logger:  logger,
		http:    &http.Client{Timeout: httpTimeout},
		httpGen: &http.Client{Timeout: genTimeout},
	}
}

// ─── Dossier moteur/ ──────────────────────────────────────────────────────────

// moteurDir retourne le chemin absolu du dossier moteur/ PARTAGE.
// Il est place au meme niveau que le repertoire du projet courant,
// afin que tous les projets GolandProjects puissent le reutiliser.
//
// Exemple :
//
//	exe dans  : C:\Users\X\GolandProjects\rf-sandbox-go\rf-sandbox.exe
//	moteur/   : C:\Users\X\GolandProjects\moteur\
//
// Si la resolution via l'exe echoue, fallback sur ../moteur/ depuis cwd.
func moteurDir() string {
	var projectDir string

	// Resolution principale : parent du dossier contenant l'exe
	if exe, err := os.Executable(); err == nil {
		// exe          = .../GolandProjects/rf-sandbox-go/rf-sandbox.exe
		// Dir(exe)     = .../GolandProjects/rf-sandbox-go
		// Dir(Dir(exe))= .../GolandProjects   <- niveau partage
		projectDir = filepath.Dir(filepath.Dir(exe))
	}

	// Fallback : ../  depuis le repertoire de travail courant
	if projectDir == "" {
		if cwd, err := os.Getwd(); err == nil {
			projectDir = filepath.Dir(cwd)
		}
	}

	dir := filepath.Join(projectDir, "moteur")
	os.MkdirAll(filepath.Join(dir, "models"), 0755)
	return dir
}

func llamaBinary() string {
	dir := moteurDir()
	for _, name := range []string{"llama-server.exe", "llama-server"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func modelPath(mDir, modelName string) string {
	return filepath.Join(mDir, "models", modelName)
}

func modelPresent(mDir, modelName string) bool {
	p := modelPath(mDir, modelName)
	info, err := os.Stat(p)
	if err != nil || info.Size() < 100*1024*1024 {
		return false
	}
	return isValidGGUF(p)
}

// ─── Verifications ────────────────────────────────────────────────────────────

func (c *Client) isRunning() bool {
	resp, err := c.http.Get(c.baseURL + "/health")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

// ─── EnsureReady ──────────────────────────────────────────────────────────────

func (c *Client) EnsureReady(progressFn func(string)) error {
	if progressFn == nil {
		progressFn = func(s string) { c.logger.Println(s) }
	}

	mDir := moteurDir()
	progressFn(cHeader("AI", fmt.Sprintf("INITIALISATION MOTEUR IA  —  llama.cpp / llama-server")))
	progressFn(logDetail("AI", fmt.Sprintf("Dossier moteur : %s", mDir)))
	progressFn(logDetail("AI", fmt.Sprintf("Modèle demandé : %s", c.model)))
	progressFn(logDetail("AI", fmt.Sprintf("Port réseau    : %s  (localhost uniquement, isolé)", llamaPort)))

	// Analyse complète du matériel — calcul des paramètres optimaux pour cette machine
	progressFn(logInfo("AI", "Analyse du matériel (CPU / RAM / GPU)..."))
	machineProfile := analyseMachine(progressFn)

	// 1. Binaire llama-server
	binPath := llamaBinary()
	if binPath != "" {
		progressFn(logInfo("AI", fmt.Sprintf("llama-server présent : %s", binPath)))
	} else {
		progressFn(logWarn("AI", "llama-server absent — téléchargement llama.cpp depuis GitHub..."))
		var err error
		binPath, err = downloadLlamaCpp(mDir, progressFn)
		if err != nil {
			return fmt.Errorf("téléchargement llama.cpp échoué: %w", err)
		}
		progressFn(logOK("AI", fmt.Sprintf("llama-server téléchargé : %s", binPath)))
	}

	// 2. Modele GGUF
	if modelPresent(mDir, c.model) {
		progressFn(logInfo("AI", fmt.Sprintf("Modèle %s présent dans moteur/models/", c.model)))
	} else {
		progressFn(logWarn("AI", "Modèle absent — téléchargement Mistral 7B Q4_K_M (~4.1 Go)..."))
		if err := downloadModel(mDir, c.model, progressFn); err != nil {
			return fmt.Errorf("téléchargement modèle échoué: %w", err)
		}
		progressFn(logOK("AI", fmt.Sprintf("Modèle %s téléchargé", c.model)))
	}

	// 3. Demarrer llama-server
	// Règle absolue : on tue TOUJOURS toute instance existante avant de démarrer.
	// Ne jamais "réutiliser" une instance existante — elle peut être en train de mourir.
	logPath := filepath.Join(mDir, "llama-server.log")

	progressFn(logInfo("AI", "Arrêt de toute instance llama-server existante..."))
	killLlamaServer()
	killPort(llamaPort) // tuer aussi par port au cas où le nom diffère
	time.Sleep(2 * time.Second)

	// Kill par PID via netstat si le port reste occupé après kill par nom
	if isPortInUse(llamaPort) {
		progressFn(logWarn("AI", fmt.Sprintf("Port %s encore occupé par %s — kill forcé par PID...", llamaPort, portOwnerInfo(llamaPort))))
		for attempt := 1; attempt <= 15; attempt++ {
			killLlamaServer()
			killPortOwner(llamaPort) //nolint
			time.Sleep(1 * time.Second)
			if !isPortInUse(llamaPort) {
				progressFn(logInfo("AI", fmt.Sprintf("Port %s libéré (tentative %d)", llamaPort, attempt)))
				break
			}
			if attempt == 15 {
				progressFn(cErr(fmt.Sprintf("[AI] ✗ Port %s impossible à libérer — processus : %s", llamaPort, portOwnerInfo(llamaPort))))
				return fmt.Errorf("port %s inaccessible après 15 tentatives", llamaPort)
			}
		}
	}

	progressFn(logInfo("AI", fmt.Sprintf("Démarrage llama-server sur le port %s...", llamaPort)))
	progressFn(cGrey(fmt.Sprintf("[AI]    Log : %s", logPath)))
	if err := startLlamaServerWithProfile(binPath, modelPath(mDir, c.model), machineProfile); err != nil {
		return fmt.Errorf("démarrage llama-server échoué: %w", err)
	}

	// Attendre jusqu'a startupTimeout en surveillant le log en temps réel.
	// Dès qu'on détecte "couldn't bind" → kill immédiat + retry (max 3 fois).
	const maxRetries = 3
	for retry := 1; retry <= maxRetries; retry++ {
		if retry > 1 {
			progressFn(logWarn("AI", fmt.Sprintf("Relance llama-server (tentative %d/%d) — kill + redémarrage...", retry, maxRetries)))
			killLlamaServer()
			killPort(llamaPort)
			time.Sleep(3 * time.Second)
			if err := startLlamaServerWithProfile(binPath, modelPath(mDir, c.model), machineProfile); err != nil {
				return fmt.Errorf("relance llama-server échouée: %w", err)
			}
		}

		deadline := time.Now().Add(startupTimeout)
		lastLog := time.Now()
		bindFailed := false

		for time.Now().Before(deadline) {
			time.Sleep(2 * time.Second)

			// ── Surveillance log en temps réel ──────────────────────────────
			// Lire le log à chaque itération pour détecter une erreur fatale
			if logData, err := os.ReadFile(logPath); err == nil {
				content := string(logData)
				if strings.Contains(content, "couldn't bind") {
					progressFn(logErr("AI", fmt.Sprintf("Port %s déjà occupé (couldn't bind détecté) — kill + retry...", llamaPort)))
					killLlamaServer()
					killPort(llamaPort)
					time.Sleep(3 * time.Second)
					bindFailed = true
					break
				}
				if strings.Contains(content, "exiting due to HTTP server error") {
					progressFn(logErr("AI", "Erreur HTTP server dans le log — kill + retry..."))
					killLlamaServer()
					killPort(llamaPort)
					time.Sleep(3 * time.Second)
					bindFailed = true
					break
				}
			}

			if c.isRunning() {
				bindFailed = false
				break
			}

			if time.Since(lastLog) >= 10*time.Second {
				elapsed := int(time.Since(deadline.Add(-startupTimeout)).Seconds())
				progressFn(cGrey(fmt.Sprintf("[AI]    Chargement du modèle en mémoire... %ds / %ds", elapsed, int(startupTimeout.Seconds()))))
				lastLog = time.Now()
			}
		}

		if c.isRunning() {
			break // succès
		}

		if !bindFailed && retry == maxRetries {
			// Timeout réel (120s écoulées sans réponse, pas d'erreur bind)
			if logData, err := os.ReadFile(logPath); err == nil && len(logData) > 0 {
				lines := strings.Split(strings.TrimSpace(string(logData)), "\n")
				start := len(lines) - 8
				if start < 0 {
					start = 0
				}
				progressFn(logErr("AI", "Timeout — dernières lignes du log :"))
				for _, l := range lines[start:] {
					l = strings.TrimSpace(l)
					if l == "" {
						continue
					}
					if strings.Contains(l, "couldn't bind") || strings.Contains(l, "error") || strings.Contains(l, "failed") {
						progressFn(cErr("    ↳ " + l))
					} else {
						progressFn(cGrey("    ↳ " + l))
					}
				}
			}
			return fmt.Errorf("llama-server ne répond pas sur le port %s après %v — voir %s",
				llamaPort, startupTimeout, logPath)
		}
	}

	if !c.isRunning() {
		return fmt.Errorf("llama-server indisponible après %d tentatives — voir %s", maxRetries, logPath)
	}
	progressFn(logOK("AI", fmt.Sprintf("llama-server opérationnel | %s | Modèle : %s", c.baseURL, c.model)))
	return nil
}

// isPortInUse vérifie si un port TCP local est déjà en écoute.
func isPortInUse(port string) bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// killLlamaServer tue tout processus llama-server en cours d'exécution.
func killLlamaServer() {
}

// KillLlamaServer est la version exportée de killLlamaServer.
// Utilisée par le handler /api/cancel pour arrêter une génération en cours.
func KillLlamaServer() {
	killLlamaServer()
	if runtime.GOOS == "windows" {
		exec.Command("taskkill", "/F", "/IM", "llama-server.exe").Run()
	} else {
		exec.Command("pkill", "-9", "-f", "llama-server").Run()
	}
}

// killPort tue tous les processus qui occupent un port local via netstat -ano.
// Ne filtre pas sur l'état TCP — capture LISTENING, TIME_WAIT, ESTABLISHED, etc.
func killPort(port string) {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("netstat", "-ano").Output()
		if err != nil {
			return
		}
		target := ":" + port
		killed := map[string]bool{}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			// Format netstat Windows : Proto  LocalAddr  ForeignAddr  State  PID
			if len(fields) < 5 {
				continue
			}
			if !strings.HasSuffix(fields[1], target) {
				continue
			}
			pid := fields[len(fields)-1]
			if pid == "0" || killed[pid] {
				continue
			}
			exec.Command("taskkill", "/F", "/PID", pid).Run()
			killed[pid] = true
		}
	} else {
		// Linux/macOS : fuser puis lsof en double sécurité
		exec.Command("fuser", "-k", "-9", port+"/tcp").Run()
		if out, err := exec.Command("lsof", "-ti", "tcp:"+port).Output(); err == nil {
			for _, pid := range strings.Fields(string(out)) {
				exec.Command("kill", "-9", strings.TrimSpace(pid)).Run()
			}
		}
	}
}

// killPortOwner est un alias pour la compatibilité.
func killPortOwner(port string) error {
	killPort(port)
	return nil
}

// portOwnerInfo retourne "PID=XXXX (nom)" pour les logs de diagnostic.
func portOwnerInfo(port string) string {
	if runtime.GOOS != "windows" {
		out, _ := exec.Command("lsof", "-ti", "tcp:"+port).Output()
		pid := strings.TrimSpace(string(out))
		if pid == "" {
			return "inconnu"
		}
		return "PID=" + pid
	}
	out, err := exec.Command("netstat", "-ano").Output()
	if err != nil {
		return "inconnu"
	}
	target := ":" + port
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 5 || !strings.HasSuffix(fields[1], target) {
			continue
		}
		pid := fields[len(fields)-1]
		if pid == "0" {
			continue
		}
		nameOut, _ := exec.Command("tasklist", "/FI", "PID eq "+pid, "/FO", "CSV", "/NH").Output()
		name := strings.TrimSpace(string(nameOut))
		if idx := strings.Index(name, ","); idx > 0 {
			name = strings.Trim(name[:idx], `"`)
		} else {
			name = "?"
		}
		return fmt.Sprintf("PID=%s (%s)", pid, name)
	}
	return "port libre"
}

// RestartWithModel arrête llama-server et le redémarre avec un modèle différent.
// Utilisé pour le fallback Qwen2.5-14B si Mistral 7B produit un JSON invalide.
// Le modèle secondaire Qwen2.5-14B utilise systématiquement le GPU (ngl=99) si disponible.
func (c *Client) RestartWithModel(modelName string, progressFn func(string)) error {
	mDir := moteurDir()

	// Vérifier que le modèle est bien présent dans moteur/models/
	if !modelPresent(mDir, modelName) {
		return fmt.Errorf("modèle %s absent de moteur/models/ — téléchargement nécessaire", modelName)
	}

	// Arrêter llama-server en cours
	progressFn(logWarn("AI-FALLBACK", fmt.Sprintf("Arrêt llama-server (modèle actuel: %s)...", c.model)))
	killLlamaServer()
	killPort(llamaPort)
	time.Sleep(2 * time.Second)

	// Changer le modèle du client
	c.model = modelName
	binPath := llamaBinary()
	if binPath == "" {
		return fmt.Errorf("llama-server introuvable dans moteur/")
	}

	// Log config GPU pour le modèle secondaire
	gpuLayers, threads, batchSize := detectOptimalGPUConfig()
	if gpuLayers > 0 {
		progressFn(logOK("AI-FALLBACK", fmt.Sprintf("GPU détecté pour %s — config : -ngl %d | threads=%d | batch=%d (CUDA activé)", modelName, gpuLayers, threads, batchSize)))
	} else {
		progressFn(logWarn("AI-FALLBACK", fmt.Sprintf("Aucun GPU détecté pour %s — mode CPU | threads=%d | batch=%d (génération plus lente)", modelName, threads, batchSize)))
	}

	// Redémarrer avec le nouveau modèle
	progressFn(logInfo("AI-FALLBACK", fmt.Sprintf("Démarrage llama-server avec %s...", modelName)))
	if err := startLlamaServer(binPath, modelPath(mDir, modelName)); err != nil {
		return fmt.Errorf("démarrage llama-server avec %s: %w", modelName, err)
	}

	// Attendre que le serveur soit prêt — avec logs de progression
	deadline := time.Now().Add(startupTimeout)
	lastLog := time.Now()
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		if c.isRunning() {
			progressFn(logOK("AI-FALLBACK", fmt.Sprintf("llama-server actif avec %s — prêt pour génération", modelName)))
			return nil
		}
		// Log progression toutes les 10s
		if time.Since(lastLog) >= 10*time.Second {
			elapsed := int(time.Since(deadline.Add(-startupTimeout)).Seconds())
			progressFn(cGrey(fmt.Sprintf("[AI-FALLBACK]    Chargement %s en mémoire... %ds / %ds", modelName, elapsed, int(startupTimeout.Seconds()))))
			lastLog = time.Now()
		}
	}
	return fmt.Errorf("llama-server avec %s ne répond pas après %v", modelName, startupTimeout)
}

// ─── Demarrage llama-server ──────────────────────────────────────────────────

func startLlamaServer(binPath, ggufPath string) error {
	return startLlamaServerWithProfile(binPath, ggufPath, nil)
}

func startLlamaServerWithProfile(binPath, ggufPath string, profile *MachineProfile) error {
	// Analyse dynamique du matériel si pas de profil fourni
	if profile == nil {
		profile = analyseMachine(nil)
	}

	args := []string{
		"--model", ggufPath,
		"--port", llamaPort,
		"--host", "127.0.0.1",
		"-ngl", fmt.Sprintf("%d", profile.GPULayers), // couches GPU : 0=CPU / 99=tout sur VRAM
		"-c", fmt.Sprintf("%d", profile.CtxSize), // context window adapté à la VRAM/RAM dispo
		"-n", fmt.Sprintf("%d", profile.MaxOutputTok), // max output tokens
		"--temp", "0.1", // temperature basse pour JSON déterministe
		"--repeat-penalty", "1.1",
		"--threads", fmt.Sprintf("%d", profile.CPUThreads), // threads CPU (cœurs physiques réels)
		"--threads-batch", fmt.Sprintf("%d", profile.CPUThreads), // batch processing
		"--batch-size", fmt.Sprintf("%d", profile.BatchSize), // batch adapté VRAM/RAM
	}
	// mmap : désactivé seulement si RAM serrée (prévient les swaps imprévisibles)
	if !profile.UseMmap {
		args = append(args, "--no-mmap")
	}
	cmd := exec.Command(binPath, args...)

	// Repertoire de travail = moteur/ — indispensable pour que Windows
	// trouve les DLLs CUDA (cudart64_12.dll, cublas64_12.dll...) a cote du .exe
	cmd.Dir = filepath.Dir(binPath)

	// Rediriger stdout+stderr vers moteur/llama-server.log pour diagnostics
	logPath := filepath.Join(filepath.Dir(binPath), "llama-server.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err == nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		// logFile sera ferme par le GC — llama-server garde le handle ouvert
	}

	return cmd.Start()
}

// MachineProfile contient l'analyse complète du matériel disponible.
// Calculé une seule fois au démarrage via analyseMachine().
type MachineProfile struct {
	// CPU
	LogicalCores  int    // runtime.NumCPU() — cœurs logiques totaux
	PhysicalCores int    // cœurs physiques (sans HyperThreading)
	CPUName       string // ex: "Intel Core i7-12700K"

	// RAM
	TotalRAMGB float64 // RAM système totale en Go
	AvailRAMGB float64 // RAM disponible au moment de l'analyse

	// GPU
	HasGPU      bool
	GPUName     string  // ex: "NVIDIA GeForce RTX 3080"
	VRAMTotalGB float64 // VRAM totale du GPU
	VRAMFreeGB  float64 // VRAM libre au moment de l'analyse

	// Config dérivée pour llama.cpp
	GPULayers    int  // 0=CPU only, 99=all layers on GPU
	CPUThreads   int  // threads pour --threads et --threads-batch
	BatchSize    int  // --batch-size
	UseKVCache   bool // true si VRAM suffisante pour cache KV
	CtxSize      int  // --ctx-size (32768 si VRAM>=8Go, 16384 sinon)
	MaxOutputTok int  // -n
	UseMmap      bool // --no-mmap si RAM serrée
}

// analyseMachine effectue une analyse complète du matériel et calcule
// les paramètres optimaux pour llama.cpp sur cette machine spécifique.
// Cette fonction est appelée une seule fois au démarrage et son résultat
// est réutilisé pour tous les appels à startLlamaServer.
func analyseMachine(progressFn func(string)) *MachineProfile {
	p := &MachineProfile{}

	// ── 1. CPU ───────────────────────────────────────────────────────────────
	p.LogicalCores = runtime.NumCPU()
	p.PhysicalCores = detectPhysicalCores()
	p.CPUName = detectCPUName()

	// ── 2. RAM système ───────────────────────────────────────────────────────
	p.TotalRAMGB, p.AvailRAMGB = detectSystemRAM()

	// ── 3. GPU ───────────────────────────────────────────────────────────────
	p.HasGPU, p.GPUName, p.VRAMTotalGB, p.VRAMFreeGB = detectGPUDetails()

	// ── 4. Calcul des paramètres optimaux ────────────────────────────────────
	p.computeOptimalConfig()

	// ── 5. Log du profil machine ─────────────────────────────────────────────
	if progressFn != nil {
		progressFn(logDetail("AI", fmt.Sprintf(
			"CPU : %s  |  %d cœurs logiques / %d physiques",
			p.CPUName, p.LogicalCores, p.PhysicalCores)))
		progressFn(logDetail("AI", fmt.Sprintf(
			"RAM : %.1f Go total  |  %.1f Go disponible",
			p.TotalRAMGB, p.AvailRAMGB)))
		if p.HasGPU {
			progressFn(logOK("AI", fmt.Sprintf(
				"GPU : %s  |  VRAM %.1f Go total / %.1f Go libre (CUDA activé)",
				p.GPUName, p.VRAMTotalGB, p.VRAMFreeGB)))
		} else {
			progressFn(logWarn("AI", "GPU : aucun GPU NVIDIA détecté — mode CPU uniquement"))
		}
		progressFn(logDetail("AI", fmt.Sprintf(
			"Config llama.cpp → -ngl %d | threads=%d | batch=%d | ctx=%d | max_tokens=%d | mmap=%v",
			p.GPULayers, p.CPUThreads, p.BatchSize, p.CtxSize, p.MaxOutputTok, p.UseMmap)))
	}

	return p
}

// computeOptimalConfig calcule les paramètres llama.cpp optimaux
// en fonction du profil matériel réel de la machine.
func (p *MachineProfile) computeOptimalConfig() {
	// ── Threads CPU ──────────────────────────────────────────────────────────
	// Référence : benchmark llama.cpp — les cœurs physiques sont plus efficaces
	// que les hyperthreads pour l'inférence LLM (opérations mémoire-bound).
	if p.PhysicalCores > 0 {
		// Utiliser tous les cœurs physiques, plafonné à 16
		// Au-delà, la bande passante mémoire devient le goulot d'étranglement
		p.CPUThreads = p.PhysicalCores
		if p.CPUThreads > 16 {
			p.CPUThreads = 16
		}
	} else {
		// Fallback si détection physique échoue : 75% des logiques
		p.CPUThreads = (p.LogicalCores * 3) / 4
		if p.CPUThreads < 2 {
			p.CPUThreads = 2
		}
		if p.CPUThreads > 16 {
			p.CPUThreads = 16
		}
	}

	// ── Mode GPU ─────────────────────────────────────────────────────────────
	if p.HasGPU {
		p.GPULayers = 99 // toutes couches sur VRAM

		// Batch size selon la VRAM disponible
		// Plus la VRAM est grande, plus le batch peut être grand (meilleur débit)
		switch {
		case p.VRAMFreeGB >= 16:
			p.BatchSize = 2048
		case p.VRAMFreeGB >= 10:
			p.BatchSize = 1024
		case p.VRAMFreeGB >= 6:
			p.BatchSize = 512
		default:
			p.BatchSize = 256 // VRAM serrée (<6 Go) — batch conservateur
		}

		// Avec GPU, réduire les threads CPU (le GPU fait le décodage)
		// Garder assez pour le prefill du prompt (~20k tokens)
		if p.CPUThreads > 8 {
			p.CPUThreads = 8
		}

		// Context window selon VRAM disponible
		// Le cache KV consomme ~2 * ctx * layers * head_size * 2 bytes
		// Pour Qwen 14B Q4 : ctx=32768 tient dans 7+ Go VRAM (le modèle spill en RAM)
		// IMPORTANT : le seuil passe de 8 Go à 6 Go pour couvrir RTX 4060 (7.2 Go libre)
		if p.VRAMFreeGB >= 6 {
			p.CtxSize = 32768
		} else if p.VRAMFreeGB >= 3 {
			p.CtxSize = 16384
		} else {
			p.CtxSize = 8192 // VRAM très serrée
		}

	} else {
		// ── Mode CPU pur ─────────────────────────────────────────────────────
		p.GPULayers = 0

		// Batch size selon RAM disponible
		switch {
		case p.AvailRAMGB >= 16:
			p.BatchSize = 512
		case p.AvailRAMGB >= 8:
			p.BatchSize = 256
		default:
			p.BatchSize = 128 // RAM serrée
		}

		// Context window selon RAM disponible
		// Pour Mistral 7B en CPU : modèle ~4.1 Go + KV cache
		if p.AvailRAMGB >= 12 {
			p.CtxSize = 32768
		} else if p.AvailRAMGB >= 8 {
			p.CtxSize = 16384
		} else {
			p.CtxSize = 8192
		}
	}

	// ── Max output tokens ────────────────────────────────────────────────────
	// Limité par le context window : max_output < ctx_size
	p.MaxOutputTok = p.CtxSize / 2 // moitié du contexte pour la sortie
	if p.MaxOutputTok > 16384 {
		p.MaxOutputTok = 16384 // cap absolu
	}
	if p.MaxOutputTok < 4096 {
		p.MaxOutputTok = 4096 // minimum pour un rapport utile
	}

	// ── mmap ─────────────────────────────────────────────────────────────────
	// mmap = accès lazy au modèle depuis le disque → démarrage plus rapide
	// mais si la RAM est serrée, le kernel peut swap → ralentissements imprévisibles
	// On désactive mmap seulement si la RAM disponible est <2x la taille du modèle estimée
	modelEstimatedGB := 5.0 // Mistral 7B Q4 ≈ 4.1 Go, Qwen 14B ≈ 8.7 Go — valeur conservative
	p.UseMmap = p.AvailRAMGB > modelEstimatedGB*2
}

// ── Détection bas niveau ────────────────────────────────────────────────────

// detectPhysicalCores retourne le nombre de cœurs physiques (sans hyperthreading).
func detectPhysicalCores() int {
	var out []byte
	var err error

	switch runtime.GOOS {
	case "windows":
		// WMIC : retourne le nombre de cœurs physiques par socket
		out, err = exec.Command("wmic", "cpu", "get", "NumberOfCores", "/value").Output()
		if err == nil {
			var total int64
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "NumberOfCores=") {
					val := strings.TrimPrefix(line, "NumberOfCores=")
					if n, e := parseInt(val); e == nil && n > 0 {
						total += n
					}
				}
			}
			if total > 0 {
				return int(total)
			}
		}
	case "linux":
		// /proc/cpuinfo : compter les "core id" uniques par socket physique
		out, err = os.ReadFile("/proc/cpuinfo")
		if err == nil {
			coreSet := map[string]bool{}
			physicalID := ""
			for _, line := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(line, "physical id") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						physicalID = strings.TrimSpace(parts[1])
					}
				}
				if strings.HasPrefix(line, "core id") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						coreSet[physicalID+":"+strings.TrimSpace(parts[1])] = true
					}
				}
			}
			if len(coreSet) > 0 {
				return len(coreSet)
			}
		}
	}

	// Fallback : moitié des logiques (hypothèse HyperThreading)
	n := runtime.NumCPU()
	if n > 1 {
		return n / 2
	}
	return 1
}

// detectCPUName retourne le nom du processeur.
func detectCPUName() string {
	var out []byte
	var err error

	switch runtime.GOOS {
	case "windows":
		out, err = exec.Command("wmic", "cpu", "get", "Name", "/value").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "Name=") {
					name := strings.TrimPrefix(line, "Name=")
					if name != "" {
						return name
					}
				}
			}
		}
	case "linux":
		if data, e := os.ReadFile("/proc/cpuinfo"); e == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "model name") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						return strings.TrimSpace(parts[1])
					}
				}
			}
		}
	}
	return fmt.Sprintf("%d cœurs logiques", runtime.NumCPU())
}

// detectSystemRAM retourne (totalGB, availGB) de la RAM système.
func detectSystemRAM() (total, avail float64) {
	const GB = 1024 * 1024 * 1024

	switch runtime.GOOS {
	case "windows":
		// TotalVisibleMemorySize et FreePhysicalMemory sont en Ko
		if out, err := exec.Command("wmic", "OS", "get",
			"TotalVisibleMemorySize,FreePhysicalMemory", "/value").Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "TotalVisibleMemorySize=") {
					if v, e := parseInt(strings.TrimPrefix(line, "TotalVisibleMemorySize=")); e == nil {
						total = float64(v*1024) / float64(GB)
					}
				}
				if strings.HasPrefix(line, "FreePhysicalMemory=") {
					if v, e := parseInt(strings.TrimPrefix(line, "FreePhysicalMemory=")); e == nil {
						avail = float64(v*1024) / float64(GB)
					}
				}
			}
		}
	case "linux":
		if data, err := os.ReadFile("/proc/meminfo"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 2 {
					continue
				}
				val, _ := parseInt(fields[1]) // kB
				switch fields[0] {
				case "MemTotal:":
					total = float64(val*1024) / float64(GB)
				case "MemAvailable:":
					avail = float64(val*1024) / float64(GB)
				}
			}
		}
	}

	// Valeurs de sécurité si détection échoue
	if total == 0 {
		total = 8.0
	}
	if avail == 0 {
		avail = total / 2
	}
	return total, avail
}

// detectGPUDetails retourne (hasGPU, name, vramTotalGB, vramFreeGB).
// Utilise nvidia-smi avec une query précise pour obtenir VRAM exacte.
func detectGPUDetails() (hasGPU bool, name string, vramTotal, vramFree float64) {
	const MB = 1024 * 1024

	// nvidia-smi : query précis (nom + VRAM total + VRAM libre)
	out, err := exec.Command("nvidia-smi",
		"--query-gpu=name,memory.total,memory.free",
		"--format=csv,noheader,nounits").Output()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) > 0 {
			parts := strings.SplitN(lines[0], ",", 3)
			if len(parts) == 3 {
				gpuName := strings.TrimSpace(parts[0])
				totalMB, e1 := parseInt(strings.TrimSpace(parts[1]))
				freeMB, e2 := parseInt(strings.TrimSpace(parts[2]))
				if gpuName != "" && e1 == nil && e2 == nil {
					return true, gpuName,
						float64(totalMB) / 1024.0,
						float64(freeMB) / 1024.0
				}
			}
		}
	}

	// Fallback Windows : DLLs CUDA présentes dans moteur/ (GPU sans nvidia-smi dans PATH)
	if runtime.GOOS == "windows" {
		mDir := moteurDir()
		if entries, e := os.ReadDir(mDir); e == nil {
			for _, entry := range entries {
				if strings.HasPrefix(strings.ToLower(entry.Name()), "cudart64_") &&
					strings.HasSuffix(strings.ToLower(entry.Name()), ".dll") {
					// GPU présent mais nvidia-smi inaccessible — VRAM inconnue, on suppose 8 Go
					return true, "NVIDIA GPU (VRAM inconnue)", 8.0, 6.0
				}
			}
		}
	}

	// Fallback Linux : /dev/nvidia0
	if runtime.GOOS == "linux" {
		if _, e := os.Stat("/dev/nvidia0"); e == nil {
			return true, "NVIDIA GPU (VRAM inconnue)", 8.0, 6.0
		}
	}

	return false, "", 0, 0
}

// parseInt parse un entier depuis une string, en ignorant les espaces.
func parseInt(s string) (int64, error) {
	s = strings.TrimSpace(s)
	var n int64
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// detectOptimalGPUConfig est conservé pour compatibilité — délègue à analyseMachine.
// Utilisé par les endroits qui logguent sans avoir accès à un profil complet.
func detectOptimalGPUConfig() (gpuLayers int, threads int, batchSize int) {
	p := analyseMachine(nil) // sans logs (utilisé pour affichage uniquement)
	return p.GPULayers, p.CPUThreads, p.BatchSize
}

// ─── Telechargement llama.cpp ────────────────────────────────────────────────

func downloadLlamaCpp(mDir string, progressFn func(string)) (string, error) {
	os.MkdirAll(mDir, 0755)
	switch runtime.GOOS {
	case "windows":
		return downloadLlamaCppWindows(mDir, progressFn)
	case "linux":
		return downloadLlamaCppLinux(mDir, progressFn)
	default:
		return "", fmt.Errorf("OS non supporte: %s", runtime.GOOS)
	}
}

func downloadLlamaCppWindows(mDir string, progressFn func(string)) (string, error) {
	destExe := filepath.Join(mDir, "llama-server.exe")
	if _, err := os.Stat(destExe); err == nil {
		return destExe, nil
	}
	zipPath := filepath.Join(mDir, "llama-cpp.zip")

	// Tentative 1 : CUDA (binaire principal)
	progressFn("[AI] Telechargement llama.cpp b8185 (GPU NVIDIA + CPU) depuis GitHub...")
	cudaOk := false
	if err := downloadFile(llamaCppWindowsMain, zipPath, progressFn); err == nil {
		if exe, err := extractLlamaServer(zipPath, mDir, destExe); err == nil {
			// Telecharger aussi les DLLs CUDA runtime (cudart64, cublas64...)
			progressFn("[AI] Telechargement DLLs CUDA runtime...")
			cudartZip := filepath.Join(mDir, "cudart.zip")
			if err2 := downloadFile(llamaCppWindowsCUDArt, cudartZip, progressFn); err2 == nil {
				extractCudaRt(cudartZip, mDir)
			}
			progressFn("[AI] llama.cpp CUDA installe avec succes.")
			cudaOk = true
			_ = cudaOk
			return exe, nil
		}
		os.Remove(zipPath)
	}

	// Fallback : CPU
	progressFn("[AI] CUDA build indisponible — fallback CPU...")
	if err := downloadFile(llamaCppWindowsCPU, zipPath, progressFn); err != nil {
		return "", fmt.Errorf("telechargement llama.cpp: %w", err)
	}
	return extractLlamaServer(zipPath, mDir, destExe)
}

// extractCudaRt extrait les DLLs CUDA runtime dans mDir.
func extractCudaRt(zipPath, mDir string) {
	extractDir := filepath.Join(mDir, "cudart-extract")
	os.MkdirAll(extractDir, 0755)
	defer os.RemoveAll(extractDir)
	exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`Expand-Archive -Path '%s' -DestinationPath '%s' -Force`, zipPath, extractDir)).Run()
	os.Remove(zipPath)
	// Copier toutes les DLL dans mDir
	filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && strings.ToLower(filepath.Ext(path)) == ".dll" {
			dst := filepath.Join(mDir, filepath.Base(path))
			if data, e := os.ReadFile(path); e == nil {
				os.WriteFile(dst, data, 0755)
			}
		}
		return nil
	})
}

func downloadLlamaCppLinux(mDir string, progressFn func(string)) (string, error) {
	destBin := filepath.Join(mDir, "llama-server")
	if _, err := os.Stat(destBin); err == nil {
		return destBin, nil
	}
	zipPath := filepath.Join(mDir, "llama-cpp.zip")
	progressFn("[AI] Telechargement llama.cpp Linux...")
	if err := downloadFile(llamaCppLinux, zipPath, progressFn); err != nil {
		return "", err
	}
	return extractLlamaServer(zipPath, mDir, destBin)
}

func extractLlamaServer(zipPath, mDir, destExe string) (string, error) {
	extractDir := filepath.Join(mDir, "llama-extract")
	os.MkdirAll(extractDir, 0755)
	defer os.RemoveAll(extractDir)

	if runtime.GOOS == "windows" {
		err := exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf(`Expand-Archive -Path '%s' -DestinationPath '%s' -Force`, zipPath, extractDir)).Run()
		if err != nil {
			return "", fmt.Errorf("extraction zip: %w", err)
		}
	} else {
		if err := exec.Command("unzip", "-o", zipPath, "-d", extractDir).Run(); err != nil {
			return "", fmt.Errorf("extraction zip: %w", err)
		}
	}
	os.Remove(zipPath)

	serverName := "llama-server"
	if runtime.GOOS == "windows" {
		serverName = "llama-server.exe"
	}
	var found string
	filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && strings.EqualFold(filepath.Base(path), serverName) {
			found = path
		}
		return nil
	})
	if found == "" {
		return "", fmt.Errorf("llama-server introuvable dans le zip")
	}

	// Copier llama-server + toutes les DLL CUDA necessaires
	srcDir := filepath.Dir(found)
	entries, _ := os.ReadDir(srcDir)
	for _, e := range entries {
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".dll" || ext == ".so" || strings.EqualFold(e.Name(), serverName) {
			src := filepath.Join(srcDir, e.Name())
			dst := filepath.Join(mDir, e.Name())
			if data, err := os.ReadFile(src); err == nil {
				os.WriteFile(dst, data, 0755)
			}
		}
	}

	if _, err := os.Stat(destExe); err != nil {
		return "", fmt.Errorf("llama-server non copie vers %s", destExe)
	}
	os.Chmod(destExe, 0755)
	return destExe, nil
}

// ─── Telechargement modele GGUF ──────────────────────────────────────────────

func downloadModel(mDir, modelName string, progressFn func(string)) error {
	dest := modelPath(mDir, modelName)
	if modelPresent(mDir, modelName) {
		return nil
	}

	if info, ok := KnownModels[modelName]; ok {
		if info.ManualInstall {
			return fmt.Errorf("'%s' nécessite une installation manuelle — voir %s", info.DisplayName, info.SourceURL)
		}
		if info.DownloadURL != "" {
			progressFn(fmt.Sprintf("[AI] Téléchargement %s (%.1f Go)...", info.DisplayName, info.SizeGB))
			return downloadFile(info.DownloadURL, dest, progressFn)
		}
	}

	switch modelName {
	case FallbackModel:
		progressFn("[AI] Téléchargement Qwen2.5 14B Q4_K_M (~8.7 Go)...")
		return downloadFile(qwenGGUFURL, dest, progressFn)
	default:
		progressFn("[AI] Téléchargement Mistral 7B Q4_K_M (~4.1 Go)...")
		return downloadFile(mistralGGUFURL, dest, progressFn)
	}
}

// FallbackModelPresent indique si le modèle secondaire Qwen est disponible dans moteur/models/.
func FallbackModelPresent() bool {
	return modelPresent(moteurDir(), FallbackModel)
}

// PrimusModelPresent indique si le modèle Primus 8B est disponible dans moteur/models/.
func PrimusModelPresent() bool {
	return modelPresent(moteurDir(), PrimusModel)
}

// EnsureFallbackModel télécharge Qwen2.5-14B en arrière-plan si absent.
// A appeler de manière non-bloquante (goroutine) après une génération réussie avec Mistral.
func EnsureFallbackModel(progressFn func(string)) {
	mDir := moteurDir()
	if modelPresent(mDir, FallbackModel) {
		return
	}
	progressFn(logWarn("AI-FALLBACK", "Téléchargement moteur secondaire Qwen2.5-14B en arrière-plan..."))
	if err := downloadModel(mDir, FallbackModel, progressFn); err != nil {
		progressFn(logWarn("AI-FALLBACK", fmt.Sprintf("Téléchargement Qwen échoué (non bloquant): %v", err)))
	} else {
		progressFn(logOK("AI-FALLBACK", "Qwen2.5-14B disponible dans moteur/models/ — actif au prochain besoin"))
	}
}

// EnsurePrimusModel télécharge Primus 8B depuis tensorblock/Llama-Primus-Merged-GGUF.
// Repo public TensorBlock — aucun token requis, téléchargement direct.
func EnsurePrimusModel(progressFn func(string)) {
	mDir := moteurDir()
	if modelPresent(mDir, PrimusModel) {
		return
	}
	progressFn(logInfo("AI-PRIMUS", "Téléchargement Primus 8B Q4_K_M depuis tensorblock/Llama-Primus-Merged-GGUF (~4.9 Go)..."))
	progressFn(logInfo("AI-PRIMUS", "Repo public TensorBlock — aucun token requis."))
	dest := modelPath(mDir, PrimusModel)
	if err := downloadResumable(primusGGUFURL, dest, progressFn); err != nil {
		progressFn(logErr("AI-PRIMUS", fmt.Sprintf("Téléchargement Primus 8B échoué: %v", err)))
		return
	}
	progressFn(logOK("AI-PRIMUS", fmt.Sprintf("Primus 8B téléchargé → moteur/models/%s", PrimusModel)))
}

// EnsureFoundationSecModel télécharge Foundation-Sec-8B Instruct Q4_K_M depuis mradermacher.
// Modèle Cisco Apache 2.0 — public, aucun token requis.
// C'est le seul modèle du projet fine-tunable via Unsloth QLoRA.
func EnsureFoundationSecModel(progressFn func(string)) {
	mDir := moteurDir()
	if modelPresent(mDir, FoundationSecModel) {
		progressFn(logOK("AI-FOUNDATION", fmt.Sprintf("Foundation-Sec-8B déjà présent : %s", FoundationSecModel)))
		return
	}
	progressFn(logInfo("AI-FOUNDATION", "Téléchargement Foundation-Sec-8B Instruct Q4_K_M (~4.9 Go)..."))
	progressFn(logInfo("AI-FOUNDATION", "Source : mradermacher/Foundation-Sec-8B-Instruct-GGUF (Cisco, Apache 2.0)"))
	progressFn(logInfo("AI-FOUNDATION", "Aucun token Hugging Face requis — repo public."))
	dest := modelPath(mDir, FoundationSecModel)
	if err := downloadResumable(foundationSecGGUFURL, dest, progressFn); err != nil {
		progressFn(logErr("AI-FOUNDATION", fmt.Sprintf("Téléchargement Foundation-Sec-8B échoué: %v", err)))
		return
	}
	progressFn(logOK("AI-FOUNDATION", fmt.Sprintf("Foundation-Sec-8B téléchargé → moteur/models/%s", FoundationSecModel)))
	progressFn(logOK("AI-FOUNDATION", "Modèle prêt — sera utilisé en priorité pour les analyses cybersécurité"))
	progressFn(logOK("AI-FOUNDATION", "Fine-tuning disponible via Unsloth QLoRA avec le dataset analyses.db"))
}

// EnsureModelByURL télécharge un modèle GGUF quelconque depuis une URL directe.
// Utilisé pour les modèles du catalogue qui n'ont pas de fonction dédiée.
func EnsureModelByURL(filename, url string, progressFn func(string)) {
	mDir := moteurDir()
	if modelPresent(mDir, filename) {
		progressFn(logOK("AI-DOWNLOAD", fmt.Sprintf("%s déjà présent", filename)))
		return
	}
	progressFn(logInfo("AI-DOWNLOAD", fmt.Sprintf("Téléchargement %s...", filename)))
	progressFn(logInfo("AI-DOWNLOAD", fmt.Sprintf("Source : %s", url)))
	dest := modelPath(mDir, filename)
	if err := downloadResumable(url, dest, progressFn); err != nil {
		progressFn(logErr("AI-DOWNLOAD", fmt.Sprintf("Téléchargement %s échoué: %v", filename, err)))
		return
	}
	progressFn(logOK("AI-DOWNLOAD", fmt.Sprintf("%s téléchargé → moteur/models/%s", filename, filename)))
}

func (c *Client) Generate(prompt string, progressFn func(string)) (string, error) {
	// Analyse dynamique pour max_tokens adapté à la machine
	profile := analyseMachine(nil)
	maxTokens := profile.MaxOutputTok

	// ── Garde-fou : troncature du prompt si trop grand ───────────────────────
	// Règle empirique llama.cpp : 1 token ≈ 3.5 caractères pour du JSON/français.
	// On réserve 50% du contexte pour la sortie, et on laisse une marge de sécurité
	// de 10% pour les tokens spéciaux et le system prompt interne du modèle.
	maxPromptChars := int(float64(profile.CtxSize) * 0.40 * 3.5) // 40% du ctx × 3.5 chars/token
	if len(prompt) > maxPromptChars {
		if progressFn != nil {
			progressFn(logWarn("AI", fmt.Sprintf(
				"Prompt trop long (%d chars > %d max) — troncature automatique des données sandbox",
				len(prompt), maxPromptChars,
			)))
		}
		// Tronquer proprement : garder l'en-tête du prompt (instructions) + fin (schéma JSON)
		// La partie centrale (données sandbox JSON) est la moins critique à tronquer
		keepHead := maxPromptChars * 30 / 100 // 30% = instructions + début données
		keepTail := maxPromptChars * 30 / 100 // 30% = schéma JSON de sortie
		if keepHead+keepTail < len(prompt) {
			prompt = prompt[:keepHead] + "\n\n[... données tronquées pour respecter la fenêtre de contexte — analyser les éléments disponibles ...]\n\n" + prompt[len(prompt)-keepTail:]
		} else {
			prompt = prompt[:maxPromptChars]
		}
		if progressFn != nil {
			progressFn(logInfo("AI", fmt.Sprintf("Prompt après troncature : %d chars", len(prompt))))
		}
	}

	if progressFn != nil {
		progressFn(cHeader("AI", "GÉNÉRATION IA  —  llama.cpp"))
		progressFn(logDetail("AI", fmt.Sprintf("Modèle   : %s", c.model)))
		progressFn(logDetail("AI", fmt.Sprintf("Endpoint : %s/v1/chat/completions", c.baseURL)))
		progressFn(logDetail("AI", fmt.Sprintf("Tokens   : max_output=%d | ctx=%d | temp=0.1", maxTokens, profile.CtxSize)))
		progressFn(logDetail("AI", fmt.Sprintf("Prompt   : %d caractères envoyés", len(prompt))))
		progressFn(logInfo("AI", "Envoi du prompt au moteur local llama-server..."))
	}

	reqBody := map[string]interface{}{
		"model": "local",
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"max_tokens":     maxTokens,
		"temperature":    0.1,
		"top_p":          0.9,
		"repeat_penalty": 1.1,
		"stream":         false,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	httpStart := time.Now()
	resp, err := c.httpGen.Post(c.baseURL+"/v1/chat/completions", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("appel llama-server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("llama-server HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("parsing reponse llama-server: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("llama-server erreur: %s", result.Error.Message)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("llama-server: aucune reponse retournee")
	}

	response := strings.TrimSpace(result.Choices[0].Message.Content)
	httpElapsed := time.Since(httpStart)

	if progressFn != nil {
		// Estimation tokens/s : 1 token ≈ 3.5 chars (JSON/français)
		estimToks := float64(len(response)) / 3.5
		secs := httpElapsed.Seconds()
		tokPerSec := 0.0
		if secs > 0 {
			tokPerSec = estimToks / secs
		}
		progressFn(logOK("AI", fmt.Sprintf(
			"✓ Génération terminée — %d caractères reçus (modèle: %s)",
			len(response), c.model)))
		progressFn(cGrey(fmt.Sprintf(
			"[AI]    ↳ Durée: %s | Vitesse: ~%.1f tok/s | Tokens estimés: ~%d",
			httpElapsed.Round(time.Second), tokPerSec, int(estimToks))))
		preview := response
		if len(preview) > 150 {
			preview = preview[:150] + "..."
		}
		progressFn(cGrey(fmt.Sprintf("[AI]    ↳ Début réponse : %s", preview)))
	}
	return response, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// downloadFile telecharge url -> dest.
// Utilise downloadResumable qui supporte la reprise sur coupure reseau.
func downloadFile(url, dest string, progressFn func(string)) error {
	return downloadResumable(url, dest, progressFn)
}

// downloadResumable telecharge url -> dest avec reprise automatique (Range header).
// Si dest existe partiellement, reprend depuis l'offset exact.
// Retente jusqu'a maxRetries fois en cas de coupure — ideal pour gros fichiers (~4 Go).
// Le client HTTP préserve l'en-tête Authorization sur les redirections cross-domain
// (nécessaire pour HuggingFace Xet CDN).
func downloadResumable(url, dest string, progressFn func(string)) error {
	const maxRetries = 20
	const retryWait = 5 * time.Second

	// Client HTTP qui préserve Authorization sur toutes les redirections
	// (comportement par défaut de Go : supprimer Auth sur changement de domaine)
	httpClient := &http.Client{
		Timeout: 0,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 15 {
				return fmt.Errorf("trop de redirections (>15)")
			}
			// Préserver Authorization si présent dans la première requête
			if len(via) > 0 {
				if auth := via[0].Header.Get("Authorization"); auth != "" {
					req.Header.Set("Authorization", auth)
				}
				if ua := via[0].Header.Get("User-Agent"); ua != "" {
					req.Header.Set("User-Agent", ua)
				}
			}
			return nil
		},
	}

	// Taille totale via HEAD
	var total int64
	if resp, err := httpClient.Head(url); err == nil {
		total = resp.ContentLength
		resp.Body.Close()
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			progressFn(fmt.Sprintf("[AI] Reprise du telechargement (tentative %d/%d)...", attempt+1, maxRetries))
			time.Sleep(retryWait)
		}

		// Offset = taille du fichier partiel deja present
		var offset int64
		if info, err := os.Stat(dest); err == nil {
			offset = info.Size()
		}
		if total > 0 && offset >= total {
			return nil // deja complet
		}
		if offset > 0 && attempt == 0 {
			progressFn(fmt.Sprintf("[AI] Fichier partiel detecte (%s) — reprise...", formatBytes(offset)))
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return err
		}
		if offset > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; rf-sandbox-go/2.0)")
		req.Header.Set("Accept", "*/*")
		// Token HuggingFace pour les modèles gated (Primus, Llama, etc.)
		if hfToken != "" {
			req.Header.Set("Authorization", "Bearer "+hfToken)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			progressFn(fmt.Sprintf("[AI] Erreur connexion: %v", err))
			continue
		}

		if resp.StatusCode != 200 && resp.StatusCode != 206 {
			resp.Body.Close()
			if resp.StatusCode == 416 {
				// Range Not Satisfiable = fichier deja complet cote serveur
				return nil
			}
			return fmt.Errorf("HTTP %d : %s", resp.StatusCode, url)
		}

		// Mise a jour taille totale
		if total == 0 && resp.ContentLength > 0 {
			if resp.StatusCode == 206 {
				total = offset + resp.ContentLength
			} else {
				total = resp.ContentLength
			}
		}

		// Ouvrir en append
		f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			resp.Body.Close()
			return fmt.Errorf("ouverture fichier: %w", err)
		}

		buf := make([]byte, 256*1024)
		lastLog := time.Now()
		downloaded := offset
		var readErr error

		for {
			var n int
			n, readErr = resp.Body.Read(buf)
			if n > 0 {
				if _, werr := f.Write(buf[:n]); werr != nil {
					f.Close()
					resp.Body.Close()
					return fmt.Errorf("ecriture disque: %w", werr)
				}
				downloaded += int64(n)
				if time.Since(lastLog) >= 5*time.Second {
					if total > 0 {
						progressFn(fmt.Sprintf("[AI] %.1f%% (%s / %s)",
							float64(downloaded)/float64(total)*100,
							formatBytes(downloaded), formatBytes(total)))
					} else {
						progressFn(fmt.Sprintf("[AI] Telecharge : %s", formatBytes(downloaded)))
					}
					lastLog = time.Now()
				}
			}
			if readErr != nil {
				break
			}
		}
		f.Close()
		resp.Body.Close()

		if readErr == io.EOF {
			// Verifier que le fichier est complet
			if total > 0 {
				if info, err := os.Stat(dest); err == nil && info.Size() >= total {
					return nil
				}
				// Taille incorrecte — reessayer
				progressFn(fmt.Sprintf("[AI] Telechargement incomplet (%s / %s) — nouvelle tentative...",
					formatBytes(func() int64 {
						i, _ := os.Stat(dest)
						if i != nil {
							return i.Size()
						}
						return 0
					}()),
					formatBytes(total)))
				continue
			}
			return nil // taille inconnue, on suppose OK
		}

		// Erreur reseau — on reessaie depuis l'offset actuel
		progressFn(fmt.Sprintf("[AI] Coupure reseau: %v — nouvelle tentative...", readErr))
	}

	return fmt.Errorf("telechargement echoue apres %d tentatives", maxRetries)
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// SelectBestModel retourne le modèle le plus puissant disponible sur disque.
// Priorité : Foundation-Sec-8B (cyber spécialisé + fine-tunable) > Qwen 14B (plus grand) >
//
//	Primus 8B (cyber Trend Micro) > Mistral 7B (généraliste)
//
// isValidGGUF vérifie que le fichier commence par le magic GGUF (0x47 0x47 0x55 0x46).
// Détecte les téléchargements incomplets, les fichiers HTML d'erreur, etc.
func isValidGGUF(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	magic := make([]byte, 4)
	n, err := f.Read(magic)
	if err != nil || n < 4 {
		return false
	}
	// GGUF magic: 0x47 0x47 0x55 0x46 ("GGUF")
	if magic[0] == 0x47 && magic[1] == 0x47 && magic[2] == 0x55 && magic[3] == 0x46 {
		return true
	}
	// GGML legacy (v1/v2/v3)
	if magic[0] == 0x67 && magic[1] == 0x6A && magic[2] == 0x74 {
		return true
	}
	return false
}

func SelectBestModel() string {
	mDir := moteurDir()
	// Ordre de priorité explicite — le premier présent ET valide sur disque gagne.
	// Note: GraniteCodeModel exclu ici — utilisé en M1 pipeline chaîné uniquement.
	priority := []string{
		FoundationSecModel, // Cisco cyber LLM, fine-tunable — priorité max si présent
		LlamaForensicModel, // Meta Llama 3.1 8B — base forensic fine-tunable, contexte 128k
		FallbackModel,      // Qwen 14B — plus grand, meilleur JSON structuré
		PrimusModel,        // Trend Micro cyber
		DefaultModel,       // Mistral 7B — fallback généraliste
	}
	for _, m := range priority {
		p := modelPath(mDir, m)
		info, statErr := os.Stat(p)
		if statErr != nil {
			continue // absent
		}
		if info.Size() < 100*1024*1024 {
			log.Printf("[AI] ⚠ %s — taille suspecte (%d Mo), téléchargement incomplet ?", m, info.Size()>>20)
			continue
		}
		if !isValidGGUF(p) {
			log.Printf("[AI] ✗ %s — magic GGUF invalide, fichier corrompu ou interrompu", m)
			continue
		}
		return m
	}
	// Aucun modèle connu valide — chercher n'importe quel GGUF valide
	models := ListAvailableModels()
	if len(models) > 0 {
		sort.Slice(models, func(i, j int) bool { return models[i].SizeGB > models[j].SizeGB })
		for _, km := range models {
			if isValidGGUF(modelPath(mDir, km.Filename)) {
				return km.Filename
			}
		}
	}
	return DefaultModel
}

// FoundationSecModelPresent indique si Foundation-Sec-8B est disponible.
func FoundationSecModelPresent() bool {
	return modelPresent(moteurDir(), FoundationSecModel)
}

// IsFineTunable retourne true si le modèle peut être fine-tuné localement via Unsloth QLoRA.
// Seul Foundation-Sec-8B (LLaMA 3.1 8B base) est entraînable — les autres sont quantifiés
// ou reposent sur des architectures propriétaires non redistribuables en FP16.
func IsFineTunable(filename string) bool {
	return filename == FoundationSecModel
}

// ─── Pipeline bi-modèle en chaîne ────────────────────────────────────────────
//
// Architecture : M1 (cyber spécialiste) → M2 (généraliste structuré)
//
//   M1 rôle : extraction technique pure (famille, TTPs, C2, IOCs)
//             → prompt court (~6k), réponse JSON partiel rapide
//   M2 rôle : synthèse narrative + JSON final structuré (résumé exécutif, recs COMEX)
//             → reçoit le résultat M1 + schéma complet
//
// Pertinence : les modèles cyber spécialisés (Foundation-Sec, Primus) sont précis
// techniquement mais produisent souvent un JSON malformé ou un style trop technique
// pour le management. Qwen 14B excelle sur la structure JSON et la prose managériale
// mais manque de précision sur l'identification des TTPs et familles malware.
// La chaîne tire profit des deux forces.

// SelectChainModels retourne (M1, M2) pour le pipeline bi-modèle.
// M1 = meilleur spécialiste cyber disponible (extraction technique)
// M2 = meilleur généraliste structuré disponible (synthèse rapport)
// Retourne ("", "") si pas assez de modèles distincts pour une chaîne.
func SelectChainModels() (m1, m2 string) {
	mDir := moteurDir()

	// Détecter la VRAM disponible pour choisir M2 adapté
	_, _, _, vramFree := detectGPUDetails()

	// M1 : priorité aux spécialistes cyber
	cyberModels := []string{FoundationSecModel, LlamaForensicModel, PrimusModel, GraniteCodeModel}
	for _, m := range cyberModels {
		if modelPresent(mDir, m) {
			m1 = m
			break
		}
	}

	// M2 : meilleur généraliste structuré, différent de M1
	// Si VRAM < 10 Go : Qwen 14B risque d'être trop grand → utiliser 7B
	var generalistModels []string
	if vramFree >= 10.0 {
		generalistModels = []string{FallbackModel, DefaultModel} // Qwen 14B en priorité
	} else if vramFree >= 6.0 {
		generalistModels = []string{DefaultModel, FallbackModel} // Mistral 7B prioritaire
	} else {
		// VRAM très serrée : M2 = même modèle que M1 en mode mono
		generalistModels = []string{DefaultModel}
	}
	for _, m := range generalistModels {
		if modelPresent(mDir, m) && m != m1 {
			m2 = m
			break
		}
	}

	// Fallback : si M2 toujours vide, essayer n'importe quel modèle ≠ M1
	if m2 == "" {
		for _, m := range []string{FallbackModel, DefaultModel, PrimusModel, FoundationSecModel, LlamaForensicModel} {
			if modelPresent(mDir, m) && m != m1 {
				m2 = m
				break
			}
		}
	}

	// Si M1 et M2 sont identiques ou l'un est absent → pas de chaîne possible
	if m1 == "" || m2 == "" || m1 == m2 {
		return "", ""
	}
	return m1, m2
}

func ChainAvailable() bool {
	m1, m2 := SelectChainModels()
	return m1 != "" && m2 != ""
}

// LlamaForensicModelPresent indique si Meta Llama 3.1 8B est disponible.
func LlamaForensicModelPresent() bool {
	return modelPresent(moteurDir(), LlamaForensicModel)
}

// EnsureLlamaForensicModel télécharge Meta Llama 3.1 8B Instruct Q4_K_M.
// Architecture LLaMA 3.1 — même base que Foundation-Sec et ForensicLLM.
// Contexte 128k tokens. Fine-tunable localement via LoRA/QLoRA.
func EnsureLlamaForensicModel(progressFn func(string)) {
	mDir := moteurDir()
	if modelPresent(mDir, LlamaForensicModel) {
		progressFn(logOK("AI-LLAMA31", fmt.Sprintf("Llama 3.1 8B déjà présent : %s", LlamaForensicModel)))
		return
	}
	progressFn(logInfo("AI-LLAMA31", "Téléchargement Meta Llama 3.1 8B Instruct Q4_K_M (~4.9 Go)..."))
	progressFn(logInfo("AI-LLAMA31", "Source : bartowski/Meta-Llama-3.1-8B-Instruct-GGUF"))
	progressFn(logInfo("AI-LLAMA31", "Contexte 128k | Fine-tunable LoRA | Llama 3.1 Community License"))
	dest := modelPath(mDir, LlamaForensicModel)
	if err := downloadResumable(llamaForensicGGUFURL, dest, progressFn); err != nil {
		progressFn(logErr("AI-LLAMA31", fmt.Sprintf("Téléchargement Llama 3.1 8B échoué: %v", err)))
		return
	}
	progressFn(logOK("AI-LLAMA31", fmt.Sprintf("Llama 3.1 8B téléchargé → moteur/models/%s", LlamaForensicModel)))
	progressFn(logOK("AI-LLAMA31", "Modèle prêt — fine-tuning forensic disponible via le trainer intégré"))
	progressFn(logOK("AI-LLAMA31", "Template : LLaMA 3.1 Chat — même architecture que Foundation-Sec"))
}

// GraniteCodeModelPresent indique si IBM Granite 8B Code est disponible.
func GraniteCodeModelPresent() bool {
	return modelPresent(moteurDir(), GraniteCodeModel)
}

// EnsureGraniteCodeModel télécharge IBM Granite 8B Code Instruct.
func EnsureGraniteCodeModel(progressFn func(string)) {
	mDir := moteurDir()
	if modelPresent(mDir, GraniteCodeModel) {
		progressFn(logOK("AI-GRANITE", "IBM Granite 8B Code déjà présent"))
		return
	}
	dest := modelPath(mDir, GraniteCodeModel)

	// Essayer les URLs dans l'ordre — le repo bartowski original a été supprimé/renommé
	urls := []struct{ url, label string }{
		{graniteCodeGGUFURL, "ibm-granite/granite-8b-code-instruct-4k (officiel IBM)"},
		{graniteCodeGGUFFallback1, "bartowski/ibm-granite-8b-code-instruct-4k-GGUF"},
		{graniteCodeGGUFFallback2, "bartowski/ibm-granite-3.1-8b-instruct-GGUF (Granite 3.1)"},
	}

	var lastErr error
	for _, u := range urls {
		progressFn(logInfo("AI-GRANITE", fmt.Sprintf("Téléchargement IBM Granite 8B Code (~4.9 Go)...")))
		progressFn(logInfo("AI-GRANITE", fmt.Sprintf("Source : %s", u.label)))
		if err := downloadResumable(u.url, dest, progressFn); err != nil {
			progressFn(logWarn("AI-GRANITE", fmt.Sprintf("✗ Téléchargement Granite échoué: %v — essai URL suivante...", err)))
			// Supprimer le fichier partiel avant de réessayer
			os.Remove(dest)
			lastErr = err
			continue
		}
		// Vérifier magic bytes GGUF
		if !isValidGGUF(dest) {
			progressFn(logWarn("AI-GRANITE", "✗ Fichier téléchargé invalide (pas un GGUF) — essai URL suivante..."))
			os.Remove(dest)
			continue
		}
		progressFn(logOK("AI-GRANITE", fmt.Sprintf("✓ IBM Granite 8B Code téléchargé depuis %s", u.label)))
		return
	}

	// Toutes les URLs ont échoué
	progressFn(logErr("AI-GRANITE", fmt.Sprintf("✗ Toutes les URLs Granite ont échoué. Dernière erreur : %v", lastErr)))
	progressFn(logInfo("AI-GRANITE", "→ Téléchargez manuellement depuis : https://huggingface.co/ibm-granite/granite-8b-code-instruct-4k"))
	progressFn(logInfo("AI-GRANITE", "→ Placez le fichier .gguf dans le dossier moteur/models/"))
}
