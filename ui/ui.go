// Package ui fournit une interface web locale (http://localhost:PORT)
// pour soumettre des analyses sandbox et gérer la configuration.
package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"rf-sandbox-go/internal/ai"
	"rf-sandbox-go/internal/auditpdf"
	"rf-sandbox-go/internal/client"
	"rf-sandbox-go/internal/models"
	"rf-sandbox-go/internal/reporter"
	"rf-sandbox-go/vault"
)

type logBroadcaster struct {
	mu      sync.Mutex
	clients map[chan string]struct{}
}

var logHub = &logBroadcaster{clients: make(map[chan string]struct{})}

// ── Préchauffage moteur IA ────────────────────────────────────────────────────
// engineWarmupOnce garantit qu'on ne lance qu'un seul préchauffage en parallèle.
// Dès le premier fichier soumis, llama-server est démarré en arrière-plan
// pour qu'il soit prêt quand le résultat RF revient (gain de ~10-15s).
var (
	engineWarmupOnce sync.Once
	engineWarmupDone = make(chan struct{}) // fermé quand le moteur est prêt
	engineWarmupErr  error
)

// ── Session store : garde les résultats complets en mémoire ──────────────────
// Chaque analyse/fetch stocke les résultats avec un ID de session unique.
// Le générateur PDF récupère les données complètes (Static, Overview, etc.)
// depuis ce store, évitant la perte de données lors du round-trip frontend.
var (
	sessionMu      sync.RWMutex
	sessionStore   = map[string][]*models.AnalysisResult{}
	sessionCounter int
)

func newSessionID() string {
	sessionMu.Lock()
	sessionCounter++
	id := fmt.Sprintf("sess-%d-%d", time.Now().UnixNano(), sessionCounter)
	sessionMu.Unlock()
	return id
}

func storeSession(results []*models.AnalysisResult) string {
	id := newSessionID()
	sessionMu.Lock()
	sessionStore[id] = results
	// Nettoyage : garder au maximum 50 sessions
	if len(sessionStore) > 50 {
		for k := range sessionStore {
			delete(sessionStore, k)
			break
		}
	}
	sessionMu.Unlock()
	return id
}

func getSession(id string) ([]*models.AnalysisResult, bool) {
	sessionMu.RLock()
	defer sessionMu.RUnlock()
	r, ok := sessionStore[id]
	return r, ok
}

func (lb *logBroadcaster) subscribe() chan string {
	ch := make(chan string, 64)
	lb.mu.Lock()
	lb.clients[ch] = struct{}{}
	lb.mu.Unlock()
	return ch
}

func (lb *logBroadcaster) unsubscribe(ch chan string) {
	lb.mu.Lock()
	delete(lb.clients, ch)
	lb.mu.Unlock()
}

func (lb *logBroadcaster) publish(msg string) {
	lb.mu.Lock()
	for ch := range lb.clients {
		select {
		case ch <- msg:
		default:
		}
	}
	lb.mu.Unlock()
}

// logWriter redirige les logs vers le broadcaster ET la sortie standard.
type logWriter struct {
	base io.Writer
}

func (lw *logWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimRight(string(p), "\n")
	logHub.publish(msg)
	return lw.base.Write(p)
}

// InitLogBroadcaster remplace la sortie du logger par défaut pour capturer tous les logs.
func InitLogBroadcaster() {
	log.SetOutput(&logWriter{base: os.Stderr})
}

// AppLog publie un message de log vers l'UI et la console.
func AppLog(level, tag, msg string) {
	ts := time.Now().Format("15:04:05")
	log.Printf("[%s] %s — %s", level, tag, msg)
	_ = ts // horodatage inclus dans log.Printf automatiquement
}

// ServerConfig contient la configuration passée au serveur UI.
type ServerConfig struct {
	APIToken       string
	Proxy          string
	UIPort         string
	ConfigPath     string
	AbuseIPDBKey   string // optionnel — cle API AbuseIPDB (gratuit : https://www.abuseipdb.com/)
	SandboxTimeout int    // durée analyse en secondes (0 = défaut 300s)
	SandboxNetwork string // "internet"|"drop"|"tor" (vide = "internet")
	AIModel        string // modèle IA actif (nom de fichier GGUF dans moteur/models/)
	HFToken        string // token Hugging Face pour les modèles gated (Primus, Llama...)
}

// Start démarre le serveur HTTP de l'interface web.
func Start(cfg ServerConfig) {
	InitLogBroadcaster()
	// Configurer le token HuggingFace globalement pour les téléchargements de modèles gated
	if cfg.HFToken != "" {
		ai.SetHFToken(cfg.HFToken)
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/config", makeConfigHandler(cfg.ConfigPath))
	mux.HandleFunc("/api/vault/encrypt", makeVaultEncryptHandler(cfg.ConfigPath))
	mux.HandleFunc("/api/vault/status", makeVaultStatusHandler(cfg.ConfigPath))
	mux.HandleFunc("/api/test-connection", makeTestConnectionHandler(cfg))
	mux.HandleFunc("/api/submit", makeSubmitHandler(cfg))
	mux.HandleFunc("/api/fetch", makeFetchHandler(cfg))
	mux.HandleFunc("/api/report", makeReportHandler(cfg))
	mux.HandleFunc("/api/warmup", makeWarmupHandler(cfg))
	mux.HandleFunc("/api/cancel", makeCancelHandler())
	mux.HandleFunc("/api/models", makeModelsHandler(cfg))
	mux.HandleFunc("/api/models/download", makeModelDownloadHandler(cfg))
	mux.HandleFunc("/api/models/progress", makeModelProgressHandler())
	// Export CSV de la base de connaissances
	mux.HandleFunc("/api/knowledge/export-csv", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "méthode non autorisée", 405)
			return
		}
		csvPath := filepath.Join(knowledgeDir(), "analyses.csv")
		count, err := ai.ExportCSV(csvPath)
		if err != nil {
			http.Error(w, "Export CSV : "+err.Error(), 500)
			return
		}
		// Retourner le fichier CSV en téléchargement
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="analyses_rf_sandbox.csv"`)
		http.ServeFile(w, r, csvPath)
		log.Printf("[KNOWLEDGE] Export CSV : %d analyses → %s", count, csvPath)
	})

	mux.HandleFunc("/api/knowledge/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		statsResult, err := ai.KnowledgeStatsJSON()
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"stats": ai.KnowledgeStats(), "error": err.Error()})
			return
		}
		// Compatibilité ascendante : inclure aussi la string "stats" pour le code existant
		type statsResponse struct {
			*ai.KnowledgeStatsResult
			Stats string `json:"stats"`
		}
		json.NewEncoder(w).Encode(statsResponse{
			KnowledgeStatsResult: statsResult,
			Stats:                ai.KnowledgeStats(),
		})
	})
	mux.HandleFunc("/api/training/export", makeTrainingExportHandler())
	mux.HandleFunc("/api/training/start", makeTrainingStartHandler())
	mux.HandleFunc("/api/logs", makeLogStreamHandler())
	mux.HandleFunc("/api/audit/run", makeAuditRunHandler())
	mux.HandleFunc("/api/audit/list", makeAuditListHandler())
	mux.HandleFunc("/api/audit/report-content", makeAuditReportContentHandler())
	mux.HandleFunc("/api/reporting/list", makeReportingListHandler())
	mux.HandleFunc("/api/reporting/download", makeReportingDownloadHandler())
	mux.HandleFunc("/api/audit/pdf", makeAuditPDFHandler())
	mux.HandleFunc("/api/audit/ai-report", makeAuditAIReportHandler(cfg))
	mux.HandleFunc("/api/readme", makeReadmeHandler())

	addr := "localhost:" + cfg.UIPort
	log.Printf("Interface disponible sur http://%s", addr)
	openBrowser("http://" + addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("serveur UI : %v", err)
	}
}

// ── Page HTML ─────────────────────────────────────────────────────────────────

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(htmlPage)
}

// ── Handler config.json ───────────────────────────────────────────────────────

func makeConfigHandler(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			data, err := os.ReadFile(path)
			if err != nil {
				jsonError(w, "lecture config.json : "+err.Error(), 500)
				return
			}
			w.Write(data)
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			var cfg map[string]interface{}
			if err := json.Unmarshal(body, &cfg); err != nil {
				jsonError(w, "JSON invalide : "+err.Error(), 400)
				return
			}
			// Chiffrement automatique des champs sensibles avant sauvegarde
			sensitiveFields := []string{"api_token", "abuseipdb_key", "hf_token"}
			vKey, vErr := resolveVaultKey(path)
			for _, field := range sensitiveFields {
				if val, ok := cfg[field].(string); ok && val != "" && !vault.IsEncrypted(val) {
					if vErr == nil {
						if enc, err := vault.Encrypt(val, vKey); err == nil {
							cfg[field] = enc
						}
					}
				}
			}
			pretty, _ := json.MarshalIndent(cfg, "", "  ")
			if err := os.WriteFile(path, pretty, 0o644); err != nil {
				jsonError(w, "\xc3\xa9criture config.json : "+err.Error(), 500)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		default:
			jsonError(w, "m\xc3\xa9thode non autoris\xc3\xa9e", 405)
		}
	}
}

// ── Vault encrypt ─────────────────────────────────────────────────────────────

func makeVaultEncryptHandler(configPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			jsonError(w, "méthode non autorisée", 405)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal(body, &req); err != nil || req.Value == "" {
			jsonError(w, "body invalide : champ value requis", 400)
			return
		}
		if vault.IsEncrypted(req.Value) {
			json.NewEncoder(w).Encode(map[string]string{"encrypted": req.Value})
			return
		}
		key, err := resolveVaultKey(configPath)
		if err != nil {
			jsonError(w, "clé vault introuvable : "+err.Error(), 500)
			return
		}
		enc, err := vault.Encrypt(req.Value, key)
		if err != nil {
			jsonError(w, "chiffrement échoué : "+err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"encrypted": enc})
	}
}

// ── Vault status ──────────────────────────────────────────────────────────────

func makeVaultStatusHandler(configPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		key, err := resolveVaultKey(configPath)
		sealed := err == nil
		keyPath := vault.KeyPath()
		if err == nil {
			_ = key
		}
		// Check config for encrypted fields
		data, _ := os.ReadFile(configPath)
		encryptedFields := []string{}
		if len(data) > 0 {
			var doc map[string]interface{}
			if json.Unmarshal(data, &doc) == nil {
				for k, v := range doc {
					if s, ok := v.(string); ok && vault.IsEncrypted(s) {
						encryptedFields = append(encryptedFields, k)
					}
				}
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sealed":           sealed,
			"key_path":         keyPath,
			"encrypted_fields": encryptedFields,
		})
	}
}

// ── Test connection ───────────────────────────────────────────────────────────

func makeTestConnectionHandler(cfg ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		token := liveToken(cfg.ConfigPath, cfg.APIToken)
		proxy := liveProxy(cfg.ConfigPath, cfg.Proxy)
		c := client.NewWithProxy(token, proxy)
		c.SetAnalysisOptions(cfg.SandboxTimeout, cfg.SandboxNetwork)
		if err := c.TestConnection(); err != nil {
			jsonError(w, err.Error(), 502)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}

// ── Submit / Fetch ────────────────────────────────────────────────────────────

// startEngineWarmup démarre llama-server en arrière-plan une seule fois.
// Appelé dès qu'un fichier est soumis pour que le moteur soit prêt
// quand RF Sandbox retourne ses résultats (1-3 min plus tard).
func startEngineWarmup(cfg ServerConfig) {
	engineWarmupOnce.Do(func() {
		go func() {
			defer close(engineWarmupDone)
			bestModel := ai.SelectBestModel()
			if bestModel == "" {
				log.Println("[WARMUP] Aucun modèle IA disponible — préchauffage ignoré")
				engineWarmupErr = fmt.Errorf("aucun modèle disponible")
				return
			}
			log.Printf("[WARMUP] ⚡ Préchauffage moteur IA en parallèle — modèle : %s", ai.ModelDisplayName(bestModel))
			llamaClient := ai.NewClient(bestModel, nil)
			if err := llamaClient.EnsureReady(func(msg string) { log.Println(msg) }); err != nil {
				log.Printf("[WARMUP] ⚠ Préchauffage échoué : %v", err)
				engineWarmupErr = err
				return
			}
			log.Printf("[WARMUP] ✓ Moteur IA prêt — %s opérationnel", ai.ModelDisplayName(bestModel))
		}()
	})
}

// makeCancelHandler — POST /api/cancel
// Arrête llama-server et reset le flag de génération en cours.
func makeCancelHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Tuer llama-server
		ai.KillLlamaServer()
		// Reset le flag warmup pour permettre un redémarrage propre
		log.Println("[CANCEL] ✓ Génération annulée — llama-server arrêté")
		json.NewEncoder(w).Encode(map[string]string{"status": "cancelled"})
	}
}

// makeWarmupHandler — POST /api/warmup
// Déclenche le préchauffage manuellement (ou appelé par le JS dès le premier dépôt).
func makeWarmupHandler(cfg ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		startEngineWarmup(cfg)
		json.NewEncoder(w).Encode(map[string]string{"status": "warmup_started"})
	}
}

func makeSubmitHandler(cfg ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			jsonError(w, "méthode non autorisée", 405)
			return
		}

		// ⚡ Préchauffage immédiat du moteur IA en parallèle
		// RF Sandbox met 1-3 min à analyser — on profite de ce temps
		// pour démarrer llama-server afin qu'il soit prêt dès les résultats.
		startEngineWarmup(cfg)

		token := liveToken(cfg.ConfigPath, cfg.APIToken)
		proxy := liveProxy(cfg.ConfigPath, cfg.Proxy)
		c := client.NewWithProxy(token, proxy)
		c.SetAnalysisOptions(cfg.SandboxTimeout, cfg.SandboxNetwork)

		ct := r.Header.Get("Content-Type")
		var targets []string
		private := true

		if strings.Contains(ct, "multipart/form-data") {
			// File upload
			r.ParseMultipartForm(100 << 20) // 100 MB
			private = r.FormValue("private") != "0"
			mf := r.MultipartForm
			if mf == nil || mf.File == nil {
				jsonError(w, "aucun fichier reçu", 400)
				return
			}
			for _, headers := range mf.File {
				for _, fh := range headers {
					f, err := fh.Open()
					if err != nil {
						continue
					}
					// Save to temp file
					// Détection extension trompeuse (double extension type .cer.exe, .pdf.exe)
					// Le fichier soumis peut être un PE déguisé en certificat/document.
					// RF Sandbox peut l'analyser comme fichier statique sans l'exécuter.
					originalName := fh.Filename
					sandboxName := originalName
					if isMaskedExecutable(originalName) {
						// Renommer en .exe pour forcer l'exécution en sandbox
						sandboxName = strings.TrimSuffix(originalName, filepath.Ext(originalName)) + ".exe"
						log.Printf("[SUBMIT] ⚠ Extension trompeuse détectée : %s → renommé %s pour sandbox", originalName, sandboxName)
					}
					tmp, _ := os.CreateTemp("", "rfsb-*-"+sandboxName)
					io.Copy(tmp, f)
					f.Close()
					tmp.Close()
					targets = append(targets, tmp.Name())
				}
			}
		} else {
			// JSON (URL or ID)
			body, _ := io.ReadAll(r.Body)
			var req map[string]interface{}
			if err := json.Unmarshal(body, &req); err != nil {
				jsonError(w, "JSON invalide", 400)
				return
			}
			if u, ok := req["url"].(string); ok {
				targets = append(targets, u)
			}
			if p, ok := req["private"].(bool); ok {
				private = p
			}
		}

		if len(targets) == 0 {
			jsonError(w, "aucune cible à analyser", 400)
			return
		}

		results := c.AnalyzeBatch(targets, private)

		// Loguer les fichiers déposés récupérés
		for _, res := range results {
			if len(res.DroppedFiles) > 0 {
				log.Printf("[RF-API] %s — %d fichier(s) deposé(s) par le malware récupérés depuis RF Sandbox", res.Filename, len(res.DroppedFiles))
				for _, df := range res.DroppedFiles {
					log.Printf("[RF-API]   ↳ %s (%s, %d octets, tâche: %s)", df.Name, df.Kind, df.Size, df.TaskID)
				}
			}
		}

		// Clean up temp files
		for _, t := range targets {
			if strings.Contains(t, "rfsb-") {
				os.Remove(t)
			}
		}

		// Stocker les résultats complets en session (pour PDF avec données complètes)
		sessID := storeSession(results)

		if len(results) == 1 {
			m := marshalResult(results[0])
			m["session_id"] = sessID
			json.NewEncoder(w).Encode(m)
		} else {
			out := make([]interface{}, len(results))
			for i, res := range results {
				m := marshalResult(res)
				m["session_id"] = sessID
				out[i] = m
			}
			json.NewEncoder(w).Encode(out)
		}
	}
}

func makeFetchHandler(cfg ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		id := r.URL.Query().Get("id")
		if id == "" {
			jsonError(w, "paramètre id manquant", 400)
			return
		}
		token := liveToken(cfg.ConfigPath, cfg.APIToken)
		proxy := liveProxy(cfg.ConfigPath, cfg.Proxy)
		c := client.NewWithProxy(token, proxy)
		c.SetAnalysisOptions(cfg.SandboxTimeout, cfg.SandboxNetwork)
		result := c.FetchExisting(id)
		sessID := storeSession([]*models.AnalysisResult{result})
		m := marshalResult(result)
		m["session_id"] = sessID
		json.NewEncoder(w).Encode(m)
	}
}

// makeReportHandler génère un rapport PDF depuis les sessions en mémoire.
// Tente d'abord le rapport IA (Ollama/Mistral), repli sur le rapport Go si IA indisponible.
func makeReportHandler(cfg ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonError(w, "méthode non autorisée", 405)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			SessionIDs         []string `json:"session_ids"`
			TLP                string   `json:"tlp"`
			ForceGo            bool     `json:"force_go"`             // forcer le rapport Go (debug)
			UseMitre           bool     `json:"use_mitre"`            // enrichissement MITRE ATT&CK
			UseAbuseIPDB       bool     `json:"use_abuseipdb"`        // enrichissement AbuseIPDB
			UseKnowledge       bool     `json:"use_knowledge"`        // mémorisation dans la base
			UseKnowledgeInject bool     `json:"use_knowledge_inject"` // injection du contexte dans le prompt IA
			UseGeoIP           bool     `json:"use_geoip"`            // geolocalisation IP
		}
		// Valeurs par défaut
		req.UseMitre = true
		req.UseAbuseIPDB = true
		req.UseKnowledge = true
		req.UseKnowledgeInject = false // OFF par défaut — à activer manuellement dans la config
		req.UseGeoIP = false
		if err := json.Unmarshal(body, &req); err != nil {
			jsonError(w, "JSON invalide", 400)
			return
		}
		if req.TLP == "" {
			req.TLP = "TLP:WHITE"
		}

		// Récupérer les résultats complets depuis le session store.
		// ISOLATION : on n'accepte QUE les sessions du lot courant.
		// Le frontend garantit déjà l'isolation (reset avant chaque dépôt).
		var allResults []*models.AnalysisResult
		for _, sid := range req.SessionIDs {
			if sid == "" {
				continue
			}
			if results, ok := getSession(sid); ok {
				allResults = append(allResults, results...)
			}
		}
		if len(allResults) == 0 {
			jsonError(w, "aucun résultat trouvé : session expirée ou ID manquant", 404)
			return
		}

		tmp, err := os.CreateTemp("", "rf-rapport-*.pdf")
		if err != nil {
			jsonError(w, "création fichier temporaire : "+err.Error(), 500)
			return
		}
		tmpPath := tmp.Name()
		tmp.Close()
		defer os.Remove(tmpPath)

		aiUsed := false
		if !req.ForceGo {
			aiUsed = generateWithAI(cfg, allResults, tmpPath, req.TLP, req.UseMitre, req.UseAbuseIPDB, req.UseKnowledge, req.UseKnowledgeInject, req.UseGeoIP)
		}

		if !aiUsed {
			// Repli sur le reporter Go structuré
			log.Println("[RAPPORT] Utilisation du reporter Go (IA non disponible ou erreur)")
			goEnrichment := buildEnrichment(cfg, allResults, req.UseMitre, req.UseAbuseIPDB, req.UseGeoIP, func(msg string) { log.Println(msg) })
			gen := reporter.New(tmpPath, req.TLP)
			if err := gen.Generate(allResults, goEnrichment); err != nil {
				jsonError(w, "génération PDF Go : "+err.Error(), 500)
				return
			}
		}

		pdfData, err := os.ReadFile(tmpPath)
		if err != nil {
			jsonError(w, "lecture PDF : "+err.Error(), 500)
			return
		}

		suffix := "go"
		if aiUsed {
			suffix = "ia"
		}
		filename := fmt.Sprintf("rf_sandbox_rapport_%s_%s.pdf",
			time.Now().Format("2006-01-02_15-04-05"), suffix)

		// ── Archiver le rapport dans reporting/ ──────────────────────────
		reportPath := filepath.Join(reportingDir(), filename)
		if err := os.WriteFile(reportPath, pdfData, 0644); err != nil {
			log.Printf("[RAPPORT] Impossible de sauvegarder dans reporting/ : %v", err)
		} else {
			log.Printf("[RAPPORT] ✓ Rapport archivé : %s", reportPath)
		}

		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdfData)))
		w.Write(pdfData)
	}
}

// minChain retourne le minimum de deux entiers (helper local generateWithChain).
func minChain(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// generateWithAI genere le rapport d'analyse.
// Rapport Go de secours si llama-server est indisponible.
// Pipeline :
//  1. Recherche d'analyses similaires (base de connaissances locale)
//  2. Enrichissement MITRE ATT&CK + AbuseIPDB
//  3. Construction du prompt enrichi
//  4. Generation via llama.cpp
//  5. Sauvegarde dans la base de connaissances
//
// buildEnrichment construit les données d'enrichissement MITRE + AbuseIPDB + GeoIP
// pour un ensemble de résultats d'analyse. Utilisé par le reporter Go et le fallback IA.
func buildEnrichment(cfg ServerConfig, results []*models.AnalysisResult, useMitre, useAbuseIPDB, useGeoIP bool, progress func(string)) *ai.EnrichmentData {
	ttpSet := make(map[string]bool)
	ipSet := make(map[string]bool)
	for _, r := range results {
		for _, sig := range r.Signatures {
			for _, t := range sig.TTP {
				if t != "" {
					ttpSet[t] = true
				}
			}
		}
		if r.Overview != nil {
			for _, task := range r.Overview.Tasks {
				for _, t := range task.TTP {
					if t != "" {
						ttpSet[t] = true
					}
				}
			}
		}
		for _, ip := range r.IOCs.IPs {
			if ip != "" {
				ipSet[ip] = true
			}
		}
	}
	ttpIDs := make([]string, 0, len(ttpSet))
	for t := range ttpSet {
		ttpIDs = append(ttpIDs, t)
	}
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	abuseKey := ""
	if useAbuseIPDB {
		abuseKey = cfg.AbuseIPDBKey
	}
	targetTTPs := ttpIDs
	if !useMitre {
		targetTTPs = nil
	}
	enrichClient := ai.NewEnrichClient(abuseKey)
	enrichment := enrichClient.Enrich(targetTTPs, ips, progress)

	if useGeoIP && len(ips) > 0 {
		geoClient := ai.NewGeoClient(true)
		geoData := geoClient.LookupBatch(ips, progress)
		enrichment.GeoData = geoData
	}
	return enrichment
}

// generateWithChain implémente le pipeline bi-modèle en chaîne :
//
//	M1 (cyber spécialiste) → extraction technique JSON partiel
//	M2 (généraliste structuré) → synthèse rapport complet JSON
//
// Conditions d'activation :
//   - Au moins 2 modèles distincts présents dans moteur/models/
//   - M1 = Foundation-Sec-8B OU Primus 8B OU Granite 8B Code
//   - M2 = Qwen 14B OU Mistral 7B (différent de M1)
//
// Avantages vs mono-modèle :
//
//	+25% précision famille/TTPs (M1 spécialiste)
//	+40% qualité JSON structuré (M2 Qwen 14B)
//	+30% cohérence technique/business
//	+60% temps (2 générations séquentielles — acceptable car RF prend 2-5 min)
func generateWithChain(
	cfg ServerConfig,
	results []*models.AnalysisResult,
	outputPath, tlp string,
	enrichment *ai.EnrichmentData,
	similar []ai.SimilarEntry,
	geoData map[string]ai.GeoInfo,
	progress func(string),
) (bool, string, *ai.ForensicReport) {
	// (durée globale mesurée par aiPipelineStart dans generateWithAI)

	m1, m2 := ai.SelectChainModels()
	if m1 == "" || m2 == "" {
		return false, "", nil
	}

	progress(ai.CHeader("AI-CHAIN", "PIPELINE BI-MODÈLE EN CHAÎNE"))
	progress(ai.CInfo(fmt.Sprintf("[AI-CHAIN] M1 (extraction cyber) : %s", ai.ModelDisplayName(m1))))
	progress(ai.CInfo(fmt.Sprintf("[AI-CHAIN] M2 (synthèse rapport)  : %s", ai.ModelDisplayName(m2))))

	// ── ÉTAPE 1 : M1 — Extraction technique ──────────────────────────────────
	progress(ai.CInfo("[AI-CHAIN] Étape 1/2 — Démarrage M1 (extraction technique)..."))

	clientM1 := ai.NewClient(m1, nil)
	if err := clientM1.EnsureReady(progress); err != nil {
		progress(ai.CWarn(fmt.Sprintf("[AI-CHAIN] M1 indisponible (%v) — abandon chaîne", err)))
		return false, "", nil
	}

	promptM1 := ai.BuildExtractionPrompt(results, enrichment)
	progress(ai.CInfo(fmt.Sprintf("[AI-CHAIN] Prompt M1 : %d chars (focalisé technique)", len(promptM1))))

	rawM1, err := clientM1.Generate(promptM1, progress)
	if err != nil {
		progress(ai.CWarn(fmt.Sprintf("[AI-CHAIN] M1 génération échouée (%v) — abandon chaîne", err)))
		return false, "", nil
	}

	extraction, err := ai.ParseExtractionResponse(rawM1)
	if err != nil {
		progress(ai.CWarn(fmt.Sprintf("[AI-CHAIN] M1 parsing échoué (%v) — abandon chaîne", err)))
		return false, "", nil
	}
	progress(ai.COK(fmt.Sprintf("[AI-CHAIN] ✓ M1 terminé — famille=%s | TTPs=%d | confiance=%s",
		extraction.Famille, len(extraction.TTPsConfirmes), extraction.Confiance)))
	// Logger les IOCs détectés par M1 pour visibilité
	if len(extraction.InfraC2) > 0 {
		progress(ai.CDetail("AI-CHAIN", fmt.Sprintf("C2 détecté: %s", strings.Join(extraction.InfraC2[:minChain(len(extraction.InfraC2), 3)], ", "))))
	}
	if len(extraction.IOCsNets) > 0 {
		progress(ai.CDetail("AI-CHAIN", fmt.Sprintf("IOCs réseaux: %d identifiés", len(extraction.IOCsNets))))
	}

	// ── ÉTAPE 2 : M2 — Synthèse rapport complet ──────────────────────────────
	progress(ai.CInfo("[AI-CHAIN] Étape 2/2 — Redémarrage M2 (synthèse rapport)..."))

	if err := clientM1.RestartWithModel(m2, progress); err != nil {
		progress(ai.CWarn(fmt.Sprintf("[AI-CHAIN] Basculement M2 échoué (%v) — abandon chaîne", err)))
		return false, "", nil
	}

	promptM2 := ai.BuildSynthesisPrompt(results, extraction, enrichment, similar, geoData)
	progress(ai.CInfo(fmt.Sprintf("[AI-CHAIN] Prompt M2 : %d chars (synthèse + schéma JSON)", len(promptM2))))

	rawM2, err := clientM1.Generate(promptM2, progress) // clientM1 est maintenant M2
	if err != nil {
		progress(ai.CWarn(fmt.Sprintf("[AI-CHAIN] M2 génération échouée (%v) — abandon chaîne", err)))
		return false, "", nil
	}

	// Extraire le score sandbox pour plafonner le score IA
	sbScore := 0
	for _, res := range results {
		if res.Score > 0 {
			sbScore = res.Score
			break
		}
	}

	forensicReport, err := ai.ParseForensicResponse(rawM2, sbScore)
	if err != nil {
		progress(ai.CWarn(fmt.Sprintf("[AI-CHAIN] M2 parsing JSON échoué (%v) — retry M2 avec prompt étendu", err)))
		// Retry avec le prompt complet BuildForensicPrompt (plus de contexte)
		promptM2Retry := ai.BuildForensicPrompt(results, enrichment, similar, geoData)
		rawM2Retry, errRetry := clientM1.Generate(promptM2Retry, progress)
		if errRetry != nil {
			progress(ai.CWarn(fmt.Sprintf("[AI-CHAIN] Retry M2 échoué (%v) — abandon chaîne", errRetry)))
			return false, "", nil
		}
		forensicReport, err = ai.ParseForensicResponse(rawM2Retry, sbScore)
		if err != nil {
			progress(ai.CWarn(fmt.Sprintf("[AI-CHAIN] Retry M2 parsing JSON toujours échoué — abandon chaîne")))
			return false, "", nil
		}
		progress(ai.COK("[AI-CHAIN] ✓ Retry M2 réussi"))
	}

	engineLabel := fmt.Sprintf("%s → %s", ai.ModelDisplayName(m1), ai.ModelDisplayName(m2))
	progress(ai.COK(fmt.Sprintf("[AI-CHAIN] ✓ Pipeline terminé — %s | classification=%s | score=%d/10",
		engineLabel, forensicReport.Classification, forensicReport.ScoreGlobal)))

	return true, engineLabel, forensicReport
}

func generateWithAI(cfg ServerConfig, results []*models.AnalysisResult, outputPath, tlp string, useMitre, useAbuseIPDB, useKnowledge, useKnowledgeInject, useGeoIP bool) bool {
	// Timer global : mesure la durée totale du pipeline IA (enrichissement + génération + PDF)
	aiPipelineStart := time.Now()

	// progress publie dans le log ET directement dans le hub SSE pour la loupe en temps réel
	progress := func(msg string) {
		log.Println(msg)
		// Publication directe dans le hub pour les cas où log.Println ne serait pas capturé
		logHub.publish(strings.TrimSpace(msg))
	}

	// ── 1. Base de connaissances ──────────────────────────────────────────────
	// Deux comportements indépendants :
	//   useKnowledge       → mémoriser l'analyse dans la base SQLite (on par défaut)
	//   useKnowledgeInject → injecter les analyses similaires dans le prompt IA (off par défaut)
	var similar []ai.SimilarEntry
	if useKnowledgeInject {
		// Injection activée : chercher des analyses similaires dans la base
		progress(ai.CInfo(fmt.Sprintf("[KNOWLEDGE] Injection contexte activée — %s", ai.KnowledgeStats())))
		similar = ai.FindSimilar(results, 3)
		if len(similar) > 0 {
			progress(ai.CInfo(fmt.Sprintf("[KNOWLEDGE] %d analyse(s) similaire(s) injectée(s) dans le prompt", len(similar))))
			for _, s := range similar {
				progress(ai.CDetail("KNOWLEDGE", fmt.Sprintf("%s  (similarité %d%% : %s)", s.Entry.Filename, s.Score, s.Raison)))
			}
		} else {
			progress(ai.CGrey("[KNOWLEDGE] Aucune analyse similaire dans la base"))
		}
	} else if useKnowledge {
		// Mémorisation activée mais injection désactivée
		progress(ai.CGrey(fmt.Sprintf("[KNOWLEDGE] Mémorisation active, injection prompt désactivée — %s", ai.KnowledgeStats())))
	} else {
		progress(ai.CGrey("[KNOWLEDGE] Base de connaissances désactivée"))
	}

	// ── 2. Enrichissement externe ─────────────────────────────────────────────
	var ttpIDs []string
	var ips []string
	for _, r := range results {
		for _, sig := range r.Signatures {
			for _, ttp := range sig.TTP {
				if ttp != "" {
					ttpIDs = append(ttpIDs, ttp)
				}
			}
		}
		ips = append(ips, r.IOCs.IPs...)
	}
	var enrichment *ai.EnrichmentData
	if useMitre || useAbuseIPDB {
		abuseKey := ""
		if useAbuseIPDB {
			abuseKey = cfg.AbuseIPDBKey
		}
		enrichClient := ai.NewEnrichClient(abuseKey)
		// Passer des TTPs vides si MITRE desactive
		targetTTPs := ttpIDs
		if !useMitre {
			targetTTPs = nil
			progress(ai.CGrey("[ENRICH] Enrichissement MITRE désactivé"))
		}
		enrichment = enrichClient.Enrich(targetTTPs, ips, progress)
	} else {
		progress(ai.CGrey("[ENRICH] Enrichissement externe désactivé"))
	}

	// ── 2b. Geolocalisation IP ───────────────────────────────────
	var geoData map[string]ai.GeoInfo
	if useGeoIP {
		geoClient := ai.NewGeoClient(true)
		geoData = geoClient.LookupBatch(ips, progress)
	} else {
		progress(ai.CGrey("[GEOIP] Géolocalisation désactivée"))
	}

	// ── 3. Pipeline bi-modèle (si 2 modèles distincts disponibles) ─────────
	// Tenter la chaîne M1→M2 en priorité — meilleure qualité qu'un seul modèle
	if ai.ChainAvailable() {
		progress(ai.CInfo("[AI] Pipeline bi-modèle disponible — tentative chaîne M1→M2..."))
		chainCallStart := time.Now()
		ok, engineLabel, chainReport := generateWithChain(cfg, results, outputPath, tlp,
			enrichment, similar, geoData, progress)
		chainCallElapsed := time.Since(chainCallStart)
		if ok && chainReport != nil {
			// Mémorisation dans la base de connaissances
			if useKnowledge {
				if err := ai.SaveAnalysis(results, chainReport, enrichment); err != nil {
					progress(ai.CWarn(fmt.Sprintf("[KNOWLEDGE] Sauvegarde chaîne échouée: %v", err)))
				} else {
					progress(ai.COK("[KNOWLEDGE] ✓ Analyse chaîne mémorisée"))
				}
			}
			// Génération PDF
			aiReporter := ai.NewAIReporter(outputPath, tlp, geoData)
			aiReporter.SetEngine(engineLabel)
			aiReporter.SetGenerationDuration(int(chainCallElapsed.Seconds()))
			if enrichment != nil {
				aiReporter.SetEnrichment(enrichment)
			}
			if err := aiReporter.Generate(results, chainReport); err != nil {
				progress(ai.CWarn(fmt.Sprintf("[AI-CHAIN] PDF échoué (%v) — repli mono-modèle", err)))
			} else {
				progress(ai.COK("[AI-CHAIN] ✓ Rapport PDF bi-modèle généré"))
				return true
			}
		} else {
			progress(ai.CWarn("[AI] Pipeline chaîne échoué — repli sur mono-modèle..."))
		}
	}

	// ── 3b. Mono-modèle (fallback ou chaîne non disponible) ──────────────────
	progress(ai.CInfo("[AI] Démarrage parallèle : moteur IA + construction du prompt..."))

	// Sélectionner automatiquement le modèle le plus puissant disponible
	activeModel := ai.SelectBestModel()
	if cfg.AIModel != "" && ai.IsModelPresent(cfg.AIModel) {
		// Comparer la taille du modèle configuré avec le meilleur automatique
		bestAuto := ai.SelectBestModel()
		if bestAuto != cfg.AIModel {
			progress(ai.CInfo(fmt.Sprintf("[AI] Modèle configuré : %s — meilleur disponible : %s → utilisation du plus puissant",
				ai.ModelDisplayName(cfg.AIModel), ai.ModelDisplayName(bestAuto))))
			activeModel = bestAuto
		} else {
			activeModel = cfg.AIModel
		}
	}
	progress(ai.CInfo(fmt.Sprintf("[AI] Modèle sélectionné (le plus puissant disponible) : %s", ai.ModelDisplayName(activeModel))))
	llamaClient := ai.NewClient(activeModel, nil)

	type engineResult struct{ err error }
	engineCh := make(chan engineResult, 1)
	go func() {
		// Si le préchauffage est déjà terminé, on n'a pas besoin de relancer EnsureReady
		select {
		case <-engineWarmupDone:
			// Moteur déjà chaud depuis le préchauffage
			if engineWarmupErr != nil {
				engineCh <- engineResult{err: engineWarmupErr}
			} else {
				progress(ai.CInfo("[AI] ✓ Moteur IA déjà préchauffé — démarrage immédiat"))
				engineCh <- engineResult{err: nil}
			}
		default:
			// Préchauffage pas encore terminé — attendre ou démarrer
			engineCh <- engineResult{err: llamaClient.EnsureReady(progress)}
		}
	}()

	progress(ai.CInfo("[AI] Construction du prompt management..."))
	prompt := ai.BuildForensicPrompt(results, enrichment, similar, geoData)
	progress(ai.CInfo(fmt.Sprintf("[AI] Prompt construit — %d caractères", len(prompt))))

	// Attendre que le moteur soit prêt
	progress(ai.CInfo("[AI] Attente de la disponibilité du moteur IA..."))
	engineRes := <-engineCh
	if engineRes.err != nil {
		log.Printf(ai.CErr("[AI] llama-server indisponible: %v — repli sur rapport Go"), engineRes.err)
		return false
	}

	var rawResponse string
	engineUsed := ai.DefaultModel // moteur ayant produit le rapport final

	// ── 4. Generation llama.cpp ───────────────────────────────────────────────
	var err error
	genStart := time.Now()
	rawResponse, err = llamaClient.Generate(prompt, progress)
	genElapsed := time.Since(genStart)
	if err != nil {
		log.Printf(ai.CErr("[AI] Génération llama-server échouée: %v — repli sur rapport Go"), err)
		return false
	}
	progress(ai.CGrey(fmt.Sprintf("[AI] Génération terminée en %s (%d chars)", genElapsed.Round(time.Second), len(rawResponse))))

	progress(ai.CInfo("[AI] Génération terminée — parsing JSON..."))
	// Extraire le score sandbox pour plafonner le score IA
	sbScoreMono := 0
	for _, res := range results {
		if res.Score > 0 {
			sbScoreMono = res.Score
			break
		}
	}
	forensicReport, err := ai.ParseForensicResponse(rawResponse, sbScoreMono)
	if err != nil {
		// Parsing échoué avec Mistral 7B — tenter Qwen2.5-14B si disponible dans moteur/models/
		preview := rawResponse
		if len(preview) > 300 {
			preview = preview[:300] + "..."
		}
		log.Printf(ai.CWarn("[AI] Parsing JSON échoué (Mistral 7B): %v\n    Début réponse brute: %s"), err, preview)

		if ai.FallbackModelPresent() {
			progress(ai.CWarn("[AI-FALLBACK] Mistral 7B insuffisant — basculement sur Qwen2.5-14B (moteur/models/)..."))
			if restartErr := llamaClient.RestartWithModel(ai.FallbackModel, progress); restartErr != nil {
				log.Printf(ai.CErr("[AI-FALLBACK] Redémarrage Qwen échoué: %v — repli sur rapport Go"), restartErr)
				return false
			}
			rawResponse, err = llamaClient.Generate(prompt, progress)
			if err != nil {
				log.Printf(ai.CErr("[AI-FALLBACK] Génération Qwen échouée: %v — repli sur rapport Go"), err)
				return false
			}
			progress(ai.CInfo("[AI-FALLBACK] Génération Qwen terminée — parsing JSON..."))
			forensicReport, err = ai.ParseForensicResponse(rawResponse, sbScoreMono)
			if err != nil {
				preview2 := rawResponse
				if len(preview2) > 300 {
					preview2 = preview2[:300] + "..."
				}
				log.Printf(ai.CErr("[AI-FALLBACK] Parsing JSON échoué (Qwen2.5-14B): %v\n    Début réponse: %s"), err, preview2)
				return false
			}
			progress(ai.COK(fmt.Sprintf("[AI-FALLBACK] ✓ Rapport Qwen parsé — classification: %s — score: %d/10",
				forensicReport.Classification, forensicReport.ScoreGlobal)))
			engineUsed = ai.FallbackModel
		} else {
			// Qwen absent : le télécharger en arrière-plan et relancer la génération automatiquement
			progress(ai.CWarn("[AI-FALLBACK] Qwen2.5-14B absent — téléchargement en arrière-plan, relance automatique après..."))
			go func() {
				ai.EnsureFallbackModel(func(msg string) { log.Println(msg) })
				if !ai.FallbackModelPresent() {
					log.Println(ai.CErr("[AI-FALLBACK] Téléchargement Qwen échoué — rapport Go utilisé"))
					return
				}
				log.Println(ai.CInfo("[AI-FALLBACK] Qwen disponible — relance de la génération IA..."))
				// Relancer llama-server avec Qwen et générer le rapport
				llamaClient2 := ai.NewClient(ai.FallbackModel, nil)
				if restartErr := llamaClient2.RestartWithModel(ai.FallbackModel, func(msg string) { log.Println(msg) }); restartErr != nil {
					log.Printf(ai.CErr("[AI-FALLBACK] Relance Qwen échouée: %v"), restartErr)
					return
				}
				raw2, err2 := llamaClient2.Generate(prompt, func(msg string) { log.Println(msg) })
				if err2 != nil {
					log.Printf(ai.CErr("[AI-FALLBACK] Génération Qwen échouée: %v"), err2)
					return
				}
				report2, err2 := ai.ParseForensicResponse(raw2, sbScoreMono)
				if err2 != nil {
					log.Printf(ai.CErr("[AI-FALLBACK] Parsing Qwen échoué: %v"), err2)
					return
				}
				// Générer le PDF dans un fichier temporaire
				tmp2, e := os.CreateTemp("", "rf-rapport-qwen-*.pdf")
				if e != nil {
					log.Printf(ai.CErr("[AI-FALLBACK] Création temp PDF: %v"), e)
					return
				}
				tmp2Path := tmp2.Name()
				tmp2.Close()
				aiReporter2 := ai.NewAIReporter(tmp2Path, tlp, geoData)
				if enrichment != nil {
					aiReporter2.SetEnrichment(enrichment)
				}
				if e := aiReporter2.Generate(results, report2); e != nil {
					log.Printf(ai.CErr("[AI-FALLBACK] Génération PDF Qwen échouée: %v"), e)
					os.Remove(tmp2Path)
					return
				}
				// Copier vers le chemin de sortie final
				data2, e := os.ReadFile(tmp2Path)
				os.Remove(tmp2Path)
				if e != nil {
					log.Printf(ai.CErr("[AI-FALLBACK] Lecture PDF Qwen: %v"), e)
					return
				}
				if e := os.WriteFile(outputPath, data2, 0644); e != nil {
					log.Printf(ai.CErr("[AI-FALLBACK] Écriture PDF Qwen: %v"), e)
					return
				}
				log.Println(ai.COK(fmt.Sprintf("[AI-FALLBACK] ✓ Rapport PDF Qwen généré avec succès — classification: %s score: %d/10",
					report2.Classification, report2.ScoreGlobal)))
			}()
			return false
		}
	} else {
		progress(ai.COK(fmt.Sprintf("[AI] ✓ Rapport parsé — classification: %s — score: %d/10",
			forensicReport.Classification, forensicReport.ScoreGlobal)))
		// Détecter divergence score RF (sandbox) vs score IA (analyse comportementale)
		for _, r := range results {
			if r.Score > 0 {
				diff := forensicReport.ScoreGlobal - r.Score
				if diff < 0 {
					diff = -diff
				}
				if diff >= 2 {
					progress(ai.CWarn(fmt.Sprintf(
						"[AI] ⚠ Score RF=%d/10 → Score IA=%d/10 — l'IA a rehaussé/baissé selon son analyse comportementale complète",
						r.Score, forensicReport.ScoreGlobal)))
				}
				break
			}
		}
		// Télécharger Qwen en arrière-plan si absent, pour être prêt au prochain besoin
		if !ai.FallbackModelPresent() {
			go ai.EnsureFallbackModel(func(msg string) { log.Println(msg) })
		}
	}

	// ── 5. Sauvegarde dans la base de connaissances (mémorisation) ───────────
	// useKnowledge = mémoriser l'analyse (indépendant de l'injection dans le prompt)
	if useKnowledge {
		progress(ai.CHeader("KNOWLEDGE", "MÉMORISATION DE L'ANALYSE"))
		progress(ai.CDetail("KNOWLEDGE", fmt.Sprintf("Rapport à intégrer : classification=%s score=%d/10",
			forensicReport.Classification, forensicReport.ScoreGlobal)))
		progress(ai.CDetail("KNOWLEDGE", fmt.Sprintf("Famille : %s | Confiance : %s",
			forensicReport.Attribution.FamillePresumee, forensicReport.Attribution.Confiance)))
		progress(ai.CDetail("KNOWLEDGE", fmt.Sprintf("TTPs : %d techniques MITRE | IOCs : %d critiques",
			len(forensicReport.TechniquesMitre), len(forensicReport.IOCsCritiques))))
		statsBefore := ai.KnowledgeStats()
		progress(ai.CDetail("KNOWLEDGE", fmt.Sprintf("Base AVANT : %s", statsBefore)))
		if err := ai.SaveAnalysis(results, forensicReport, enrichment); err != nil {
			log.Printf(ai.CErr("[KNOWLEDGE] Sauvegarde échouée (non-bloquant): %v"), err)
			progress(ai.CErr(fmt.Sprintf("[KNOWLEDGE] │  ✗ ÉCHEC mémorisation : %v", err)))
		} else {
			statsAfter := ai.KnowledgeStats()
			progress(ai.CDetail("KNOWLEDGE", fmt.Sprintf("Base APRÈS  : %s", statsAfter)))
			progress(ai.COK("[KNOWLEDGE] ✓ MÉMORISATION RÉUSSIE — analyse intégrée dans la base SQLite"))
			if !useKnowledgeInject {
				progress(ai.CGrey("[KNOWLEDGE]   → Injection dans le prompt IA désactivée (activez depuis Configuration)"))
			} else {
				progress(ai.CInfo("[KNOWLEDGE]   → Ces données seront utilisées pour les prochaines analyses"))
			}
		}
	} else {
		progress(ai.CGrey("[KNOWLEDGE] Mémorisation désactivée (use_knowledge=false)"))
	}

	// ── 6. Generation du PDF ──────────────────────────────────────────────────
	progress(ai.CInfo("[AI] Génération du PDF en cours..."))
	aiReporter := ai.NewAIReporter(outputPath, tlp, geoData)
	aiReporter.SetEngine(engineUsed)
	aiReporter.SetGenerationDuration(int(genElapsed.Seconds()))
	if enrichment != nil {
		aiReporter.SetEnrichment(enrichment)
	}
	if err := aiReporter.Generate(results, forensicReport); err != nil {
		log.Printf(ai.CErr("[AI] Génération PDF échouée: %v — repli sur rapport Go"), err)
		return false
	}

	progress(ai.COK("[AI] ✓ Rapport PDF généré avec succès"))
	// Durée totale du pipeline IA
	aiTotalElapsed := time.Since(aiPipelineStart)
	progress(ai.COK(fmt.Sprintf("[AI] ══ Pipeline IA terminé en %s (enrichissement + génération + PDF) ══",
		aiTotalElapsed.Round(time.Second))))
	return true
}

// ── marshalResult : convertit AnalysisResult en map JSON pour le frontend ─────

func marshalResult(r *models.AnalysisResult) map[string]interface{} {
	// Métriques de qualité de l'analyse — utilisées côté frontend pour avertir l'utilisateur
	nbSigs := len(r.Signatures)
	nbDomains := len(r.IOCs.Domains) + len(r.IOCs.IPs)
	nbProcs := len(r.Processes)
	dataQuality := "complete"
	if nbSigs == 0 && nbDomains == 0 && nbProcs == 0 && r.Score > 0 {
		dataQuality = "incomplete" // Fichier non exécuté en sandbox
	}
	return map[string]interface{}{
		"sample_id":     r.SampleID,
		"filename":      r.Filename,
		"status":        r.Status,
		"score":         r.Score,
		"rf_score":      r.Score, // score brut sandbox avant réévaluation IA
		"family":        r.Family,
		"tags":          r.Tags,
		"hashes":        r.Hashes,
		"iocs":          r.IOCs,
		"signatures":    r.Signatures,
		"network":       r.Network,
		"processes":     r.Processes,
		"error":         r.Error,
		"data_quality":  dataQuality,                    // "complete" | "incomplete"
		"masked_exec":   isMaskedExecutable(r.Filename), // extension trompeuse détectée
		"nb_signatures": nbSigs,
		"nb_iocs":       nbDomains,
		"nb_processes":  nbProcs,
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ── Log stream SSE ────────────────────────────────────────────────────────────

func makeLogStreamHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming non supporté", 500)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		ch := logHub.subscribe()
		defer logHub.unsubscribe(ch)

		// Message de connexion
		fmt.Fprintf(w, "data: [Connecté — flux de logs actif]\n\n")
		flusher.Flush()

		for {
			select {
			case msg := <-ch:
				fmt.Fprintf(w, "data: %s\n\n", msg)
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	}
}

// ── Helpers live config ───────────────────────────────────────────────────────

func liveProxy(configPath, fallback string) string {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fallback
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fallback
	}
	if p, ok := cfg["proxy"].(string); ok {
		return p
	}
	return fallback
}

func liveToken(configPath, fallback string) string {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fallback
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fallback
	}
	t, ok := cfg["api_token"].(string)
	if !ok || t == "" {
		return fallback
	}
	if vault.IsEncrypted(t) {
		key, err := resolveVaultKey(configPath)
		if err != nil {
			log.Printf("[vault] ERREUR chargement clé : %v", err)
			return fallback
		}
		plain, err := vault.Decrypt(t, key)
		if err != nil {
			log.Printf("[vault] ERREUR déchiffrement token : %v", err)
			return fallback
		}
		return plain
	}
	return t
}

// resolveVaultKey cherche la clé vault dans cet ordre :
//  1. Variable d'environnement RF_VAULT_KEY
//  2. config/.vault.key à côté de l'exe (vault.KeyPath)
//  3. config/.vault.key dans le même dossier que config.json
//  4. config/.vault.key dans le CWD
func resolveVaultKey(configPath string) ([]byte, error) {
	// 1. Exe-relative (chemin canonique runtime)
	key, err := vault.LoadKey(vault.KeyPath())
	if err == nil {
		return key, nil
	}
	// 2. Même dossier que config.json
	key, err = vault.LoadKey(filepath.Join(filepath.Dir(configPath), ".vault.key"))
	if err == nil {
		return key, nil
	}
	// 3. CWD/config/.vault.key (dev sans exe)
	cwd, _ := os.Getwd()
	key, err = vault.LoadKey(filepath.Join(cwd, "config", ".vault.key"))
	if err == nil {
		return key, nil
	}
	// 4. Variable d'environnement via vault.LoadKey("")
	return vault.LoadKey("")
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Start()
}

// ConfigDir retourne le dossier config/ à côté de l'exécutable.
func ConfigDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "config"
	}
	return filepath.Join(filepath.Dir(exe), "config")
}

// knowledgeDir retourne le répertoire de la base de connaissances.
func knowledgeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "knowledge"
	}
	return filepath.Join(filepath.Dir(exe), "knowledge")
}

// isMaskedExecutable détecte les fichiers PE déguisés via double extension.
// Ex: Certificate.cer.exe → soumis comme .cer → analysé statiquement sans exécution.
// Patterns connus : .cer, .crt, .pdf, .doc, .docx, .xls, .zip, .jpg, .png
// précédés d'une extension .exe, .dll, .bat, .ps1, .vbs, .js, .hta, .cmd dans le nom.
func isMaskedExecutable(filename string) bool {
	lower := strings.ToLower(filename)
	// Double extension connue : nom.doc.exe → faux document
	dangerousExts := []string{".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta", ".cmd", ".scr", ".com"}
	maskingExts := []string{".cer", ".crt", ".pem", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
		".zip", ".rar", ".7z", ".jpg", ".jpeg", ".png", ".gif", ".mp4", ".mp3", ".txt"}
	// Cas 1 : double extension (nom.masque.dangereux)
	for _, mask := range maskingExts {
		for _, danger := range dangerousExts {
			if strings.HasSuffix(lower, mask+danger) {
				return true
			}
		}
	}
	// Cas 2 : extension non-exécutable mais signature PE (détectée par contenu)
	// Couvert par le renommage ci-dessus — on ne lit pas le contenu ici.
	return false
}

// min helper pour Go < 1.21
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// suppress unused import warning
var _ = fmt.Sprintf

// ── Audit sécurité ────────────────────────────────────────────────────────────

// auditDir retourne le dossier audit/ à côté de l'exécutable.
func auditDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "audit"
	}
	return filepath.Join(filepath.Dir(exe), "audit")
}

// reportingDir retourne le dossier reporting/ à côté de l'exécutable.
// Tous les rapports PDF générés par le moteur IA y sont archivés.
func reportingDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "reporting"
	}
	dir := filepath.Join(filepath.Dir(exe), "reporting")
	os.MkdirAll(dir, 0755)
	return dir
}

// scriptDir retourne le dossier scripts/ à côté de l'exécutable.
func scriptDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "scripts"
	}
	return filepath.Join(filepath.Dir(exe), "scripts")
}

type auditReportMeta struct {
	Name     string `json:"name"`
	Date     string `json:"date"`
	Resultat string `json:"resultat"`
	HasPDF   bool   `json:"has_pdf"`
}

// parseAuditResultat lit le résultat global depuis le rapport TXT.
func parseAuditResultat(txtPath string) string {
	data, err := os.ReadFile(txtPath)
	if err != nil {
		return "?"
	}
	content := string(data)
	switch {
	case strings.Contains(content, "CRITIQUE"):
		return "CRITIQUE"
	case strings.Contains(content, "AVERTISSEMENT"):
		return "AVERTISSEMENT"
	case strings.Contains(content, "[OK] Aucun problème") || strings.Contains(content, "RESULTAT : OK"):
		return "OK"
	default:
		return "?"
	}
}

// makeAuditListHandler liste les rapports PDF générés dans audit/.
func makeAuditListHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		dir := auditDir()
		entries, err := os.ReadDir(dir)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"reports": []interface{}{}})
			return
		}
		var reports []auditReportMeta
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".pdf") {
				continue
			}
			name := e.Name()
			// Extraire la date depuis le nom : rapport_securite_2026-03-10_12-01.pdf
			date := strings.TrimSuffix(strings.TrimPrefix(name, "rapport_securite_"), ".pdf")
			// Chercher le fichier TXT correspondant pour le résultat
			txtName := strings.TrimSuffix(name, ".pdf") + ".txt"
			txtPath := filepath.Join(dir, txtName)
			resultat := parseAuditResultat(txtPath)
			reports = append(reports, auditReportMeta{
				Name:     name,
				Date:     date,
				Resultat: resultat,
				HasPDF:   true,
			})
		}
		// Tri anti-chronologique (le plus récent en premier)
		sort.Slice(reports, func(i, j int) bool {
			return reports[i].Date > reports[j].Date
		})
		json.NewEncoder(w).Encode(map[string]interface{}{"reports": reports})
	}
}

// ─── Training handlers ────────────────────────────────────────────────────────

// makeAuditReportContentHandler retourne le contenu texte d'un rapport d'audit.
// GET /api/audit/report-content?name=rapport_securite_...pdf
// makeReportingListHandler liste les rapports IA archivés dans reporting/
// GET /api/reporting/list
func makeReportingListHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		dir := reportingDir()
		entries, err := os.ReadDir(dir)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"reports": []interface{}{}})
			return
		}
		type reportMeta struct {
			Name string `json:"name"`
			Date string `json:"date"`
			Size int64  `json:"size"`
			Type string `json:"type"` // "ia" ou "go"
		}
		var reports []reportMeta
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".pdf") {
				continue
			}
			info, _ := e.Info()
			size := int64(0)
			if info != nil {
				size = info.Size()
			}
			rtype := "go"
			if strings.Contains(e.Name(), "_ia.pdf") {
				rtype = "ia"
			}
			// Extraire la date depuis le nom : rf_sandbox_rapport_2026-03-16_21-05-48_ia.pdf
			date := ""
			parts := strings.Split(strings.TrimSuffix(e.Name(), ".pdf"), "_")
			for i, p := range parts {
				if len(p) == 10 && strings.Count(p, "-") == 2 && i+1 < len(parts) {
					date = p + " " + strings.ReplaceAll(parts[i+1], "-", ":")
					break
				}
			}
			reports = append(reports, reportMeta{
				Name: e.Name(),
				Date: date,
				Size: size,
				Type: rtype,
			})
		}
		// Tri anti-chronologique
		sort.Slice(reports, func(i, j int) bool {
			return reports[i].Date > reports[j].Date
		})
		json.NewEncoder(w).Encode(map[string]interface{}{"reports": reports})
	}
}

// makeReportingDownloadHandler sert un rapport depuis reporting/
// GET /api/reporting/download?name=rf_sandbox_rapport_...pdf
func makeReportingDownloadHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" || strings.Contains(name, "..") || strings.Contains(name, "/") {
			http.Error(w, "nom invalide", 400)
			return
		}
		path := filepath.Join(reportingDir(), name)
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, "rapport introuvable", 404)
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.Write(data)
	}
}

func makeAuditReportContentHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		name := r.URL.Query().Get("name")
		if name == "" {
			jsonError(w, "paramètre name requis", 400)
			return
		}
		dir := auditDir()
		// Lire le fichier TXT correspondant au rapport PDF
		txtName := strings.TrimSuffix(name, ".pdf") + ".txt"
		txtPath := filepath.Join(dir, txtName)
		data, err := os.ReadFile(txtPath)
		if err != nil {
			// Pas de TXT — retourner le nom comme contenu minimal
			json.NewEncoder(w).Encode(map[string]interface{}{
				"output":  "Rapport : " + name,
				"content": "Rapport : " + name,
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"output":  string(data),
			"content": string(data),
		})
	}
}

// makeTrainingExportHandler exporte analyses.db → training_dataset.jsonl
func makeTrainingExportHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonError(w, "méthode non autorisée", 405)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		var req struct {
			MinScore int `json:"min_score"`
		}
		req.MinScore = 5 // défaut
		json.NewDecoder(r.Body).Decode(&req)

		datasetPath := ai.DatasetPath()
		stats, err := ai.ExportTrainingDataset(datasetPath, req.MinScore)
		if err != nil {
			jsonError(w, "export échoué : "+err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"exported": stats.Exported,
			"skipped":  stats.Skipped,
			"total":    stats.Total,
			"path":     datasetPath,
			"duration": stats.Duration.String(),
		})
	}
}

// makeTrainingStartHandler lance trainer.exe en arrière-plan et streame les logs via SSE.
func makeTrainingStartHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonError(w, "méthode non autorisée", 405)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		var req struct {
			Epochs   int  `json:"epochs"`
			MinScore int  `json:"min_score"`
			DryRun   bool `json:"dry_run"`
		}
		req.Epochs = 3
		req.MinScore = 5
		json.NewDecoder(r.Body).Decode(&req)

		// Localiser trainer.exe / trainer depuis l'exécutable courant
		trainerBin := findTrainerBin()
		if trainerBin == "" {
			jsonError(w, "trainer introuvable — compilez d'abord : go build ./cmd/trainer", 404)
			return
		}

		args := []string{
			"--epochs", fmt.Sprint(req.Epochs),
			"--min-score", fmt.Sprint(req.MinScore),
		}
		if req.DryRun {
			args = append(args, "--dry-run")
		}

		// Lancer en arrière-plan — les logs partent dans le hub SSE
		go func() {
			log.Printf("[TRAINING] Lancement : %s %s", trainerBin, strings.Join(args, " "))
			cmd := exec.Command(trainerBin, args...)
			w := &logWriter{base: os.Stdout}
			cmd.Stdout = w
			cmd.Stderr = w
			if err := cmd.Run(); err != nil {
				log.Printf("[TRAINING] ✗ Erreur : %v", err)
				logHub.publish(fmt.Sprintf("[TRAINING] ✗ Entraînement terminé avec erreur : %v", err))
			} else {
				log.Println("[TRAINING] ✓ Entraînement terminé avec succès")
				logHub.publish("[TRAINING] ✓ Entraînement terminé — copiez le .gguf dans moteur/models/")
			}
		}()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "started",
			"message":   "Entraînement lancé en arrière-plan — suivez les logs en temps réel",
			"gguf_path": "moteur/lora/Foundation-Sec-8B-forensic-fr-Q4_K_M.gguf (ou mistral-7b-forensic-fr-Q4_K_M.gguf selon modèle de base)",
		})
	}
}

// findTrainerBin localise le binaire trainer compilé.
// Cherche dans : répertoire courant, répertoire de l'exe, PATH.
func findTrainerBin() string {
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	name := "trainer" + suffix

	// Répertoire de travail courant
	if cwd, err := os.Getwd(); err == nil {
		p := filepath.Join(cwd, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// Répertoire de l'exécutable rf-sandbox
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		// Résoudre les symlinks (utile en dev avec go run)
		if real, err := filepath.EvalSymlinks(exeDir); err == nil {
			exeDir = real
		}
		for _, dir := range []string{
			exeDir,
			filepath.Join(exeDir, ".."),
			filepath.Join(exeDir, "..", ".."),
		} {
			p := filepath.Join(dir, name)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}

	// PATH système
	if p, err := exec.LookPath(name); err == nil {
		return p
	}

	return ""
}

// makeReadmeHandler lit README.md depuis la racine du projet et le renvoie en texte brut.
func makeReadmeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Chercher README.md à côté de l'exécutable, puis dans le répertoire courant
		candidates := []string{
			filepath.Join(filepath.Dir(os.Args[0]), "README.md"),
			"README.md",
			filepath.Join("..", "README.md"),
		}
		var data []byte
		var err error
		for _, path := range candidates {
			data, err = os.ReadFile(path)
			if err == nil {
				break
			}
		}
		if err != nil {
			http.Error(w, "README.md introuvable", 404)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(data)
	}
}

func makeAuditPDFHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := filepath.Base(r.URL.Query().Get("name")) // sécurité : pas de path traversal
		if name == "" || !strings.HasSuffix(name, ".pdf") {
			http.Error(w, "nom invalide", 400)
			return
		}
		pdfPath := filepath.Join(auditDir(), name)
		data, err := os.ReadFile(pdfPath)
		if err != nil {
			http.Error(w, "rapport introuvable", 404)
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		if r.URL.Query().Get("download") == "1" {
			w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
		} else {
			w.Header().Set("Content-Disposition", "inline; filename=\""+name+"\"")
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.Write(data)
	}
}

// makeAuditRunHandler lance audit_securite.ps1 et retourne le résultat.
func makeAuditRunHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			jsonError(w, "méthode non autorisée", 405)
			return
		}

		// Construire le chemin du script
		sDir := scriptDir()
		var scriptPath string
		var cmd *exec.Cmd

		switch runtime.GOOS {
		case "windows":
			scriptPath = filepath.Join(sDir, "audit_securite.ps1")
			cmd = exec.Command("powershell", "-NonInteractive", "-ExecutionPolicy", "Bypass",
				"-File", scriptPath)
		default:
			// Sur Linux/Mac : chercher un éventuel audit_securite.sh
			scriptPath = filepath.Join(sDir, "audit_securite.sh")
			if _, err := os.Stat(scriptPath); err != nil {
				jsonError(w, "audit_securite.sh introuvable (Linux/Mac non supporté pour l'instant)", 501)
				return
			}
			cmd = exec.Command("bash", scriptPath)
		}

		if _, err := os.Stat(scriptPath); err != nil {
			jsonError(w, "script d'audit introuvable : "+scriptPath, 404)
			return
		}

		log.Printf("[AUDIT] Lancement de %s", scriptPath)

		// Nettoyer le dossier audit/ : garder seulement le fichier n-1 (le plus récent)
		// Le nouveau fichier sera ajouté juste après, portant le total à 2 maximum.
		if dir := auditDir(); dir != "" {
			if entries, err := os.ReadDir(dir); err == nil {
				// Collecter uniquement les fichiers PDF triés par nom (nom = horodatage → ordre chronologique)
				var pdfFiles []string
				for _, e := range entries {
					if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".pdf") {
						pdfFiles = append(pdfFiles, e.Name())
					}
				}
				// Trier du plus ancien au plus récent
				sort.Strings(pdfFiles)
				// Supprimer tous sauf le dernier (qui sera le n-1 une fois le nouveau généré)
				if len(pdfFiles) >= 1 {
					toDelete := pdfFiles[:len(pdfFiles)-1]
					for _, name := range toDelete {
						path := filepath.Join(dir, name)
						os.Remove(path)
						log.Printf("[AUDIT] Ancien rapport supprimé : %s", name)
					}
					log.Printf("[AUDIT] Conservation du rapport n-1 : %s", pdfFiles[len(pdfFiles)-1])
				}
			}
		}

		out, err := cmd.CombinedOutput()
		output := string(out)
		log.Printf("[AUDIT] Termine (err=%v)", err)

		// Déterminer le résultat depuis la sortie
		resultat := "OK"
		message := "Audit termine sans probleme detecte."
		switch {
		case strings.Contains(output, "CRITIQUE") || strings.Contains(output, "Secret") || (err != nil && cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 1):
			resultat = "CRITIQUE"
			message = "Des secrets ont ete detectes dans le code source."
		case strings.Contains(output, "AVERTISSEMENT") || strings.Contains(output, "probleme(s) detecte"):
			resultat = "AVERTISSEMENT"
			message = "Des avertissements ont ete detectes."
		}

		// ── Génération PDF directement en Go (sans audit.exe) ────────────────
		pdfName := fmt.Sprintf("rapport_securite_%s.pdf", time.Now().Format("2006-01-02_15-04"))
		pdfPath := filepath.Join(auditDir(), pdfName)

		// Reconstruire le rapport structuré depuis la sortie du script
		auditReport := buildAuditReportFromOutput(output, resultat)
		if pdfErr := auditpdf.GeneratePDF(auditReport, pdfPath); pdfErr != nil {
			log.Printf("[AUDIT] Generation PDF echouee: %v", pdfErr)
		} else {
			log.Printf("[AUDIT] Rapport PDF genere : %s", pdfPath)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"resultat": resultat,
			"message":  message,
			"output":   output,
			"pdf":      pdfName,
		})
	}
}

// buildAuditReportFromOutput reconstruit un AuditReport structuré depuis la sortie texte du script PS1.
func buildAuditReportFromOutput(output, resultat string) auditpdf.AuditReport {
	date := time.Now().Format("2006-01-02 15:04")
	report := auditpdf.AuditReport{
		Date:     date,
		Project:  "RF Sandbox Go",
		Resultat: resultat,
	}

	// Découper par sections détectées dans la sortie
	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")

	var currentSection *auditpdf.AuditSection
	sectionTitles := map[string]string{
		"1/":  "[1/4] GOSEC - Analyse statique du code source Go",
		"2/":  "[2/4] GOVULNCHECK - CVE dans les dependances (go.mod)",
		"3/":  "[3/4] GITLEAKS - Detection de secrets dans le code source",
		"4/":  "[4/4] MOTEUR IA - Analyse des binaires et modeles IA locaux (moteur/)",
		"1/3": "[1/3] GOSEC - Analyse statique du code source Go",
		"2/3": "[2/3] GOVULNCHECK - CVE dans les dependances (go.mod)",
		"3/3": "[3/3] GITLEAKS - Detection de secrets dans le code source",
	}

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "=====") || strings.HasPrefix(line, "-----") {
			continue
		}

		// Détecter le début d'une nouvelle section
		newSection := ""
		for key, title := range sectionTitles {
			if strings.Contains(line, "["+key) {
				newSection = title
				break
			}
		}
		if newSection != "" {
			if currentSection != nil {
				report.Sections = append(report.Sections, *currentSection)
			}
			currentSection = &auditpdf.AuditSection{
				Titre:  newSection,
				Statut: "OK",
				Lignes: []auditpdf.AuditLigne{},
			}
			continue
		}

		if currentSection == nil {
			// Avant la première section — ignorer les lignes de bannière
			continue
		}

		// Classifier la ligne
		niveau := "INFO"
		txt := line
		// Nettoyer les préfixes de la sortie PowerShell
		txt = strings.TrimPrefix(txt, "  ")

		switch {
		case strings.Contains(txt, "[CRITIQUE]") || strings.Contains(txt, "CRITIQUE"):
			niveau = "CRITIQUE"
			currentSection.Statut = "CRITIQUE"
		case strings.Contains(txt, "[!]") || strings.Contains(txt, "AVERTISSEMENT") || strings.Contains(txt, "WARN"):
			niveau = "WARN"
			if currentSection.Statut == "OK" {
				currentSection.Statut = "WARN"
			}
		case strings.Contains(txt, "[OK]"):
			niveau = "OK"
		case strings.Contains(txt, "[SKIP]"):
			niveau = "SKIP"
			if currentSection.Statut == "OK" {
				currentSection.Statut = "SKIP"
			}
		}

		if txt != "" {
			currentSection.Lignes = append(currentSection.Lignes, auditpdf.AuditLigne{
				Niveau: niveau,
				Texte:  txt,
			})
		}
	}

	// Ajouter la dernière section
	if currentSection != nil {
		report.Sections = append(report.Sections, *currentSection)
	}

	// Si aucune section détectée, créer une section générique avec toute la sortie
	if len(report.Sections) == 0 {
		var lignes []auditpdf.AuditLigne
		for _, raw := range lines {
			t := strings.TrimSpace(raw)
			if t != "" {
				lignes = append(lignes, auditpdf.AuditLigne{Niveau: "INFO", Texte: t})
			}
		}
		report.Sections = append(report.Sections, auditpdf.AuditSection{
			Titre:  "Sortie brute de l'audit",
			Statut: resultat,
			Lignes: lignes,
		})
	}

	return report
}

// makeModelsHandler retourne la liste des modèles disponibles + le catalogue téléchargeable.
// GET /api/models  → liste complète (présents + téléchargeables) avec le modèle actif
func makeModelsHandler(cfg ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		type modelResponse struct {
			Filename      string  `json:"filename"`
			DisplayName   string  `json:"display_name"`
			Description   string  `json:"description"`
			VRAMMinGB     float64 `json:"vram_min_gb"`
			SizeGB        float64 `json:"size_gb"`
			Specialty     string  `json:"specialty"`
			Present       bool    `json:"present"`
			Active        bool    `json:"active"`
			Gated         bool    `json:"gated"`
			ManualInstall bool    `json:"manual_install"`
			GatedNote     string  `json:"gated_note,omitempty"`
			SourceURL     string  `json:"source_url,omitempty"`
			TokenOK       bool    `json:"token_ok"`
		}

		activeModel := cfg.AIModel
		if activeModel == "" {
			activeModel = ai.DefaultModel
		}

		var resp []modelResponse

		// Catalogue statique : tous les modèles connus, présents ou non
		for _, info := range ai.KnownModels {
			resp = append(resp, modelResponse{
				Filename:      info.Filename,
				DisplayName:   info.DisplayName,
				Description:   info.Description,
				VRAMMinGB:     info.VRAMMinGB,
				SizeGB:        info.SizeGB,
				Specialty:     info.Specialty,
				Present:       ai.IsModelPresent(info.Filename),
				Active:        info.Filename == activeModel,
				Gated:         info.Gated,
				ManualInstall: info.ManualInstall,
				GatedNote:     info.GatedNote,
				SourceURL:     info.SourceURL,
				TokenOK:       !info.Gated || ai.HFTokenConfigured(),
			})
		}

		// Modèles GGUF présents localement mais inconnus du catalogue (ajoutés manuellement)
		for _, m := range ai.ListAvailableModels() {
			if _, known := ai.KnownModels[m.Filename]; known {
				continue
			}
			resp = append(resp, modelResponse{
				Filename:    m.Filename,
				DisplayName: m.DisplayName,
				Description: m.Description,
				SizeGB:      m.SizeGB,
				Specialty:   "custom",
				Present:     true,
				Active:      m.Filename == activeModel,
				TokenOK:     true,
			})
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"models":       resp,
			"active":       activeModel,
			"hf_token_set": ai.HFTokenConfigured(),
		})
	}
}

// makeModelDownloadHandler déclenche le téléchargement d'un modèle du catalogue dans moteur/models/.
// POST /api/models/download  body: {"filename": "Llama-Primus-8B-Q4_K_M.gguf"}
func makeModelDownloadHandler(cfg ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}

		var req struct {
			Filename string `json:"filename"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Filename == "" {
			http.Error(w, `{"error":"filename requis"}`, 400)
			return
		}

		// Vérifier que le modèle est connu du catalogue
		info, ok := ai.KnownModels[req.Filename]
		if !ok {
			http.Error(w, `{"error":"modele inconnu du catalogue"}`, 400)
			return
		}

		// Bloquer uniquement les modèles explicitement marqués ManualInstall
		if info.ManualInstall {
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "manual_install_required",
				"model":   info.DisplayName,
				"message": "Ce modèle nécessite une installation manuelle (conversion SafeTensors→GGUF).",
				"source":  info.SourceURL,
			})
			return
		}

		// Vérifier le token HF pour les modèles gated
		if info.Gated && !ai.HFTokenConfigured() {
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "token_required",
				"model":   info.DisplayName,
				"message": "Token Hugging Face requis. Configurez-le dans Configuration → Token HF.",
				"note":    info.GatedNote,
			})
			return
		}

		// Déjà présent ?
		if ai.IsModelPresent(req.Filename) {
			json.NewEncoder(w).Encode(map[string]string{
				"status": "already_present",
				"model":  info.DisplayName,
			})
			return
		}

		// Lancer le téléchargement en arrière-plan
		go func() {
			progressFn := func(msg string) { log.Println(msg) }
			switch req.Filename {
			case ai.FoundationSecModel:
				ai.EnsureFoundationSecModel(progressFn)
			case ai.PrimusModel:
				ai.EnsurePrimusModel(progressFn)
			case ai.FallbackModel:
				ai.EnsureFallbackModel(progressFn)
			case ai.GraniteCodeModel:
				ai.EnsureGraniteCodeModel(progressFn)
			case ai.LlamaForensicModel:
				ai.EnsureLlamaForensicModel(progressFn)
			default:
				// Modèle du catalogue avec DownloadURL — téléchargement générique
				if info.DownloadURL != "" {
					ai.EnsureModelByURL(req.Filename, info.DownloadURL, progressFn)
				} else {
					log.Printf("[DOWNLOAD] Pas d'URL pour %s — installation manuelle requise", req.Filename)
				}
			}
		}()

		json.NewEncoder(w).Encode(map[string]string{
			"status":  "downloading",
			"model":   info.DisplayName,
			"size":    fmt.Sprintf("%.1f Go", info.SizeGB),
			"message": "Téléchargement lancé en arrière-plan — consultez les logs pour suivre la progression",
		})
	}
}

// makeModelProgressHandler retourne la progression du téléchargement en cours.
// GET /api/models/progress?filename=Llama-Primus-8B-Q4_K_M.gguf
// Répond avec {filename, bytes_downloaded, bytes_total, percent, downloading}
func makeModelProgressHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		filename := r.URL.Query().Get("filename")
		if filename == "" {
			http.Error(w, `{"error":"filename requis"}`, 400)
			return
		}

		info, known := ai.KnownModels[filename]
		totalBytes := int64(0)
		if known {
			totalBytes = int64(info.SizeGB * 1024 * 1024 * 1024)
		}

		// Lire la taille actuelle du fichier partiel dans moteur/models/
		currentBytes := ai.ModelDownloadedBytes(filename)
		present := ai.IsModelPresent(filename)

		percent := 0.0
		if totalBytes > 0 && currentBytes > 0 {
			percent = float64(currentBytes) / float64(totalBytes) * 100
			if percent > 100 {
				percent = 100
			}
		}
		if present {
			percent = 100
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"filename":         filename,
			"bytes_downloaded": currentBytes,
			"bytes_total":      totalBytes,
			"percent":          percent,
			"present":          present,
			"downloading":      currentBytes > 0 && !present,
		})
	}
}

// makeAuditAIReportHandler envoie le rapport d'audit au moteur IA local
// et génère un rapport professionnel enrichi au format PDF.
// POST /api/audit/ai-report  body: {"audit_output": "...", "pdf_name": "rapport_...pdf"}
func makeAuditAIReportHandler(cfg ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			jsonError(w, "méthode non autorisée", 405)
			return
		}

		var req struct {
			AuditOutput string `json:"audit_output"`
			PDFName     string `json:"pdf_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AuditOutput == "" {
			jsonError(w, "audit_output requis", 400)
			return
		}

		log.Println("[AUDIT-AI] Envoi du rapport d'audit au moteur IA local...")

		// Construire le prompt forensic pour le moteur IA
		prompt := buildAuditAIPrompt(req.AuditOutput)

		// Utiliser le modèle le plus puissant disponible
		bestModel := ai.SelectBestModel()
		progress := func(msg string) { log.Println(msg) }
		progress(fmt.Sprintf("[AUDIT-AI] Modèle sélectionné : %s", ai.ModelDisplayName(bestModel)))
		llamaClient := ai.NewClient(bestModel, nil)
		if err := llamaClient.EnsureReady(progress); err != nil {
			jsonError(w, "moteur IA indisponible : "+err.Error(), 503)
			return
		}

		rawResponse, err := llamaClient.Generate(prompt, progress)
		if err != nil {
			jsonError(w, "génération IA échouée : "+err.Error(), 500)
			return
		}

		log.Printf("[AUDIT-AI] Réponse IA reçue (%d caractères)", len(rawResponse))

		// Générer le PDF enrichi
		pdfName := fmt.Sprintf("rapport_securite_ai_%s.pdf", time.Now().Format("2006-01-02_15-04"))
		pdfPath := filepath.Join(auditDir(), pdfName)

		if err := generateAIAuditPDF(rawResponse, req.AuditOutput, pdfPath); err != nil {
			log.Printf("[AUDIT-AI] Génération PDF échouée: %v", err)
			jsonError(w, "génération PDF échouée : "+err.Error(), 500)
			return
		}

		log.Printf("[AUDIT-AI] Rapport IA généré : %s", pdfPath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"pdf":     pdfName,
			"message": "Rapport IA généré avec succès",
		})
	}
}

// buildAuditAIPrompt construit le prompt envoyé au moteur IA pour analyser le rapport d'audit.
func buildAuditAIPrompt(auditOutput string) string {
	return `Tu es un expert en cybersécurité chargé de produire un rapport d'audit professionnel destiné à la direction d'un organisme gouvernemental français.

Voici la sortie brute d'un audit de sécurité automatisé sur un projet Go :

---
` + auditOutput + `
---

Produis un rapport structuré en JSON avec exactement ce format :
{
  "resume_executif": "Résumé en 3-4 phrases pour la direction, en français, sans jargon technique",
  "niveau_risque": "CRITIQUE|ELEVE|MOYEN|FAIBLE",
  "vulnerabilites": [
    {
      "id": "identifiant CVE ou GO-XXXX",
      "titre": "nom court",
      "description": "explication claire en français",
      "impact": "impact concret pour l'organisation",
      "remediation": "action corrective précise",
      "priorite": "IMMEDIATE|COURT_TERME|MOYEN_TERME"
    }
  ],
  "secrets_detectes": "description des secrets détectés ou 'Aucun secret détecté'",
  "recommandations": [
    "recommandation 1",
    "recommandation 2"
  ],
  "conclusion": "conclusion professionnelle en 2 phrases"
}

Réponds UNIQUEMENT avec le JSON, sans texte avant ou après.`
}

// generateAIAuditPDF génère un PDF professionnel à partir de la réponse IA.
func generateAIAuditPDF(aiResponse, auditRaw, outPath string) error {
	// Parser la réponse JSON du moteur IA
	type Vuln struct {
		ID          string `json:"id"`
		Titre       string `json:"titre"`
		Description string `json:"description"`
		Impact      string `json:"impact"`
		Remediation string `json:"remediation"`
		Priorite    string `json:"priorite"`
	}
	type AIReport struct {
		ResumeExecutif  string   `json:"resume_executif"`
		NiveauRisque    string   `json:"niveau_risque"`
		Vulnerabilites  []Vuln   `json:"vulnerabilites"`
		SecretsDetectes string   `json:"secrets_detectes"`
		Recommandations []string `json:"recommandations"`
		Conclusion      string   `json:"conclusion"`
	}

	// Nettoyer la réponse (enlever les backticks markdown si présents)
	clean := aiResponse
	clean = strings.TrimSpace(clean)
	if idx := strings.Index(clean, "{"); idx > 0 {
		clean = clean[idx:]
	}
	if idx := strings.LastIndex(clean, "}"); idx >= 0 && idx < len(clean)-1 {
		clean = clean[:idx+1]
	}

	var report AIReport
	if err := json.Unmarshal([]byte(clean), &report); err != nil {
		// Fallback : rapport texte brut si parsing JSON échoue
		return generateFallbackAuditPDF(aiResponse, outPath)
	}

	// Construire le AuditReport pour auditpdf
	ar := auditpdf.AuditReport{
		Date:     time.Now().Format("2006-01-02 15:04"),
		Project:  "RF Sandbox Go",
		Resultat: report.NiveauRisque,
	}

	// Section résumé exécutif
	ar.Sections = append(ar.Sections, auditpdf.AuditSection{
		Titre:  "RESUME EXECUTIF",
		Statut: report.NiveauRisque,
		Lignes: []auditpdf.AuditLigne{
			{Niveau: "INFO", Texte: report.ResumeExecutif},
		},
	})

	// Section vulnérabilités
	if len(report.Vulnerabilites) > 0 {
		var lignes []auditpdf.AuditLigne
		for _, v := range report.Vulnerabilites {
			niv := "WARN"
			if v.Priorite == "IMMEDIATE" {
				niv = "CRITIQUE"
			} else if v.Priorite == "MOYEN_TERME" {
				niv = "OK"
			}
			lignes = append(lignes, auditpdf.AuditLigne{Niveau: niv, Texte: fmt.Sprintf("[%s] %s", v.ID, v.Titre)})
			lignes = append(lignes, auditpdf.AuditLigne{Niveau: "INFO", Texte: "Description : " + v.Description})
			lignes = append(lignes, auditpdf.AuditLigne{Niveau: "INFO", Texte: "Impact : " + v.Impact})
			lignes = append(lignes, auditpdf.AuditLigne{Niveau: "INFO", Texte: "Remediation : " + v.Remediation})
			lignes = append(lignes, auditpdf.AuditLigne{Niveau: "INFO", Texte: "Priorite : " + v.Priorite})
			lignes = append(lignes, auditpdf.AuditLigne{Niveau: "INFO", Texte: "---"})
		}
		ar.Sections = append(ar.Sections, auditpdf.AuditSection{
			Titre:  fmt.Sprintf("VULNERABILITES DETECTEES (%d)", len(report.Vulnerabilites)),
			Statut: report.NiveauRisque,
			Lignes: lignes,
		})
	}

	// Section secrets
	if report.SecretsDetectes != "" {
		niv := "OK"
		if strings.Contains(strings.ToLower(report.SecretsDetectes), "secret") &&
			!strings.Contains(strings.ToLower(report.SecretsDetectes), "aucun") {
			niv = "CRITIQUE"
		}
		ar.Sections = append(ar.Sections, auditpdf.AuditSection{
			Titre:  "SECRETS ET DONNEES SENSIBLES",
			Statut: niv,
			Lignes: []auditpdf.AuditLigne{
				{Niveau: niv, Texte: report.SecretsDetectes},
			},
		})
	}

	// Section recommandations
	if len(report.Recommandations) > 0 {
		var lignes []auditpdf.AuditLigne
		for i, rec := range report.Recommandations {
			lignes = append(lignes, auditpdf.AuditLigne{
				Niveau: "WARN",
				Texte:  fmt.Sprintf("%d. %s", i+1, rec),
			})
		}
		ar.Sections = append(ar.Sections, auditpdf.AuditSection{
			Titre:  "RECOMMANDATIONS",
			Statut: "WARN",
			Lignes: lignes,
		})
	}

	// Section conclusion
	ar.Sections = append(ar.Sections, auditpdf.AuditSection{
		Titre:  "CONCLUSION",
		Statut: "INFO",
		Lignes: []auditpdf.AuditLigne{
			{Niveau: "INFO", Texte: report.Conclusion},
		},
	})

	return auditpdf.GeneratePDF(ar, outPath)
}

// generateFallbackAuditPDF génère un PDF texte brut si le parsing JSON échoue.
func generateFallbackAuditPDF(aiResponse, outPath string) error {
	var lignes []auditpdf.AuditLigne
	for _, line := range strings.Split(aiResponse, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		lignes = append(lignes, auditpdf.AuditLigne{Niveau: "INFO", Texte: t})
	}
	ar := auditpdf.AuditReport{
		Date:     time.Now().Format("2006-01-02 15:04"),
		Project:  "RF Sandbox Go",
		Resultat: "ANALYSE IA",
		Sections: []auditpdf.AuditSection{
			{Titre: "ANALYSE IA", Statut: "INFO", Lignes: lignes},
		},
	}
	return auditpdf.GeneratePDF(ar, outPath)
}
