package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joho/godotenv"

	"rf-sandbox-go/config"
	"rf-sandbox-go/internal/ai"
	"rf-sandbox-go/internal/client"
	"rf-sandbox-go/internal/models"
	"rf-sandbox-go/internal/reporter"
	"rf-sandbox-go/ui"
)

const version = "2.0.0"

func banner() {
	fmt.Print(`
╔══════════════════════════════════════════════════════════════════════╗
║  ██████╗ ███████╗    ███████╗ █████╗ ███╗  ██╗██████╗  ██████╗      ║
║  ██╔══██╗██╔════╝    ██╔════╝██╔══██╗████╗ ██║██╔══██╗██╔═══██╗     ║
║  ██████╔╝█████╗      ███████╗███████║██╔██╗██║██║  ██║██║   ██║     ║
║  ██╔══██╗██╔══╝      ╚════██║██╔══██║██║╚████║██║  ██║██║   ██║     ║
║  ██║  ██║██║         ███████║██║  ██║██║ ╚███║██████╔╝╚██████╔╝     ║
║         SANDBOX  API  ANALYSER  —  Go Edition  v` + version + `              ║
╚══════════════════════════════════════════════════════════════════════╝
`)
}

func usage() {
	fmt.Fprintf(os.Stderr, `
Usage:
  rf-sandbox [options]

Options:
  -token    string   Token API RF Sandbox (défaut: config/config.json)
  -proxy    string   Proxy HTTP d'entreprise (ex: http://proxy:8080) — NTLM auto
  -file     string   Fichier à analyser (répéter pour plusieurs fichiers)
  -url      string   URL à analyser (répéter pour plusieurs URLs)
  -batch    string   Fichier texte : un fichier/URL par ligne
  -id       string   ID sandbox existant à récupérer (répéter pour plusieurs)
  -output   string   Chemin du rapport PDF (défaut: output/rapport_<date>.pdf)
  -json     string   Exporter les résultats bruts en JSON
  -class    string   Classification TLP (défaut: TLP:WHITE)
  -private  bool     Soumission privée (défaut: true)
  -ui                Ouvrir l'interface graphique web
  -demo              Générer un rapport de démonstration sans API
  -version           Afficher la version
  -help              Afficher cette aide

Gestion des règles YARA :
  -yara-list         Lister les règles YARA configurées dans RF Sandbox
  -yara-upload file  Uploader une règle YARA (.yara) dans RF Sandbox
  -yara-delete name  Supprimer une règle YARA par son nom

Exemples:
  rf-sandbox -ui
  rf-sandbox -demo
  rf-sandbox -file malware.exe -file trojan.dll
  rf-sandbox -url https://evil.com/payload
  rf-sandbox -batch targets.txt -output rapport.pdf
  rf-sandbox -id 230615-abc12emotet -id 230710-xyz99ransom
  rf-sandbox -file sample.exe -proxy http://proxy.corp.fr:8080
  rf-sandbox -yara-list
  rf-sandbox -yara-upload rules/emotet.yara
  rf-sandbox -yara-delete emotet.yara

`)
}

// MultiFlag permet de répéter un flag plusieurs fois
type MultiFlag []string

func (m *MultiFlag) String() string     { return strings.Join(*m, ", ") }
func (m *MultiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	banner()

	if err := godotenv.Load(); err != nil {
		log.Println("pas de .env, utilisation des variables d'environnement")
	}

	var (
		token     = flag.String("token", "", "Token API")
		proxy     = flag.String("proxy", config.App.Proxy, "Proxy HTTP (host:port)")
		output    = flag.String("output", "", "Chemin du rapport PDF")
		jsonOut   = flag.String("json", "", "Chemin du fichier JSON de sortie")
		class     = flag.String("class", "TLP:WHITE", "Classification TLP")
		private   = flag.Bool("private", true, "Soumission privée")
		demo      = flag.Bool("demo", false, "Mode démonstration")
		uiMode    = flag.Bool("ui", false, "Ouvrir l'interface graphique web")
		showVer   = flag.Bool("version", false, "Afficher la version")
		showHelp  = flag.Bool("help", false, "Afficher l'aide")
		batchFile = flag.String("batch", "", "Fichier batch")
		// Gestion des règles YARA
		yaraList   = flag.Bool("yara-list", false, "Lister les règles YARA configurées dans RF Sandbox")
		yaraUpload = flag.String("yara-upload", "", "Uploader une règle YARA (chemin vers le fichier .yara)")
		yaraDelete = flag.String("yara-delete", "", "Supprimer une règle YARA par son nom")
	)

	var files, urls, ids MultiFlag
	flag.Var(&files, "file", "Fichier à analyser (répétable)")
	flag.Var(&urls, "url", "URL à analyser (répétable)")
	flag.Var(&ids, "id", "ID sandbox existant (répétable)")

	flag.Usage = usage
	flag.Parse()

	if *showHelp {
		usage()
		os.Exit(0)
	}
	if *showVer {
		fmt.Printf("rf-sandbox v%s\n", version)
		os.Exit(0)
	}

	// ── Mode : Interface graphique ──────────────────────────────────────────
	if *uiMode {
		exe, _ := os.Executable()
		configDir := filepath.Join(filepath.Dir(exe), "config")

		ui.Start(ui.ServerConfig{
			APIToken:       config.App.APIToken,
			Proxy:          config.App.Proxy,
			UIPort:         config.App.UIPort,
			ConfigPath:     filepath.Join(configDir, "config.json"),
			AbuseIPDBKey:   config.App.AbuseIPDBKey,
			SandboxTimeout: config.App.SandboxTimeout,
			SandboxNetwork: config.App.SandboxNetwork,
			AIModel:        config.App.AIModel,
			HFToken:        config.App.HFToken,
		})
		return
	}

	// Résoudre le token
	tok := *token
	if tok == "" {
		tok = os.Getenv("RF_SANDBOX_TOKEN")
	}
	if tok == "" {
		tok = config.App.APIToken
	}
	if tok == "" {
		log.Fatal("token manquant : définir -token, RF_SANDBOX_TOKEN dans .env ou api_token dans config/config.json")
	}

	// Proxy
	proxyAddr := *proxy
	if proxyAddr == "" {
		proxyAddr = os.Getenv("HTTP_PROXY")
	}

	// ── Client API (réutilisé pour toutes les opérations) ──────────────────
	c := client.NewWithProxy(tok, proxyAddr)
	c.SetAnalysisOptions(config.App.SandboxTimeout, config.App.SandboxNetwork)

	// ── Mode : Gestion YARA ─────────────────────────────────────────────────
	if *yaraList {
		rules, err := c.ListYaraRules()
		if err != nil {
			log.Fatalf("Erreur liste YARA : %v", err)
		}
		if len(rules) == 0 {
			fmt.Println("  Aucune règle YARA configurée.")
		} else {
			fmt.Printf("  %d règle(s) YARA :\n", len(rules))
			for _, r := range rules {
				status := "✓"
				if r.Error != "" {
					status = "✗ (erreur: " + r.Error + ")"
				}
				fmt.Printf("    %s  %s\n", status, r.Name)
			}
		}
		return
	}

	if *yaraUpload != "" {
		content, err := os.ReadFile(*yaraUpload)
		if err != nil {
			log.Fatalf("Impossible de lire '%s' : %v", *yaraUpload, err)
		}
		name := filepath.Base(*yaraUpload)
		if err := c.UploadYaraRule(name, string(content)); err != nil {
			log.Fatalf("Erreur upload YARA : %v", err)
		}
		fmt.Printf("  ✓ Règle YARA '%s' uploadée avec succès\n", name)
		return
	}

	if *yaraDelete != "" {
		if err := c.DeleteYaraRule(*yaraDelete); err != nil {
			log.Fatalf("Erreur suppression YARA : %v", err)
		}
		fmt.Printf("  ✓ Règle YARA '%s' supprimée\n", *yaraDelete)
		return
	}

	// Chemin de sortie PDF
	outPath := *output
	if outPath == "" {
		ts := time.Now().UTC().Format("20060102_150405")
		if err := os.MkdirAll("output", 0755); err != nil {
			log.Fatalf("Impossible de créer le dossier output : %v", err)
		}
		outPath = filepath.Join("output", fmt.Sprintf("rf_sandbox_rapport_%s.pdf", ts))
	}

	var results []*models.AnalysisResult

	if *demo {
		// ── Mode démonstration ─────────────────────────────────────────
		fmt.Println("Mode DÉMONSTRATION — génération avec données simulées...\n")
		results = demoResults()

	} else if len(ids) > 0 {
		// ── Récupération d'IDs existants ───────────────────────────────
		for _, id := range ids {
			fmt.Printf("  → Récupération de %s...\n", id)
			results = append(results, c.FetchExisting(id))
		}

	} else {
		// ── Analyse de nouveaux targets ────────────────────────────────
		targets := []string{}
		targets = append(targets, files...)
		targets = append(targets, urls...)

		if *batchFile != "" {
			batchTargets, err := loadBatchFile(*batchFile)
			if err != nil {
				log.Fatalf("Erreur lecture batch : %v", err)
			}
			targets = append(targets, batchTargets...)
		}

		if len(targets) == 0 {
			fmt.Fprintln(os.Stderr, "[ERREUR] Aucune cible. Utilisez -file, -url, -batch, -ui ou -demo")
			usage()
			os.Exit(1)
		}

		fmt.Printf("  → %d cible(s) à analyser\n\n", len(targets))
		results = c.AnalyzeBatch(targets, *private)
	}

	// ── Affichage résumé console ────────────────────────────────────────
	fmt.Printf("\n%s\n  RÉSULTATS\n%s\n",
		strings.Repeat("═", 65), strings.Repeat("═", 65))
	for _, r := range results {
		icon := "✓"
		if r.Status != "reported" {
			icon = "✗"
		}
		name := r.Filename
		if len(name) > 44 {
			name = "…" + name[len(name)-43:]
		}
		tags := strings.Join(r.Tags, ", ")
		if len(tags) > 30 {
			tags = tags[:30] + "…"
		}
		fmt.Printf("  %s  %-46s Score: %2d/10  %s\n", icon, name, r.Score, tags)
	}
	fmt.Println(strings.Repeat("═", 65))

	// ── Export JSON ─────────────────────────────────────────────────────
	if *jsonOut != "" {
		if err := exportJSON(results, *jsonOut); err != nil {
			log.Printf("Erreur export JSON : %v", err)
		} else {
			fmt.Printf("\n  ✓ JSON exporté : %s\n", *jsonOut)
		}
	}

	// ── Enrichissement MITRE ATT&CK + AbuseIPDB + GeoIP + MalwareBazaar ───
	var enrichment *ai.EnrichmentData
	{
		// Collecter tous les TTPs, IPs et hashes de tous les résultats
		ttpSet := make(map[string]bool)
		ipSet := make(map[string]bool)
		hashSet := make(map[string]bool)
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
			// Hashes : fichier principal + fichiers droppés
			if r.Hashes.SHA256 != "" {
				hashSet[r.Hashes.SHA256] = true
			}
			for _, df := range r.DroppedFiles {
				if df.SHA256 != "" {
					hashSet[df.SHA256] = true
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
		hashes := make([]string, 0, len(hashSet))
		for h := range hashSet {
			hashes = append(hashes, h)
		}

		enrichClient := ai.NewEnrichClient(config.App.AbuseIPDBKey)
		enrichment = enrichClient.Enrich(ttpIDs, ips, func(msg string) {
			fmt.Printf("  %s\n", msg)
		})

		// MalwareBazaar : enrichissement des hashes (API publique, sans clé)
		if len(hashes) > 0 {
			fmt.Printf("  → Enrichissement MalwareBazaar pour %d hash(es)...\n", len(hashes))
			mbResults := enrichClient.EnrichHashes(hashes, func(msg string) {
				fmt.Printf("  %s\n", msg)
			})
			enrichment.MalwareBazaar = mbResults
		}

		// Enrichissement GeoIP
		if config.App.UseGeoIP || len(ips) > 0 {
			geoClient := ai.NewGeoClient(true)
			geoData := geoClient.LookupBatch(ips, func(msg string) {
				fmt.Printf("  %s\n", msg)
			})
			enrichment.GeoData = geoData
		}
	}

	// ── Génération PDF ──────────────────────────────────────────────────
	fmt.Printf("\n  → Génération du rapport PDF : %s\n", outPath)
	gen := reporter.New(outPath, *class)
	if err := gen.Generate(results, enrichment); err != nil {
		log.Fatalf("Erreur génération PDF : %v", err)
	}
	fmt.Printf("  ✓ Rapport généré avec succès : %s\n", outPath)
	fmt.Printf("    %d échantillon(s)  |  Classification : %s\n\n", len(results), *class)
}

// ─── Helpers ───────────────────────────────────────────────────────────────

func loadBatchFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var targets []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	return targets, scanner.Err()
}

func exportJSON(results []*models.AnalysisResult, path string) error {
	type exportEntry struct {
		SampleID   string           `json:"sample_id"`
		Filename   string           `json:"filename"`
		Status     string           `json:"status"`
		Score      int              `json:"score"`
		Family     string           `json:"family,omitempty"`
		Tags       []string         `json:"tags"`
		Hashes     models.Hashes    `json:"hashes"`
		IOCs       models.IOCBundle `json:"iocs"`
		Signatures int              `json:"signatures_count"`
		Error      string           `json:"error,omitempty"`
	}
	entries := make([]exportEntry, 0, len(results))
	for _, r := range results {
		entries = append(entries, exportEntry{
			SampleID:   r.SampleID,
			Filename:   r.Filename,
			Status:     r.Status,
			Score:      r.Score,
			Family:     r.Family,
			Tags:       r.Tags,
			Hashes:     r.Hashes,
			IOCs:       r.IOCs,
			Signatures: len(r.Signatures),
			Error:      r.Error,
		})
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

// ─── Données de démonstration ──────────────────────────────────────────────

func demoResults() []*models.AnalysisResult {
	return []*models.AnalysisResult{
		{
			SampleID: "230615-abc12emotet",
			Filename: "invoice_Q2_2024.doc",
			Status:   "reported",
			Score:    10,
			Family:   "emotet",
			Tags:     []string{"trojan", "banker", "spyware", "persistence", "evasion", "family:emotet"},
			Hashes: models.Hashes{
				MD5:    "3e241f5a1e7be77f25078560c8660351",
				SHA1:   "ba25c371e75d1a52c1f41c163dc8840626423948",
				SHA256: "22d653dab4765e13c5fce0bf46a28a098d05582148fdf3101093f3687b42a5f1",
			},
			Signatures: []models.AggregatedSignature{
				{TaskID: "behavioral1", Signature: models.Signature{
					Name: "martian_command", Label: "Suspicious Command Execution",
					Score: 10, Tags: []string{"trojan", "evasion"}, TTP: []string{"T1059", "T1055"},
					Desc: "Executable spawned from Office document via cmd.exe",
				}},
				{TaskID: "behavioral1", Signature: models.Signature{
					Name: "network_cnc_http", Label: "C2 Communication over HTTP",
					Score: 9, Tags: []string{"trojan", "cnc"}, TTP: []string{"T1071"},
					Desc: "HTTP requests to known C2 infrastructure",
				}},
				{TaskID: "behavioral1", Signature: models.Signature{
					Name: "autostart_registry", Label: "Registry Persistence (Run Key)",
					Score: 8, Tags: []string{"persistence"}, TTP: []string{"T1547"},
					Desc: "Writes to HKCU\\Run for persistence",
				}},
			},
			IOCs: models.IOCBundle{
				IPs:     []string{"185.220.101.45", "91.108.4.105"},
				Domains: []string{"cdn-delivery-fast.com", "telemetry-api.xyz"},
				URLs:    []string{"http://185.220.101.45/gate.php"},
			},
		},
		{
			SampleID: "230710-xyz99ransom",
			Filename: "update_security_patch.exe",
			Status:   "reported",
			Score:    10,
			Family:   "lockbit",
			Tags:     []string{"ransomware", "trojan", "persistence", "family:lockbit"},
			Hashes: models.Hashes{
				MD5:    "7f83b1657ff1fc53b92dc18148a1d65d",
				SHA1:   "0ade7c2cf97f75d009975f4d720d1fa6c19f4897",
				SHA256: "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
			},
			Signatures: []models.AggregatedSignature{
				{TaskID: "behavioral1", Signature: models.Signature{
					Name: "ransomware_extensions", Label: "Mass File Encryption",
					Score: 10, Tags: []string{"ransomware"}, TTP: []string{"T1486"},
					Desc: "Encrypts files with custom extension .lockbit3",
				}},
			},
			IOCs: models.IOCBundle{
				IPs:     []string{"198.51.100.22"},
				Domains: []string{"lockbit-stats-report.onion.ly"},
			},
		},
	}
}
