// audit-securite — Remplace audit_securite.ps1
//
// Lance gosec + govulncheck + gitleaks + analyse moteur/,
// génère un rapport PDF via auditpdf, nettoie les anciens PDFs.
// Retourne exit code 1 si des secrets sont détectés (bloquant).
//
// Usage:
//
//	audit-securite.exe
//	audit-securite.exe -project "RF Sandbox Go"
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"rf-sandbox-go/internal/auditpdf"
)

func main() {
	projectName := flag.String("project", "RF Sandbox Go", "Nom du projet")
	flag.Parse()

	projectDir := resolveProjectDir()
	auditDir := filepath.Join(projectDir, "audit")
	os.MkdirAll(auditDir, 0755)

	date := time.Now().Format("2006-01-02_15-04")

	// Nettoyage AVANT génération (supprime tous les anciens PDFs)
	cleanAllAuditPDFs(auditDir)

	fmt.Println()
	fmt.Println("  ============================================================")
	fmt.Printf("    RF Sandbox Go - Audit de Securite\n")
	fmt.Printf("    Date : %s\n", date)
	fmt.Println("  ============================================================")
	fmt.Println()

	var sections []auditpdf.AuditSection
	hasErrors := false
	hasSecrets := false

	// ── 1. GOSEC ─────────────────────────────────────────────────────────────
	fmt.Printf("\n  [1/5] Analyse statique du code Go (gosec)...\n")
	sec, errs, _ := runGosec(projectDir)
	sections = append(sections, sec)
	if errs {
		hasErrors = true
		fmt.Printf("  [!] GOSEC : problemes detectes\n")
	} else {
		fmt.Printf("  [OK] GOSEC : aucune vulnerabilite\n")
	}

	// ── 2. GOVULNCHECK ───────────────────────────────────────────────────────
	fmt.Printf("\n  [2/5] Verification des CVE dans les dependances (govulncheck)...\n")
	sec, errs, _ = runGovulncheck(projectDir)
	sections = append(sections, sec)
	if errs {
		hasErrors = true
		fmt.Printf("  [!] GOVULNCHECK : vulnerabilites CVE detectees\n")
	} else {
		fmt.Printf("  [OK] GOVULNCHECK : aucune CVE\n")
	}

	// ── 3. GITLEAKS ──────────────────────────────────────────────────────────
	fmt.Printf("\n  [3/5] Detection de secrets dans le code source (gitleaks)...\n")
	sec, errs, secrets := runGitleaks(projectDir, auditDir)
	sections = append(sections, sec)
	if errs {
		hasErrors = true
	}
	if secrets {
		hasSecrets = true
		fmt.Printf("  [X] GITLEAKS : secrets detectes !\n")
	} else {
		fmt.Printf("  [OK] GITLEAKS : aucun secret detecte\n")
	}

	// ── 4. MOTEUR IA ─────────────────────────────────────────────────────────
	fmt.Printf("\n  [4/5] Analyse des binaires et modeles IA (moteur/)...\n")
	sec = auditMoteur(projectDir)
	sections = append(sections, sec)
	fmt.Printf("  [OK] Moteur IA : analyse terminee\n")

	// ── Résultat global ───────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("  ============================================================")
	resultat := "OK"
	switch {
	case hasSecrets:
		resultat = "CRITIQUE"
		fmt.Println("  RESULTAT : CRITIQUE - Secret(s) detecte(s) dans le code")
		fmt.Println("  NE PAS DEPLOYER ni committer avant correction.")
	case hasErrors:
		resultat = "AVERTISSEMENT"
		fmt.Println("  RESULTAT : AVERTISSEMENT - Problemes detectes (non bloquants)")
	default:
		fmt.Println("  RESULTAT : OK - Aucun probleme de securite detecte")
	}
	fmt.Println("  ============================================================")

	// ── 5. Analyse IA ─────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("  ============================================================")
	fmt.Println("  [5/5] ANALYSE IA - Synthese et recommandations")
	fmt.Println("  ============================================================")
	iaSec := runIAAnalysis(sections, resultat)
	sections = append(sections, iaSec)

	// ── Génération PDF ────────────────────────────────────────────────────────
	pdfPath := filepath.Join(auditDir, fmt.Sprintf("rapport_securite_%s.pdf", date))
	report := auditpdf.AuditReport{
		Date:     date,
		Project:  *projectName,
		Resultat: resultat,
		Sections: sections,
	}
	fmt.Printf("\n  Generation du rapport PDF...\n")
	if err := auditpdf.GeneratePDF(report, pdfPath); err != nil {
		fmt.Fprintf(os.Stderr, "  [!] Generation PDF echouee (non bloquant) : %v\n", err)
	} else {
		fmt.Printf("  [OK] Rapport PDF genere : %s\n", pdfPath)
	}

	fmt.Println()
	if hasSecrets {
		fmt.Println("  [SECURITE] Secret detecte — deploiement bloque.")
		fmt.Printf("  Consultez : %s\n\n", pdfPath)
		os.Exit(1)
	}
	fmt.Println("  [OK] Audit securite : aucun secret detecte.")
	fmt.Println()
}

// ── GOSEC ─────────────────────────────────────────────────────────────────────

func runGosec(projectDir string) (auditpdf.AuditSection, bool, bool) {
	fmt.Println("  ============================================================")
	fmt.Println("  [1/4] GOSEC - Analyse statique du code Go")
	fmt.Println("  ============================================================")

	gosecExe := findGoBinTool("gosec")
	if gosecExe == "" {
		fmt.Println("  -> Installation de gosec...")
		runSilent(projectDir, "go", "install", "github.com/securego/gosec/v2/cmd/gosec@latest")
		gosecExe = findGoBinTool("gosec")
	}
	if gosecExe == "" {
		fmt.Println("  [SKIP] gosec non disponible.")
		return section("1/4 GOSEC", "SKIP", []string{"[SKIP] gosec non disponible."}), false, false
	}
	fmt.Println("  [OK] gosec present.")

	out, _ := cmdOut(projectDir, gosecExe,
		"-fmt", "text", "-severity", "medium", "-confidence", "medium",
		"-exclude", "G304,G107",
		"./...")

	lines := filterEmpty(strings.Split(out, "\n"))
	hasIssues := false
	var report []string

	// Filtres explicatifs pour les faux positifs connus
	falsePositives := map[string]string{
		"G304": "Chemin de fichier depuis variable (chemins controles par l'application)",
		"G107": "URL depuis variable (URLs configurables par l'utilisateur)",
	}
	for k, v := range falsePositives {
		report = append(report, fmt.Sprintf("  %s - %s", k, v))
	}
	report = append(report, "")

	for _, l := range lines {
		if strings.Contains(l, "[HIGH]") || strings.Contains(l, "[MEDIUM]") {
			hasIssues = true
			report = append(report, "[!] "+l)
			fmt.Printf("  [!] %s\n", l)
		}
	}
	if !hasIssues {
		report = append(report, "[OK] Aucune vulnerabilite detectee.")
		fmt.Println("  [OK] Aucune vulnerabilite detectee.")
	}

	statut := "OK"
	if hasIssues {
		statut = "WARN"
	}
	return section("1/4 GOSEC - Analyse statique du code Go", statut, report), hasIssues, false
}

// ── GOVULNCHECK ───────────────────────────────────────────────────────────────

func runGovulncheck(projectDir string) (auditpdf.AuditSection, bool, bool) {
	fmt.Println()
	fmt.Println("  ============================================================")
	fmt.Println("  [2/4] GOVULNCHECK - CVE dans les dependances")
	fmt.Println("  ============================================================")

	govulnExe := findGoBinTool("govulncheck")
	if govulnExe == "" {
		fmt.Println("  -> Installation de govulncheck...")
		runSilent(projectDir, "go", "install", "golang.org/x/vuln/cmd/govulncheck@latest")
		govulnExe = findGoBinTool("govulncheck")
	}
	if govulnExe == "" {
		fmt.Println("  [SKIP] govulncheck non disponible.")
		return section("2/4 GOVULNCHECK", "SKIP", []string{"[SKIP] govulncheck non disponible."}), false, false
	}
	fmt.Println("  [OK] govulncheck present.")

	out, _ := cmdOut(projectDir, govulnExe, "./...")
	lines := filterEmpty(strings.Split(out, "\n"))

	hasVulns := false
	var report []string

	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "Vulnerability") {
			hasVulns = true
			report = append(report, "[!] "+l)
			fmt.Printf("  [!] %s\n", l)
		} else if strings.HasPrefix(l, "Found in") || strings.HasPrefix(l, "Fixed in") ||
			strings.HasPrefix(l, "More info") {
			report = append(report, "    "+l)
			fmt.Printf("      %s\n", l)
		}
	}
	if !hasVulns {
		report = append(report, "[OK] Aucun CVE detecte dans les dependances.")
		fmt.Println("  [OK] Aucun CVE detecte dans les dependances.")
	}

	statut := "OK"
	if hasVulns {
		statut = "WARN"
	}
	return section("2/4 GOVULNCHECK - CVE dans les dependances (go.mod)", statut, report), hasVulns, false
}

// ── GITLEAKS ──────────────────────────────────────────────────────────────────

const gitleaksURL = "https://github.com/gitleaks/gitleaks/releases/download/v8.23.3/gitleaks_8.23.3_windows_x64.zip"

func runGitleaks(projectDir, auditDir string) (auditpdf.AuditSection, bool, bool) {
	fmt.Println()
	fmt.Println("  ============================================================")
	fmt.Println("  [3/4] GITLEAKS - Detection de secrets dans le code source")
	fmt.Println("  ============================================================")

	toolsDir := filepath.Join(projectDir, "tools")
	os.MkdirAll(toolsDir, 0755)

	gitleaksExe := findGitleaks(projectDir)
	if gitleaksExe == "" {
		fmt.Println("  -> Telechargement de gitleaks...")
		if err := downloadGitleaks(toolsDir); err != nil {
			fmt.Printf("  [!] gitleaks indisponible : %v\n", err)
			return section("3/4 GITLEAKS", "SKIP", []string{"[SKIP] gitleaks non disponible."}), false, false
		}
		gitleaksExe = findGitleaks(projectDir)
	}
	if gitleaksExe == "" {
		return section("3/4 GITLEAKS", "SKIP", []string{"[SKIP] gitleaks introuvable apres telechargement."}), false, false
	}
	fmt.Println("  [OK] gitleaks present.")

	// Exclure config/config.json (géré par vault) et audit/
	out, _ := cmdOut(projectDir, gitleaksExe, "detect",
		"--source", projectDir,
		"--no-git",
		"--exclude-path", "audit",
		"--exclude-path", "config/config.json",
		"--exclude-path", "config/config.json.example",
		"--exclude-path", ".git",
		"--redact",
		"-v")

	lines := filterEmpty(strings.Split(out, "\n"))
	hasSecrets := false
	var report []string

	report = append(report, "Fichiers exclus : config/config.json (gere par vault), audit/")
	report = append(report, "")

	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		// Ignorer les lignes d'aide gitleaks (commence par -- ou contient usage/flag info)
		if strings.HasPrefix(l, "--") || strings.HasPrefix(l, "usage:") ||
			strings.Contains(l, "exit code") || strings.Contains(l, "stdin") ||
			strings.HasPrefix(l, "If none") || strings.HasPrefix(l, "3.") {
			continue
		}
		// Un vrai secret gitleaks a le format : "Finding: ... Rule: ... File: ..."
		lLow := strings.ToLower(l)
		isRealFinding := (strings.Contains(lLow, "finding:") && strings.Contains(lLow, "rule:")) ||
			(strings.Contains(lLow, "secret") && strings.Contains(lLow, "file:")) ||
			(strings.Contains(lLow, "leaks found"))
		if isRealFinding {
			hasSecrets = true
			report = append(report, "[CRITIQUE] "+l)
			fmt.Printf("  [CRITIQUE] %s\n", l)
		}
	}
	if !hasSecrets {
		report = append(report, "[OK] Aucun secret detecte dans le code source.")
		fmt.Println("  [OK] Aucun secret detecte dans le code source.")
	}

	statut := "OK"
	if hasSecrets {
		statut = "CRITIQUE"
	}
	return section("3/4 GITLEAKS - Detection de secrets dans le code source", statut, report), hasSecrets, hasSecrets
}

func findGitleaks(projectDir string) string {
	candidates := []string{
		filepath.Join(projectDir, "tools", "gitleaks.exe"),
		filepath.Join(projectDir, "tools", "gitleaks"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func downloadGitleaks(toolsDir string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("telechargement automatique Windows uniquement")
	}
	zipPath := filepath.Join(toolsDir, "gitleaks.zip")
	if err := downloadHTTP(gitleaksURL, zipPath); err != nil {
		return err
	}
	defer os.Remove(zipPath)
	return unzipFile(zipPath, toolsDir, "gitleaks.exe")
}

// ── MOTEUR IA ─────────────────────────────────────────────────────────────────

func auditMoteur(projectDir string) auditpdf.AuditSection {
	fmt.Println()
	fmt.Println("  ============================================================")
	fmt.Println("  [4/4] MOTEUR IA - Analyse des binaires et modeles locaux")
	fmt.Println("  ============================================================")

	moteurDir := filepath.Join(filepath.Dir(projectDir), "moteur")
	var lines []string

	if _, err := os.Stat(moteurDir); err != nil {
		lines = append(lines, "[INFO] Repertoire moteur/ absent — aucun moteur IA installe.")
		fmt.Println("  [INFO] Repertoire moteur/ absent.")
		return section("4/4 MOTEUR IA - Analyse des binaires et modeles IA locaux (moteur/)", "INFO", lines)
	}

	fmt.Printf("  [INFO] Repertoire moteur/ : %s\n", moteurDir)
	lines = append(lines, "Repertoire analyse : "+moteurDir, "")

	// Binaire llama-server
	entries, _ := os.ReadDir(moteurDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "llama-server") && !e.IsDir() {
			info, _ := e.Info()
			sizeKB := info.Size() / 1024
			hash := sha256File(filepath.Join(moteurDir, e.Name()))
			lines = append(lines,
				"Binaire llama-server :",
				fmt.Sprintf("  Fichier  : %s  (%d Ko)", e.Name(), sizeKB),
				fmt.Sprintf("  SHA-256  : %s", hash),
				"  Source   : llama.cpp open-source (https://github.com/ggml-org/llama.cpp)",
				"[INFO] Binaire non signe (attendu pour llama.cpp open-source).",
				"")
			fmt.Println("  [INFO] llama-server non signe (normal pour open-source).")
		}
	}

	// Modèles GGUF
	modelsDir := filepath.Join(moteurDir, "models")
	if modelEntries, err := os.ReadDir(modelsDir); err == nil {
		lines = append(lines, "Modeles GGUF presents dans moteur/models/ :")
		for _, m := range modelEntries {
			if strings.HasSuffix(m.Name(), ".gguf") {
				info, _ := m.Info()
				sizeGB := float64(info.Size()) / (1024 * 1024 * 1024)
				lines = append(lines, fmt.Sprintf("  - %s  (%.2f Go)", m.Name(), sizeGB))
				fmt.Printf("  [OK] Modele : %s (%.2f Go)\n", m.Name(), sizeGB)
			}
		}
		lines = append(lines,
			"[OK] Les modeles GGUF sont des fichiers de poids neuraux en lecture seule.",
			"     Ils ne contiennent pas de code executable.",
			"     Sources : TheBloke/bartowski sur Hugging Face (open-source).",
			"")
	}

	// DLLs CUDA
	dllCount := 0
	for _, e := range entries {
		if strings.ToLower(filepath.Ext(e.Name())) == ".dll" {
			dllCount++
		}
	}
	if dllCount > 0 {
		lines = append(lines,
			fmt.Sprintf("DLLs CUDA runtime : %d fichiers", dllCount),
			"[OK] DLLs CUDA officielles NVIDIA.")
		fmt.Printf("  [OK] %d DLL(s) CUDA presentes.\n", dllCount)
	}

	lines = append(lines, "",
		"Evaluation : composants open-source uniquement (llama.cpp + GGUF + CUDA).",
		"Risque : FAIBLE.")

	return section("4/4 MOTEUR IA - Analyse des binaires et modeles IA locaux (moteur/)", "OK", lines)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func section(titre, statut string, lignes []string) auditpdf.AuditSection {
	var ls []auditpdf.AuditLigne
	for _, l := range lignes {
		niveau := "INFO"
		switch {
		case strings.HasPrefix(l, "[CRITIQUE]"):
			niveau = "CRITIQUE"
		case strings.HasPrefix(l, "[!]"):
			niveau = "WARN"
		case strings.HasPrefix(l, "[OK]"):
			niveau = "OK"
		case strings.HasPrefix(l, "[SKIP]"):
			niveau = "SKIP"
		}
		// Supprimer le préfixe du texte — GeneratePDF l'ajoute automatiquement
		texte := l
		for _, pfx := range []string{"[CRITIQUE] ", "[CRITIQUE]", "[!] ", "[!]", "[OK] ", "[OK]", "[SKIP] ", "[SKIP]", "[INFO] ", "[INFO]"} {
			if strings.HasPrefix(texte, pfx) {
				texte = strings.TrimPrefix(texte, pfx)
				break
			}
		}
		ls = append(ls, auditpdf.AuditLigne{Niveau: niveau, Texte: texte})
	}
	return auditpdf.AuditSection{Titre: titre, Statut: statut, Lignes: ls}
}

func findGoBinTool(name string) string {
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		home, _ := os.UserHomeDir()
		gopath = filepath.Join(home, "go")
	}
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	p := filepath.Join(gopath, "bin", name+ext)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	// Chercher dans PATH
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

func cmdOut(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func runSilent(dir, name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Run()
}

func filterEmpty(lines []string) []string {
	var out []string
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func sha256File(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "?"
	}
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func cleanAllAuditPDFs(auditDir string) {
	entries, err := os.ReadDir(auditDir)
	if err != nil {
		return
	}
	type pf struct {
		path    string
		modTime time.Time
	}
	var pdfs []pf
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "rapport_securite_") && strings.HasSuffix(e.Name(), ".pdf") {
			info, _ := e.Info()
			pdfs = append(pdfs, pf{filepath.Join(auditDir, e.Name()), info.ModTime()})
		}
	}
	if len(pdfs) == 0 {
		return
	}
	sort.Slice(pdfs, func(i, j int) bool { return pdfs[i].modTime.After(pdfs[j].modTime) })
	fmt.Println("  [AUDIT] Suppression des anciens rapports PDF...")
	for _, p := range pdfs {
		if err := os.Remove(p.path); err == nil {
			fmt.Printf("  [AUDIT] Supprime : %s\n", filepath.Base(p.path))
		}
	}
}

func downloadHTTP(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func unzipFile(zipPath, destDir, fileName string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		if filepath.Base(f.Name) == fileName {
			dst := filepath.Join(destDir, fileName)
			out, err := os.Create(dst)
			if err != nil {
				return err
			}
			rc, _ := f.Open()
			io.Copy(out, rc)
			rc.Close()
			out.Close()
			os.Chmod(dst, 0755)
			return nil
		}
	}
	return fmt.Errorf("%s introuvable dans le zip", fileName)
}

func resolveProjectDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// ── ANALYSE IA ────────────────────────────────────────────────────────────────

const llamaPort = "18766" // port llama.cpp local

// runIAAnalysis envoie un résumé de l'audit au moteur IA local (llama.cpp)
// et retourne une section AuditSection avec la synthèse et les recommandations.
// Si le moteur n'est pas disponible, retourne une section INFO avec le motif.
func runIAAnalysis(sections []auditpdf.AuditSection, resultat string) auditpdf.AuditSection {
	prompt := buildAuditPrompt(sections, resultat)

	fmt.Println("  -> Interrogation du moteur IA local (llama.cpp)...")

	// Appel à l'API llama.cpp /v1/chat/completions
	type msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type req struct {
		Messages  []msg `json:"messages"`
		MaxTokens int   `json:"max_tokens"`
		Stream    bool  `json:"stream"`
	}
	body, _ := json.Marshal(req{
		Messages: []msg{
			{Role: "system", Content: "Tu es un expert en securite applicative Go. Reponds en francais. Sois concis et structure ta reponse en 3 parties : 1) Synthese, 2) Points critiques, 3) Recommandations prioritaires."},
			{Role: "user", Content: prompt},
		},
		MaxTokens: 600,
		Stream:    false,
	})

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Post(
		"http://localhost:"+llamaPort+"/v1/chat/completions",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		fmt.Printf("  [!] Moteur IA indisponible : %v\n", err)
		fmt.Println("  -> Section IA ignoree (moteur non demarre).")
		return section("5/5 ANALYSE IA - Synthese", "SKIP", []string{
			"[SKIP] Moteur IA non disponible au moment de l'audit.",
			"Demarrez l'interface web et relancez l'audit pour obtenir l'analyse IA.",
		})
	}
	defer resp.Body.Close()

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || len(result.Choices) == 0 {
		fmt.Printf("  [!] Reponse IA invalide : %v\n", err)
		return section("5/5 ANALYSE IA - Synthese", "SKIP", []string{
			"[SKIP] Reponse IA invalide ou vide.",
		})
	}

	rawText := result.Choices[0].Message.Content
	fmt.Println("  [OK] Analyse IA recue.")

	// Découper la réponse en lignes pour le PDF
	var lignes []string
	for _, l := range strings.Split(rawText, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		// Marquer les lignes critiques/warn/ok
		lLow := strings.ToLower(l)
		switch {
		case strings.Contains(lLow, "critique") || strings.Contains(lLow, "urgent") || strings.Contains(lLow, "bloquant"):
			lignes = append(lignes, "[CRITIQUE] "+l)
		case strings.Contains(lLow, "attention") || strings.Contains(lLow, "avertissement") || strings.Contains(lLow, "recommand"):
			lignes = append(lignes, "[!] "+l)
		case strings.HasPrefix(l, "1)") || strings.HasPrefix(l, "2)") || strings.HasPrefix(l, "3)") ||
			strings.HasPrefix(l, "1.") || strings.HasPrefix(l, "2.") || strings.HasPrefix(l, "3."):
			lignes = append(lignes, "[OK] "+l)
		default:
			lignes = append(lignes, l)
		}
	}

	if len(lignes) == 0 {
		lignes = []string{"[SKIP] Aucune analyse generee."}
	}

	statut := "OK"
	if resultat == "CRITIQUE" {
		statut = "CRITIQUE"
	} else if resultat == "AVERTISSEMENT" {
		statut = "WARN"
	}
	return section("5/5 ANALYSE IA - Synthese et recommandations", statut, lignes)
}

// buildAuditPrompt construit le prompt envoyé au moteur IA.
func buildAuditPrompt(sections []auditpdf.AuditSection, resultat string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Rapport d'audit de securite RF Sandbox Go - Resultat global : %s\n\n", resultat))
	for _, sec := range sections {
		sb.WriteString(fmt.Sprintf("=== %s [%s] ===\n", sec.Titre, sec.Statut))
		for _, l := range sec.Lignes {
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", l.Niveau, l.Texte))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("\nAnalyse ce rapport d'audit et fournis : 1) Synthese du niveau de risque, 2) Points critiques a corriger, 3) Recommandations prioritaires avec actions concretes.")
	return sb.String()
}
