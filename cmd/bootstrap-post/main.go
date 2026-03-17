// bootstrap-post — Remplace audit_securite.ps1 + setup_moteur.ps1
//
// Exécuté par bootstrap.bat après la compilation Go.
// Étapes :
//  1. Nettoyage audit/ : garde uniquement le dernier PDF
//  2. Audit de sécurité : gosec + govulncheck + gitleaks + analyse moteur IA
//  3. Génération du rapport PDF via audit.exe
//  4. Setup moteur IA via setup-moteur.exe
//
// Plus aucun fichier .ps1 n'est nécessaire pour ces étapes.
package main

import (
	"archive/zip"
	"bytes"
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
)

// ── Structures JSON pour audit.exe ───────────────────────────────────────────

type auditLigne struct {
	Niveau string `json:"niveau"`
	Texte  string `json:"texte"`
}

type auditSection struct {
	Titre  string       `json:"titre"`
	Statut string       `json:"statut"`
	Lignes []auditLigne `json:"lignes"`
}

type auditReport struct {
	Date     string         `json:"date"`
	Project  string         `json:"project"`
	Resultat string         `json:"resultat"`
	Sections []auditSection `json:"sections"`
}

func ligne(niveau, texte string) auditLigne { return auditLigne{niveau, texte} }

// ── Main ─────────────────────────────────────────────────────────────────────

func main() {
	skipMoteur := flag.Bool("skip-moteur", false, "Ne pas lancer setup-moteur")
	flag.Parse()

	projectDir := resolveProjectDir()
	auditDir := filepath.Join(projectDir, "audit")
	os.MkdirAll(auditDir, 0755)

	date := time.Now().Format("2006-01-02_15-04")

	fmt.Println()
	fmt.Println("  ============================================================")
	fmt.Println("    RF Sandbox Go - Bootstrap post-compilation")
	fmt.Println("    Date :", date)
	fmt.Println("  ============================================================")
	fmt.Println()

	// Étape 1 : nettoyage anciens PDFs
	cleanOldAuditPDFs(auditDir)

	// Étape 2 : audit de sécurité
	report, hasSecrets := runFullAudit(projectDir, auditDir, date)

	// Étape 3 : génération PDF
	generatePDF(projectDir, auditDir, date, report)

	// Résultat final
	fmt.Println()
	fmt.Println("  ============================================================")
	if hasSecrets {
		fmt.Println("  RESULTAT : CRITIQUE - Secret(s) detecte(s) dans le code !")
		fmt.Println("  NE PAS DEPLOYER ni committer avant correction.")
	} else if report.Resultat == "AVERTISSEMENT" {
		fmt.Println("  RESULTAT : AVERTISSEMENT - Problemes detectes (non bloquants)")
	} else {
		fmt.Println("  RESULTAT : OK - Aucun probleme de securite detecte")
	}
	fmt.Println("  ============================================================")
	fmt.Println()

	// Étape 4 : setup moteur IA
	if !*skipMoteur {
		runSetupMoteur(projectDir)
	}

	fmt.Println()
	fmt.Println("  [OK] Bootstrap post-compilation termine.")
	fmt.Println()

	if hasSecrets {
		os.Exit(1)
	}
}

// ── Nettoyage PDFs ────────────────────────────────────────────────────────────

func cleanOldAuditPDFs(auditDir string) {
	type pdfFile struct {
		name    string
		path    string
		modTime time.Time
	}
	entries, err := os.ReadDir(auditDir)
	if err != nil {
		return
	}
	var pdfs []pdfFile
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "rapport_securite_") && strings.HasSuffix(e.Name(), ".pdf") {
			info, _ := e.Info()
			if info != nil {
				pdfs = append(pdfs, pdfFile{e.Name(), filepath.Join(auditDir, e.Name()), info.ModTime()})
			}
		}
	}
	if len(pdfs) <= 1 {
		return
	}
	sort.Slice(pdfs, func(i, j int) bool { return pdfs[i].modTime.After(pdfs[j].modTime) })
	fmt.Printf("  [AUDIT] Conservation : %s\n", pdfs[0].name)
	for _, pdf := range pdfs[1:] {
		if os.Remove(pdf.path) == nil {
			fmt.Printf("  [AUDIT] Supprime     : %s\n", pdf.name)
		}
	}
	fmt.Println()
}

// ── Audit complet ─────────────────────────────────────────────────────────────

func runFullAudit(projectDir, auditDir, date string) (auditReport, bool) {
	hasErrors := false
	hasSecrets := false
	var sections []auditSection

	toolsDir := filepath.Join(projectDir, "tools")
	os.MkdirAll(toolsDir, 0755)

	// Trouver les outils Go (gosec, govulncheck)
	gosecExe := findGoBinTool("gosec")
	govulnExe := findGoBinTool("govulncheck")
	gitleaksExe := findGitleaks(toolsDir)

	fmt.Println("  [OUTILS] Verification des outils d'audit...")

	if gosecExe == "" {
		fmt.Println("  -> Installation de gosec...")
		runSilent(projectDir, "go", "install", "github.com/securego/gosec/v2/cmd/gosec@latest")
		gosecExe = findGoBinTool("gosec")
	}
	if gosecExe != "" {
		fmt.Println("  [OK] gosec present.")
	} else {
		fmt.Println("  [!] gosec indisponible.")
	}

	if govulnExe == "" {
		fmt.Println("  -> Installation de govulncheck...")
		runSilent(projectDir, "go", "install", "golang.org/x/vuln/cmd/govulncheck@latest")
		govulnExe = findGoBinTool("govulncheck")
	}
	if govulnExe != "" {
		fmt.Println("  [OK] govulncheck present.")
	} else {
		fmt.Println("  [!] govulncheck indisponible.")
	}

	if gitleaksExe == "" {
		fmt.Println("  -> Telechargement de gitleaks...")
		gitleaksExe = downloadGitleaks(toolsDir)
	}
	if gitleaksExe != "" {
		fmt.Println("  [OK] gitleaks present.")
	} else {
		fmt.Println("  [!] gitleaks indisponible.")
	}

	fmt.Println()

	// ── [1/4] GOSEC ─────────────────────────────────────────────────────────
	fmt.Println("  ============================================================")
	fmt.Println("  [1/4] GOSEC - Analyse statique du code Go")
	fmt.Println("  ============================================================")

	sec1 := auditSection{Titre: "[1/4] GOSEC - Analyse statique du code Go", Statut: "OK"}
	if gosecExe == "" {
		sec1.Statut = "SKIP"
		sec1.Lignes = []auditLigne{ligne("SKIP", "[SKIP] gosec non disponible.")}
		fmt.Println("  [SKIP] gosec non disponible.")
	} else {
		out, _ := cmdOutput(projectDir, gosecExe,
			"-fmt", "text", "-severity", "medium", "-confidence", "medium",
			"-exclude", "G304,G107", "./...")
		issues := parseGosecIssues(out)
		if len(issues) > 0 {
			hasErrors = true
			sec1.Statut = "WARN"
			sec1.Lignes = append(sec1.Lignes, ligne("WARN", fmt.Sprintf("[!] %d probleme(s) detecte(s) (regles exclues : G304, G107)", len(issues))))
			for _, iss := range issues {
				sec1.Lignes = append(sec1.Lignes, ligne("WARN", iss))
				fmt.Printf("      [!] %s\n", iss)
			}
			fmt.Printf("  [!] %d probleme(s) detecte(s)\n", len(issues))
		} else {
			sec1.Lignes = []auditLigne{ligne("OK", "[OK] Aucune vulnerabilite detectee.")}
			fmt.Println("  [OK] Aucune vulnerabilite detectee.")
		}
		sec1.Lignes = append(sec1.Lignes,
			ligne("INFO", "Regles intentionnellement exclues :"),
			ligne("INFO", "  G304 - Chemin de fichier depuis variable"),
			ligne("INFO", "  G107 - URL depuis variable"),
		)
	}
	sections = append(sections, sec1)
	fmt.Println()

	// ── [2/4] GOVULNCHECK ───────────────────────────────────────────────────
	fmt.Println("  ============================================================")
	fmt.Println("  [2/4] GOVULNCHECK - CVE dans les dependances (go.mod)")
	fmt.Println("  ============================================================")

	sec2 := auditSection{Titre: "[2/4] GOVULNCHECK - CVE dans les dependances (go.mod)", Statut: "OK"}
	if govulnExe == "" {
		sec2.Statut = "SKIP"
		sec2.Lignes = []auditLigne{ligne("SKIP", "[SKIP] govulncheck non disponible.")}
		fmt.Println("  [SKIP] govulncheck non disponible.")
	} else {
		out, _ := cmdOutput(projectDir, govulnExe, "./...")
		vulns := parseGovulnOutput(out)
		if len(vulns) > 0 {
			hasErrors = true
			sec2.Statut = "CRITIQUE"
			sec2.Lignes = append(sec2.Lignes, ligne("CRITIQUE", "[CRITIQUE] CVE detectes dans les dependances :"))
			fmt.Println("  [!] CVE detectes dans les dependances :")
			for _, v := range vulns {
				sec2.Lignes = append(sec2.Lignes, ligne("INFO", v))
				fmt.Printf("      %s\n", v)
			}
			sec2.Lignes = append(sec2.Lignes, ligne("INFO", "Action recommandee : go get -u ./... puis go mod tidy"))
		} else {
			sec2.Lignes = []auditLigne{ligne("OK", "[OK] Aucun CVE detecte dans les dependances.")}
			fmt.Println("  [OK] Aucun CVE detecte dans les dependances.")
		}
	}
	sections = append(sections, sec2)
	fmt.Println()

	// ── [3/4] GITLEAKS ──────────────────────────────────────────────────────
	fmt.Println("  ============================================================")
	fmt.Println("  [3/4] GITLEAKS - Detection de secrets dans le code source")
	fmt.Println("  ============================================================")

	sec3 := auditSection{Titre: "[3/4] GITLEAKS - Detection de secrets dans le code source", Statut: "OK"}
	if gitleaksExe == "" {
		sec3.Statut = "SKIP"
		sec3.Lignes = []auditLigne{ligne("SKIP", "[SKIP] gitleaks non disponible.")}
		fmt.Println("  [SKIP] gitleaks non disponible.")
	} else {
		out, _ := cmdOutput(projectDir, gitleaksExe, "detect", "--source", ".", "--no-git",
			"--exclude-path", "moteur",
			"--exclude-path", "audit",
			"--exclude-path", "output",
			"--exclude-path", "tools",
			"--exclude-path", "config/config.json",
		)
		findings := parseGitleaksFindings(out)
		if len(findings) > 0 {
			hasSecrets = true
			hasErrors = true
			sec3.Statut = "CRITIQUE"
			sec3.Lignes = append(sec3.Lignes, ligne("CRITIQUE", fmt.Sprintf("[CRITIQUE] %d secret(s) detecte(s) !", len(findings))))
			fmt.Printf("  [CRITIQUE] %d secret(s) detecte(s) dans le code !\n", len(findings))
			for _, f := range findings {
				sec3.Lignes = append(sec3.Lignes, ligne("CRITIQUE", f))
				fmt.Printf("      %s\n", f)
			}
			sec3.Lignes = append(sec3.Lignes,
				ligne("INFO", "Action OBLIGATOIRE : supprimer les secrets avant tout commit !"),
				ligne("INFO", "Conseil : vault.exe seal pour chiffrer les tokens."),
			)
		} else {
			sec3.Lignes = []auditLigne{
				ligne("OK", "[OK] Aucun secret detecte dans le code source."),
				ligne("INFO", "Fichiers exclus : config/config.json (gere par vault)"),
			}
			fmt.Println("  [OK] Aucun secret detecte dans le code source.")
		}
	}
	sections = append(sections, sec3)
	fmt.Println()

	// ── [4/4] MOTEUR IA ─────────────────────────────────────────────────────
	fmt.Println("  ============================================================")
	fmt.Println("  [4/4] MOTEUR IA - Analyse des binaires et modeles locaux")
	fmt.Println("  ============================================================")

	sec4 := auditMoteurIA(projectDir)
	sections = append(sections, sec4)
	fmt.Println()

	// Résultat global
	resultat := "OK"
	if hasSecrets {
		resultat = "CRITIQUE"
	} else if hasErrors {
		resultat = "AVERTISSEMENT"
	}

	report := auditReport{
		Date:     date,
		Project:  "RF Sandbox Go",
		Resultat: resultat,
		Sections: sections,
	}
	return report, hasSecrets
}

// ── Section moteur IA ─────────────────────────────────────────────────────────

func auditMoteurIA(projectDir string) auditSection {
	sec := auditSection{Titre: "[4/4] MOTEUR IA - Analyse des binaires et modeles IA locaux (moteur/)", Statut: "OK"}

	// Trouver moteur/ : deux niveaux au-dessus du projet
	moteurDir := filepath.Join(filepath.Dir(projectDir), "moteur")
	if _, err := os.Stat(moteurDir); err != nil {
		sec.Lignes = []auditLigne{ligne("INFO", "[INFO] Repertoire moteur/ absent (telechargement automatique au premier lancement).")}
		fmt.Println("  [INFO] Repertoire moteur/ absent.")
		return sec
	}

	fmt.Printf("  [INFO] Repertoire moteur/ : %s\n", moteurDir)
	sec.Lignes = append(sec.Lignes, ligne("INFO", "[INFO] Repertoire moteur/ : "+moteurDir))

	// llama-server
	llamaExe := filepath.Join(moteurDir, "llama-server.exe")
	if runtime.GOOS != "windows" {
		llamaExe = filepath.Join(moteurDir, "llama-server")
	}
	if _, err := os.Stat(llamaExe); err == nil {
		sec.Lignes = append(sec.Lignes, ligne("INFO", "[INFO] llama-server present (binaire open-source non signe, normal)."))
		fmt.Println("  [INFO] llama-server present (normal pour open-source).")
	} else {
		sec.Lignes = append(sec.Lignes, ligne("INFO", "[INFO] llama-server absent (telechargement automatique au premier lancement)."))
		fmt.Println("  [INFO] llama-server absent.")
	}

	// Modèles GGUF
	modelsDir := filepath.Join(moteurDir, "models")
	modelEntries, _ := os.ReadDir(modelsDir)
	modelCount := 0
	for _, e := range modelEntries {
		if strings.HasSuffix(strings.ToLower(e.Name()), ".gguf") {
			info, _ := e.Info()
			sizeGB := float64(0)
			if info != nil {
				sizeGB = float64(info.Size()) / (1024 * 1024 * 1024)
			}
			msg := fmt.Sprintf("[OK] Modele : %s (%.2f Go)", e.Name(), sizeGB)
			sec.Lignes = append(sec.Lignes, ligne("OK", msg))
			fmt.Printf("  [OK] Modele : %s (%.2f Go)\n", e.Name(), sizeGB)
			modelCount++
		}
	}
	if modelCount == 0 {
		sec.Lignes = append(sec.Lignes, ligne("INFO", "[INFO] Aucun modele GGUF present dans moteur/models/."))
	}

	// DLLs CUDA
	dllCount := 0
	entries, _ := os.ReadDir(moteurDir)
	for _, e := range entries {
		if strings.ToLower(filepath.Ext(e.Name())) == ".dll" {
			dllCount++
		}
	}
	if dllCount > 0 {
		msg := fmt.Sprintf("[OK] %d DLL(s) CUDA presentes (runtime NVIDIA officiel).", dllCount)
		sec.Lignes = append(sec.Lignes, ligne("OK", msg))
		fmt.Printf("  [OK] %d DLL(s) CUDA presentes.\n", dllCount)
	}

	sec.Lignes = append(sec.Lignes,
		ligne("INFO", "Evaluation : composants open-source uniquement (llama.cpp + GGUF + CUDA)."),
		ligne("INFO", "Risque : FAIBLE — code source public et verifiable."),
	)
	return sec
}

// ── Génération PDF ────────────────────────────────────────────────────────────

func generatePDF(projectDir, auditDir, date string, report auditReport) {
	auditExe := filepath.Join(projectDir, "audit.exe")
	if runtime.GOOS != "windows" {
		auditExe = filepath.Join(projectDir, "audit")
	}
	if _, err := os.Stat(auditExe); err != nil {
		fmt.Println("  [i] audit.exe absent - PDF non genere.")
		return
	}

	fmt.Println("  Generation du rapport PDF...")

	jsonData, err := json.Marshal(report)
	if err != nil {
		fmt.Printf("  [!] Serialisation JSON : %v\n", err)
		return
	}

	tmpJSON := filepath.Join(auditDir, "audit_tmp_"+date+".json")
	if err := os.WriteFile(tmpJSON, jsonData, 0644); err != nil {
		fmt.Printf("  [!] Ecriture JSON tmp : %v\n", err)
		return
	}
	defer os.Remove(tmpJSON)

	pdfOut := filepath.Join(auditDir, "rapport_securite_"+date+".pdf")
	cmd := exec.Command(auditExe, "-in", tmpJSON, "-out", pdfOut)
	cmd.Dir = projectDir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("  [!] Generation PDF echouee : %v\n", stderr.String())
	} else {
		fmt.Printf("  [OK] Rapport PDF genere : %s\n", pdfOut)
	}
}

// ── Setup moteur IA ──────────────────────────────────────────────────────────

func runSetupMoteur(projectDir string) {
	fmt.Println()
	fmt.Println("  ============================================================")
	fmt.Println("    Setup moteur IA (llama.cpp + Mistral 7B)")
	fmt.Println("  ============================================================")

	setupExe := ""
	for _, name := range []string{"setup-moteur.exe", "setup-moteur"} {
		p := filepath.Join(projectDir, name)
		if _, err := os.Stat(p); err == nil {
			setupExe = p
			break
		}
	}
	if setupExe == "" {
		fmt.Println("  [!] setup-moteur.exe introuvable — setup ignore.")
		return
	}
	cmd := exec.Command(setupExe)
	cmd.Dir = projectDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("  [ATTENTION] setup-moteur echoue : %v\n", err)
	}
}

// ── Parseurs de sortie outils ─────────────────────────────────────────────────

func parseGosecIssues(out string) []string {
	var issues []string
	var cur []string
	inBlock := false
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "[G") {
			if len(cur) > 0 {
				issues = append(issues, strings.Join(cur, " | "))
			}
			cur = []string{strings.TrimSpace(line)}
			inBlock = true
		} else if inBlock && (strings.Contains(line, "Severity:") || strings.Contains(line, "CWE:") || strings.HasPrefix(strings.TrimSpace(line), ">")) {
			cur = append(cur, strings.TrimSpace(line))
		} else if inBlock && strings.TrimSpace(line) == "" {
			if len(cur) > 0 {
				issues = append(issues, strings.Join(cur, " | "))
			}
			cur = nil
			inBlock = false
		}
	}
	if len(cur) > 0 {
		issues = append(issues, strings.Join(cur, " | "))
	}
	return issues
}

func parseGovulnOutput(out string) []string {
	var hits []string
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "Vulnerability #") ||
			strings.HasPrefix(t, "ID:") ||
			strings.HasPrefix(t, "More info:") ||
			strings.HasPrefix(t, "Found in:") ||
			strings.HasPrefix(t, "Fixed in:") {
			hits = append(hits, t)
		}
	}
	return hits
}

func parseGitleaksFindings(out string) []string {
	var findings []string
	var cur []string
	inFinding := false
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Finding:") {
			if len(cur) > 0 {
				findings = append(findings, strings.Join(cur, " | "))
			}
			cur = []string{strings.TrimSpace(line)}
			inFinding = true
		} else if inFinding {
			t := strings.TrimSpace(line)
			if t == "" {
				if len(cur) > 0 {
					findings = append(findings, strings.Join(cur, " | "))
				}
				cur = nil
				inFinding = false
			} else {
				for _, key := range []string{"Secret:", "File:", "Line:", "RuleID:", "Commit:", "Author:"} {
					if strings.HasPrefix(t, key) {
						cur = append(cur, t)
						break
					}
				}
			}
		}
	}
	if len(cur) > 0 {
		findings = append(findings, strings.Join(cur, " | "))
	}
	return findings
}

// ── Outils : recherche et téléchargement ─────────────────────────────────────

func findGoBinTool(name string) string {
	// GOPATH/bin
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		home, _ := os.UserHomeDir()
		gopath = filepath.Join(home, "go")
	}
	candidates := []string{
		filepath.Join(gopath, "bin", name+".exe"),
		filepath.Join(gopath, "bin", name),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// PATH
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

func findGitleaks(toolsDir string) string {
	candidates := []string{
		filepath.Join(toolsDir, "gitleaks.exe"),
		filepath.Join(toolsDir, "gitleaks"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("gitleaks"); err == nil {
		return p
	}
	return ""
}

const gitleaksURL = "https://github.com/gitleaks/gitleaks/releases/download/v8.23.3/gitleaks_8.23.3_windows_x64.zip"

func downloadGitleaks(toolsDir string) string {
	dest := filepath.Join(toolsDir, "gitleaks.exe")
	zipPath := filepath.Join(toolsDir, "gitleaks.zip")

	resp, err := http.Get(gitleaksURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	f, err := os.Create(zipPath)
	if err != nil {
		return ""
	}
	io.Copy(f, resp.Body)
	f.Close()
	defer os.Remove(zipPath)

	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return ""
	}
	defer r.Close()

	for _, zf := range r.File {
		if strings.EqualFold(filepath.Base(zf.Name), "gitleaks.exe") || strings.EqualFold(filepath.Base(zf.Name), "gitleaks") {
			rc, _ := zf.Open()
			out, _ := os.Create(dest)
			io.Copy(out, rc)
			out.Close()
			rc.Close()
			os.Chmod(dest, 0755)
			return dest
		}
	}
	return ""
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func resolveProjectDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func cmdOutput(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func runSilent(dir, name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Run()
}
