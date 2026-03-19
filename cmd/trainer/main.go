// cmd/trainer/main.go
//
// Entraîneur LoRA 100% Go — zéro Python, zéro PyTorch.
//
// Utilise les binaires llama.cpp natifs déjà présents dans moteur/ :
//   - llama-finetune(.exe)  : fine-tuning LoRA depuis un .gguf de base
//   - llama-quantize(.exe)  : quantification Q4_K_M du modèle entraîné
//
// Ces binaires sont dans le MÊME zip que llama-server.exe (déjà téléchargé
// par setup-moteur). Si absents, ce programme les extrait ou re-télécharge.
//
// Usage (appelé par ui.go via /api/training/start) :
//
//	trainer.exe [--dry-run] [--min-score=5] [--epochs=3]
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"rf-sandbox-go/internal/ai"
)

const (
	// Build b4109 — dernier release llama.cpp incluant llama-finetune.exe
	// Les versions ultérieures ont supprimé llama-finetune des releases binaires.
	llamaBuild       = "b4109"
	llamaWindowsCUDA = "https://github.com/ggml-org/llama.cpp/releases/download/b4109/llama-b4109-bin-win-cuda-cu12.2.0-x64.zip"
	llamaWindowsCPU  = "https://github.com/ggml-org/llama.cpp/releases/download/b4109/llama-b4109-bin-win-noavx-x64.zip"
	llamaLinux       = "https://github.com/ggml-org/llama.cpp/releases/download/b4109/llama-b4109-bin-ubuntu-x64.zip"
)

type Config struct {
	MinScore int
	Epochs   int
	DryRun   bool
}

type Profile struct {
	Name    string
	Threads int
	Batch   int
	Ctx     int
}

func main() {
	cfg := Config{}
	flag.IntVar(&cfg.MinScore, "min-score", 5, "Score minimum des analyses (0-10)")
	flag.IntVar(&cfg.Epochs, "epochs", 3, "Nombre d'epochs")
	flag.BoolVar(&cfg.DryRun, "dry-run", false, "Simuler sans entraîner")
	flag.Parse()

	log.SetFlags(0)
	printBanner()

	mDir := moteurDir()

	// Supprimer l'ancien cache zip si présent (mauvais build)
	oldZip := filepath.Join(mDir, "llama-cpp-cached.zip")
	if _, err := os.Stat(oldZip); err == nil {
		os.Remove(oldZip)
		log.Printf("  ↻ Ancien cache llama.cpp supprimé (build obsolète)")
	}

	// ── 1. GPU ────────────────────────────────────────────────────────────────
	sep("[1/5] DÉTECTION MATÉRIEL")
	hasGPU, gpuName, vramTotal, vramFree := detectGPU()
	if hasGPU {
		log.Printf("  ✓ GPU  : %s", gpuName)
		log.Printf("  ✓ VRAM : %.1f Go total / %.1f Go libre", vramTotal, vramFree)
	} else {
		log.Println("  ⚠ Aucun GPU NVIDIA — mode CPU (fonctionnel mais lent)")
	}
	p := selectProfile(vramFree, hasGPU)
	log.Printf("  ✓ Profil : %s  threads=%d batch=%d ctx=%d", p.Name, p.Threads, p.Batch, p.Ctx)

	// ── 2. Dataset ────────────────────────────────────────────────────────────
	sep("[2/5] EXPORT DATASET")
	datasetJSONL := ai.DatasetPath()
	stats, err := ai.ExportTrainingDataset(datasetJSONL, cfg.MinScore)
	if err != nil {
		fatal("Export dataset : " + err.Error())
	}
	log.Printf("  ✓ %d exemples exportés (%d ignorés) en %s",
		stats.Exported, stats.Skipped, stats.Duration.Round(time.Millisecond))
	if stats.Exported == 0 {
		fatal("Base vide — analysez d'abord des fichiers malveillants (score >= " + fmt.Sprint(cfg.MinScore) + ")")
	}
	if stats.Exported < 10 {
		log.Printf("  ⚠ %d exemples seulement — idéalement 50+ pour un bon résultat", stats.Exported)
	}

	// Conversion JSONL → texte brut pour llama-finetune
	datasetTXT := strings.TrimSuffix(datasetJSONL, ".jsonl") + ".txt"
	if err := convertJSONLtoTXT(datasetJSONL, datasetTXT, isFoundationSec); err != nil {
		fatal("Conversion dataset : " + err.Error())
	}
	log.Printf("  ✓ Converti → %s", datasetTXT)

	// ── 3. Binaires ───────────────────────────────────────────────────────────
	sep("[3/5] BINAIRES llama.cpp")
	finetuneBin, err := ensureBinary(mDir, "llama-finetune", hasGPU)
	if err != nil {
		fatal("llama-finetune : " + err.Error())
	}
	log.Printf("  ✓ llama-finetune : %s", finetuneBin)

	quantizeBin, _ := ensureBinary(mDir, "llama-quantize", hasGPU)
	if quantizeBin != "" {
		log.Printf("  ✓ llama-quantize : %s", quantizeBin)
	} else {
		log.Println("  ⚠ llama-quantize absent — pas de quantification Q4_K_M")
	}

	// ── 4. Modèle de base ─────────────────────────────────────────────────────
	sep("[4/5] MODÈLE DE BASE")
	baseModel, modelName := findBaseModel(mDir)
	if baseModel == "" {
		fatal("Aucun modèle .gguf dans moteur/models/ — téléchargez Foundation-Sec-8B depuis l'interface")
	}
	isFoundationSec := strings.Contains(baseModel, "Foundation-Sec")
	log.Printf("  ✓ Modèle de base : %s", modelName)
	if isFoundationSec {
		log.Println("  ✓ Foundation-Sec-8B sélectionné — template LLaMA 3.1 Chat activé")
	} else {
		log.Println("  ⚠ Mistral sélectionné — installez Foundation-Sec-8B pour de meilleurs résultats")
	}

	// Nom du fichier de sortie adapté au modèle fine-tuné
	loraBaseName := "forensic-fr-lora.bin"
	ggufOutName := "mistral-7b-forensic-fr-Q4_K_M.gguf"
	if isFoundationSec {
		loraBaseName = "foundation-sec-forensic-fr-lora.bin"
		ggufOutName = "Foundation-Sec-8B-forensic-fr-Q4_K_M.gguf"
	}
	loraOut := filepath.Join(mDir, "lora", loraBaseName)
	os.MkdirAll(filepath.Dir(loraOut), 0755)
	log.Printf("  ✓ Sortie LoRA : %s", loraOut)

	// ── 5. Fine-tuning ────────────────────────────────────────────────────────
	sep(fmt.Sprintf("[5/5] FINE-TUNING (%d epochs, %d exemples)", cfg.Epochs, stats.Exported))

	args := []string{
		"--model-base", baseModel,
		"--train-data", datasetTXT,
		"--lora-out", loraOut,
		"--ctx", fmt.Sprint(p.Ctx),
		"--threads", fmt.Sprint(p.Threads),
		"--batch", fmt.Sprint(p.Batch),
		"--adam-iter", fmt.Sprint(cfg.Epochs * 100),
		"--adam-alpha", "0.0002",
		"--lora-r", "16",
		"--lora-alpha", "32",
		"--save-every", "50",
	}
	if hasGPU {
		args = append(args, "--gpu-layers", "99")
	}

	if cfg.DryRun {
		log.Println("  *** DRY-RUN :")
		log.Printf("  %s %s", finetuneBin, strings.Join(args, " "))
		log.Println("\n  ✓ Dry-run OK")
		return
	}

	log.Println()
	start := time.Now()
	if err := runCmd(finetuneBin, args...); err != nil {
		fatal("[TRAINING] ✗ Fine-tuning échoué : " + err.Error())
	}
	log.Printf("\n  [TRAINING] ✓ Fine-tuning terminé en %s", time.Since(start).Round(time.Second))

	// Quantification
	if quantizeBin != "" {
		ggufOut := filepath.Join(mDir, "lora", ggufOutName)
		log.Println("\n  Quantification Q4_K_M...")
		if err := runCmd(quantizeBin, loraOut, ggufOut, "Q4_K_M"); err != nil {
			log.Printf("  ⚠ Quantification échouée : %v", err)
		} else {
			sz := float64(fileSize(ggufOut)) / 1024 / 1024 / 1024
			log.Printf("  [TRAINING] ✓ Modèle prêt : %s (%.1f Go)", ggufOut, sz)
			log.Println("\n  PROCHAINE ÉTAPE : copiez le .gguf dans moteur/models/")
		}
	}

	log.Println()
	sep("[TRAINING] ✓ ENTRAÎNEMENT TERMINÉ")
}

// ─── Profils ──────────────────────────────────────────────────────────────────

func selectProfile(vramFreeGB float64, hasGPU bool) Profile {
	switch {
	case hasGPU && vramFreeGB >= 20:
		return Profile{"24Go (RTX 3090/4090)", 8, 32, 512}
	case hasGPU && vramFreeGB >= 14:
		return Profile{"16Go (RTX 3080Ti/4080)", 8, 16, 512}
	case hasGPU && vramFreeGB >= 10:
		return Profile{"12Go (RTX 3080/4070)", 6, 8, 256}
	case hasGPU && vramFreeGB >= 6:
		return Profile{"8Go (RTX 3070/4060)", 4, 4, 256}
	case hasGPU:
		return Profile{"GPU <6Go", 4, 2, 128}
	default:
		n := runtime.NumCPU()
		if n > 8 {
			n = 8
		}
		return Profile{"CPU only", n, 1, 64}
	}
}

// ─── Conversion JSONL → TXT ───────────────────────────────────────────────────

// convertJSONLtoTXT convertit le dataset Alpaca JSONL vers le format texte
// adapté au modèle cible :
//   - Foundation-Sec-8B (LLaMA 3.1) → template <|begin_of_text|> ... <|eot_id|>
//   - Mistral 7B                     → template Alpaca ### Instruction / ### Response
//
// Le template LLaMA 3.1 est obligatoire pour Foundation-Sec — sinon le modèle
// fine-tuné ne reconnaît pas les tokens spéciaux et produit des réponses incohérentes.
func convertJSONLtoTXT(src, dst string, foundationSec bool) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	var sb strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		instruction := extractField(line, "instruction")
		input := extractField(line, "input")
		output := extractField(line, "output")
		if instruction == "" || output == "" {
			continue
		}
		if foundationSec {
			// Template LLaMA 3.1 Chat — Foundation-Sec-8B natif
			sb.WriteString("<|begin_of_text|>")
			sb.WriteString("<|start_header_id|>system<|end_header_id|>\n\n")
			sb.WriteString(instruction)
			sb.WriteString("<|eot_id|>")
			sb.WriteString("<|start_header_id|>user<|end_header_id|>\n\n")
			sb.WriteString(input)
			sb.WriteString("<|eot_id|>")
			sb.WriteString("<|start_header_id|>assistant<|end_header_id|>\n\n")
			sb.WriteString(output)
			sb.WriteString("<|eot_id|>\n")
		} else {
			// Template Alpaca — Mistral 7B
			sb.WriteString("### Instruction:\n")
			sb.WriteString(instruction)
			sb.WriteString("\n\n### Input:\n")
			sb.WriteString(input)
			sb.WriteString("\n\n### Response:\n")
			sb.WriteString(output)
			sb.WriteString("\n\n")
		}
	}
	return os.WriteFile(dst, []byte(sb.String()), 0644)
}

// extractField extrait la valeur d'un champ string JSON sans librairie externe.
func extractField(jsonLine, field string) string {
	marker := `"` + field + `":`
	idx := strings.Index(jsonLine, marker)
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(jsonLine[idx+len(marker):])
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	var result strings.Builder
	i := 1
	for i < len(rest) {
		c := rest[i]
		if c == '\\' && i+1 < len(rest) {
			i++
			switch rest[i] {
			case '"':
				result.WriteByte('"')
			case 'n':
				result.WriteByte('\n')
			case 't':
				result.WriteByte('\t')
			case '\\':
				result.WriteByte('\\')
			default:
				result.WriteByte('\\')
				result.WriteByte(rest[i])
			}
		} else if c == '"' {
			break
		} else {
			result.WriteByte(c)
		}
		i++
	}
	return result.String()
}

// ─── Binaires llama.cpp ───────────────────────────────────────────────────────

func ensureBinary(mDir, name string, hasGPU bool) (string, error) {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	binName := name + ext

	// 1. Déjà présent dans moteur/ ?
	binPath := filepath.Join(mDir, binName)
	if _, err := os.Stat(binPath); err == nil {
		return binPath, nil
	}

	// 2. Chercher dans les sous-dossiers de moteur/ (extraction précédente)
	var foundInSubdir string
	filepath.Walk(mDir, func(path string, info os.FileInfo, _ error) error {
		if info != nil && !info.IsDir() && strings.EqualFold(info.Name(), binName) {
			foundInSubdir = path
		}
		return nil
	})
	if foundInSubdir != "" {
		// Copier au bon endroit
		data, err := os.ReadFile(foundInSubdir)
		if err == nil {
			if err2 := os.WriteFile(binPath, data, 0755); err2 == nil {
				log.Printf("  ✓ %s copié depuis %s", binName, foundInSubdir)
				return binPath, nil
			}
		}
	}

	log.Printf("  ⚠ %s absent — téléchargement du zip llama.cpp build %s...", binName, llamaBuild)
	zipPath := filepath.Join(mDir, "llama-finetune-cached.zip")

	// Invalider le cache si le zip est d'un autre build (fichier marqueur)
	markerPath := zipPath + ".build"
	if markerData, err := os.ReadFile(markerPath); err == nil {
		if string(markerData) != llamaBuild {
			log.Printf("  ↻ Cache obsolète (build %s → %s) — re-téléchargement", string(markerData), llamaBuild)
			os.Remove(zipPath)
		}
	}

	if _, err := os.Stat(zipPath); os.IsNotExist(err) {
		url := selectURL(hasGPU)
		log.Printf("  ↓ URL : %s", url)
		if err := dlFile(url, zipPath); err != nil {
			return "", fmt.Errorf("téléchargement : %w", err)
		}
		os.WriteFile(markerPath, []byte(llamaBuild), 0644)
		log.Println("  ✓ Téléchargement terminé")
	}

	if err := extractBin(zipPath, binName, mDir); err != nil {
		return "", fmt.Errorf("extraction %s : %w", binName, err)
	}
	if _, err := os.Stat(binPath); err != nil {
		return "", fmt.Errorf("%s introuvable après extraction (build %s ne contient peut-être pas ce binaire)", binName, llamaBuild)
	}
	os.Chmod(binPath, 0755)
	return binPath, nil
}

func selectURL(hasGPU bool) string {
	if runtime.GOOS == "windows" {
		if hasGPU {
			return llamaWindowsCUDA
		}
		return llamaWindowsCPU
	}
	return llamaLinux
}

func extractBin(zipPath, binName, destDir string) error {
	extractDir := filepath.Join(destDir, "llama-extract-tmp")
	os.MkdirAll(extractDir, 0755)
	defer os.RemoveAll(extractDir)

	var err error
	if runtime.GOOS == "windows" {
		err = exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf(`Expand-Archive -Path '%s' -DestinationPath '%s' -Force`, zipPath, extractDir)).Run()
	} else {
		err = exec.Command("unzip", "-o", zipPath, "-d", extractDir).Run()
	}
	if err != nil {
		return fmt.Errorf("décompression : %w", err)
	}

	var found string
	filepath.Walk(extractDir, func(path string, info os.FileInfo, _ error) error {
		if strings.EqualFold(filepath.Base(path), binName) {
			found = path
		}
		return nil
	})
	if found == "" {
		return fmt.Errorf("%s introuvable dans le zip", binName)
	}
	data, err := os.ReadFile(found)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(destDir, binName), data, 0755)
}

func dlFile(url, dest string) error {
	cmd := exec.Command("curl", "-L", "--progress-bar", "-o", dest, url)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err == nil {
		return nil
	}
	if runtime.GOOS == "windows" {
		return exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf(`Invoke-WebRequest -Uri '%s' -OutFile '%s'`, url, dest)).Run()
	}
	return fmt.Errorf("curl indisponible")
}

// ─── Modèle de base ───────────────────────────────────────────────────────────

// findBaseModel retourne le modèle GGUF à utiliser comme base pour le fine-tuning.
// Priorité : Foundation-Sec-8B (Cisco, LLaMA 3.1 base, Apache 2.0, seul fine-tunable officiellement)
// → Mistral 7B en fallback (moins optimal — architecture différente)
func findBaseModel(mDir string) (path string, modelName string) {
	modelsDir := filepath.Join(mDir, "models")

	// Priorité 1 : Foundation-Sec-8B Instruct (cible principale du fine-tuning)
	priority := []struct{ file, name string }{
		{"Foundation-Sec-8B-Instruct-Q4_K_M.gguf", "Foundation-Sec-8B (Cisco — recommandé)"},
		{"mistral-7b-instruct-v0.2.Q4_K_M.gguf", "Mistral 7B Instruct v0.2 (fallback)"},
		{"mistral-7b-instruct-v0.3.Q4_K_M.gguf", "Mistral 7B Instruct v0.3 (fallback)"},
	}
	for _, m := range priority {
		p := filepath.Join(modelsDir, m.file)
		if _, err := os.Stat(p); err == nil {
			return p, m.name
		}
	}

	// Fallback générique : n'importe quel GGUF présent
	entries, _ := os.ReadDir(modelsDir)
	for _, e := range entries {
		if strings.ToLower(filepath.Ext(e.Name())) == ".gguf" {
			return filepath.Join(modelsDir, e.Name()), e.Name()
		}
	}
	return "", ""
}

// ─── moteurDir ────────────────────────────────────────────────────────────────

func moteurDir() string {
	var base string
	if exe, err := os.Executable(); err == nil {
		base = filepath.Dir(filepath.Dir(exe))
	}
	if base == "" {
		if cwd, err := os.Getwd(); err == nil {
			base = filepath.Dir(cwd)
		}
	}
	dir := filepath.Join(base, "moteur")
	os.MkdirAll(filepath.Join(dir, "models"), 0755)
	return dir
}

// ─── GPU ──────────────────────────────────────────────────────────────────────

func detectGPU() (bool, string, float64, float64) {
	out, err := exec.Command("nvidia-smi",
		"--query-gpu=name,memory.total,memory.free",
		"--format=csv,noheader,nounits").Output()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) > 0 {
			parts := strings.SplitN(lines[0], ",", 3)
			if len(parts) == 3 {
				name := strings.TrimSpace(parts[0])
				var total, free int64
				fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &total)
				fmt.Sscanf(strings.TrimSpace(parts[2]), "%d", &free)
				if name != "" && total > 0 {
					return true, name, float64(total) / 1024, float64(free) / 1024
				}
			}
		}
	}
	if runtime.GOOS == "linux" {
		if _, e := os.Stat("/dev/nvidia0"); e == nil {
			return true, "NVIDIA GPU (VRAM inconnue)", 8.0, 6.0
		}
	}
	return false, "", 0, 0
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func runCmd(bin string, args ...string) error {
	cmd := exec.Command(bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func fileSize(path string) int64 {
	if info, err := os.Stat(path); err == nil {
		return info.Size()
	}
	return 0
}

func fatal(msg string) {
	log.Println("  [TRAINING] ✗ " + msg)
	os.Exit(1)
}

func sep(title string) {
	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	if title != "" {
		log.Println("  " + title)
		log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	}
}

func printBanner() {
	log.Println()
	log.Println("  ╔════════════════════════════════════════════════════╗")
	log.Println("  ║   RF Sandbox Go — Entraîneur LoRA                  ║")
	log.Println("  ║   100% Go — llama-finetune natif (zéro Python)     ║")
	log.Println("  ║   Cible : Foundation-Sec-8B (Cisco, Apache 2.0)    ║")
	log.Println("  ║   Format : LLaMA 3.1 Chat Template                 ║")
	log.Println("  ╚════════════════════════════════════════════════════╝")
	log.Println()
}
