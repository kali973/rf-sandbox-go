// setup-moteur — Remplace setup_moteur.ps1
//
// Télécharge llama.cpp (CUDA ou CPU) + Mistral 7B GGUF dans moteur\
// Idempotent : ne re-télécharge pas si les fichiers sont déjà présents.
// Détecte le GPU et affiche la configuration optimale pour llama-server.
//
// Usage:
//
//	setup-moteur.exe            — dossier moteur\ détecté automatiquement
//	setup-moteur.exe -moteur D:\GolandProjects\moteur
package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	llamaCppWinCUDA   = "https://github.com/ggml-org/llama.cpp/releases/download/b8185/llama-b8185-bin-win-cuda-cu12.4-x64.zip"
	llamaCppWinCUDArt = "https://github.com/ggml-org/llama.cpp/releases/download/b8185/cudart-llama-bin-win-cuda-12.4-x64.zip"
	llamaCppWinCPU    = "https://github.com/ggml-org/llama.cpp/releases/download/b8185/llama-b8185-bin-win-cpu-x64.zip"
	llamaCppLinux     = "https://github.com/ggml-org/llama.cpp/releases/download/b8185/llama-b8185-bin-ubuntu-x64.zip"
	mistralURL        = "https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF/resolve/main/mistral-7b-instruct-v0.2.Q4_K_M.gguf"
	mistralModel      = "mistral-7b-instruct-v0.2.Q4_K_M.gguf"
	modelMinSize      = 100 * 1024 * 1024 // 100 Mo minimum
)

func main() {
	moteurFlag := flag.String("moteur", "", "Chemin du dossier moteur\\ (défaut : auto)")
	flag.Parse()

	mDir := *moteurFlag
	if mDir == "" {
		mDir = resolveMoteurDir()
	}
	modelsDir := filepath.Join(mDir, "models")
	llamaExe := llamaServerExe(mDir)
	modelFile := filepath.Join(modelsDir, mistralModel)

	fmt.Println()
	fmt.Println("  ==============================================")
	fmt.Println("    RF Sandbox Go - Setup moteur IA (llama.cpp)")
	fmt.Println("  ==============================================")
	fmt.Printf("  Moteur  : llama.cpp b8185 + GPU CUDA\n")
	fmt.Printf("  Modele  : Mistral 7B Q4_K_M (~4.1 Go)\n")
	fmt.Printf("  Dossier : %s\n", mDir)
	fmt.Println()

	// Vérification rapide
	llamaOK := fileExists(llamaExe)
	modelOK := fileExistsMin(modelFile, modelMinSize)
	if llamaOK && modelOK {
		sizeMB := fileSize(modelFile) / (1024 * 1024)
		fmt.Printf("  [OK] Moteur IA deja pret (llama-server + modele %d Mo) — aucun telechargement necessaire.\n", sizeMB)
		printGPUReport(mDir)
		return
	}

	if err := os.MkdirAll(modelsDir, 0755); err != nil {
		fatalf("Impossible de créer %s : %v", mDir, err)
	}

	// Étape 1 : llama-server
	if llamaOK {
		fmt.Println("  [OK] llama-server deja present — etape ignoree.")
	} else {
		if err := installLlama(mDir); err != nil {
			fatalf("Installation llama.cpp échouée : %v", err)
		}
	}

	// Étape 2 : Modèle GGUF
	if modelOK {
		sizeMB := fileSize(modelFile) / (1024 * 1024)
		fmt.Printf("  [OK] Modele Mistral 7B deja present (%d Mo) — etape ignoree.\n", sizeMB)
	} else {
		if fileExists(modelFile) {
			sizeMB := fileSize(modelFile) / (1024 * 1024)
			fmt.Printf("  [!] Modele partiel detecte (%d Mo) — suppression et re-telechargement.\n", sizeMB)
			os.Remove(modelFile)
		}
		fmt.Println("  [2/2] Telechargement Mistral 7B Q4_K_M depuis Hugging Face (~4.1 Go)...")
		fmt.Println("        Cela peut prendre plusieurs minutes selon votre connexion.")
		fmt.Println()
		start := time.Now()
		if err := downloadResumable(mistralURL, modelFile); err != nil {
			os.Remove(modelFile)
			fmt.Fprintf(os.Stderr, "  [ERREUR] Telechargement echoue : %v\n", err)
			fmt.Fprintf(os.Stderr, "  Telechargez manuellement depuis :\n  %s\n  Placez le fichier dans : %s\n", mistralURL, modelsDir)
			os.Exit(1)
		}
		dur := time.Since(start).Minutes()
		sizeMB := fileSize(modelFile) / (1024 * 1024)
		fmt.Printf("  [OK] Modele telecharge : %d Mo en %.1f min.\n", sizeMB, dur)
	}

	printGPUReport(mDir)

	fmt.Println()
	fmt.Println("  [OK] Moteur IA pret. Demarrage automatique au prochain lancement.")
	fmt.Println()
}

// ── Installation llama.cpp ────────────────────────────────────────────────────

func installLlama(mDir string) error {
	zipPath := filepath.Join(mDir, "llama-cpp.zip")

	switch runtime.GOOS {
	case "windows":
		// Tentative CUDA
		fmt.Println("  [1/2] Telechargement llama.cpp CUDA (GPU NVIDIA) b8185...")
		if err := downloadFile(llamaCppWinCUDA, zipPath); err == nil {
			if err2 := extractLlamaServer(zipPath, mDir); err2 == nil {
				fmt.Println("  [OK] Build CUDA telecharge.")
				// DLLs CUDA runtime
				installCUDArt(mDir)
				return nil
			}
			os.Remove(zipPath)
		}
		// Fallback CPU
		fmt.Println("  [!] CUDA indisponible — fallback CPU...")
		fmt.Println("  [1/2] Telechargement llama.cpp CPU b8185...")
		if err := downloadFile(llamaCppWinCPU, zipPath); err != nil {
			return fmt.Errorf("telechargement CPU : %w", err)
		}
		if err := extractLlamaServer(zipPath, mDir); err != nil {
			return fmt.Errorf("extraction CPU : %w", err)
		}
		fmt.Println("  [OK] Build CPU telecharge.")
		return nil

	case "linux":
		fmt.Println("  [1/2] Telechargement llama.cpp Linux b8185...")
		if err := downloadFile(llamaCppLinux, zipPath); err != nil {
			return fmt.Errorf("telechargement Linux : %w", err)
		}
		if err := extractLlamaServer(zipPath, mDir); err != nil {
			return fmt.Errorf("extraction Linux : %w", err)
		}
		fmt.Println("  [OK] Build Linux telecharge.")
		return nil

	default:
		return fmt.Errorf("OS non supporte : %s", runtime.GOOS)
	}
}

func installCUDArt(mDir string) {
	// Vérifier si déjà présent
	entries, _ := os.ReadDir(mDir)
	for _, e := range entries {
		if strings.HasPrefix(strings.ToLower(e.Name()), "cudart64_") {
			fmt.Println("  [OK] DLLs CUDA runtime deja presentes — etape ignoree.")
			return
		}
	}
	fmt.Println("  Telechargement DLLs CUDA runtime...")
	cudartZip := filepath.Join(mDir, "cudart.zip")
	if err := downloadFile(llamaCppWinCUDArt, cudartZip); err != nil {
		fmt.Println("  [!] DLLs CUDA runtime non telecharges (optionnel si CUDA Toolkit installe).")
		return
	}
	defer os.Remove(cudartZip)
	extractDir := filepath.Join(mDir, "cudart-extract")
	if err := unzip(cudartZip, extractDir); err != nil {
		fmt.Println("  [!] Extraction DLLs CUDA echouee.")
		return
	}
	defer os.RemoveAll(extractDir)
	count := 0
	filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && strings.ToLower(filepath.Ext(path)) == ".dll" {
			dst := filepath.Join(mDir, filepath.Base(path))
			if data, e := os.ReadFile(path); e == nil {
				os.WriteFile(dst, data, 0755)
				count++
			}
		}
		return nil
	})
	fmt.Printf("  [OK] %d DLLs CUDA runtime installes.\n", count)
}

func extractLlamaServer(zipPath, mDir string) error {
	extractDir := filepath.Join(mDir, "llama-extract")
	defer os.RemoveAll(extractDir)
	defer os.Remove(zipPath)

	if err := unzip(zipPath, extractDir); err != nil {
		return err
	}

	serverName := "llama-server"
	if runtime.GOOS == "windows" {
		serverName = "llama-server.exe"
	}

	var srcDir string
	filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && strings.EqualFold(filepath.Base(path), serverName) {
			srcDir = filepath.Dir(path)
		}
		return nil
	})
	if srcDir == "" {
		return fmt.Errorf("llama-server introuvable dans le zip")
	}

	entries, _ := os.ReadDir(srcDir)
	for _, e := range entries {
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".exe" || ext == ".dll" || ext == ".so" || strings.EqualFold(e.Name(), serverName) {
			src := filepath.Join(srcDir, e.Name())
			dst := filepath.Join(mDir, e.Name())
			if data, err := os.ReadFile(src); err == nil {
				os.WriteFile(dst, data, 0755)
			}
		}
	}

	if !fileExists(filepath.Join(mDir, serverName)) {
		return fmt.Errorf("llama-server non copie vers %s", mDir)
	}
	fmt.Printf("  [OK] llama-server installe dans %s\n", mDir)
	return nil
}

// ── Rapport GPU ───────────────────────────────────────────────────────────────

func printGPUReport(mDir string) {
	fmt.Println()
	fmt.Println("  [3/3] Detection GPU et configuration optimale...")
	fmt.Println()

	gpuName, gpuVRAM, gpuFound := detectGPU(mDir)
	cpuCount := runtime.NumCPU()
	optThreads := clamp(cpuCount/2, 2, 16)

	if gpuFound {
		fmt.Printf("  [GPU] Detecte    : %s\n", gpuName)
		if gpuVRAM > 0 {
			fmt.Printf("  [GPU] VRAM       : %.1f Go\n", gpuVRAM)
		}
		fmt.Printf("  [GPU] Config     : -ngl 99 (toutes couches GPU) | --batch-size 512\n")
		fmt.Printf("  [CPU] Threads    : %d / %d logiques (reduit car GPU actif)\n", clamp(optThreads, 2, 4), cpuCount)
		fmt.Println()
		fmt.Println("  NOTE : Le moteur IA utilisera votre GPU au maximum pour des")
		fmt.Println("         performances optimales (inference acceleree CUDA).")
	} else {
		fmt.Printf("  [GPU] Aucun GPU NVIDIA detecte — mode CPU uniquement\n")
		fmt.Printf("  [CPU] Threads    : %d / %d logiques\n", optThreads, cpuCount)
		fmt.Printf("  [CPU] Batch size : 256\n")
		fmt.Println()
		fmt.Println("  CONSEIL : Pour de meilleures performances, installez les drivers NVIDIA")
		fmt.Println("            et relancez bootstrap.bat pour activer l'acceleration GPU.")
	}
}

func detectGPU(mDir string) (name string, vramGB float64, found bool) {
	// nvidia-smi
	if out, err := exec.Command("nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits").Output(); err == nil {
		line := strings.TrimSpace(string(out))
		if line != "" {
			parts := strings.SplitN(line, ",", 2)
			gpuName := strings.TrimSpace(parts[0])
			var vram float64
			if len(parts) == 2 {
				fmt.Sscanf(strings.TrimSpace(parts[1]), "%f", &vram)
				vram = vram / 1024
			}
			return gpuName, vram, true
		}
	}
	// DLLs CUDA (Windows)
	if runtime.GOOS == "windows" {
		if entries, err := os.ReadDir(mDir); err == nil {
			for _, e := range entries {
				if strings.HasPrefix(strings.ToLower(e.Name()), "cudart64_") {
					return "GPU NVIDIA (DLLs CUDA presentes, nvidia-smi indisponible)", 0, true
				}
			}
		}
	}
	// /dev/nvidia0 (Linux)
	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/dev/nvidia0"); err == nil {
			return "GPU NVIDIA (/dev/nvidia0 detecte)", 0, true
		}
	}
	return "", 0, false
}

// ── Téléchargement ───────────────────────────────────────────────────────────

func downloadFile(url, dest string) error {
	return downloadResumable(url, dest)
}

func downloadResumable(url, dest string) error {
	const maxRetries = 20
	client := &http.Client{Timeout: 0}

	var total int64
	if resp, err := client.Head(url); err == nil {
		total = resp.ContentLength
		resp.Body.Close()
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			fmt.Printf("  [AI] Reprise telechargement (tentative %d/%d)...\n", attempt+1, maxRetries)
			time.Sleep(5 * time.Second)
		}

		var offset int64
		if info, err := os.Stat(dest); err == nil {
			offset = info.Size()
		}
		if total > 0 && offset >= total {
			return nil
		}
		if offset > 0 && attempt == 0 {
			fmt.Printf("  Fichier partiel detecte (%s) — reprise...\n", fmtBytes(offset))
		}

		req, _ := http.NewRequest("GET", url, nil)
		if offset > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
		}
		req.Header.Set("User-Agent", "rf-sandbox-go/2.0")

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("  Erreur connexion: %v\n", err)
			continue
		}
		if resp.StatusCode == 416 {
			resp.Body.Close()
			return nil
		}
		if resp.StatusCode != 200 && resp.StatusCode != 206 {
			resp.Body.Close()
			return fmt.Errorf("HTTP %d : %s", resp.StatusCode, url)
		}
		if total == 0 && resp.ContentLength > 0 {
			if resp.StatusCode == 206 {
				total = offset + resp.ContentLength
			} else {
				total = resp.ContentLength
			}
		}

		f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			resp.Body.Close()
			return err
		}

		buf := make([]byte, 256*1024)
		downloaded := offset
		lastLog := time.Now()
		var readErr error

		for {
			n, e := resp.Body.Read(buf)
			if n > 0 {
				f.Write(buf[:n])
				downloaded += int64(n)
				if time.Since(lastLog) >= 5*time.Second {
					if total > 0 {
						fmt.Printf("  %.1f%% (%s / %s)\n",
							float64(downloaded)/float64(total)*100,
							fmtBytes(downloaded), fmtBytes(total))
					} else {
						fmt.Printf("  Telecharge : %s\n", fmtBytes(downloaded))
					}
					lastLog = time.Now()
				}
			}
			if e != nil {
				readErr = e
				break
			}
		}
		f.Close()
		resp.Body.Close()

		if readErr == io.EOF {
			if total > 0 {
				if info, err := os.Stat(dest); err == nil && info.Size() >= total {
					return nil
				}
				continue
			}
			return nil
		}
		fmt.Printf("  Coupure reseau: %v — nouvelle tentative...\n", readErr)
	}
	return fmt.Errorf("telechargement echoue apres %d tentatives", maxRetries)
}

// ── ZIP ───────────────────────────────────────────────────────────────────────

func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	os.MkdirAll(dest, 0755)
	for _, f := range r.File {
		path := filepath.Join(dest, filepath.FromSlash(f.Name))
		if f.FileInfo().IsDir() {
			os.MkdirAll(path, 0755)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(path)
		if err != nil {
			rc.Close()
			return err
		}
		io.Copy(out, rc)
		out.Close()
		rc.Close()
	}
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func resolveMoteurDir() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join("..", "moteur")
	}
	return filepath.Join(filepath.Dir(filepath.Dir(exe)), "moteur")
}

func llamaServerExe(mDir string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(mDir, "llama-server.exe")
	}
	return filepath.Join(mDir, "llama-server")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func fileExistsMin(path string, minSize int64) bool {
	info, err := os.Stat(path)
	return err == nil && info.Size() >= minSize
}

func fileSize(path string) int64 {
	info, _ := os.Stat(path)
	if info == nil {
		return 0
	}
	return info.Size()
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func fmtBytes(b int64) string {
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

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "  [ERREUR] "+format+"\n", args...)
	os.Exit(1)
}
