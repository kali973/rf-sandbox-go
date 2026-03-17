// compilateur — Post-compilation : audit sécurité, vault, lancement UI, installation USB.
// La compilation elle-même est gérée par bootstrap.bat (Windows) ou bootstrap.sh (Linux/macOS).
// Détecte automatiquement l'OS au runtime.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func main() {
	noUI := flag.Bool("no-ui", false, "Ne pas lancer l'UI après compilation")
	flag.Parse()

	projectDir := resolveProjectDir()

	// Extension des binaires selon l'OS
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}

	fmt.Println()
	fmt.Printf("  ==========================================\n")
	fmt.Printf("    RF Sandbox Go - Post-compilation (%s/%s)\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  ==========================================\n")
	fmt.Println()

	// ── 1. Détection USB (Windows uniquement) ───────────────────────────────
	usbDrive := detectUSB()
	if usbDrive != "" {
		fmt.Printf("  Clé USB détectée : %s\n", usbDrive)
		installUSB(projectDir, usbDrive, ext)
		return
	}

	// ── 2. Vault seal anticipé ──────────────────────────────────────────────
	// Chiffre api_token, hf_token, abuseipdb_key AVANT que gitleaks ne scanne
	vaultExe := findExe(projectDir, "vault")
	if vaultExe != "" {
		_ = runPrintErr(projectDir, vaultExe, "seal")
	}

	// ── 3. Pré-compilation audit-securite (version fraîche) ─────────────────
	fmt.Println("=== Pre-compilation audit-securite ===")
	localTmp := filepath.Join(projectDir, ".gotmp")
	os.MkdirAll(localTmp, 0755)
	// Windows : GetTempPath() lit TEMP/TMP
	// Linux/macOS : Go lit TMPDIR
	os.Setenv("TEMP", localTmp)
	os.Setenv("TMP", localTmp)
	os.Setenv("TMPDIR", localTmp)
	os.Setenv("GOTMPDIR", localTmp)

	auditSecOut := filepath.Join(projectDir, "audit-securite"+ext)
	buildCmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", auditSecOut, "./cmd/audit-securite")
	buildCmd.Dir = projectDir
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		fmt.Printf("  [!] audit-securite%s : compilation echouee - utilisation du binaire existant.\n", ext)
	} else {
		fmt.Printf("  [OK] audit-securite%s mis a jour.\n", ext)
	}
	os.RemoveAll(localTmp)
	fmt.Println()

	// ── 4. Audit sécurité ───────────────────────────────────────────────────
	fmt.Println("=== Audit securite du code source ===")
	auditSecExe := findExe(projectDir, "audit-securite")
	if auditSecExe != "" {
		cmd := exec.Command(auditSecExe)
		cmd.Dir = projectDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 1 {
				fmt.Println()
				fmt.Println("  [!] ATTENTION : Des secrets ont ete detectes dans le code.")
				fmt.Println("      Consultez le rapport dans audit/ avant de distribuer.")
				fmt.Println()
			}
		}
	} else {
		fmt.Println("  [i] audit-securite absent - audit ignore.")
	}
	fmt.Println()

	// ── 5. Vault init + seal + status ───────────────────────────────────────
	if vaultExe != "" {
		runPrint(projectDir, vaultExe, "init")
		fmt.Println("Chiffrement/synchronisation du token...")
		if err := runPrintErr(projectDir, vaultExe, "seal"); err != nil {
			fmt.Fprintln(os.Stderr, "ERREUR : vault seal echoue.")
			os.Exit(1)
		}
		runPrint(projectDir, vaultExe, "status")
	}

	if *noUI {
		return
	}

	// ── 6. Kill port + lancement UI ─────────────────────────────────────────
	fmt.Println()
	fmt.Println("Verification du port 8766...")
	killPort(8766)
	fmt.Println()
	fmt.Println("Lancement sur http://localhost:8766 ...")

	mainExe := filepath.Join(projectDir, "rf-sandbox"+ext)
	// launchUI est défini dans launch_windows.go ou launch_unix.go selon l'OS
	if err := launchUI(mainExe, projectDir); err != nil {
		fmt.Fprintf(os.Stderr, "ERREUR lancement UI : %v\n", err)
		os.Exit(1)
	}
	// NB : openBrowser est déjà appelé par ui.Start() dans rf-sandbox.exe
	// Ne pas l'appeler ici pour éviter une double ouverture du navigateur
}

// ── Installation USB ──────────────────────────────────────────────────────────

func installUSB(projectDir, usbDrive, ext string) {
	usbRoot := filepath.Join(usbDrive, "rf-sandbox-go")
	fmt.Println()
	fmt.Println("==========================================")
	fmt.Printf("  Installation sur %s\n", usbRoot)
	fmt.Println("==========================================")
	for _, sub := range []string{"", "config", "output", "samples"} {
		os.MkdirAll(filepath.Join(usbRoot, sub), 0755)
	}
	for _, name := range []string{
		"rf-sandbox", "vault", "audit", "audit-securite",
		"setup-moteur", "bootstrap-post", "compilateur",
		"update-proxy", "trainer",
	} {
		src := filepath.Join(projectDir, name+ext)
		if _, err := os.Stat(src); err == nil {
			copyFile(src, filepath.Join(usbRoot, name+ext))
			fmt.Printf("  [OK] %s%s\n", name, ext)
		}
	}
	copyDir(filepath.Join(projectDir, "config"), filepath.Join(usbRoot, "config"))
	fmt.Println("  [OK] config/")
	moteurSrc := filepath.Join(filepath.Dir(projectDir), "moteur")
	if _, err := os.Stat(moteurSrc); err == nil {
		fmt.Println("  Copie du moteur IA (~4+ Go, patience)...")
		copyDir(moteurSrc, filepath.Join(usbRoot, "moteur"))
		fmt.Println("  [OK] moteur/")
	} else {
		fmt.Println("  [INFO] moteur/ absent - executer setup-moteur sur la cible.")
	}
	copyDir(filepath.Join(projectDir, "samples"), filepath.Join(usbRoot, "samples"))
	fmt.Println("  [OK] samples/")
	// Script de lancement selon l'OS
	if runtime.GOOS == "windows" {
		src := filepath.Join(projectDir, "scripts", "lancer.bat")
		if _, err := os.Stat(src); err == nil {
			copyFile(src, filepath.Join(usbRoot, "lancer.bat"))
			fmt.Println("  [OK] lancer.bat")
		}
	} else {
		src := filepath.Join(projectDir, "scripts", "bootstrap.sh")
		if _, err := os.Stat(src); err == nil {
			copyFile(src, filepath.Join(usbRoot, "bootstrap.sh"))
			os.Chmod(filepath.Join(usbRoot, "bootstrap.sh"), 0755)
			fmt.Println("  [OK] bootstrap.sh")
		}
	}
	fmt.Println()
	fmt.Println("  Installation terminee !")
	fmt.Println("==========================================")
}

// ── Détection USB ─────────────────────────────────────────────────────────────

func detectUSB() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	for _, letter := range "DEFGHIJKLMNOPQRSTUVWXYZ" {
		drive := string(letter) + ":"
		out, err := exec.Command("fsutil", "fsinfo", "driveType", drive).Output()
		if err == nil && strings.Contains(strings.ToLower(string(out)), "removable") {
			return string(letter) + `:\`
		}
	}
	return ""
}

// ── Kill port ─────────────────────────────────────────────────────────────────

func killPort(port int) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		fmt.Printf("  -> Port %d libre.\n", port)
		return
	}
	conn.Close()
	fmt.Printf("  -> Port %d occupe - kill...\n", port)
	switch runtime.GOOS {
	case "windows":
		out, _ := exec.Command("netstat", "-ano").Output()
		target := fmt.Sprintf(":%d", port)
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) < 5 || !strings.HasSuffix(fields[1], target) {
				continue
			}
			pid := fields[len(fields)-1]
			if pid != "0" {
				exec.Command("taskkill", "/F", "/PID", pid).Run()
			}
		}
	default:
		exec.Command("fuser", "-k", "-9", fmt.Sprintf("%d/tcp", port)).Run()
	}
	time.Sleep(500 * time.Millisecond)
	fmt.Printf("  -> Port %d libere.\n", port)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func findExe(projectDir, name string) string {
	// Linux/macOS : chercher sans extension en premier
	candidates := []string{name, name + ".exe"}
	if runtime.GOOS == "windows" {
		candidates = []string{name + ".exe", name}
	}
	for _, n := range candidates {
		p := filepath.Join(projectDir, n)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func runPrint(dir, name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func runPrintErr(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func copyFile(src, dst string) {
	data, err := os.ReadFile(src)
	if err == nil {
		os.WriteFile(dst, data, 0755)
	}
}

func copyDir(src, dst string) {
	filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		copyFile(path, target)
		return nil
	})
}

func resolveProjectDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return filepath.Dir(exe)
}
