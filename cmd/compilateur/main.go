// compilateur — Post-compilation : audit, vault, lancement UI, installation USB.
// La compilation elle-même est gérée par bootstrap.bat via _build_tmp.bat.
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
	ext := ".exe"
	if runtime.GOOS != "windows" {
		ext = ""
	}

	fmt.Println()
	fmt.Println("  ==========================================")
	fmt.Println("    RF Sandbox Go - Post-compilation")
	fmt.Println("  ==========================================")
	fmt.Println()

	// ── 1. Détection USB ────────────────────────────────────────────────────
	usbDrive := detectUSB()
	if usbDrive != "" {
		fmt.Printf("  Clé USB détectée : %s\\\n", usbDrive)
		installUSB(projectDir, usbDrive, ext)
		return
	}

	// ── 2. Vault seal anticipé (avant audit gitleaks) ───────────────────────
	// Chiffre api_token, hf_token, abuseipdb_key avant que gitleaks ne scanne
	vaultExe := findExe(projectDir, "vault")
	if vaultExe != "" {
		_ = runPrintErr(projectDir, vaultExe, "seal")
	}

	// ── 3. Pré-compilation audit-securite (version fraîche) ─────────────────
	fmt.Println("=== Pre-compilation audit-securite ===")
	// Recréer .gotmp si bootstrap.bat l'a supprimé entre-temps
	localTmp := filepath.Join(projectDir, ".gotmp")
	os.MkdirAll(localTmp, 0755)
	os.Setenv("TEMP", localTmp)
	os.Setenv("TMP", localTmp)
	auditSecOut := filepath.Join(projectDir, "audit-securite"+ext)
	buildCmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", auditSecOut, "./cmd/audit-securite")
	buildCmd.Dir = projectDir
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		fmt.Println("  [!] Pre-compilation audit-securite echouee - utilisation du binaire existant.")
	} else {
		fmt.Println("  [OK] audit-securite.exe mis a jour.")
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
		fmt.Println("  [i] audit-securite.exe absent - audit ignore.")
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
	if runtime.GOOS == "windows" {
		// Lancer dans une nouvelle fenetre CMD independante.
		// "cmd /C start" cree un processus detache qui survit
		// apres la fermeture de bootstrap.bat/compilateur.exe.
		exec.Command("cmd", "/C", "start", "RF Sandbox Go", mainExe, "-ui").Run()
	} else {
		cmd := exec.Command(mainExe, "-ui")
		cmd.Dir = projectDir
		cmd.Start()
	}
}

func installUSB(projectDir, usbDrive, ext string) {
	usbRoot := usbDrive + `rf-sandbox-go`
	fmt.Println()
	fmt.Println("==========================================")
	fmt.Printf("  Installation sur %srf-sandbox-go\n", usbDrive)
	fmt.Println("==========================================")
	for _, sub := range []string{"", "config", "output", "samples"} {
		os.MkdirAll(filepath.Join(usbRoot, sub), 0755)
	}
	for _, name := range []string{
		"rf-sandbox" + ext, "vault" + ext, "audit" + ext,
		"audit-securite" + ext, "setup-moteur" + ext,
		"bootstrap-post" + ext, "compilateur" + ext,
		"update-proxy" + ext, "trainer" + ext,
	} {
		src := filepath.Join(projectDir, name)
		if _, err := os.Stat(src); err == nil {
			copyFile(src, filepath.Join(usbRoot, name))
			fmt.Printf("  [OK] %s\n", name)
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
		fmt.Println("  [INFO] moteur/ absent - executer setup-moteur.exe sur la cible.")
	}
	copyDir(filepath.Join(projectDir, "samples"), filepath.Join(usbRoot, "samples"))
	fmt.Println("  [OK] samples/")
	lancer := filepath.Join(projectDir, "scripts", "lancer.bat")
	if _, err := os.Stat(lancer); err == nil {
		copyFile(lancer, filepath.Join(usbRoot, "lancer.bat"))
		fmt.Println("  [OK] lancer.bat")
	}
	fmt.Println()
	fmt.Println("  Installation terminee !")
	fmt.Printf("  %srf-sandbox-go\\\n", usbDrive)
	fmt.Println("==========================================")
}

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

func killPort(port int) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		fmt.Printf("  -> Port %d libre.\n", port)
		return
	}
	conn.Close()
	fmt.Printf("  -> Port %d occupe - kill...\n", port)
	if runtime.GOOS == "windows" {
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
	} else {
		exec.Command("fuser", "-k", "-9", fmt.Sprintf("%d/tcp", port)).Run()
	}
	time.Sleep(500 * time.Millisecond)
	fmt.Printf("  -> Port %d libere.\n", port)
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

func findExe(projectDir, name string) string {
	for _, n := range []string{name + ".exe", name} {
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
	data, _ := os.ReadFile(src)
	os.WriteFile(dst, data, 0755)
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
	return filepath.Dir(exe)
}
