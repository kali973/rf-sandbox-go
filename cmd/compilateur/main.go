// compilateur — Remplace compilateur.ps1 + bootstrap.bat
//
// Orchestre l'ensemble du bootstrap :
//  1. Détection USB automatique
//  2. Audit sécurité (via audit-securite.exe)
//  3. Compilation Go (rf-sandbox, vault, audit, setup-moteur, bootstrap-post, compilateur)
//  4. Vault init + seal
//  5. Kill port 8766 + lancement UI  (mode local)
//     OU installation sur clé USB     (mode USB)
//
// Usage:
//
//	compilateur.exe              — auto
//	compilateur.exe -target windows|linux|darwin
//	compilateur.exe -no-ui       — compile sans lancer l'UI
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
	targetFlag := flag.String("target", "", "Cible : windows|linux|darwin (défaut : auto)")
	noUI := flag.Bool("no-ui", false, "Ne pas lancer l'UI après compilation")
	flag.Parse()

	projectDir := resolveProjectDir()

	fmt.Println()
	fmt.Println("  ==========================================")
	fmt.Println("    RF Sandbox Go - Compilateur")
	fmt.Println("  ==========================================")
	fmt.Println()

	// ── 1. Détection USB ─────────────────────────────────────────────────────
	usbDrive := detectUSB()
	usbMode := usbDrive != ""
	if usbMode {
		fmt.Println()
		fmt.Println("  ==========================================")
		fmt.Printf("    CLE USB DETECTEE : %s\\\n", usbDrive)
		fmt.Println("    Installation automatique sur la cle.")
		fmt.Println("  ==========================================")
	} else {
		fmt.Println("  Aucune cle USB detectee -> compilation dans le dossier courant.")
	}
	fmt.Println()

	// ── 1b. Vault seal automatique ───────────────────────────────────────────
	// Chiffre hf_token, api_token, abuseipdb_key AVANT l'audit gitleaks
	// pour qu'aucun secret ne soit visible en clair dans config.json.
	vaultExeEarly := findExe(projectDir, "vault")
	if vaultExeEarly != "" {
		_ = runPrintErr(projectDir, vaultExeEarly, "seal")
	}

	// ── 2. Compilation anticipée de audit-securite ───────────────────────────
	// On compile audit-securite.exe EN PREMIER pour que l'audit tourne
	// toujours avec la dernière version du code (analyse IA incluse).
	fmt.Println("=== Pre-compilation audit-securite ===")
	targetEarly := detectOS()
	_, _, extEarly := targetToEnv(targetEarly)
	auditSecOut := filepath.Join(projectDir, "audit-securite"+extEarly)
	args := []string{"build", "-ldflags=-s -w", "-o", auditSecOut, "./cmd/audit-securite"}
	buildCmd := exec.Command("go", args...)
	buildCmd.Dir = projectDir
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		fmt.Println("  [!] Pre-compilation audit-securite echouee — utilisation du binaire existant.")
	} else {
		fmt.Println("  [OK] audit-securite.exe mis a jour.")
	}
	fmt.Println()

	// ── 3. Audit sécurité ────────────────────────────────────────────────────
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

	// ── 4. Cible de compilation ───────────────────────────────────────────────
	target := *targetFlag
	if usbMode {
		target = "windows"
		fmt.Println("=== Compilation de RF Sandbox Go ===")
		fmt.Println("  -> Mode USB : cible forcee windows/amd64")
	} else if target == "" {
		target = detectOS()
		fmt.Println("=== Compilation de RF Sandbox Go ===")
		fmt.Printf("  -> Cible auto-detectee : %s\n", target)
	} else {
		fmt.Println("=== Compilation de RF Sandbox Go ===")
		fmt.Printf("  -> Cible forcee : %s\n", target)
	}

	goos, goarch, ext := targetToEnv(target)
	if goos == "" {
		fmt.Fprintf(os.Stderr, "Cible invalide : %s. Utilise : windows, linux ou darwin\n", target)
		os.Exit(1)
	}

	env := append(os.Environ(),
		"GOOS="+goos,
		"GOARCH="+goarch,
	)

	// ── 4. Dépendances Go ─────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("Installation des dependances Go...")
	deps := [][]string{
		{"go", "get", "github.com/Azure/go-ntlmssp@v0.0.0-20221128193559-754e69321358"},
		{"go", "get", "github.com/joho/godotenv@v1.5.1"},
		{"go", "mod", "tidy"},
	}
	for _, d := range deps {
		fmt.Printf("  -> %s\n", strings.Join(d[1:], " "))
		if err := runEnv(projectDir, env, d[0], d[1:]...); err != nil {
			fmt.Fprintf(os.Stderr, "ERREUR : %s : %v\n", d[1], err)
			os.Exit(1)
		}
	}

	// ── 5. Compilation ────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Printf("Compilation en cours pour %s/%s...\n", goos, goarch)

	binaries := []struct {
		name string
		pkg  string
		must bool
	}{
		{"rf-sandbox" + ext, "./cmd", true},
		{"vault" + ext, "./cmd/vault", true},
		{"audit" + ext, "./cmd/audit", false},
		{"audit-securite" + ext, "./cmd/audit-securite", false},
		{"setup-moteur" + ext, "./cmd/setup-moteur", false},
		{"bootstrap-post" + ext, "./cmd/bootstrap-post", false},
		{"compilateur" + ext, "./cmd/compilateur", false},
		{"update-proxy" + ext, "./cmd/update-proxy", false},
		{"trainer" + ext, "./cmd/trainer", false},
	}

	for _, b := range binaries {
		fmt.Printf("  -> %s\n", b.name)
		outPath := filepath.Join(projectDir, b.name)
		args := []string{"build", "-ldflags=-s -w", "-o", outPath, b.pkg}
		if err := runEnv(projectDir, env, "go", args...); err != nil {
			if b.must {
				fmt.Fprintf(os.Stderr, "ERREUR : compilation de %s echouee.\n", b.name)
				os.Exit(1)
			}
			fmt.Printf("  [!] %s : compilation echouee (non bloquant)\n", b.name)
		} else {
			fmt.Printf("  [OK] %s\n", b.name)
		}
	}

	fmt.Println()
	fmt.Printf("[OK] Compilation reussie\n")

	// ── 6. Mode USB : installation sur la clé ────────────────────────────────
	if usbMode {
		installUSB(projectDir, usbDrive, ext)
		return
	}

	// ── 7. Mode local : vault + lancement UI ─────────────────────────────────
	vaultExe := filepath.Join(projectDir, "vault"+ext)

	fmt.Println()
	runPrint(projectDir, vaultExe, "init")
	fmt.Println("Chiffrement/synchronisation du token...")
	if err := runPrintErr(projectDir, vaultExe, "seal"); err != nil {
		fmt.Fprintf(os.Stderr, "ERREUR : vault seal echoue.\n")
		os.Exit(1)
	}
	runPrint(projectDir, vaultExe, "status")

	if *noUI {
		return
	}

	fmt.Println()
	fmt.Println("Verification du port 8766...")
	killPort(8766)
	fmt.Println()
	fmt.Println("Lancement sur http://localhost:8766 ...")
	mainExe := filepath.Join(projectDir, "rf-sandbox"+ext)
	cmd := exec.Command(mainExe, "-ui")
	cmd.Dir = projectDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Run()
}

// ── Installation USB ──────────────────────────────────────────────────────────

func installUSB(projectDir, usbDrive, ext string) {
	usbRoot := usbDrive + `rf-sandbox-go`

	fmt.Println()
	fmt.Println("==========================================")
	fmt.Printf("  Installation sur %srf-sandbox-go\n", usbDrive)
	fmt.Println("==========================================")

	for _, sub := range []string{"", "config", "output", "samples"} {
		os.MkdirAll(filepath.Join(usbRoot, sub), 0755)
	}

	// Exécutables principaux
	for _, name := range []string{
		"rf-sandbox" + ext,
		"vault" + ext,
		"audit" + ext,
		"audit-securite" + ext,
		"setup-moteur" + ext,
		"bootstrap-post" + ext,
		"compilateur" + ext,
		"update-proxy" + ext,
		"trainer" + ext,
	} {
		src := filepath.Join(projectDir, name)
		if _, err := os.Stat(src); err == nil {
			copyFile(src, filepath.Join(usbRoot, name))
			fmt.Printf("  [OK] %s\n", name)
		}
	}

	// config/
	copyDir(filepath.Join(projectDir, "config"), filepath.Join(usbRoot, "config"))
	fmt.Println("  [OK] config/")

	// moteur/ (optionnel — peut être volumineux)
	moteurSrc := filepath.Join(filepath.Dir(projectDir), "moteur")
	if _, err := os.Stat(moteurSrc); err == nil {
		fmt.Println("  Copie du moteur IA (~4+ Go, patience)...")
		copyDir(moteurSrc, filepath.Join(usbRoot, "moteur"))
		fmt.Println("  [OK] moteur/")
	} else {
		fmt.Println("  [INFO] moteur/ absent - moteur IA non inclus sur la cle.")
		fmt.Println("         Sur la machine cible, executer : setup-moteur.exe")
	}

	// samples/
	copyDir(filepath.Join(projectDir, "samples"), filepath.Join(usbRoot, "samples"))
	fmt.Println("  [OK] samples/")

	// lancer.bat
	lancer := filepath.Join(projectDir, "scripts", "lancer.bat")
	if _, err := os.Stat(lancer); err == nil {
		copyFile(lancer, filepath.Join(usbRoot, "lancer.bat"))
		fmt.Println("  [OK] lancer.bat")
	}

	fmt.Println()
	fmt.Println("==========================================")
	fmt.Println("  Installation terminee !")
	fmt.Printf("  %srf-sandbox-go\\\n", usbDrive)
	fmt.Println()
	fmt.Println("  Contenu installe :")
	fmt.Println("    rf-sandbox.exe       executable principal")
	fmt.Println("    vault.exe            gestion des secrets")
	fmt.Println("    audit-securite.exe   audit de securite (Go natif)")
	fmt.Println("    setup-moteur.exe     telecharge le moteur IA (Go natif)")
	fmt.Println("    bootstrap-post.exe   post-compilation (Go natif)")
	fmt.Println("    compilateur.exe      compilation complete (Go natif)")
	fmt.Println("    update-proxy.exe     mise a jour proxy config (Go natif)")
	fmt.Println("    config/              configuration")
	fmt.Println("    samples/             fichiers batch exemples")
	fmt.Println("    lancer.bat           point d'entree")
	fmt.Println("==========================================")
}

// ── Détection USB ─────────────────────────────────────────────────────────────

func detectUSB() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	// Parcourir les lettres de lecteur D: à Z:
	for _, letter := range "DEFGHIJKLMNOPQRSTUVWXYZ" {
		drive := string(letter) + `:\`
		if isRemovable(string(letter) + ":") {
			return drive
		}
	}
	return ""
}

func isRemovable(drive string) bool {
	// Utilise fsutil pour détecter un disque amovible — pas de PowerShell requis.
	// "fsutil fsinfo driveType X:" retourne "Drive type : Removable Drive" pour les clés USB.
	out, err := exec.Command("fsutil", "fsinfo", "driveType", drive).Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "removable")
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

	fmt.Printf("  -> Port %d occupe — kill...\n", port)
	if runtime.GOOS == "windows" {
		out, _ := exec.Command("netstat", "-ano").Output()
		target := fmt.Sprintf(":%d", port)
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) < 5 {
				continue
			}
			if !strings.HasSuffix(fields[1], target) {
				continue
			}
			pid := fields[len(fields)-1]
			if pid == "0" {
				continue
			}
			exec.Command("taskkill", "/F", "/PID", pid).Run()
		}
	} else {
		exec.Command("fuser", "-k", "-9", fmt.Sprintf("%d/tcp", port)).Run()
	}
	time.Sleep(500 * time.Millisecond)
	fmt.Printf("  -> Port %d libere.\n", port)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func detectOS() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	case "darwin":
		return "darwin"
	default:
		return "windows"
	}
}

func targetToEnv(target string) (goos, goarch, ext string) {
	switch strings.ToLower(target) {
	case "windows":
		return "windows", "amd64", ".exe"
	case "linux":
		return "linux", "amd64", ""
	case "darwin":
		return "darwin", "amd64", ""
	default:
		return "", "", ""
	}
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

func runEnv(dir string, env []string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
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

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0755)
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		return copyFile(path, target)
	})
}

func resolveProjectDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}
