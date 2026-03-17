// vault.exe — CLI autonome de gestion du vault AES-256-GCM
//
// Usage :
//
//	vault init    — Génère la clé vault si elle n'existe pas (idempotent)
//	vault seal    — Chiffre les secrets en clair dans config/config.json
//	vault status  — Affiche l'état du vault et des champs chiffrés
//	vault encrypt <valeur>  — Chiffre une valeur et affiche le résultat enc:...
//	vault decrypt <valeur>  — Déchiffre une valeur enc:...
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"rf-sandbox-go/vault"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		cmdInit()
	case "seal":
		cmdSeal()
	case "status":
		cmdStatus()
	case "encrypt":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: vault encrypt <valeur>")
			os.Exit(1)
		}
		cmdEncrypt(os.Args[2])
	case "decrypt":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: vault decrypt <valeur>")
			os.Exit(1)
		}
		cmdDecrypt(os.Args[2])
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Commande inconnue : %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

// ─── init ────────────────────────────────────────────────────────────────────

// cmdInit génère la clé vault si elle n'existe pas encore (idempotent).
func cmdInit() {
	keyPath := vault.KeyPath()

	if _, err := os.Stat(keyPath); err == nil {
		fmt.Printf("[OK] Clé vault déjà présente : %s\n", keyPath)
		return
	}

	key, err := vault.GenerateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERREUR] Génération de la clé : %v\n", err)
		os.Exit(1)
	}

	if err := vault.SaveKey(key, keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "[ERREUR] Sauvegarde de la clé : %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[OK] Clé vault générée : %s\n", keyPath)
	fmt.Println("[INFO] Cette clé est dans .gitignore — ne la commitez jamais.")
}

// ─── seal ────────────────────────────────────────────────────────────────────

// cmdSeal chiffre les secrets en clair dans config/config.json.
func cmdSeal() {
	keyPath := vault.KeyPath()
	key, err := vault.LoadKey(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERREUR] Chargement de la clé vault : %v\n", err)
		fmt.Fprintln(os.Stderr, "  -> Exécutez d'abord : vault init")
		os.Exit(1)
	}

	cfgPath := configPath()
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERREUR] Lecture de %s : %v\n", cfgPath, err)
		os.Exit(1)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "[ERREUR] Parsing JSON : %v\n", err)
		os.Exit(1)
	}

	// Champs à chiffrer si non vides et non déjà chiffrés
	secretFields := []string{"api_token", "abuseipdb_key", "hf_token"}
	sealed := 0

	for _, field := range secretFields {
		val, ok := cfg[field].(string)
		if !ok || val == "" || vault.IsEncrypted(val) {
			continue
		}
		encrypted, err := vault.Encrypt(val, key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERREUR] Chiffrement de %s : %v\n", field, err)
			os.Exit(1)
		}
		cfg[field] = encrypted
		fmt.Printf("[OK] %s chiffré\n", field)
		sealed++
	}

	if sealed == 0 {
		fmt.Println("[OK] Aucun champ à chiffrer (déjà chiffrés ou vides).")
		return
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERREUR] Sérialisation JSON : %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(cfgPath, out, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "[ERREUR] Écriture de %s : %v\n", cfgPath, err)
		os.Exit(1)
	}

	fmt.Printf("[OK] %d champ(s) chiffré(s) et sauvegardé(s) dans %s\n", sealed, cfgPath)
}

// ─── status ──────────────────────────────────────────────────────────────────

// cmdStatus affiche l'état du vault et des champs dans config.json.
func cmdStatus() {
	keyPath := vault.KeyPath()
	_, keyErr := os.Stat(keyPath)
	keyPresent := keyErr == nil

	fmt.Println("=== État du vault ===")
	if keyPresent {
		fmt.Printf("  Clé       : ✓ présente (%s)\n", keyPath)
	} else {
		fmt.Printf("  Clé       : ✗ absente  (%s)\n", keyPath)
		fmt.Println("  -> Exécutez : vault init")
	}

	cfgPath := configPath()
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Config    : ✗ introuvable (%s)\n", cfgPath)
		return
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "  Config    : ✗ JSON invalide : %v\n", err)
		return
	}

	fmt.Printf("  Config    : ✓ %s\n", cfgPath)
	fmt.Println("\n  Champs sensibles :")

	secretFields := []string{"api_token", "abuseipdb_key"}
	allSealed := true
	for _, field := range secretFields {
		val, _ := cfg[field].(string)
		switch {
		case val == "":
			fmt.Printf("    %-20s  — (vide)\n", field)
		case vault.IsEncrypted(val):
			fmt.Printf("    %-20s  🔒 chiffré\n", field)
		default:
			fmt.Printf("    %-20s  ⚠  EN CLAIR — exécutez : vault seal\n", field)
			allSealed = false
		}
	}

	fmt.Println()
	if !keyPresent {
		fmt.Println("  Statut : ⚠  Vault non initialisé")
	} else if allSealed {
		fmt.Println("  Statut : ✓  Tous les secrets sont chiffrés")
	} else {
		fmt.Println("  Statut : ⚠  Secrets en clair détectés → exécutez : vault seal")
	}
}

// ─── encrypt ─────────────────────────────────────────────────────────────────

func cmdEncrypt(value string) {
	key, err := loadKeyOrExit()
	if err != nil {
		return
	}
	if vault.IsEncrypted(value) {
		fmt.Println(value)
		return
	}
	encrypted, err := vault.Encrypt(value, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERREUR] %v\n", err)
		os.Exit(1)
	}
	fmt.Println(encrypted)
}

// ─── decrypt ─────────────────────────────────────────────────────────────────

func cmdDecrypt(value string) {
	key, err := loadKeyOrExit()
	if err != nil {
		return
	}
	if !vault.IsEncrypted(value) {
		fmt.Println(value)
		return
	}
	decrypted, err := vault.Decrypt(value, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERREUR] %v\n", err)
		os.Exit(1)
	}
	fmt.Println(decrypted)
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// configPath retourne le chemin de config/config.json relatif à l'exécutable.
func configPath() string {
	exe, err := os.Executable()
	if err != nil {
		// Fallback : dossier courant
		return filepath.Join("config", "config.json")
	}
	return filepath.Join(filepath.Dir(exe), "config", "config.json")
}

func loadKeyOrExit() ([]byte, error) {
	keyPath := vault.KeyPath()
	key, err := vault.LoadKey(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERREUR] Chargement de la clé vault : %v\n", err)
		fmt.Fprintln(os.Stderr, "  -> Exécutez d'abord : vault init")
		os.Exit(1)
	}
	return key, nil
}

func printUsage() {
	fmt.Println(`vault.exe — Gestionnaire de secrets RF Sandbox (AES-256-GCM)

Usage:
  vault init              Génère la clé vault (idempotent, ne re-génère pas si existante)
  vault seal              Chiffre les secrets en clair dans config/config.json
  vault status            Affiche l'état du vault et des champs sensibles
  vault encrypt <valeur>  Chiffre une valeur et retourne enc:...
  vault decrypt <valeur>  Déchiffre une valeur enc:...

Exemples:
  vault init
  vault seal
  vault status
  vault encrypt "mon-token-secret"
  vault decrypt "enc:aBc123..."

La clé est stockée dans config/.vault.key (gitignored).
Variable d'environnement RF_VAULT_KEY_PATH pour un chemin alternatif.`)
}
