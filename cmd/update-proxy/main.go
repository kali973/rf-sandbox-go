// update-proxy — Remplace update_proxy.ps1
//
// Met à jour le champ "proxy" dans config/config.json.
// Écrit le fichier en UTF-8 sans BOM (compatible avec le parser JSON de Go).
//
// Usage:
//
//	update-proxy.exe -proxy-active 0   — vide le proxy (connexion directe)
//	update-proxy.exe -proxy-active 1   — conserve le proxy existant
//	update-proxy.exe -config /chemin/config.json   — chemin explicite
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	proxyActive := flag.Int("proxy-active", -1, "0 = vider le proxy, 1 = conserver")
	configPath := flag.String("config", "", "Chemin vers config.json (défaut : auto)")
	flag.Parse()

	if *proxyActive < 0 {
		fmt.Fprintln(os.Stderr, "ERREUR : -proxy-active 0|1 requis")
		os.Exit(1)
	}

	cfg := resolveConfig(*configPath)
	if cfg == "" {
		fmt.Fprintln(os.Stderr, "  [WARN] config/config.json introuvable")
		os.Exit(0)
	}

	data, err := os.ReadFile(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERREUR lecture %s : %v\n", cfg, err)
		os.Exit(1)
	}

	// Parse en map générique pour préserver tous les champs inconnus
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		fmt.Fprintf(os.Stderr, "ERREUR JSON %s : %v\n", cfg, err)
		os.Exit(1)
	}

	if *proxyActive == 0 {
		obj["proxy"] = ""
		fmt.Println("  -> proxy vide : connexion directe a https://sandbox.recordedfuture.com")
	} else {
		fmt.Printf("  -> proxy conserve : %v\n", obj["proxy"])
	}

	// Sérialisation indentée, UTF-8 sans BOM
	out, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERREUR sérialisation JSON : %v\n", err)
		os.Exit(1)
	}
	// Ajouter un saut de ligne final (convention Unix)
	out = append(out, '\n')

	if err := os.WriteFile(cfg, out, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "ERREUR écriture %s : %v\n", cfg, err)
		os.Exit(1)
	}
}

// resolveConfig cherche config.json à partir de l'exécutable ou du chemin fourni.
func resolveConfig(explicit string) string {
	if explicit != "" {
		if _, err := os.Stat(explicit); err == nil {
			return explicit
		}
		return ""
	}

	// Dossier de l'exécutable
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	exeDir := filepath.Dir(exe)

	// Cas 1 : scripts/ → ../config/config.json  (mode projet)
	// Cas 2 : racine du projet → config/config.json
	// Cas 3 : même dossier → config/config.json  (mode USB, config/ à côté)
	candidates := []string{
		filepath.Join(exeDir, "config", "config.json"),
		filepath.Join(exeDir, "..", "config", "config.json"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return filepath.Clean(c)
		}
	}
	return ""
}
