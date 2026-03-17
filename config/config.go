// Package config charge et expose la configuration runtime depuis config.json.
// Les champs chiffrés (enc:...) sont déchiffrés transparemment via le vault.
package config

import (
	_ "embed"
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	"rf-sandbox-go/vault"
)

// ── config.json ───────────────────────────────────────────────────────────────

//go:embed config.json
var configFile []byte

// AppConfig contient la configuration runtime.
type AppConfig struct {
	APIToken       string `json:"api_token"`
	Proxy          string `json:"proxy"`
	UIPort         string `json:"ui_port"`
	AbuseIPDBKey   string `json:"abuseipdb_key,omitempty"`   // optionnel
	UseGeoIP       bool   `json:"use_geoip,omitempty"`       // geolocalisation IP (ip-api.com)
	SandboxTimeout int    `json:"sandbox_timeout,omitempty"` // durée analyse sandbox en secondes (défaut: 300)
	SandboxNetwork string `json:"sandbox_network,omitempty"` // réseau sandbox: "internet"|"drop"|"tor" (défaut: "internet")
	AIModel        string `json:"ai_model,omitempty"`        // modèle IA actif (nom de fichier GGUF dans moteur/models/)
	HFToken        string `json:"hf_token,omitempty"`        // token Hugging Face — requis pour les modèles "gated" (Primus, Llama, etc.)
}

// App est la configuration globale chargée depuis config.json.
// Priorité : config/config.json à côté de l'exe (modifiable), sinon version embarquée.
// Les champs chiffrés (enc:...) sont déchiffrés transparemment.
var App = func() AppConfig {
	data := configFile
	if exe, err := os.Executable(); err == nil {
		diskPath := filepath.Join(filepath.Dir(exe), "config", "config.json")
		if diskData, err := os.ReadFile(diskPath); err == nil {
			data = diskData
		}
	}

	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("config.json invalide : %v", err)
	}
	if cfg.UIPort == "" {
		cfg.UIPort = "8766"
	}

	// Déchiffrement transparent des secrets
	key, err := loadVaultKey()
	if err != nil {
		if vault.IsEncrypted(cfg.APIToken) {
			log.Fatalf("config: api_token est chiffré mais aucune clé vault n'est disponible.\n"+
				"  Lancez 'vault init' ou définissez RF_VAULT_KEY.\n  Détail : %v", err)
		}
		return cfg
	}

	if dec, err := vault.Resolve(cfg.APIToken, key); err != nil {
		log.Fatalf("config: déchiffrement api_token échoué : %v\n"+
			"  La clé vault ne correspond pas aux tokens chiffrés.\n"+
			"  Relancez 'vault seal' pour rechiffrer avec la clé courante.", err)
	} else {
		cfg.APIToken = dec
	}

	if dec, err := vault.Resolve(cfg.AbuseIPDBKey, key); err != nil {
		log.Fatalf("config: déchiffrement abuseipdb_key échoué : %v", err)
	} else {
		cfg.AbuseIPDBKey = dec
	}

	if dec, err := vault.Resolve(cfg.HFToken, key); err != nil {
		log.Fatalf("config: déchiffrement hf_token échoué : %v", err)
	} else {
		cfg.HFToken = dec
	}

	return cfg
}()

// loadVaultKey cherche la clé vault dans l'ordre :
// 1. Variable d'environnement RF_VAULT_KEY
// 2. config/.vault.key à côté de l'exécutable
// 3. config/.vault.key dans le répertoire courant (développement)
func loadVaultKey() ([]byte, error) {
	key, err := vault.LoadKey(vault.KeyPath())
	if err == nil {
		return key, nil
	}
	cwd, _ := os.Getwd()
	key, err = vault.LoadKey(filepath.Join(cwd, "config", ".vault.key"))
	if err == nil {
		return key, nil
	}
	return vault.LoadKey("")
}
