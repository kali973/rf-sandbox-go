// Package vault gère le chiffrement/déchiffrement AES-256-GCM des secrets
// stockés dans config.json.
//
// Format des valeurs chiffrées : enc:<base64(nonce||ciphertext)>
// La clé est stockée dans config/.vault.key ou via RF_VAULT_KEY (env).
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const prefix = "enc:"

// ─── Chiffrement / Déchiffrement ─────────────────────────────────────────────

// IsEncrypted retourne true si la valeur est au format enc:...
func IsEncrypted(val string) bool {
	return strings.HasPrefix(val, prefix)
}

// Encrypt chiffre val avec AES-256-GCM et retourne "enc:<base64(nonce||ciphertext)>".
func Encrypt(val string, key []byte) (string, error) {
	if val == "" {
		return val, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("cipher.NewGCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("rand nonce: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(val), nil)
	return prefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt déchiffre une valeur au format enc:... avec la clé donnée.
func Decrypt(val string, key []byte) (string, error) {
	if !IsEncrypted(val) {
		return val, nil
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(val, prefix))
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("cipher.NewGCM: %w", err)
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return "", errors.New("ciphertext trop court")
	}
	plain, err := gcm.Open(nil, data[:ns], data[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("déchiffrement: %w", err)
	}
	return string(plain), nil
}

// Resolve retourne la valeur en clair : déchiffre si enc:..., sinon retourne val tel quel.
func Resolve(val string, key []byte) (string, error) {
	if !IsEncrypted(val) {
		return val, nil
	}
	return Decrypt(val, key)
}

// ─── Gestion de la clé ───────────────────────────────────────────────────────

// GenerateKey génère une clé AES-256 aléatoire (32 bytes).
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// KeyPath retourne le chemin canonique de .vault.key :
//  1. Variable d'environnement RF_VAULT_KEY_PATH si définie
//  2. config/.vault.key à côté de l'exécutable
func KeyPath() string {
	if p := os.Getenv("RF_VAULT_KEY_PATH"); p != "" {
		return p
	}
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join("config", ".vault.key")
	}
	return filepath.Join(filepath.Dir(exe), "config", ".vault.key")
}

// LoadKey charge la clé vault depuis :
//  1. path (si non vide)
//  2. Variable d'environnement RF_VAULT_KEY (base64 ou raw 32 bytes)
func LoadKey(path string) ([]byte, error) {
	// Essayer le fichier en premier
	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			key := strings.TrimSpace(string(data))
			// Essayer base64 d'abord
			if decoded, err := base64.StdEncoding.DecodeString(key); err == nil && len(decoded) == 32 {
				return decoded, nil
			}
			// Sinon raw bytes
			if len(data) >= 32 {
				return data[:32], nil
			}
			return nil, fmt.Errorf("clé trop courte dans %s (attendu 32 bytes)", path)
		}
	}

	// Fallback : variable d'environnement
	if envKey := os.Getenv("RF_VAULT_KEY"); envKey != "" {
		// Essayer base64
		if decoded, err := base64.StdEncoding.DecodeString(envKey); err == nil && len(decoded) == 32 {
			return decoded, nil
		}
		// Sinon raw
		if len(envKey) >= 32 {
			return []byte(envKey[:32]), nil
		}
		return nil, errors.New("RF_VAULT_KEY trop courte (attendu 32 bytes)")
	}

	return nil, errors.New("aucune clé vault disponible (fichier absent et RF_VAULT_KEY non défini)")
}

// SaveKey sauvegarde la clé (en base64) dans path.
func SaveKey(key []byte, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	return os.WriteFile(path, []byte(encoded), 0600)
}
