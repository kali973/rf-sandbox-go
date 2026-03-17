package client

// yara.go - Gestion des règles YARA via l'API RF Sandbox v0.
//
// L'API expose /api/v0/yara pour uploader, lister, mettre à jour et supprimer
// des règles YARA personnalisées qui seront appliquées à toutes les analyses.
//
// Utile pour ajouter des règles sur des campagnes en cours avant soumission
// d'un échantillon suspect. Les règles sont compilées côté serveur à l'upload.
//
// Endpoints implémentés :
//   GET    /yara            → lister toutes les règles
//   GET    /yara/{name}     → détail d'une règle
//   POST   /yara            → uploader une nouvelle règle
//   PUT    /yara/{name}     → mettre à jour une règle existante
//   DELETE /yara/{name}     → supprimer une règle

import (
	"fmt"
	"strings"
)

// YaraRule représente une règle YARA stockée dans RF Sandbox.
type YaraRule struct {
	Name   string `json:"name"`            // nom du fichier (ex: "emotet.yara")
	Rule   string `json:"rule"`            // contenu de la règle
	Public bool   `json:"public"`          // visible par tous les utilisateurs de l'org
	Error  string `json:"error,omitempty"` // erreur de compilation le cas échéant
}

// ListYaraRules retourne toutes les règles YARA accessibles par l'utilisateur.
func (c *Client) ListYaraRules() ([]YaraRule, error) {
	var result struct {
		Data []YaraRule `json:"data"`
	}
	if err := c.get("/yara", &result); err != nil {
		return nil, fmt.Errorf("list yara rules: %w", err)
	}
	return result.Data, nil
}

// GetYaraRule retourne le détail d'une règle YARA par son nom.
// Le nom doit inclure l'extension (ex: "emotet.yara").
func (c *Client) GetYaraRule(name string) (*YaraRule, error) {
	var rule YaraRule
	if err := c.get("/yara/"+name, &rule); err != nil {
		return nil, fmt.Errorf("get yara rule %s: %w", name, err)
	}
	return &rule, nil
}

// UploadYaraRule uploade une nouvelle règle YARA dans RF Sandbox.
// La règle est compilée côté serveur à la réception — une erreur de syntaxe
// retourne un COMPILE_ERROR immédiatement.
// name doit se terminer par ".yara" (ex: "campaign_abc.yara").
func (c *Client) UploadYaraRule(name, rule string) error {
	if !strings.HasSuffix(strings.ToLower(name), ".yara") {
		name = name + ".yara"
	}
	payload := map[string]string{
		"name": name,
		"rule": rule,
	}
	var result map[string]interface{}
	if err := c.postJSON("/yara", payload, &result); err != nil {
		return fmt.Errorf("upload yara rule %s: %w", name, err)
	}
	c.logger.Printf("[YARA] Règle '%s' uploadée avec succès", name)
	return nil
}

// UpdateYaraRule met à jour une règle YARA existante (nom et/ou contenu).
// oldName est le nom actuel de la règle, newName le nouveau nom (peut être identique).
func (c *Client) UpdateYaraRule(oldName, newName, rule string) error {
	if !strings.HasSuffix(strings.ToLower(oldName), ".yara") {
		oldName = oldName + ".yara"
	}
	if newName != "" && !strings.HasSuffix(strings.ToLower(newName), ".yara") {
		newName = newName + ".yara"
	}
	payload := map[string]string{}
	if newName != "" {
		payload["name"] = newName
	} else {
		payload["name"] = oldName
	}
	if rule != "" {
		payload["rule"] = rule
	}

	fullURL := BaseURL + "/yara/" + oldName
	resp, err := c.session.Put(fullURL, payload, nil)
	if err != nil {
		return fmt.Errorf("update yara rule %s: %w", oldName, err)
	}
	if !resp.OK() {
		return fmt.Errorf("HTTP %d pour PUT /yara/%s: %s", resp.StatusCode, oldName, resp.Text())
	}
	c.logger.Printf("[YARA] Règle '%s' mise à jour", oldName)
	return nil
}

// DeleteYaraRule supprime une règle YARA par son nom.
func (c *Client) DeleteYaraRule(name string) error {
	if !strings.HasSuffix(strings.ToLower(name), ".yara") {
		name = name + ".yara"
	}
	fullURL := BaseURL + "/yara/" + name
	resp, err := c.session.Delete(fullURL, nil)
	if err != nil {
		return fmt.Errorf("delete yara rule %s: %w", name, err)
	}
	if resp.StatusCode == 404 {
		return fmt.Errorf("règle YARA '%s' introuvable", name)
	}
	if !resp.OK() {
		return fmt.Errorf("HTTP %d pour DELETE /yara/%s: %s", resp.StatusCode, name, resp.Text())
	}
	c.logger.Printf("[YARA] Règle '%s' supprimée", name)
	return nil
}
