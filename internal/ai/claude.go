package ai

// claude.go - Client API Claude (Anthropic) comme alternative a Ollama local.
//
// Avantages vs Mistral 7B local :
//   - Qualite de rapport bien superieure
//   - Contexte 200k tokens (vs 4096 Ollama)
//   - Pas besoin de moteur/ ni GPU
//   - Necessite une cle API Anthropic et une connexion Internet
//
// Configuration : ajouter dans config/config.json :
//   "claude_api_key": "sk-ant-..."
//   "ai_engine": "claude"    (defaut: "ollama")

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	ClaudeAPIURL = "https://api.anthropic.com/v1/messages"
	ClaudeModel  = "claude-sonnet-4-5"
)

// ClaudeClient est le client pour l'API Anthropic.
type ClaudeClient struct {
	apiKey string
	http   *http.Client
}

// NewClaudeClient cree un client Claude avec la cle API donnee.
func NewClaudeClient(apiKey string) *ClaudeClient {
	return &ClaudeClient{
		apiKey: apiKey,
		http:   &http.Client{Timeout: 120 * time.Second},
	}
}

// IsAvailable verifie que la cle API est valide.
func (c *ClaudeClient) IsAvailable() bool {
	return c.apiKey != "" && len(c.apiKey) > 10
}

// Generate envoie le prompt a Claude et retourne la reponse complete.
func (c *ClaudeClient) Generate(prompt string, progressFn func(string)) (string, error) {
	if progressFn != nil {
		progressFn(cHeader("AI", "GÉNÉRATION IA  —  Claude API (Anthropic)"))
		progressFn(logDetail("AI", fmt.Sprintf("Modèle   : %s", ClaudeModel)))
		progressFn(logDetail("AI", fmt.Sprintf("Endpoint : %s", ClaudeAPIURL)))
		progressFn(logDetail("AI", "Tokens   : max_output=4096 | ctx=200k | cloud"))
		progressFn(logDetail("AI", fmt.Sprintf("Prompt   : %d caractères envoyés", len(prompt))))
		progressFn(logInfo("AI", "Envoi du prompt à Claude API (Anthropic)..."))
	}

	reqBody := map[string]interface{}{
		"model":      ClaudeModel,
		"max_tokens": 4096,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", ClaudeAPIURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("appel Claude API: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Claude API HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("parsing reponse Claude: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("Claude API error: %s", result.Error.Message)
	}

	var sb bytes.Buffer
	for _, block := range result.Content {
		if block.Type == "text" {
			sb.WriteString(block.Text)
		}
	}

	response := sb.String()
	if progressFn != nil {
		progressFn(logOK("AI", fmt.Sprintf("Réponse Claude reçue — %d caractères (modèle: %s)", len(response), ClaudeModel)))
		preview := response
		if len(preview) > 150 {
			preview = preview[:150] + "..."
		}
		progressFn(cGrey(fmt.Sprintf("[AI]    ↳ Début réponse : %s", preview)))
	}
	return response, nil
}
