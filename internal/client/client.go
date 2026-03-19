package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"rf-sandbox-go/httpclient"
	"rf-sandbox-go/internal/models"
)

const (
	BaseURL      = "https://sandbox.recordedfuture.com/api/v0"
	PollInterval = 15 * time.Second
	PollTimeout  = 15 * time.Minute // Malwares avec comportements tardifs (tâches planifiées, DLL sideloading) peuvent dépasser 10 min
)

// Client est le client API Recorded Future Sandbox
type Client struct {
	token          string
	session        *httpclient.Client
	logger         *log.Logger
	sandboxTimeout int    // durée analyse en secondes (0 = défaut 300s)
	sandboxNetwork string // "internet"|"drop"|"tor" (vide = "internet")
}

// New crée un nouveau client avec le token fourni
func New(token string) *Client {
	return NewWithProxy(token, "")
}

// NewWithProxy crée un client avec proxy d'entreprise (NTLM auto).
func NewWithProxy(token, proxy string) *Client {
	c := &Client{
		token:          token,
		session:        httpclient.New(),
		logger:         log.Default(),
		sandboxTimeout: 300,        // 5 minutes — capture tâches planifiées, DLL sideloading, curl/ftp…
		sandboxNetwork: "internet", // accès internet pour capturer C2, SharePoint, ipinfo.io…
	}
	c.session.Headers["Authorization"] = "Bearer " + token
	c.session.Headers["Accept"] = "application/json"

	if os.Getenv("RF_VERBOSE") == "1" {
		c.session.Verbose = true
	}

	if proxy != "" {
		c.session.SetProxy(proxy)
		switch strings.ToLower(os.Getenv("RF_AUTH")) {
		case "negotiate", "kerberos":
			c.session.AuthType = httpclient.AuthNegotiate
			c.logger.Printf("proxy: %s (auth: Negotiate/Kerberos)", proxy)
		default:
			c.session.AuthType = httpclient.AuthNTLM
			c.logger.Printf("proxy: %s (auth: NTLM)", proxy)
		}
		if !c.session.ProxyReachable() {
			c.logger.Printf("proxy %s injoignable — bascule en connexion directe", proxy)
			c.session.ClearProxy()
			c.session.AuthType = httpclient.AuthNone
		} else {
			c.logger.Printf("proxy joignable — authentification entreprise activée")
		}
	}
	return c
}

// ─── Méthodes HTTP de base ────────────────────────────────────────────────

func (c *Client) get(path string, out interface{}) error {
	resp, err := c.session.Get(BaseURL+path, nil)
	if err != nil {
		if _, ok := err.(*httpclient.ProxyError); ok {
			c.session.ClearProxy()
			resp, err = c.session.Get(BaseURL+path, nil)
		}
		if err != nil {
			return fmt.Errorf("GET %s : %w", path, err)
		}
	}
	if resp.StatusCode == 404 || resp.StatusCode == 400 {
		return fmt.Errorf("HTTP %d pour %s", resp.StatusCode, path)
	}
	return resp.Decode(out)
}

func (c *Client) postJSON(path string, payload interface{}, out interface{}) error {
	resp, err := c.session.Post(BaseURL+path, payload, nil)
	if err != nil {
		if _, ok := err.(*httpclient.ProxyError); ok {
			c.session.ClearProxy()
			resp, err = c.session.Post(BaseURL+path, payload, nil)
		}
		if err != nil {
			return fmt.Errorf("POST %s : %w", path, err)
		}
	}
	if !resp.OK() {
		return fmt.Errorf("HTTP %d pour %s : %s", resp.StatusCode, path, resp.Text())
	}
	if out != nil {
		return resp.Decode(out)
	}
	return nil
}

func (c *Client) postMultipart(path string, filePath string, private bool, out interface{}) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("ouverture fichier %s : %w", filePath, err)
	}
	defer f.Close()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return fmt.Errorf("création champ fichier : %w", err)
	}
	b := make([]byte, 32*1024)
	for {
		n, rerr := f.Read(b)
		if n > 0 {
			part.Write(b[:n])
		}
		if rerr != nil {
			break
		}
	}

	// Paramètres d'analyse via _json (requis pour timeout + network)
	// Sans ces options, RF Sandbox utilise un timeout minimal (60s) et peut couper le réseau,
	// ce qui empêche la capture des comportements tardifs : tâches planifiées, DLL sideloading,
	// commandes curl/ftp, connexions SharePoint, etc.
	timeout := c.sandboxTimeout
	if timeout <= 0 {
		timeout = 300 // 5 minutes par défaut — capture les comportements retardés
	}
	network := c.sandboxNetwork
	if network == "" {
		network = "internet" // accès internet requis pour capturer C2, SharePoint, ipinfo.io…
	}

	jsonParams := map[string]interface{}{
		"kind": "file",
		"defaults": map[string]interface{}{
			"timeout": timeout,
			"network": network,
		},
	}
	if private {
		jsonParams["is_private"] = true
	}
	jsonBytes, err := json.Marshal(jsonParams)
	if err != nil {
		return fmt.Errorf("sérialisation _json : %w", err)
	}
	if err := mw.WriteField("_json", string(jsonBytes)); err != nil {
		return fmt.Errorf("écriture champ _json : %w", err)
	}
	mw.Close()

	// Utiliser un client avec timeout long pour l'upload (fichiers volumineux sur proxy NTLM)
	// Le timeout standard de 60s est insuffisant pour des .7z de plusieurs Mo.
	uploadClient := c.session.WithTimeout(10 * time.Minute)

	resp, err := uploadClient.Post(BaseURL+path, buf.Bytes(), map[string]string{
		"Content-Type": mw.FormDataContentType(),
	})
	if err != nil {
		if _, ok := err.(*httpclient.ProxyError); ok {
			// Proxy en erreur → retry en connexion directe
			uploadClient.ClearProxy()
			resp, err = uploadClient.Post(BaseURL+path, buf.Bytes(), map[string]string{
				"Content-Type": mw.FormDataContentType(),
			})
		}
		if err != nil {
			return fmt.Errorf("upload %s : %w", path, err)
		}
	}
	if !resp.OK() {
		return fmt.Errorf("HTTP %d pour %s : %s", resp.StatusCode, path, resp.Text())
	}
	if out != nil {
		return resp.Decode(out)
	}
	return nil
}

// ─── Soumission ──────────────────────────────────────────────────────────

type submitResp struct {
	ID string `json:"id"`
}

type submitURLPayload struct {
	URL     string `json:"url"`
	Private bool   `json:"is_private"`
}

func (c *Client) submitFile(filePath string, private bool) (string, error) {
	var resp submitResp
	if err := c.postMultipart("/samples", filePath, private, &resp); err != nil {
		return "", err
	}
	return resp.ID, nil
}

func (c *Client) submitURL(targetURL string, private bool) (string, error) {
	var resp submitResp
	if err := c.postJSON("/urls", submitURLPayload{URL: targetURL, Private: private}, &resp); err != nil {
		return "", err
	}
	return resp.ID, nil
}

// ─── Polling ─────────────────────────────────────────────────────────────

func (c *Client) waitForCompletion(sampleID string, timeout time.Duration) error {
	isNonExec := timeout < PollTimeout // timeout réduit = fichier non-exécutable
	deadline := time.Now().Add(timeout)
	consecutiveErrors := 0
	const maxConsecutiveErrors = 5
	runningStarted := time.Time{}

	for time.Now().Before(deadline) {
		var status struct {
			Status string `json:"status"`
		}
		if err := c.get("/samples/"+sampleID, &status); err != nil {
			if isNetworkError(err) {
				consecutiveErrors++
				if consecutiveErrors >= maxConsecutiveErrors {
					return fmt.Errorf("polling interrompu apres %d erreurs reseau consecutives: %w", consecutiveErrors, err)
				}
				log.Printf("[RETRY] polling %s erreur reseau (%d/%d): %v — nouvel essai...",
					sampleID[:min(12, len(sampleID))], consecutiveErrors, maxConsecutiveErrors, err)
				time.Sleep(10 * time.Second)
				continue
			}
			return err
		}
		consecutiveErrors = 0
		short := sampleID
		if len(short) > 12 {
			short = short[:12]
		}
		switch status.Status {
		case "reported":
			return nil
		case "failed":
			return fmt.Errorf("analyse echouee pour %s", sampleID)
		case "static_analysis":
			log.Printf("[RF-SANDBOX] [%s] statut: static_analysis — rapport statique pret.", short)
			if isNonExec {
				time.Sleep(5 * time.Second)
				log.Printf("[RF-SANDBOX] [%s] Fichier non-executable : static_analysis accepte comme terminal.", short)
				return nil
			}
		case "running":
			if runningStarted.IsZero() {
				runningStarted = time.Now()
			}
			// Pour les non-exécutables : accepter running après 45s
			// (le sandbox a démarré l'analyse mais le fichier n'exécute rien)
			if isNonExec && time.Since(runningStarted) > 45*time.Second {
				log.Printf("[RF-SANDBOX] [%s] Fichier non-executable en running depuis >45s — recuperation des resultats partiels.", short)
				return nil
			}
			log.Printf("[RF-SANDBOX] [%s] statut: running — attente %v...", short, PollInterval)
		case "processing":
			log.Printf("[RF-SANDBOX] [%s] statut: processing — finalisation du rapport...", short)
		default:
			log.Printf("[RF-SANDBOX] [%s] statut: %s — attente %v...", short, status.Status, PollInterval)
		}
		time.Sleep(PollInterval)
	}

	// Timeout atteint — tenter de récupérer les résultats partiels dans tous les cas.
	// RF Sandbox peut avoir des données utiles même si l'analyse n'est pas "reported" :
	// signatures, réseau, processus déjà capturés avant le timeout.
	shortID := sampleID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}
	if isNonExec {
		log.Printf("[RF-SANDBOX] [%s] Timeout atteint pour fichier non-executable — recuperation des resultats disponibles.", shortID)
	} else {
		log.Printf("[RF-SANDBOX] [%s] Timeout (%v) — tentative de recuperation des resultats partiels (comportements deja captures).", shortID, timeout)
		log.Printf("[RF-SANDBOX] [%s] Astuce : augmentez sandbox_timeout dans config.json pour les malwares avec comportements tardifs.", shortID)
	}
	return nil // nil = tenter fetchResults même avec timeout
}

// ─── Récupération résultats ───────────────────────────────────────────────

// fetchResults construit un AnalysisResult complet en combinant 3 endpoints :
//  1. GET /samples/{id}/summary        → liste des tâches, scores, SHA256
//  2. GET /samples/{id}/overview.json  → IOCs, signatures, configs malware extraites
//  3. GET /samples/{id}/{task}/report_triage.json → arbre de processus, réseau, dumps
func (c *Client) fetchResults(sampleID string) (*models.AnalysisResult, error) {
	// ── 1. Summary ───────────────────────────────────────────────────────
	var summary models.Summary
	if err := c.get("/samples/"+sampleID+"/summary", &summary); err != nil {
		return nil, fmt.Errorf("summary: %w", err)
	}

	r := &models.AnalysisResult{
		SampleID: sampleID,
		Filename: summary.Target,
		Status:   summary.Status,
		Score:    summary.Score,
		Hashes:   models.Hashes{SHA256: summary.SHA256},
		Tasks:    make(map[string]models.TaskResult),
		Network:  make(map[string]models.NetworkReport),
		Summary:  &summary,
	}

	// Pour les fichiers non-exécutables (statut static_analysis), récupérer
	// le rapport statique qui contient hashes + métadonnées de base.
	// Pas d'analyse comportementale possible → score = 0.
	if summary.Status == "static_analysis" {
		log.Printf("[RF-SANDBOX] Statut static_analysis — recuperation rapport statique pour %s", sampleID)
		var staticReport struct {
			Files []struct {
				Name   string `json:"filename"`
				MD5    string `json:"md5"`
				SHA1   string `json:"sha1"`
				SHA256 string `json:"sha256"`
			} `json:"files"`
		}
		if err := c.get("/samples/"+sampleID+"/reports/static", &staticReport); err == nil {
			for _, f := range staticReport.Files {
				if f.SHA256 != "" {
					r.Hashes = models.Hashes{MD5: f.MD5, SHA1: f.SHA1, SHA256: f.SHA256}
					if r.Filename == "" {
						r.Filename = f.Name
					}
					break
				}
			}
		}
		r.Score = 0
		log.Printf("[RF-SANDBOX] Fichier non-executable : analyse statique uniquement, score = 0")
	}
	for taskID, ts := range summary.Tasks {
		r.Tasks[taskID] = models.TaskResult{TaskSummary: ts}
		for _, t := range ts.Tags {
			if strings.HasPrefix(t, "family:") && r.Family == "" {
				r.Family = strings.TrimPrefix(t, "family:")
			}
		}
		r.Tags = append(r.Tags, ts.Tags...)
	}
	r.Tags = uniqueStrings(r.Tags)

	// ── 2. Overview ──────────────────────────────────────────────────────
	// overview.json n'est disponible que quand l'analyse est en statut "reported".
	// Pour les fichiers non-executables recuperes en partiel (running/static_analysis),
	// RF Sandbox n'a pas encore genere l'overview → on skippe pour eviter le 404.
	overviewAvailable := summary.Status == "reported"
	var overview models.Overview
	if overviewAvailable {
		if err := c.get("/samples/"+sampleID+"/overview.json", &overview); err != nil {
			c.logger.Printf("[WARN] overview.json indisponible pour %s: %v", sampleID, err)
		} else {
			r.Overview = &overview
			// Hashes complets depuis overview
			r.Hashes = models.Hashes{
				MD5:    overview.Sample.MD5,
				SHA1:   overview.Sample.SHA1,
				SHA256: overview.Sample.SHA256,
				SHA512: overview.Sample.SHA512,
			}
			if r.Filename == "" || r.Filename == sampleID {
				r.Filename = overview.Sample.Target
			}
			// Tags globaux depuis overview.Analysis
			r.Tags = append(r.Tags, overview.Analysis.Tags...)
			// Famille depuis overview
			if r.Family == "" && len(overview.Analysis.Family) > 0 {
				r.Family = strings.Join(overview.Analysis.Family, ", ")
			}
			// Signatures agrégées depuis overview.Targets (source principale)
			// ET depuis overview.Signatures (top-level, si présentes)
			sigSeen := map[string]bool{}
			collectSig := func(sig models.OverviewSignature, taskHint string) {
				if sigSeen[sig.Name] {
					return
				}
				sigSeen[sig.Name] = true
				r.Signatures = append(r.Signatures, models.AggregatedSignature{
					TaskID: taskHint,
					Signature: models.Signature{
						Label:      sig.Label,
						Name:       sig.Name,
						Score:      sig.Score,
						Tags:       sig.Tags,
						TTP:        sig.TTP,
						Desc:       sig.Desc,
						Indicators: sig.Indicators,
					},
				})
			}
			// Priorité : targets (plus détaillés, par fichier analysé)
			for _, tgt := range overview.Targets {
				hint := strings.Join(tgt.Tasks, ",")
				for _, sig := range tgt.Signatures {
					collectSig(sig, hint)
				}
				// Tags & famille par target
				r.Tags = append(r.Tags, tgt.Tags...)
				if r.Family == "" && len(tgt.Family) > 0 {
					r.Family = strings.Join(tgt.Family, ", ")
				}
				// IOCs par target
				if tgt.IOCs != nil {
					r.IOCs.IPs = append(r.IOCs.IPs, tgt.IOCs.IPs...)
					r.IOCs.Domains = append(r.IOCs.Domains, tgt.IOCs.Domains...)
					r.IOCs.URLs = append(r.IOCs.URLs, tgt.IOCs.URLs...)
				}
			}
			// Top-level signatures en complément (évite les doublons via sigSeen)
			for _, sig := range overview.Signatures {
				collectSig(sig, "overview")
			}
			// IOCs consolidés
			if iocs := overview.Sample.IOCs; iocs != nil {
				r.IOCs.IPs = append(r.IOCs.IPs, iocs.IPs...)
				r.IOCs.Domains = append(r.IOCs.Domains, iocs.Domains...)
				r.IOCs.URLs = append(r.IOCs.URLs, iocs.URLs...)
			}
			// Configs malware extraites (C2, botnet, clés, mutex, commandes…)
			for _, ex := range overview.Extracted {
				r.Extracted = append(r.Extracted, models.ExtractWithTask{
					TaskID:  strings.Join(ex.Tasks, ","),
					Extract: ex.Extract,
				})
				if ex.Config != nil {
					cfg := ex.Config
					if cfg.Botnet != "" {
						r.IOCs.Mutexes = append(r.IOCs.Mutexes, "botnet:"+cfg.Botnet)
					}
					r.IOCs.IPs = append(r.IOCs.IPs, cfg.C2...)
					r.IOCs.Domains = append(r.IOCs.Domains, cfg.DNS...)
					r.IOCs.Mutexes = append(r.IOCs.Mutexes, cfg.Mutex...)
					for _, cmd := range cfg.CommandLines {
						if strings.Contains(cmd, "http://") || strings.Contains(cmd, "https://") {
							r.IOCs.URLs = append(r.IOCs.URLs, cmd)
						}
						c.logger.Printf("[INFO] commande config overview : %s", truncateLog(cmd, 200))
					}
					if r.Family == "" && cfg.Family != "" {
						r.Family = cfg.Family
					}
				}
				// URLs de dropper (payload download URLs — très importantes pour l'analyse)
				if ex.Dropper != nil {
					for _, du := range ex.Dropper.URLs {
						if du.URL != "" {
							r.IOCs.URLs = append(r.IOCs.URLs, du.URL)
							c.logger.Printf("[INFO] dropper URL détectée : %s (type: %s)", du.URL, du.Type)
						}
					}
				}
			}
			// Enrichir r.Tasks depuis overview.Tasks
			for _, ot := range overview.Tasks {
				taskID := ot.Sample
				if taskID == "" {
					continue
				}
				if existing, ok := r.Tasks[taskID]; ok {
					if ot.Score > 0 && existing.TaskSummary.Score == 0 {
						existing.TaskSummary.Score = ot.Score
					}
					existing.TaskSummary.Tags = uniqueStrings(append(existing.TaskSummary.Tags, ot.Tags...))
					existing.TaskSummary.TTP = uniqueStrings(append(existing.TaskSummary.TTP, ot.TTP...))
					r.Tasks[taskID] = existing
				} else {
					r.Tasks[taskID] = models.TaskResult{
						TaskSummary: models.TaskSummary{
							Kind:     ot.Kind,
							Status:   ot.Status,
							Tags:     ot.Tags,
							TTP:      ot.TTP,
							Score:    ot.Score,
							Target:   ot.Target,
							Backend:  ot.Backend,
							Resource: ot.Resource,
							Platform: ot.Platform,
							TaskName: ot.TaskName,
						},
					}
				}
				for _, t := range ot.Tags {
					if strings.HasPrefix(t, "family:") && r.Family == "" {
						r.Family = strings.TrimPrefix(t, "family:")
					}
				}
			}
		} // fin else overview disponible
	} // fin if overviewAvailable

	// ── 2bis. Rapport Statique ───────────────────────────────────────────
	var staticReport models.StaticReport
	if err := c.get("/samples/"+sampleID+"/reports/static", &staticReport); err != nil {
		c.logger.Printf("[WARN] rapport statique indisponible pour %s: %v", sampleID, err)
	} else {
		r.Static = &staticReport
		// Si les hashes ne sont pas encore remplis, les prendre du rapport statique
		if r.Hashes.SHA256 == "" {
			for _, f := range staticReport.Files {
				if f.Selected && f.SHA256 != "" {
					r.Hashes = models.Hashes{MD5: f.MD5, SHA1: f.SHA1, SHA256: f.SHA256, SHA512: f.SHA512}
					break
				}
			}
		}
	}
	for taskID, ts := range summary.Tasks {
		if ts.Kind != "behavioral" || ts.Status != "reported" {
			continue
		}
		// L'API attend le short taskID (ex: "behavioral1"), pas la clé complète
		// ("260309-rwz69sbyvs-behavioral1"). On strip le préfixe sampleID.
		shortTaskID := taskID
		if strings.HasPrefix(taskID, sampleID+"-") {
			shortTaskID = strings.TrimPrefix(taskID, sampleID+"-")
		}
		var triage models.TriageReport
		path := fmt.Sprintf("/samples/%s/%s/report_triage.json", sampleID, shortTaskID)
		if err := c.get(path, &triage); err != nil {
			c.logger.Printf("[WARN] report_triage.json indisponible pour %s/%s: %v", sampleID, shortTaskID, err)
			continue
		}
		// Mettre à jour la tâche avec le rapport complet
		r.Tasks[taskID] = models.TaskResult{
			TaskSummary: ts,
			Report:      &triage,
		}
		// Processus
		for _, p := range triage.Processes {
			r.Processes = append(r.Processes, models.ProcessWithTask{TaskID: taskID, Process: p})
		}
		// Réseau
		r.Network[taskID] = triage.Network
		// IOCs réseau
		for _, flow := range triage.Network.Flows {
			if flow.Dest != "" {
				ip := strings.Split(flow.Dest, ":")[0]
				// Ne pas ajouter les IPs d'infrastructure légitime connue comme IOC.
				// Les malwares LOL utilisent SharePoint, OneDrive, etc. comme C2 —
				// l'IOC pertinent est le domaine, pas l'IP Microsoft derrière.
				if !isLegitOrg(flow.Org) {
					r.IOCs.IPs = append(r.IOCs.IPs, ip)
				} else {
					c.logger.Printf("[INFO] IP %s ignorée des IOCs (org légitime: %s)", ip, flow.Org)
				}
			}
			if flow.Domain != "" {
				r.IOCs.Domains = append(r.IOCs.Domains, flow.Domain)
			}
		}
		for _, req := range triage.Network.Requests {
			if req.WebReq != nil && req.WebReq.URL != "" {
				r.IOCs.URLs = append(r.IOCs.URLs, req.WebReq.URL)
			}
			if req.DomainReq != nil {
				if len(req.DomainReq.Domains) > 0 {
					r.IOCs.Domains = append(r.IOCs.Domains, req.DomainReq.Domains...)
				} else {
					for _, q := range req.DomainReq.Questions {
						if q.Name != "" {
							r.IOCs.Domains = append(r.IOCs.Domains, q.Name)
						}
					}
				}
			}
			// DNS responses : extraire aussi les IPs résolues et les domaines répondants
			if req.DomainResp != nil {
				r.IOCs.IPs = append(r.IOCs.IPs, req.DomainResp.IP...)
				for _, a := range req.DomainResp.Answers {
					if (a.Type == "A" || a.Type == "AAAA") && a.Value != "" {
						r.IOCs.IPs = append(r.IOCs.IPs, a.Value)
					}
				}
			}
		}
		// Signatures du rapport dynamique (plus détaillées avec indicateurs)
		for _, sig := range triage.Signatures {
			// Éviter les doublons avec l'overview
			alreadyPresent := false
			for _, existing := range r.Signatures {
				if existing.Name == sig.Name {
					alreadyPresent = true
					break
				}
			}
			if !alreadyPresent {
				r.Signatures = append(r.Signatures, models.AggregatedSignature{TaskID: taskID, Signature: sig})
			}
		}
		// Configs extraites depuis le rapport dynamique
		for _, ex := range triage.Extracted {
			r.Extracted = append(r.Extracted, models.ExtractWithTask{TaskID: taskID, Extract: ex})
			// Extraire les données utiles dans les IOCs et résultats
			if ex.Config != nil {
				cfg := ex.Config
				// C2 supplémentaires
				r.IOCs.IPs = append(r.IOCs.IPs, cfg.C2...)
				// Domaines DNS malveillants
				r.IOCs.Domains = append(r.IOCs.Domains, cfg.DNS...)
				// Commandes exécutées (curl, ftp, powershell, etc.) → URLs extraites
				for _, cmd := range cfg.CommandLines {
					// Chercher des URLs dans les commandes
					if strings.Contains(cmd, "http://") || strings.Contains(cmd, "https://") {
						r.IOCs.URLs = append(r.IOCs.URLs, cmd)
					}
					c.logger.Printf("[INFO] commande malware détectée : %s", cmd)
				}
				// Mutexes et Botnet
				r.IOCs.Mutexes = append(r.IOCs.Mutexes, cfg.Mutex...)
				if cfg.Botnet != "" {
					r.IOCs.Mutexes = append(r.IOCs.Mutexes, "botnet:"+cfg.Botnet)
				}
				// Identifiants volés
				for _, cred := range cfg.Credentials {
					if cred.Host != "" || cred.URL != "" {
						entry := fmt.Sprintf("cred:%s@%s", cred.Protocol, cred.Host)
						if cred.URL != "" {
							entry = "cred_url:" + cred.URL
						}
						r.IOCs.URLs = append(r.IOCs.URLs, entry)
					}
				}
				// Famille malware depuis la config
				if r.Family == "" && cfg.Family != "" {
					r.Family = cfg.Family
				}
			}
			// URLs dropper (download URLs des payloads secondaires)
			if ex.Dropper != nil {
				for _, du := range ex.Dropper.URLs {
					if du.URL != "" {
						r.IOCs.URLs = append(r.IOCs.URLs, du.URL)
						c.logger.Printf("[INFO] dropper URL payload : %s (type: %s)", du.URL, du.Type)
					}
				}
				// Commandes dans le source déobfusqué
				if ex.Dropper.Source != "" {
					c.logger.Printf("[INFO] dropper source (%s, lang=%s): %s",
						ex.Dropper.Family, ex.Dropper.Language, truncateLog(ex.Dropper.Source, 200))
				}
			}
			// Identifiants extraits (niveau Extract, pas Config)
			if ex.Credentials != nil {
				if ex.Credentials.Host != "" {
					c.logger.Printf("[INFO] credentials extraits : %s@%s (proto: %s)",
						ex.Credentials.Username, ex.Credentials.Host, ex.Credentials.Protocol)
				}
			}
		}
	}

	// ── Déduplications finales ────────────────────────────────────────────
	r.IOCs.IPs = uniqueStrings(r.IOCs.IPs)
	r.IOCs.Domains = uniqueStrings(r.IOCs.Domains)
	r.IOCs.URLs = uniqueStrings(r.IOCs.URLs)
	sort.Slice(r.Signatures, func(i, j int) bool {
		return r.Signatures[i].Score > r.Signatures[j].Score
	})

	// ── 3bis. Récupération des fichiers déposés (payloads du malware) ─────
	// Pour chaque tâche behavioral, télécharger les fichiers droppés (exe, dll, txt…)
	// La limite est de 10 Mo par fichier pour éviter la saturation mémoire.
	const maxDroppedFileSize = 10 * 1024 * 1024 // 10 Mo
	const maxDroppedFiles = 20                  // max 20 fichiers par analyse
	droppedCount := 0
	for taskID, task := range r.Tasks {
		if task.Kind != "behavioral" || task.Status != "reported" || task.Report == nil {
			continue
		}
		shortTaskID := taskID
		if strings.HasPrefix(taskID, sampleID+"-") {
			shortTaskID = strings.TrimPrefix(taskID, sampleID+"-")
		}
		for _, dump := range task.Report.Dumped {
			if droppedCount >= maxDroppedFiles {
				break
			}

			// ── Résolution du nom de fichier pour l'URL API ───────────────
			// D'après la doc RF Sandbox (GET /samples/{id}/{task}/files/{fileName}),
			// {fileName} doit être le champ "name" du Dump tel quel.
			// "name" peut contenir un préfixe comme "extracted/" (ex: "extracted/NVIDIA.exe")
			// ou juste le basename ("NVIDIA.exe"). Le "path" lui contient le chemin
			// absolu Windows ("C:\Users\Public\NVIDIA.exe") — inutilisable dans une URL.
			// Si "name" est vide (rare), on tente d'extraire le basename de "path".
			fileNameForURL := dump.Name
			if fileNameForURL == "" && dump.Path != "" {
				// Extraire le basename depuis le chemin Windows
				parts := strings.Split(strings.ReplaceAll(dump.Path, "\\", "/"), "/")
				fileNameForURL = parts[len(parts)-1]
			}
			if fileNameForURL == "" {
				c.logger.Printf("[WARN] dump sans name ni path — ignoré (sampleID=%s task=%s)", sampleID, shortTaskID)
				continue
			}

			// ── Nom d'affichage = basename uniquement ─────────────────────
			// Pour l'affichage dans le rapport on veut juste "NVIDIA.exe",
			// pas "extracted/NVIDIA.exe" ni le chemin Windows complet.
			displayName := dump.Name
			if displayName == "" {
				displayName = fileNameForURL
			}
			// Extraire le basename (supprime préfixe "extracted/" etc.)
			if idx := strings.LastIndexAny(displayName, "/\\"); idx >= 0 {
				displayName = displayName[idx+1:]
			}
			if displayName == "" {
				displayName = fileNameForURL
			}

			// ── Filtre par extension ou kind ──────────────────────────────
			// On accepte : kind=martian (déposé par le malware), kind=extracted
			// (extrait de mémoire), ou extensions intéressantes.
			ext := strings.ToLower(filepath.Ext(displayName))
			interestingExts := map[string]bool{
				".exe": true, ".dll": true, ".bat": true, ".ps1": true,
				".vbs": true, ".js": true, ".txt": true, ".zip": true,
				".7z": true, ".rar": true, ".py": true, ".sh": true,
				".lnk": true, ".msi": true, ".sys": true, ".drv": true,
				".dat": true, ".bin": true, ".tmp": true, ".hta": true,
				".jse": true, ".wsh": true, ".wsf": true, ".scr": true,
			}
			kindLower := strings.ToLower(dump.Kind)
			isMartian := kindLower == "martian"
			isExtracted := kindLower == "extracted"
			isMemory := kindLower == "memory" || kindLower == "memdump"
			if !isMartian && !isExtracted && !isMemory && !interestingExts[ext] && ext != "" {
				continue
			}

			// ── Limite de taille ──────────────────────────────────────────
			if dump.Length > 0 && dump.Length > maxDroppedFileSize {
				c.logger.Printf("[INFO] fichier droppé %s trop volumineux (%d octets) — ignoré", displayName, dump.Length)
				continue
			}

			// ── Téléchargement ────────────────────────────────────────────
			// BUG CORRIGÉ : on choisit l'endpoint AVANT de faire l'appel HTTP.
			// Avant : GetDroppedFile était appelé en premier pour TOUS les fichiers,
			// y compris kind=memory → HTTP 404 silencieux, puis GetMemoryDump écrasait.
			// Maintenant : branchement unique selon le kind.
			var content []byte
			var fetchErr error
			if isMemory {
				// GET /samples/{id}/{task}/memory/{name}
				content, fetchErr = c.GetMemoryDump(sampleID, shortTaskID, fileNameForURL)
			} else {
				// GET /samples/{id}/{task}/files/{name}
				// Note : fileNameForURL peut contenir "extracted/" — l'API l'accepte tel quel.
				content, fetchErr = c.GetDroppedFile(sampleID, shortTaskID, fileNameForURL)
			}
			if fetchErr != nil {
				c.logger.Printf("[WARN] fichier droppé %s/%s/%s : %v", sampleID, shortTaskID, fileNameForURL, fetchErr)
				continue
			}
			if len(content) > maxDroppedFileSize {
				content = content[:maxDroppedFileSize]
			}

			r.DroppedFiles = append(r.DroppedFiles, models.DroppedFileInfo{
				Name:    displayName,
				TaskID:  shortTaskID,
				Kind:    dump.Kind,
				MD5:     dump.MD5,
				SHA1:    dump.SHA1,
				SHA256:  dump.SHA256,
				Size:    dump.Length,
				Content: content,
			})
			droppedCount++
			c.logger.Printf("[INFO] fichier droppé récupéré : %s (kind=%s, %d octets)", displayName, dump.Kind, len(content))
		}
	}
	if droppedCount > 0 {
		c.logger.Printf("[INFO] %d fichier(s) droppé(s) récupérés depuis la sandbox RF", droppedCount)
	}

	// ── 3ter. Événements kernel horodatés (onemon.json) ──────────────────
	// onemon.json est le log brut du moniteur kernel RF Sandbox.
	// Il contient tous les événements système avec leurs timestamps précis :
	// création de processus, accès fichiers/registre, connexions réseau.
	// On parse les lignes JSONL et on garde max 200 événements pertinents
	// (en excluant les événements système Windows de bruit de fond).
	const maxKernelEvents = 200
	for taskID, task := range r.Tasks {
		if task.Kind != "behavioral" || task.Status != "reported" {
			continue
		}
		shortTaskID := taskID
		if strings.HasPrefix(taskID, sampleID+"-") {
			shortTaskID = strings.TrimPrefix(taskID, sampleID+"-")
		}
		rawLog, err := c.GetKernelLog(sampleID, shortTaskID)
		if err != nil {
			c.logger.Printf("[WARN] onemon.json indisponible pour %s/%s: %v", sampleID, shortTaskID, err)
			continue
		}
		events := parseOnemonEvents(rawLog, maxKernelEvents)
		if len(events) > 0 {
			r.KernelEvents = append(r.KernelEvents, events...)
			c.logger.Printf("[INFO] %d événements kernel parsés depuis onemon.json (%s)", len(events), shortTaskID)
		}
	}

	return r, nil
}

// truncateLog tronque une chaîne à maxLen caractères pour les logs
func truncateLog(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "…"
}

// parseOnemonEvents parse les lignes JSONL du log kernel onemon.json.
// Le format est une ligne JSON par événement. On filtre le bruit de fond Windows
// et on ne garde que les événements pertinents pour l'analyse forensique.
// Retourne au maximum maxEvents événements triés par timestamp.
func parseOnemonEvents(raw []byte, maxEvents int) []models.KernelEvent {
	// Processus système Windows à ignorer (bruit de fond)
	noiseProcesses := map[string]bool{
		"svchost.exe": true, "csrss.exe": true, "smss.exe": true,
		"lsass.exe": true, "services.exe": true, "spoolsv.exe": true,
		"dwm.exe": true, "winlogon.exe": true, "wininit.exe": true,
		"system": true, "registry": true, "ntoskrnl.exe": true,
	}

	events := make([]models.KernelEvent, 0, maxEvents)
	lines := strings.Split(string(raw), "\n")

	for _, line := range lines {
		if len(events) >= maxEvents {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}

		// Parser la ligne JSON de manière flexible (le format peut varier)
		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}

		// Extraire les champs communs
		ev := models.KernelEvent{}

		// Timestamp
		for _, k := range []string{"time", "ts", "timestamp", "time_ms"} {
			if v, ok := raw[k]; ok {
				switch val := v.(type) {
				case float64:
					ev.TimeMs = uint64(val)
				}
				break
			}
		}

		// PID et image du processus
		for _, k := range []string{"pid", "proc_id"} {
			if v, ok := raw[k]; ok {
				if val, ok := v.(float64); ok {
					ev.PID = uint64(val)
				}
				break
			}
		}
		for _, k := range []string{"image", "proc", "process", "name"} {
			if v, ok := raw[k]; ok {
				if s, ok := v.(string); ok && s != "" {
					// Extraire juste le nom du binaire
					parts := strings.Split(strings.ReplaceAll(s, "\\", "/"), "/")
					ev.Image = parts[len(parts)-1]
				}
				break
			}
		}

		// Filtrer le bruit système
		if noiseProcesses[strings.ToLower(ev.Image)] {
			continue
		}

		// Type d'action et cible
		for _, k := range []string{"type", "action", "kind", "event"} {
			if v, ok := raw[k]; ok {
				if s, ok := v.(string); ok {
					ev.Action = s
				}
				break
			}
		}
		for _, k := range []string{"path", "target", "key", "dst", "host", "url", "filename"} {
			if v, ok := raw[k]; ok {
				if s, ok := v.(string); ok && s != "" {
					ev.Target = s
				}
				break
			}
		}
		// Détails supplémentaires (cmdline, status, etc.)
		for _, k := range []string{"cmd", "cmdline", "command", "args", "status", "value"} {
			if v, ok := raw[k]; ok {
				if s, ok := v.(string); ok && s != "" {
					ev.Details = truncateLog(s, 200)
				}
				break
			}
		}

		// Ne garder que les événements avec au moins une information utile
		if ev.Action != "" || ev.Target != "" || ev.Details != "" {
			events = append(events, ev)
		}
	}

	return events
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool)
	out := in[:0]
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ─── API publique ─────────────────────────────────────────────────────────

// isRetriableError detecte les erreurs transitoires qui justifient un retry :
// - erreurs reseau (timeout, connexion coupee, etc.)
// - erreurs HTTP serveur temporaires (502 Bad Gateway, 503 Service Unavailable, 504 Gateway Timeout)
func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, kw := range []string{
		// Erreurs reseau
		"timeout", "i/o timeout", "connection refused", "connection reset",
		"forcibly closed", "eof", "dial tcp", "tls handshake", "temporary failure",
		"context deadline exceeded",
		// Erreurs HTTP serveur temporaires
		"http 502", "http 503", "http 504",
	} {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	return false
}

// submitWithRetry tente la soumission jusqu'a maxRetries fois en cas d'erreur transitoire.
// Backoff exponentiel : 10s, 20s, 40s, 80s... (plafonné à 120s)
func (c *Client) submitWithRetry(target string, private bool, maxRetries int) (string, error) {
	const baseWait = 10 * time.Second
	const maxWait = 120 * time.Second
	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		var (
			sampleID string
			err      error
		)
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			sampleID, err = c.submitURL(target, private)
		} else {
			sampleID, err = c.submitFile(target, private)
		}
		if err == nil {
			return sampleID, nil
		}
		lastErr = err
		if !isNetworkError(err) {
			// Erreur non-reseau (auth, fichier invalide...) : pas de retry
			return "", err
		}
		// Backoff exponentiel : 10s, 20s, 40s, 80s... plafonne a 120s
		wait := baseWait * (1 << time.Duration(attempt-1))
		if wait > maxWait {
			wait = maxWait
		}
		log.Printf("[RETRY] soumission %s echouee (tentative %d/%d) : %v — nouvel essai dans %v",
			filepath.Base(target), attempt, maxRetries, err, wait)
		time.Sleep(wait)
	}
	return "", fmt.Errorf("echec apres %d tentatives : %w", maxRetries, lastErr)
}

// ─── Helpers de qualification des IOCs ───────────────────────────────────────

// detectDoubleExtension détecte les fichiers avec double extension (ex: Certificate.cer.exe).
// C'est une technique d'ingénierie sociale classique pour déguiser un exécutable.
// Retourne (true, message d'alerte) si une double extension est détectée.
func detectDoubleExtension(filename string) (bool, string) {
	exeExts := map[string]bool{
		".exe": true, ".dll": true, ".bat": true, ".ps1": true,
		".vbs": true, ".js": true, ".hta": true, ".scr": true,
		".cmd": true, ".com": true, ".msi": true, ".pif": true,
	}
	ext := filepath.Ext(filename)
	base := strings.TrimSuffix(filename, ext)
	innerExt := strings.ToLower(filepath.Ext(base))
	if exeExts[innerExt] {
		return true, fmt.Sprintf(
			"DOUBLE EXTENSION détectée : '%s' — exécutable camouflé en '%s' (technique d'ingénierie sociale)",
			filename, ext,
		)
	}
	return false, ""
}

// isLegitOrg retourne true si l'organisation réseau est une infrastructure légitime connue.
// Ces IPs sont souvent contactées par des malwares LOL (Living off the Land) mais ne
// constituent pas des IOCs malveillants en elles-mêmes.
func isLegitOrg(org string) bool {
	if org == "" {
		return false
	}
	orgLower := strings.ToLower(org)
	legitOrgs := []string{
		"microsoft", "azure", "office365", "akamai", "cloudflare",
		"amazon", "aws", "google", "fastly", "cdn77", "limelight",
		"edgecast", "incapsula", "imperva", "zscaler", "qualys",
	}
	for _, legit := range legitOrgs {
		if strings.Contains(orgLower, legit) {
			return true
		}
	}
	return false
}

// ─── AnalyzeBatch ─────────────────────────────────────────────────────────────

// AnalyzeBatch soumet et attend les résultats pour une liste de fichiers/URLs.
// Les analyses sont lancées en parallèle (max 3 simultanées) pour réduire le temps total.
// Retry automatique sur erreurs réseau (timeout, connexion coupée, etc.)
func (c *Client) AnalyzeBatch(targets []string, private bool) []*models.AnalysisResult {
	const maxRetries = 8
	const maxConcurrent = 3 // respecter le rate limit de l'API RF Sandbox

	results := make([]*models.AnalysisResult, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrent)

	for i, target := range targets {
		wg.Add(1)
		go func(idx int, tgt string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			base := filepath.Base(tgt)
			ext := strings.ToLower(filepath.Ext(base))

			// Détecter les fichiers non-exécutables — RF Sandbox les analyse
			// mais ils ne génèrent pas de comportement dynamique (pas de process).
			// On réduit le PollTimeout et on avertit l'utilisateur.
			nonExecExts := map[string]bool{
				".cer": true, ".crt": true, ".pem": true, ".der": true,
				".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
				".txt": true, ".log": true, ".json": true, ".xml": true, ".csv": true,
				".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true,
				".zip": true, ".7z": true, ".rar": true,
			}
			execExts := map[string]bool{
				".exe": true, ".dll": true, ".bat": true, ".cmd": true, ".ps1": true,
				".js": true, ".vbs": true, ".hta": true, ".msi": true, ".scr": true,
				".lnk": true, ".jar": true, ".py": true,
			}
			if nonExecExts[ext] {
				log.Printf("[RF-SANDBOX] [INFO] '%s' est un fichier non-executables (%s) — analyse statique uniquement.", base, ext)
				log.Printf("[RF-SANDBOX] [INFO] Pas de comportement dynamique attendu. Le rapport sera disponible rapidement.")
			} else if !execExts[ext] {
				log.Printf("[RF-SANDBOX] [INFO] Extension inconnue '%s' pour '%s' — soumission standard.", ext, base)
			}

			// Timeout de polling adaptatif
			pollTimeout := PollTimeout // 10 min pour exécutables
			if nonExecExts[ext] {
				pollTimeout = 3 * time.Minute // 3 min pour non-exécutables
				log.Printf("[RF-SANDBOX] [INFO] Timeout de polling reduit a 3min (fichier non-executable).")
			}

			// Détecter double extension et adapter le timeout
			if doubled, warn := detectDoubleExtension(base); doubled {
				log.Printf("[ALERTE] %s", warn)
				// Forcer un timeout plus long : les comportements tardifs (DLL sideloading,
				// tâches planifiées) peuvent apparaître après 5-10 minutes
				if c.sandboxTimeout < 600 {
					log.Printf("[INFO] Timeout étendu à 600s pour capturer les comportements tardifs de '%s'", base)
					c.sandboxTimeout = 600
				}
			}
			// Pour tous les exécutables : log d'aide si le timeout par défaut est court
			if execExts[ext] && c.sandboxTimeout > 0 && c.sandboxTimeout < 300 {
				log.Printf("[INFO] sandbox_timeout=%ds configuré — pour des malwares avec persistance/C2,")
				log.Printf("[INFO] augmentez à 600s dans config.json pour capturer : tâches planifiées, curl/FTP répétés, DLL sideloading.")
			}

			log.Printf("[RF-API] → Soumission de %s...", base)
			sampleID, err := c.submitWithRetry(tgt, private, maxRetries)
			if err != nil {
				log.Printf("[ERREUR] soumission %s: %v", tgt, err)
				results[idx] = &models.AnalysisResult{
					Filename: base, Status: "error", Error: err.Error(),
				}
				return
			}
			log.Printf("[RF-API]   → ID: %s — analyse en cours, attente des résultats...", sampleID)
			if err := c.waitForCompletion(sampleID, pollTimeout); err != nil {
				// Erreur réseau réelle (pas un timeout) — impossible de récupérer
				log.Printf("[ERREUR] attente %s: %v", sampleID, err)
				results[idx] = &models.AnalysisResult{
					SampleID: sampleID, Filename: base, Status: "failed", Error: err.Error(),
				}
				return
			}
			// waitForCompletion retourne nil sur timeout → tenter fetchResults partiels
			result, err := c.fetchResults(sampleID)
			if err != nil {
				log.Printf("[ERREUR] récupération %s: %v", sampleID, err)
				results[idx] = &models.AnalysisResult{
					SampleID: sampleID, Filename: base, Status: "error", Error: err.Error(),
				}
				return
			}
			if result.Filename == "" {
				result.Filename = base
			}
			results[idx] = result
			log.Printf("[RF-SANDBOX] ✓ %s — Score: %d/10 | Signatures: %d | IOCs: IPs=%d Domaines=%d URLs=%d",
				result.Filename, result.Score, len(result.Signatures),
				len(result.IOCs.IPs), len(result.IOCs.Domains), len(result.IOCs.URLs))
		}(i, target)
	}

	wg.Wait()

	// Filtrer les nils (ne devrait pas arriver mais sécurité)
	var out []*models.AnalysisResult
	for _, r := range results {
		if r != nil {
			out = append(out, r)
		}
	}
	return out
}

// FetchExisting récupère les résultats d'un ID existant
func (c *Client) FetchExisting(sampleID string) *models.AnalysisResult {
	result, err := c.fetchResults(sampleID)
	if err != nil {
		return &models.AnalysisResult{
			SampleID: sampleID, Filename: sampleID, Status: "error", Error: err.Error(),
		}
	}
	return result
}

// TestConnection vérifie que le token est valide en testant /samples
func (c *Client) TestConnection() error {
	var result map[string]interface{}
	return c.get("/samples", &result)
}

// DoRequest effectue une requête vers l'API sandbox (utilisé par le proxy UI)
func (c *Client) DoRequest(method, path string, body []byte, extraHeaders map[string]string) (int, []byte, error) {
	fullURL := BaseURL + path
	headers := make(map[string]string)
	for k, v := range extraHeaders {
		headers[k] = v
	}
	var resp *httpclient.Response
	var err error
	switch method {
	case http.MethodGet:
		resp, err = c.session.Get(fullURL, headers)
	case http.MethodPost:
		resp, err = c.session.Post(fullURL, body, headers)
	default:
		return 0, nil, fmt.Errorf("méthode non supportée: %s", method)
	}
	if err != nil {
		if _, ok := err.(*httpclient.ProxyError); ok {
			c.session.ClearProxy()
			if method == http.MethodGet {
				resp, err = c.session.Get(fullURL, headers)
			} else {
				resp, err = c.session.Post(fullURL, body, headers)
			}
		}
		if err != nil {
			return 0, nil, err
		}
	}
	return resp.StatusCode, resp.Bytes(), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─── Nouveaux endpoints API v0 ────────────────────────────────────────────────

// SearchSamples recherche des analyses via l'API Search (GET /search).
// Supporte les filtres : family:emotet, tag:ransomware, sha256:<hash>, etc.
// Gère la pagination automatiquement via le curseur "next".
// subset : "owned" (défaut), "public", "org"
func (c *Client) SearchSamples(query, subset string) ([]models.Sample, error) {
	var all []models.Sample
	cursor := ""
	for {
		path := "/search?query=" + url.QueryEscape(query)
		if subset != "" {
			path += "&subset=" + subset
		}
		if cursor != "" {
			path += "&after=" + url.QueryEscape(cursor)
		}
		var result struct {
			Data []models.Sample `json:"data"`
			Next string          `json:"next"`
		}
		if err := c.get(path, &result); err != nil {
			if len(all) > 0 {
				// Retourner ce qu'on a déjà si la pagination échoue
				return all, nil
			}
			return nil, fmt.Errorf("search: %w", err)
		}
		all = append(all, result.Data...)
		if result.Next == "" || len(result.Data) == 0 {
			break
		}
		cursor = result.Next
	}
	return all, nil
}

// ListSamples liste les analyses soumises par l'utilisateur (GET /samples).
// Gère la pagination automatiquement via le curseur "next".
// subset : "owned" (défaut), "public", "org"
func (c *Client) ListSamples(subset string) ([]models.Sample, error) {
	var all []models.Sample
	cursor := ""
	for {
		path := "/samples"
		params := ""
		if subset != "" {
			params += "subset=" + subset
		}
		if cursor != "" {
			if params != "" {
				params += "&"
			}
			params += "after=" + url.QueryEscape(cursor)
		}
		if params != "" {
			path += "?" + params
		}
		var result struct {
			Data []models.Sample `json:"data"`
			Next string          `json:"next"`
		}
		if err := c.get(path, &result); err != nil {
			if len(all) > 0 {
				return all, nil
			}
			return nil, fmt.Errorf("list samples: %w", err)
		}
		all = append(all, result.Data...)
		if result.Next == "" || len(result.Data) == 0 {
			break
		}
		cursor = result.Next
	}
	return all, nil
}

// DeleteSample supprime une analyse (DELETE /samples/{sampleID}).
// Note : sur le cloud public RF, seul le support peut supprimer des samples.
func (c *Client) DeleteSample(sampleID string) error {
	fullURL := BaseURL + "/samples/" + sampleID
	resp, err := c.session.Delete(fullURL, nil)
	if err != nil {
		return fmt.Errorf("delete sample %s: %w", sampleID, err)
	}
	if resp.StatusCode == 404 {
		return fmt.Errorf("sample %s introuvable", sampleID)
	}
	if !resp.OK() {
		return fmt.Errorf("HTTP %d pour DELETE /samples/%s: %s", resp.StatusCode, sampleID, resp.Text())
	}
	return nil
}

// DownloadSample télécharge le fichier original soumis (GET /samples/{sampleID}/sample).
// Retourne les bytes bruts du fichier.
func (c *Client) DownloadSample(sampleID string) ([]byte, error) {
	fullURL := BaseURL + "/samples/" + sampleID + "/sample"
	resp, err := c.session.Get(fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("download sample %s: %w", sampleID, err)
	}
	if !resp.OK() {
		return nil, fmt.Errorf("HTTP %d pour download sample %s", resp.StatusCode, sampleID)
	}
	return resp.Bytes(), nil
}

// GetPCAP télécharge le PCAP réseau d'une tâche (GET /samples/{sampleID}/{taskID}/dump.pcap).
func (c *Client) GetPCAP(sampleID, taskID string) ([]byte, error) {
	fullURL := BaseURL + fmt.Sprintf("/samples/%s/%s/dump.pcap", sampleID, taskID)
	resp, err := c.session.Get(fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("get pcap %s/%s: %w", sampleID, taskID, err)
	}
	if !resp.OK() {
		return nil, fmt.Errorf("HTTP %d pour pcap %s/%s", resp.StatusCode, sampleID, taskID)
	}
	return resp.Bytes(), nil
}

// GetPCAPNG télécharge le PCAPNG (avec HTTPS déchiffré) d'une tâche.
// Nécessite Wireshark/TShark v3+.
func (c *Client) GetPCAPNG(sampleID, taskID string) ([]byte, error) {
	fullURL := BaseURL + fmt.Sprintf("/samples/%s/%s/dump.pcapng", sampleID, taskID)
	resp, err := c.session.Get(fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("get pcapng %s/%s: %w", sampleID, taskID, err)
	}
	if !resp.OK() {
		return nil, fmt.Errorf("HTTP %d pour pcapng %s/%s", resp.StatusCode, sampleID, taskID)
	}
	return resp.Bytes(), nil
}

// GetKernelLog récupère les logs du moniteur kernel (GET /samples/{sampleID}/{taskID}/logs/onemon.json).
func (c *Client) GetKernelLog(sampleID, taskID string) ([]byte, error) {
	fullURL := BaseURL + fmt.Sprintf("/samples/%s/%s/logs/onemon.json", sampleID, taskID)
	resp, err := c.session.Get(fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("get kernel log %s/%s: %w", sampleID, taskID, err)
	}
	if !resp.OK() {
		return nil, fmt.Errorf("HTTP %d pour kernel log %s/%s", resp.StatusCode, sampleID, taskID)
	}
	return resp.Bytes(), nil
}

// GetDroppedFile télécharge un fichier déposé par le malware pendant l'analyse.
// Le fileName doit être trouvé dans le champ "dumped" du report_triage.json.
func (c *Client) GetDroppedFile(sampleID, taskID, fileName string) ([]byte, error) {
	fullURL := BaseURL + fmt.Sprintf("/samples/%s/%s/files/%s", sampleID, taskID, fileName)
	resp, err := c.session.Get(fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("get dropped file %s: %w", fileName, err)
	}
	if !resp.OK() {
		return nil, fmt.Errorf("HTTP %d pour dropped file %s", resp.StatusCode, fileName)
	}
	return resp.Bytes(), nil
}

// GetMemoryDump télécharge un dump mémoire généré pendant l'analyse comportementale.
// Le memoryDump est le nom du fichier trouvé dans le champ "dumped" de report_triage.json
// avec kind "memory" ou "memdump". Format: GET /samples/{sampleID}/{taskID}/memory/{memoryDump}
func (c *Client) GetMemoryDump(sampleID, taskID, memoryDump string) ([]byte, error) {
	fullURL := BaseURL + fmt.Sprintf("/samples/%s/%s/memory/%s", sampleID, taskID, memoryDump)
	resp, err := c.session.Get(fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("get memory dump %s: %w", memoryDump, err)
	}
	if !resp.OK() {
		return nil, fmt.Errorf("HTTP %d pour memory dump %s", resp.StatusCode, memoryDump)
	}
	return resp.Bytes(), nil
}

// GetURLScanReport récupère le rapport URLScan JSON (GET /samples/{sampleID}/urlscan1/report_urlscan.json).
// Disponible uniquement si la cible est une URL.
func (c *Client) GetURLScanReport(sampleID string) ([]byte, error) {
	fullURL := BaseURL + fmt.Sprintf("/samples/%s/urlscan1/report_urlscan.json", sampleID)
	resp, err := c.session.Get(fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("get urlscan report %s: %w", sampleID, err)
	}
	if !resp.OK() {
		return nil, fmt.Errorf("HTTP %d pour urlscan report %s", resp.StatusCode, sampleID)
	}
	return resp.Bytes(), nil
}

// GetURLScanScreenshot récupère le screenshot PNG du site analysé (pour les URLs).
func (c *Client) GetURLScanScreenshot(sampleID string) ([]byte, error) {
	fullURL := BaseURL + fmt.Sprintf("/samples/%s/urlscan1/screenshot.png", sampleID)
	resp, err := c.session.Get(fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("get screenshot %s: %w", sampleID, err)
	}
	if !resp.OK() {
		return nil, fmt.Errorf("HTTP %d pour screenshot %s", resp.StatusCode, sampleID)
	}
	return resp.Bytes(), nil
}

// SetProfile sélectionne le profil d'analyse pour un sample en mode interactif
// (POST /samples/{sampleID}/profile).
// Options : auto=true pour sélection automatique, ou profiles=[{profile: "id"}] pour manuel.
// SetAnalysisOptions configure le timeout et le réseau pour les soumissions.
// timeout : durée en secondes (0 = défaut 300s). network : "internet", "drop", "tor" (vide = "internet").
func (c *Client) SetAnalysisOptions(timeout int, network string) {
	if timeout > 0 {
		c.sandboxTimeout = timeout
	}
	if network != "" {
		c.sandboxNetwork = network
	}
}

func (c *Client) SetProfile(sampleID string, payload map[string]interface{}) error {
	var result map[string]interface{}
	if err := c.postJSON("/samples/"+sampleID+"/profile", payload, &result); err != nil {
		return fmt.Errorf("set profile %s: %w", sampleID, err)
	}
	return nil
}

// SetProfileAuto sélectionne automatiquement le profil (raccourci pour SetProfile).
func (c *Client) SetProfileAuto(sampleID string) error {
	return c.SetProfile(sampleID, map[string]interface{}{"auto": true})
}

// WatchSampleEvents ouvre un stream JSONL d'événements pour un sample spécifique
// (GET /samples/{sampleID}/events). Appelle callback pour chaque événement reçu.
// La connexion se ferme automatiquement quand le sample atteint "reported" ou "failed".
func (c *Client) WatchSampleEvents(sampleID string, callback func(status string)) error {
	fullURL := BaseURL + "/samples/" + sampleID + "/events"
	resp, err := c.session.Get(fullURL, map[string]string{"Accept": "application/x-ndjson"})
	if err != nil {
		return fmt.Errorf("watch events %s: %w", sampleID, err)
	}
	// Parser les lignes JSONL
	lines := strings.Split(strings.TrimSpace(string(resp.Bytes())), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		var event struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal([]byte(line), &event); err == nil && callback != nil {
			callback(event.Status)
		}
	}
	return nil
}

// FetchExistingWithArtifacts récupère les résultats d'un sample ET tous ses artefacts disponibles.
// Retourne l'AnalysisResult enrichi + les noms des artefacts téléchargeables.
func (c *Client) FetchExistingWithArtifacts(sampleID string) (*models.AnalysisResult, []string, error) {
	result, err := c.fetchResults(sampleID)
	if err != nil {
		return nil, nil, err
	}

	// Lister les artefacts disponibles pour chaque tâche behavioral
	var artifacts []string
	for taskID, task := range result.Tasks {
		if task.Kind != "behavioral" || task.Status != "reported" {
			continue
		}
		// Extraire le shortTaskID (ex: "behavioral1" depuis "230615-abc12emotet-behavioral1")
		shortTaskID := taskID
		if idx := strings.LastIndex(taskID, "-"); idx >= 0 {
			shortTaskID = taskID[idx+1:]
		}

		// PCAP et PCAPNG toujours disponibles pour les tâches behavioral
		artifacts = append(artifacts, fmt.Sprintf("%s/%s/dump.pcap", sampleID, shortTaskID))
		artifacts = append(artifacts, fmt.Sprintf("%s/%s/dump.pcapng", sampleID, shortTaskID))
		// Logs kernel
		artifacts = append(artifacts, fmt.Sprintf("%s/%s/logs/onemon.json", sampleID, shortTaskID))

		// Fichiers déposés (extracted/dropped) depuis le rapport de la tâche
		if task.Report != nil {
			for _, dumped := range task.Report.Dumped {
				if dumped.Name != "" {
					// Séparer fichiers normaux et dumps mémoire selon le kind
					if strings.EqualFold(dumped.Kind, "memory") || strings.EqualFold(dumped.Kind, "memdump") {
						artifacts = append(artifacts, fmt.Sprintf("%s/%s/memory/%s", sampleID, shortTaskID, dumped.Name))
					} else {
						artifacts = append(artifacts, fmt.Sprintf("%s/%s/files/%s", sampleID, shortTaskID, dumped.Name))
					}
				}
			}
		}
	}

	// Screenshot URLScan si c'est une URL
	if result.Summary != nil && result.Summary.Kind == "url" {
		artifacts = append(artifacts, fmt.Sprintf("%s/urlscan1/screenshot.png", sampleID))
		artifacts = append(artifacts, fmt.Sprintf("%s/urlscan1/report_urlscan.json", sampleID))
	}

	return result, artifacts, nil
}
