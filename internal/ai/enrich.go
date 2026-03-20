package ai

// enrich.go - Enrichissement des analyses via APIs publiques
//
// Sources :
//   - MITRE ATT&CK (API publique TAXII, sans cle)
//     -> Descriptions completes des TTPs, mitigations, detection
//   - AbuseIPDB (cle API gratuite, 1000 req/jour)
//     -> Reputation des IPs, pays, categories d'abus

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ─── Structures ───────────────────────────────────────────────────────────────

// EnrichmentData contient toutes les donnees d'enrichissement pour un prompt.
type EnrichmentData struct {
	MitreTechniques map[string]MitreTechniqueDetail // TTP ID -> detail
	IPReputations   map[string]IPReputation         // IP -> reputation AbuseIPDB
	GeoData         map[string]GeoInfo              // IP -> geolocalisation ip-api.com
	MalwareBazaar   map[string]MalwareBazaarResult  // SHA256 -> résultat MalwareBazaar
}

type MitreTechniqueDetail struct {
	ID          string
	Nom         string
	Tactique    string
	Description string // Description complete
	Detection   string // Comment detecter
	Mitigations []string
}

type IPReputation struct {
	IP             string
	Score          int // 0-100, 100 = tres malveillant
	Pays           string
	ISP            string
	Categories     []string // "Hacking", "Scanning", "Brute-Force"...
	TotalReports   int
	EstMalveillant bool
}

// ─── Client d'enrichissement ──────────────────────────────────────────────────

// ─── Cache in-memory (durée de vie = session Go process) ─────────────────────
// Thread-safe via sync.RWMutex. Évite de re-fetcher MITRE/AbuseIPDB
// pour des TTPs/IPs déjà enrichis dans la même analyse ou session.

var (
	mitreCacheMu sync.RWMutex
	mitreCache   = make(map[string]MitreTechniqueDetail) // clé: TTP ID (ex: "T1059")

	abuseCacheMu sync.RWMutex
	abuseCache   = make(map[string]IPReputation) // clé: adresse IP
)

func getMitreCache(id string) (MitreTechniqueDetail, bool) {
	mitreCacheMu.RLock()
	defer mitreCacheMu.RUnlock()
	v, ok := mitreCache[id]
	return v, ok
}

func setMitreCache(id string, detail MitreTechniqueDetail) {
	mitreCacheMu.Lock()
	mitreCache[id] = detail
	mitreCacheMu.Unlock()
}

func getAbuseCache(ip string) (IPReputation, bool) {
	abuseCacheMu.RLock()
	defer abuseCacheMu.RUnlock()
	v, ok := abuseCache[ip]
	return v, ok
}

func setAbuseCache(ip string, rep IPReputation) {
	abuseCacheMu.Lock()
	abuseCache[ip] = rep
	abuseCacheMu.Unlock()
}

type EnrichClient struct {
	http         *http.Client
	abuseIPDBKey string // cle API AbuseIPDB (optionnel)
}

func NewEnrichClient(abuseIPDBKey string) *EnrichClient {
	return &EnrichClient{
		http:         &http.Client{Timeout: 10 * time.Second},
		abuseIPDBKey: abuseIPDBKey,
	}
}

// Enrich recupere les donnees d'enrichissement pour une liste de TTPs et d'IPs.
// Les erreurs sont non-fatales : si une API est indisponible, on continue sans.
// MITRE et AbuseIPDB sont interrogés en parallèle pour réduire la latence.
// Enrich interroge MITRE ATT&CK et AbuseIPDB en parallèle avec un timeout global de 45s.
// Timeout par appel individuel : 10s (configuré sur e.http).
// Timeout global : 45s — au-delà, les enrichissements partiels sont retournés.
func (e *EnrichClient) Enrich(ttpIDs []string, ips []string, progressFn func(string)) *EnrichmentData {
	data := &EnrichmentData{
		MitreTechniques: make(map[string]MitreTechniqueDetail),
		IPReputations:   make(map[string]IPReputation),
		GeoData:         make(map[string]GeoInfo),
		MalwareBazaar:   make(map[string]MalwareBazaarResult),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Timeout global : 45s pour l'ensemble de l'enrichissement
	// Les goroutines individuelles ont déjà timeout=10s via e.http
	enrichDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(enrichDone)
	}()

	// ── MITRE ATT&CK (parallèle, max 5 concurrent) ───────────────────────
	if len(ttpIDs) > 0 {
		progressFn(fmt.Sprintf("[ENRICH] Enrichissement MITRE ATT&CK pour %d TTPs (parallèle)...", len(ttpIDs)))
		semMitre := make(chan struct{}, 5)
		for _, id := range ttpIDs {
			if id == "" {
				continue
			}
			wg.Add(1)
			go func(ttpID string) {
				defer wg.Done()
				semMitre <- struct{}{}
				defer func() { <-semMitre }()
				if detail, err := e.fetchMitreTechnique(ttpID); err == nil {
					mu.Lock()
					data.MitreTechniques[ttpID] = detail
					mu.Unlock()
					progressFn(fmt.Sprintf("[ENRICH] MITRE %s : %s ✓", ttpID, detail.Nom))
				} else {
					progressFn(fmt.Sprintf("[ENRICH] MITRE %s : non disponible (%v)", ttpID, err))
				}
			}(id)
		}
	}

	// ── AbuseIPDB (parallèle, max 3 concurrent) ───────────────────────────
	if len(ips) > 0 && e.abuseIPDBKey != "" {
		publicIPs := filterPublicIPs(ips)
		if len(publicIPs) > 0 {
			progressFn(fmt.Sprintf("[ENRICH] Reputation AbuseIPDB pour %d IPs (parallèle)...", len(publicIPs)))
			semAbus := make(chan struct{}, 3) // rate limit AbuseIPDB : 1000 req/jour
			for _, ip := range publicIPs {
				wg.Add(1)
				go func(ipAddr string) {
					defer wg.Done()
					semAbus <- struct{}{}
					defer func() { <-semAbus }()
					if rep, err := e.fetchIPReputation(ipAddr); err == nil {
						mu.Lock()
						data.IPReputations[ipAddr] = rep
						mu.Unlock()
						if rep.EstMalveillant {
							progressFn(fmt.Sprintf("[ENRICH] IP %s : MALVEILLANTE (score %d, %s) ⚠", ipAddr, rep.Score, rep.Pays))
						} else {
							progressFn(fmt.Sprintf("[ENRICH] IP %s : score %d (%s)", ipAddr, rep.Score, rep.Pays))
						}
					}
				}(ip)
			}
		}
	} else if len(ips) > 0 && e.abuseIPDBKey == "" {
		progressFn("[ENRICH] AbuseIPDB: aucune clé API configurée — enrichissement IP ignoré")
	}

	// Attendre la fin ou le timeout global
	select {
	case <-enrichDone:
		// Tous les enrichissements terminés dans les temps
	case <-time.After(45 * time.Second):
		progressFn("[ENRICH] ⚠ Timeout global 45s — enrichissements partiels retournés")
	}
	return data
}

// ─── MITRE ATT&CK API ─────────────────────────────────────────────────────────

// fetchMitreTechnique interroge l'API MITRE ATT&CK (TAXII/STIX) pour un TTP.
// API publique, sans authentification.
func (e *EnrichClient) fetchMitreTechnique(ttpID string) (MitreTechniqueDetail, error) {
	// Vérifier le cache in-memory avant tout appel HTTP
	if cached, ok := getMitreCache(ttpID); ok {
		return cached, nil
	}
	// Normaliser l'ID : T1059.007 -> T1059/007 pour l'URL
	// L'API MITRE accepte le format avec point directement via le endpoint de recherche
	url := fmt.Sprintf("https://attack.mitre.org/techniques/%s/", strings.ReplaceAll(ttpID, ".", "/"))

	// Utiliser l'API CTI officielle (JSON/STIX)
	apiURL := fmt.Sprintf("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/attack-pattern/attack-pattern--%s.json", ttpID)
	_ = apiURL

	// Endpoint plus simple : API de recherche MITRE
	searchURL := fmt.Sprintf("https://attack.mitre.org/api/techniques/?id=%s", ttpID)
	_ = searchURL

	// Utiliser l'API TAXII officielle
	taxiiURL := "https://cti-taxii.mitre.org/taxii/"
	_ = taxiiURL

	// Le moyen le plus fiable : GitHub CTI repo (toujours disponible)
	detail, err := e.fetchMitreFromGitHub(ttpID, url)
	if err == nil {
		setMitreCache(ttpID, detail) // mémoriser pour éviter re-fetch
	}
	return detail, err
}

func (e *EnrichClient) fetchMitreFromGitHub(ttpID, _ string) (MitreTechniqueDetail, error) {
	// Chercher dans le repo CTI de MITRE via l'API GitHub
	// Format : cherche le fichier JSON correspondant au TTP
	searchURL := fmt.Sprintf(
		"https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/attack-pattern/attack-pattern--%s.json",
		strings.ToLower(ttpID),
	)

	resp, err := e.http.Get(searchURL)
	if err != nil || resp.StatusCode != 200 {
		// Fallback : API MITRE directe
		return e.fetchMitreDirectAPI(ttpID)
	}
	defer resp.Body.Close()

	var bundle struct {
		Objects []struct {
			Type            string `json:"type"`
			Name            string `json:"name"`
			Description     string `json:"description"`
			KillChainPhases []struct {
				PhaseName string `json:"phase_name"`
			} `json:"kill_chain_phases"`
			XMitreDetection string `json:"x_mitre_detection"`
		} `json:"objects"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil || len(bundle.Objects) == 0 {
		return e.fetchMitreDirectAPI(ttpID)
	}

	obj := bundle.Objects[0]
	tactique := ""
	if len(obj.KillChainPhases) > 0 {
		tactique = strings.Title(strings.ReplaceAll(obj.KillChainPhases[0].PhaseName, "-", " "))
	}

	return MitreTechniqueDetail{
		ID:          ttpID,
		Nom:         obj.Name,
		Tactique:    tactique,
		Description: truncateStr(obj.Description, 800),
		Detection:   truncateStr(obj.XMitreDetection, 400),
	}, nil
}

// fetchMitreDirectAPI utilise la page MITRE ATT&CK comme fallback.
// Extrait uniquement le nom, la tactique et un extrait de description — jamais le HTML complet.
func (e *EnrichClient) fetchMitreDirectAPI(ttpID string) (MitreTechniqueDetail, error) {
	url := fmt.Sprintf("https://attack.mitre.org/techniques/%s/", strings.ReplaceAll(ttpID, ".", "/"))

	resp, err := e.http.Get(url)
	if err != nil {
		return MitreTechniqueDetail{}, fmt.Errorf("MITRE API inaccessible: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return MitreTechniqueDetail{}, fmt.Errorf("MITRE HTTP %d", resp.StatusCode)
	}

	// Lire uniquement les 32 Ko du debut de la page (tout ce dont on a besoin)
	limitedBody, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	html := string(limitedBody)

	// Extraire le nom depuis <title>
	name := extractBetween(html, "<title>", "</title>")
	// Nettoyer : "Command and Scripting Interpreter: JavaScript - MITRE ATT&CK®" -> "JavaScript"
	if idx := strings.Index(name, " - MITRE"); idx > 0 {
		name = name[:idx]
	}
	// Si sous-technique "Parent: Sub" -> garder la partie courte
	if idx := strings.LastIndex(name, ": "); idx > 0 {
		name = name[idx+2:]
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = ttpID
	}

	// Extraire la tactique depuis les liens de la card
	tactique := ""
	if t := extractBetween(html, `href="/tactics/TA`, `</a>`); t != "" {
		if idx := strings.Index(t, `">`); idx >= 0 {
			tactique = strings.TrimSpace(t[idx+2:])
		}
	}
	if tactique == "" {
		tactique = "Voir MITRE ATT&CK"
	}

	// Extraire un extrait de description depuis description-body
	desc := ""
	if raw := extractBetween(html, `<div class="description-body">`, `</div>`); raw != "" {
		desc = stripHTMLTags(raw)
		desc = truncateStr(strings.TrimSpace(desc), 500)
	}

	return MitreTechniqueDetail{
		ID:          ttpID,
		Nom:         name,
		Tactique:    tactique,
		Description: desc,
	}, nil
}

// stripHTMLTags supprime les balises HTML d'une chaine.
func stripHTMLTags(s string) string {
	var b strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
			b.WriteRune(' ')
		case !inTag:
			b.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// ─── AbuseIPDB API ────────────────────────────────────────────────────────────

var abuseCategories = map[int]string{
	3: "Fraude - Donnees personnelles volees", 4: "Attaque DDoS", 9: "Acces non autorise",
	10: "Scan de ports", 11: "Exploitation web", 14: "Serveur email spam",
	15: "Brute-Force", 18: "Scan general", 19: "Attaque DNS",
	20: "Spam email", 21: "Hacking", 22: "Usurpation IP (Spoofing)",
}

func (e *EnrichClient) fetchIPReputation(ip string) (IPReputation, error) {
	// Cache in-memory — évite re-fetch pour la même IP dans la même session
	if cached, ok := getAbuseCache(ip); ok {
		return cached, nil
	}
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90&verbose", ip)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Key", e.abuseIPDBKey)
	req.Header.Set("Accept", "application/json")

	resp, err := e.http.Do(req)
	if err != nil {
		return IPReputation{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return IPReputation{}, fmt.Errorf("AbuseIPDB HTTP %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			IPAddress            string `json:"ipAddress"`
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			CountryCode          string `json:"countryCode"`
			ISP                  string `json:"isp"`
			TotalReports         int    `json:"totalReports"`
			LastReportedAt       string `json:"lastReportedAt"`
			Reports              []struct {
				Categories []int `json:"categories"`
			} `json:"reports"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return IPReputation{}, err
	}

	d := result.Data

	// Collecter les categories uniques
	catSet := make(map[string]bool)
	for _, r := range d.Reports {
		for _, c := range r.Categories {
			if name, ok := abuseCategories[c]; ok {
				catSet[name] = true
			}
		}
	}
	cats := make([]string, 0, len(catSet))
	for c := range catSet {
		cats = append(cats, c)
	}

	rep := IPReputation{
		IP:             d.IPAddress,
		Score:          d.AbuseConfidenceScore,
		Pays:           countryName(d.CountryCode),
		ISP:            d.ISP,
		Categories:     cats,
		TotalReports:   d.TotalReports,
		EstMalveillant: d.AbuseConfidenceScore >= 25 || d.TotalReports >= 5,
	}
	setAbuseCache(ip, rep) // mémoriser pour éviter re-fetch
	return rep, nil
}

// ─── FormatEnrichment : injecteur dans le prompt ─────────────────────────────

// FormatForPrompt convertit les donnees d'enrichissement en texte injecteable dans le prompt.
func (data *EnrichmentData) FormatForPrompt() string {
	if len(data.MitreTechniques) == 0 && len(data.IPReputations) == 0 && len(data.MalwareBazaar) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\n\n=== DONNEES D'ENRICHISSEMENT EXTERNE (utilise ces informations dans ton analyse) ===\n")

	if len(data.MitreTechniques) > 0 {
		sb.WriteString("\n--- MITRE ATT&CK (descriptions officielles) ---\n")
		for id, t := range data.MitreTechniques {
			sb.WriteString(fmt.Sprintf("\n[%s] %s (Tactique: %s)\n", id, t.Nom, t.Tactique))
			if t.Description != "" {
				sb.WriteString(fmt.Sprintf("Description: %s\n", t.Description))
			}
			if t.Detection != "" {
				sb.WriteString(fmt.Sprintf("Detection: %s\n", t.Detection))
			}
		}
	}

	if len(data.IPReputations) > 0 {
		sb.WriteString("\n--- REPUTATION DES IPs (AbuseIPDB) ---\n")
		for ip, rep := range data.IPReputations {
			status := "LEGITIME"
			if rep.EstMalveillant {
				status = "MALVEILLANTE"
			}
			sb.WriteString(fmt.Sprintf("\nIP %s : %s (score: %d/100)\n", ip, status, rep.Score))
			sb.WriteString(fmt.Sprintf("  Pays: %s | FAI: %s | Signalements: %d\n", rep.Pays, rep.ISP, rep.TotalReports))
			if len(rep.Categories) > 0 {
				sb.WriteString(fmt.Sprintf("  Types d'abus: %s\n", strings.Join(rep.Categories, ", ")))
			}
		}
	}

	if len(data.MalwareBazaar) > 0 {
		sb.WriteString("\n--- HASHES CONNUS (MalwareBazaar / abuse.ch) ---\n")
		for sha256, mbr := range data.MalwareBazaar {
			if !mbr.Found {
				sb.WriteString(fmt.Sprintf("\nSHA256 %s... : INCONNU de MalwareBazaar (possiblement inédit)\n", sha256[:16]))
				continue
			}
			sb.WriteString(fmt.Sprintf("\nSHA256 %s... : CONNU\n", sha256[:16]))
			if mbr.FileName != "" {
				sb.WriteString(fmt.Sprintf("  Nom fichier: %s | Type: %s | Taille: %d octets\n", mbr.FileName, mbr.FileType, mbr.FileSize))
			}
			if mbr.Signature != "" {
				sb.WriteString(fmt.Sprintf("  Famille: %s\n", mbr.Signature))
			}
			if len(mbr.Tags) > 0 {
				sb.WriteString(fmt.Sprintf("  Tags: %s\n", strings.Join(mbr.Tags, ", ")))
			}
			if mbr.FirstSeen != "" {
				sb.WriteString(fmt.Sprintf("  Première détection: %s | Rapporteur: %s\n", mbr.FirstSeen, mbr.Reporter))
			}
		}
	}

	sb.WriteString("\n=== FIN DONNEES D'ENRICHISSEMENT ===\n")
	return sb.String()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// filterPublicIPs exclut les IPs privées, DNS publics, et infrastructure Microsoft/CDN légitime.
// Ces plages génèrent des faux positifs car elles sont utilisées par des malwares LOL (Living off the Land)
// qui abusent des services Microsoft légitimes (SharePoint, OneDrive, Azure) comme C2.
// Elles doivent être collectées comme IOCs de domaines — pas comme IPs malveillantes.
func filterPublicIPs(ips []string) []string {
	// IPs exactes à ignorer (DNS publics)
	ignoreExact := map[string]bool{
		"8.8.8.8": true, "8.8.4.4": true,
		"1.1.1.1": true, "1.0.0.1": true,
		"208.67.222.222": true, "208.67.220.220": true,
		"9.9.9.9": true, "149.112.112.112": true,
	}

	// Plages Microsoft Azure, Office 365, CDN — faux positifs fréquents
	// Source : https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges
	legitPrefixes := []string{
		// Microsoft Azure / Office 365 / Teams
		"20.190.", "20.189.", "20.188.", "20.60.", "20.42.",
		"40.126.", "40.96.", "40.97.",
		"52.96.", "52.97.", "52.98.", "52.99.",
		"13.107.", "13.104.", "13.105.",
		// Microsoft CDN / Akamai Microsoft
		"104.40.", "104.44.", "104.45.", "104.46.", "104.47.",
		"23.100.", "23.101.", "23.102.", "23.103.",
		"52.112.", "52.113.", "52.114.", "52.115.", "52.120.", "52.121.", "52.123.",
		"52.239.",
		// Cloudflare CDN
		"104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
		"172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.",
		"162.158.",
		// Akamai
		"23.0.", "23.1.", "23.2.", "23.3.", "23.10.", "23.11.",
		"96.6.", "96.7.",
		// AWS CloudFront
		"13.32.", "13.33.", "13.35.", "99.84.", "99.86.",
		"205.251.",
		// Google / Google Cloud (GCP, YouTube, Gmail, Drive)
		// Source : https://cloud.google.com/compute/docs/faq#find_ip_range
		"216.58.", "216.239.", "209.85.",
		"74.125.", "64.233.", "66.102.", "66.249.",
		"72.14.", "142.250.", "172.217.",
		"34.64.", "34.65.", "34.66.", "34.80.", "34.96.", "34.100.",
		"35.186.", "35.190.", "35.191.", "35.203.", "35.209.", "35.220.", "35.230.", "35.240.",
	}

	var result []string
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if ignoreExact[ip] {
			continue
		}
		// Exclure IPs privées RFC1918 + loopback + link-local
		if strings.HasPrefix(ip, "10.") ||
			strings.HasPrefix(ip, "192.168.") ||
			strings.HasPrefix(ip, "127.") ||
			strings.HasPrefix(ip, "169.254.") ||
			strings.HasPrefix(ip, "172.16.") || strings.HasPrefix(ip, "172.17.") ||
			strings.HasPrefix(ip, "172.18.") || strings.HasPrefix(ip, "172.19.") ||
			strings.HasPrefix(ip, "172.20.") || strings.HasPrefix(ip, "172.21.") ||
			strings.HasPrefix(ip, "172.22.") || strings.HasPrefix(ip, "172.23.") ||
			strings.HasPrefix(ip, "172.24.") || strings.HasPrefix(ip, "172.25.") ||
			strings.HasPrefix(ip, "172.26.") || strings.HasPrefix(ip, "172.27.") ||
			strings.HasPrefix(ip, "172.28.") || strings.HasPrefix(ip, "172.29.") ||
			strings.HasPrefix(ip, "172.30.") || strings.HasPrefix(ip, "172.31.") {
			continue
		}
		// Exclure infrastructure légitime connue
		skip := false
		for _, prefix := range legitPrefixes {
			if strings.HasPrefix(ip, prefix) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		result = append(result, ip)
	}
	return result
}

func truncateStr(s string, max int) string {
	// Nettoyer le markdown STIX
	s = strings.ReplaceAll(s, "(Citation:", "")
	s = strings.ReplaceAll(s, "[[", "")
	s = strings.ReplaceAll(s, "]]", "")
	if len(s) <= max {
		return s
	}
	// Couper proprement a la derniere phrase complete
	cut := s[:max]
	if idx := strings.LastIndex(cut, ". "); idx > max/2 {
		return s[:idx+1]
	}
	return cut + "..."
}

func extractBetween(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	i += len(start)
	j := strings.Index(s[i:], end)
	if j < 0 {
		return s[i:]
	}
	return s[i : i+j]
}

func countryName(code string) string {
	countries := map[string]string{
		"US": "Etats-Unis", "CN": "Chine", "RU": "Russie", "DE": "Allemagne",
		"FR": "France", "GB": "Royaume-Uni", "NL": "Pays-Bas", "UA": "Ukraine",
		"BR": "Bresil", "IN": "Inde", "KR": "Coree du Sud", "JP": "Japon",
		"IR": "Iran", "KP": "Coree du Nord", "TR": "Turquie", "PL": "Pologne",
		"RO": "Roumanie", "HK": "Hong Kong", "SG": "Singapour", "CA": "Canada",
	}
	if name, ok := countries[code]; ok {
		return name
	}
	if code == "" {
		return "Inconnu"
	}
	return code
}

// ─── MalwareBazaar API ────────────────────────────────────────────────────────

// MalwareBazaarResult contient les informations retournées par MalwareBazaar pour un hash.
type MalwareBazaarResult struct {
	SHA256       string   // hash SHA256 du fichier
	FileName     string   // nom du fichier tel que soumis
	FileType     string   // type MIME / extension détectée
	FileSize     int64    // taille en octets
	Signature    string   // famille malware identifiée par MalwareBazaar
	Tags         []string // tags malware (ex: ["loader", "stealer"])
	FirstSeen    string   // date de première soumission (RFC3339)
	Reporter     string   // soumetteur ayant découvert ce hash
	Country      string   // pays d'origine présumé
	Intelligence string   // niveau d'intelligence (high/medium/low)
	Found        bool     // true si le hash est connu dans MalwareBazaar
}

// FetchMalwareBazaar interroge l'API publique MalwareBazaar d'abuse.ch.
// Aucune clé API n'est requise. Rate limit : ~10 req/s.
// Ref : https://bazaar.abuse.ch/api/
func (e *EnrichClient) FetchMalwareBazaar(sha256 string) (MalwareBazaarResult, error) {
	if sha256 == "" {
		return MalwareBazaarResult{}, fmt.Errorf("hash SHA256 vide")
	}

	body := strings.NewReader("query=get_info&hash=" + sha256)
	req, err := http.NewRequest("POST", "https://mb-api.abuse.ch/api/v1/", body)
	if err != nil {
		return MalwareBazaarResult{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := e.http.Do(req)
	if err != nil {
		return MalwareBazaarResult{}, fmt.Errorf("MalwareBazaar API inaccessible: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return MalwareBazaarResult{}, fmt.Errorf("MalwareBazaar HTTP %d", resp.StatusCode)
	}

	var result struct {
		QueryStatus string `json:"query_status"` // "ok" | "no_results" | "illegal_sha256"
		Data        []struct {
			SHA256       string   `json:"sha256_hash"`
			FileName     string   `json:"file_name"`
			FileType     string   `json:"file_type"`
			FileSize     int64    `json:"file_size"`
			Signature    string   `json:"signature"`
			Tags         []string `json:"tags"`
			FirstSeen    string   `json:"first_seen"`
			Reporter     string   `json:"reporter"`
			Country      string   `json:"origin_country"`
			Intelligence string   `json:"intelligence"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return MalwareBazaarResult{}, fmt.Errorf("parsing réponse MalwareBazaar: %w", err)
	}

	if result.QueryStatus != "ok" || len(result.Data) == 0 {
		return MalwareBazaarResult{SHA256: sha256, Found: false}, nil
	}

	d := result.Data[0]
	return MalwareBazaarResult{
		SHA256:    d.SHA256,
		FileName:  d.FileName,
		FileType:  d.FileType,
		FileSize:  d.FileSize,
		Signature: d.Signature,
		Tags:      d.Tags,
		FirstSeen: d.FirstSeen,
		Reporter:  d.Reporter,
		Country:   countryName(d.Country),
		Found:     true,
	}, nil
}

// EnrichHashes interroge MalwareBazaar pour une liste de hashes SHA256.
// Retourne une map SHA256 → résultat. Les hashes inconnus sont inclus avec Found=false.
// Les appels sont effectués en parallèle (max 5 concurrent).
func (e *EnrichClient) EnrichHashes(sha256s []string, progressFn func(string)) map[string]MalwareBazaarResult {
	results := make(map[string]MalwareBazaarResult, len(sha256s))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	for _, h := range sha256s {
		if h == "" {
			continue
		}
		wg.Add(1)
		go func(hash string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			mbr, err := e.FetchMalwareBazaar(hash)
			if err != nil {
				progressFn(fmt.Sprintf("[ENRICH] MalwareBazaar %s... : erreur (%v)", hash[:12], err))
				return
			}
			mu.Lock()
			results[hash] = mbr
			mu.Unlock()
			if mbr.Found {
				progressFn(fmt.Sprintf("[ENRICH] MalwareBazaar %s... : CONNU (%s, famille: %s) ⚠",
					hash[:12], mbr.FileName, mbr.Signature))
			} else {
				progressFn(fmt.Sprintf("[ENRICH] MalwareBazaar %s... : inconnu", hash[:12]))
			}
		}(h)
	}
	wg.Wait()
	return results
}
