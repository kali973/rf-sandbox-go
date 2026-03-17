package ai

// geoip.go - Geolocalisation IP gratuite via ip-api.com
//
// Limites : 100 req/min sans cle, JSON uniquement
// Toggle  : use_geoip dans config.json (on/off depuis la configuration IHM)
// Usage   : GeoLookup(ip) ou GeoLookupBatch(ips)

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// GeoInfo contient les informations de geolocalisation d'une IP.
type GeoInfo struct {
	IP         string
	Pays       string // nom complet
	CodePays   string // code ISO 2 lettres
	Region     string
	Ville      string
	FAI        string // Fournisseur d'acces
	Org        string // Organisation / ASN
	ASN        string
	Latitude   float64
	Longitude  float64
	EstPrivee  bool
	Disponible bool // false si la requete a echoue
}

// Flag retourne l'emoji drapeau pour le code pays (bonus visuel dans le rapport).
func (g GeoInfo) Flag() string {
	if len(g.CodePays) != 2 {
		return ""
	}
	// Chaque lettre ASCII -> Regional Indicator Symbol (U+1F1E6 + offset)
	a := rune(0x1F1E6) + rune(g.CodePays[0]-'A')
	b := rune(0x1F1E6) + rune(g.CodePays[1]-'A')
	return string([]rune{a, b})
}

// FormatCourt retourne "Paris, FR (OVH)" pour affichage dans le rapport.
func (g GeoInfo) FormatCourt() string {
	if !g.Disponible {
		return "Localisation indisponible"
	}
	if g.EstPrivee {
		return "Adresse privee (reseau local)"
	}
	parts := []string{}
	if g.Ville != "" {
		parts = append(parts, g.Ville)
	}
	if g.CodePays != "" {
		parts = append(parts, g.CodePays)
	}
	loc := strings.Join(parts, ", ")
	if g.FAI != "" {
		loc += " (" + g.FAI + ")"
	}
	return loc
}

// FormatComplet retourne la ligne complete pour le rapport PDF.
func (g GeoInfo) FormatComplet() string {
	if !g.Disponible {
		return "Geolocalisation non disponible"
	}
	if g.EstPrivee {
		return "Adresse IP privee — reseau interne ou loopback"
	}
	var sb strings.Builder
	sb.WriteString(g.Pays)
	if g.Ville != "" && g.Ville != g.Pays {
		sb.WriteString(", ")
		sb.WriteString(g.Ville)
	}
	if g.FAI != "" {
		sb.WriteString(" | FAI : ")
		sb.WriteString(g.FAI)
	}
	if g.ASN != "" {
		sb.WriteString(" | ASN : ")
		sb.WriteString(g.ASN)
	}
	return sb.String()
}

// GeoClient est le client de geolocalisation.
type GeoClient struct {
	http    *http.Client
	enabled bool
	cache   map[string]GeoInfo
}

// NewGeoClient cree un client GeoIP.
// enabled = false -> toutes les requetes retournent un GeoInfo vide.
func NewGeoClient(enabled bool) *GeoClient {
	return &GeoClient{
		http:    &http.Client{Timeout: 5 * time.Second},
		enabled: enabled,
		cache:   make(map[string]GeoInfo),
	}
}

// Lookup retourne les informations de geolocalisation pour une IP.
// Resultats mis en cache pour eviter les appels repetitifs.
func (g *GeoClient) Lookup(ip string) GeoInfo {
	if !g.enabled || ip == "" {
		return GeoInfo{IP: ip, Disponible: false}
	}

	// Cache
	if info, ok := g.cache[ip]; ok {
		return info
	}

	// IPs privees : pas besoin d'appel reseau
	if isPrivateIP(ip) {
		info := GeoInfo{IP: ip, EstPrivee: true, Disponible: true, Pays: "Reseau prive"}
		g.cache[ip] = info
		return info
	}

	info := g.fetchIPAPI(ip)
	g.cache[ip] = info
	return info
}

// LookupBatch geocode plusieurs IPs avec un delai entre chaque (rate limit 100/min).
func (g *GeoClient) LookupBatch(ips []string, progress func(string)) map[string]GeoInfo {
	result := make(map[string]GeoInfo)
	if !g.enabled {
		return result
	}

	publicIPs := filterPublicIPs(ips)
	if len(publicIPs) == 0 {
		return result
	}

	if progress != nil {
		progress(fmt.Sprintf("[GEOIP] Geolocalisation de %d IP(s) via ip-api.com...", len(publicIPs)))
	}

	for i, ip := range publicIPs {
		if i > 0 {
			time.Sleep(700 * time.Millisecond) // 100 req/min = 600ms minimum
		}
		info := g.Lookup(ip)
		result[ip] = info
		if progress != nil && info.Disponible && !info.EstPrivee {
			progress(fmt.Sprintf("[GEOIP] %s -> %s (%s)", ip, info.Pays, info.FAI))
		}
	}
	return result
}

// fetchIPAPI interroge ip-api.com pour une IP.
// Gratuit, sans cle, 100 req/min.
func (g *GeoClient) fetchIPAPI(ip string) GeoInfo {
	url := fmt.Sprintf(
		"http://ip-api.com/json/%s?fields=status,country,countryCode,regionName,city,isp,org,as,lat,lon,query",
		ip,
	)

	resp, err := g.http.Get(url)
	if err != nil {
		return GeoInfo{IP: ip, Disponible: false}
	}
	defer resp.Body.Close()

	var result struct {
		Status      string  `json:"status"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		Region      string  `json:"regionName"`
		City        string  `json:"city"`
		ISP         string  `json:"isp"`
		Org         string  `json:"org"`
		AS          string  `json:"as"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		Query       string  `json:"query"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || result.Status != "success" {
		return GeoInfo{IP: ip, Disponible: false}
	}

	// Extraire ASN depuis le champ "as" (format: "AS12345 Nom")
	asn := result.AS
	if idx := strings.Index(asn, " "); idx > 0 {
		asn = asn[:idx]
	}

	return GeoInfo{
		IP:         result.Query,
		Pays:       result.Country,
		CodePays:   result.CountryCode,
		Region:     result.Region,
		Ville:      result.City,
		FAI:        result.ISP,
		Org:        result.Org,
		ASN:        asn,
		Latitude:   result.Lat,
		Longitude:  result.Lon,
		Disponible: true,
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func isPrivateIP(ip string) bool {
	return strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "127.") ||
		strings.HasPrefix(ip, "169.254.") ||
		strings.HasPrefix(ip, "::1") ||
		strings.HasPrefix(ip, "fc") ||
		strings.HasPrefix(ip, "fd") ||
		ip == "0.0.0.0" ||
		isRFC1918_172(ip)
}

func isRFC1918_172(ip string) bool {
	if !strings.HasPrefix(ip, "172.") {
		return false
	}
	parts := strings.Split(ip, ".")
	if len(parts) < 2 {
		return false
	}
	var second int
	fmt.Sscanf(parts[1], "%d", &second)
	return second >= 16 && second <= 31
}

// FormatGeoForPrompt formate les donnees geo pour injection dans le prompt IA.
func FormatGeoForPrompt(geoData map[string]GeoInfo) string {
	if len(geoData) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("\n--- GEOLOCALISATION DES IPs ---\n")
	for ip, info := range geoData {
		if !info.Disponible || info.EstPrivee {
			continue
		}
		sb.WriteString(fmt.Sprintf("IP %s : %s, %s | FAI: %s | ASN: %s\n",
			ip, info.Ville, info.Pays, info.FAI, info.ASN))
	}
	return sb.String()
}
