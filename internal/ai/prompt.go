package ai

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"rf-sandbox-go/internal/models"
)

// ─── Structure de réponse IA ──────────────────────────────────────────────────

// ForensicReport est la structure JSON attendue de l'IA.
type ForensicReport struct {
	Classification                   string           `json:"classification"`
	ScoreGlobal                      int              `json:"score_global"`
	ResumeExecutif                   string           `json:"resume_executif"`
	PourquoiMalveillant              string           `json:"pourquoi_malveillant"`
	TimelineAttaque                  []TimelineEvent  `json:"timeline_attaque"`
	RisqueLateralisation             RisqueLateral    `json:"risque_lateralisation"`
	EtatCompromission                string           `json:"etat_compromission"`
	DonneesExposees                  []DonneeExposee  `json:"donnees_exposees"`
	AnalyseComportementaleIntro      string           `json:"analyse_comportementale_intro"`
	AnalyseComportementale           string           `json:"analyse_comportementale"`
	AnalyseComportementaleConclusion string           `json:"analyse_comportementale_conclusion"`
	AnalyseReseauIntro               string           `json:"analyse_reseau_intro"`
	AnalyseReseau                    string           `json:"analyse_reseau"`
	AnalyseReseauConclusion          string           `json:"analyse_reseau_conclusion"`
	AnalyseProcessusIntro            string           `json:"analyse_processus_intro"`
	AnalyseProcessus                 string           `json:"analyse_processus"`
	AnalyseProcessusConclusion       string           `json:"analyse_processus_conclusion"`
	AnalyseStatiqueIntro             string           `json:"analyse_statique_intro"`
	AnalyseStatique                  string           `json:"analyse_statique"`
	AnalyseStatiqueConclusion        string           `json:"analyse_statique_conclusion"`
	ConfigsMalware                   string           `json:"configs_malware"`
	TechniquesMitre                  []MitreEntry     `json:"techniques_mitre"`
	IOCsCritiques                    []IOCEntry       `json:"iocs_critiques"`
	Attribution                      AttributionEntry `json:"attribution"`
	PostureReponse                   PostureRI        `json:"posture_reponse"`
	Recommandations                  []Recommandation `json:"recommandations"`
	IndicateursCompromission         string           `json:"indicateurs_compromission"`
	NiveauConfiance                  string           `json:"niveau_confiance"`
	Conclusion                       string           `json:"conclusion"`
}

// TimelineEvent : action horodatee du malware.
type TimelineEvent struct {
	Phase   string `json:"phase"`
	Action  string `json:"action"`
	Impact  string `json:"impact"`
	Detecte bool   `json:"detecte"`
}

// RisqueLateral : evaluation du risque de propagation reseau.
type RisqueLateral struct {
	Niveau         string   `json:"niveau"`
	Vecteurs       []string `json:"vecteurs"`
	SystemesCibles []string `json:"systemes_cibles"`
	SignesDetectes []string `json:"signes_detectes"`
	ActionUrgente  string   `json:"action_urgente"`
}

// DonneeExposee : categorie de donnees menacees.
type DonneeExposee struct {
	Type        string `json:"type"`
	Risque      string `json:"risque"`
	Explication string `json:"explication"`
}

// PostureRI : posture de reponse a incident recommandee.
type PostureRI struct {
	Phase           string   `json:"phase"`
	ActionsImmediat []string `json:"actions_immediat"`
	Actions24h      []string `json:"actions_24h"`
	Actions72h      []string `json:"actions_72h"`
	Notification    string   `json:"notification"`
	CritereRetour   string   `json:"critere_retour"`
}

type MitreEntry struct {
	ID                    string `json:"id"`
	Nom                   string `json:"nom"`
	Tactique              string `json:"tactique"`
	Observation           string `json:"observation"`
	DescriptionOfficielle string `json:"description_officielle"`
	SourceURL             string `json:"source_url"`
	Criticite             string `json:"criticite"` // CRITIQUE/ELEVE/MOYEN/FAIBLE
}

type IOCEntry struct {
	Type     string `json:"type"` // IP/DOMAINE/URL/HASH/MUTEX
	Valeur   string `json:"valeur"`
	Contexte string `json:"contexte"`
	Risque   string `json:"risque"` // CRITIQUE/ÉLEVÉ/MOYEN/FAIBLE
}

type AttributionEntry struct {
	FamillePresumee  string   `json:"famille_presumee"`
	Confiance        string   `json:"confiance"`
	GroupePresume    string   `json:"groupe_presume,omitempty"`
	Indicateurs      []string `json:"indicateurs"`
	AutresHypotheses []string `json:"autres_hypotheses,omitempty"`
}

type Recommandation struct {
	Priorite  string `json:"priorite"`  // CRITIQUE/ÉLEVÉ/MOYEN/FAIBLE/INFO
	Categorie string `json:"categorie"` // BLOCAGE/REMEDIATION/INVESTIGATION/DURCISSEMENT/DETECTION
	Action    string `json:"action"`
	Detail    string `json:"detail"`
	Deadline  string `json:"deadline,omitempty"` // ex: "Immédiat", "24h", "7 jours"
}

// ─── Construction du prompt ───────────────────────────────────────────────────

// ─── Prompts pipeline bi-modèle ──────────────────────────────────────────────

// TechExtraction contient le résultat JSON partiel produit par M1 (extraction technique).
// C'est l'intermédiaire entre M1 et M2 dans le pipeline chaîné.
type TechExtraction struct {
	Famille          string   `json:"famille"`
	TTPsConfirmes    []string `json:"ttps_confirmes"`
	InfraC2          []string `json:"infra_c2"`
	VecteurInfection string   `json:"vecteur_infection"`
	Propagation      string   `json:"propagation_estimee"`
	IOCsNets         []string `json:"iocs_nets"`
	Comportements    []string `json:"comportements_cles"`
	PayloadStage2    []string `json:"payload_stage2,omitempty"`     // NVIDIA.exe, libcef.dll, etc.
	C2Infrastructure []string `json:"c2_infrastructure,omitempty"`  // SharePoint, OneDrive, domaines C2
	TechniquesDLL    []string `json:"dll_sideloading,omitempty"`    // DLLs malveillantes identifiées
	Persistance      []string `json:"persistance,omitempty"`        // schtasks, registry run keys, etc.
	Exfiltration     []string `json:"exfiltration_tools,omitempty"` // curl, ftp, outils d'exfiltration
	Confiance        string   `json:"confiance"`                    // "HAUTE" | "MOYENNE" | "FAIBLE"
}

// BuildExtractionPrompt construit le prompt court pour M1 (spécialiste cyber).
// Focalisé sur l'extraction technique pure — famille, TTPs, C2, IOCs.
// Volontairement court (~6k chars) pour maximiser la précision du spécialiste.
func BuildExtractionPrompt(results []*models.AnalysisResult, enrichment *EnrichmentData) string {
	var sb strings.Builder

	sb.WriteString("Tu es un analyste malware expert CTI. Analyse les données sandbox ci-dessous.\n")
	sb.WriteString("Identifie avec précision : famille malware, TTPs MITRE confirmés, infrastructure C2,\n")
	sb.WriteString("vecteur d'infection, capacités de propagation et IOCs réseaux.\n\n")
	sb.WriteString("Réponds UNIQUEMENT en JSON valide, sans texte avant ni après :\n")
	sb.WriteString(`{
  "famille": "nom exact de la famille malware ou 'Inconnue'",
  "ttps_confirmes": ["T1059.001", "T1071", "T1053.005", "T1574.002"],
  "infra_c2": ["ip:port ou domaine C2"],
  "vecteur_infection": "description courte du vecteur",
  "propagation_estimee": "CRITIQUE|ELEVE|MOYEN|FAIBLE",
  "iocs_nets": ["hash", "ip:port", "domaine"],
  "payload_stage2": ["NVIDIA.exe", "libcef.dll"],
  "c2_infrastructure": ["0bgtr-my.sharepoint.com", "graph.microsoft.com"],
  "dll_sideloading": ["libcef.dll chargée par NVIDIA.exe via DLL sideloading"],
  "persistance": ["schtasks /create NVIDIA quotidien 10:50"],
  "exfiltration_tools": ["curl.exe vers ipinfo.io", "ftp.exe via r.txt"],
  "comportements_cles": ["comportement 1 observé", "comportement 2"],
  "confiance": "HAUTE|MOYENNE|FAIBLE"
}` + "\n\n")

	sb.WriteString("--- DONNÉES SANDBOX ---\n")
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("Fichier: %s | Score: %d/10 | Famille: %s\n",
			r.Filename, r.Score, r.Family))
		if len(r.Signatures) > 0 {
			sb.WriteString("Signatures comportementales:\n")
			for i, sig := range r.Signatures {
				if i >= 8 {
					break
				}
				name := sig.Label
				if name == "" {
					name = sig.Name
				}
				sb.WriteString(fmt.Sprintf("  [%d] %s (score=%d, TTPs=%s)\n",
					i+1, name, sig.Score, strings.Join(sig.TTP, ",")))
			}
		}
		if len(r.IOCs.IPs) > 0 {
			sb.WriteString(fmt.Sprintf("IPs contactées: %s\n", strings.Join(r.IOCs.IPs[:min8(len(r.IOCs.IPs), 10)], ", ")))
		}
		if len(r.IOCs.Domains) > 0 {
			sb.WriteString(fmt.Sprintf("Domaines C2: %s\n", strings.Join(r.IOCs.Domains[:min8(len(r.IOCs.Domains), 5)], ", ")))
		}
		if r.Hashes.SHA256 != "" {
			sb.WriteString(fmt.Sprintf("SHA256: %s\n", r.Hashes.SHA256))
		}
	}

	// ── Flux réseau (top 10 destinations) ─────────────────────────────────
	netFlows := extractTopFlows(results, 10)
	if len(netFlows) > 0 {
		sb.WriteString("\n--- FLUX RÉSEAU (destinations C2 candidates) ---\n")
		for _, f := range netFlows {
			line := fmt.Sprintf("  → %s", f.dest)
			if f.domain != "" {
				line += fmt.Sprintf(" (%s)", f.domain)
			}
			if f.country != "" {
				line += fmt.Sprintf(" [%s]", f.country)
			}
			if f.txBytes > 0 {
				line += fmt.Sprintf(" ↑%d octets", f.txBytes)
			}
			sb.WriteString(line + "\n")
		}
	}

	// ── Cmdlines suspectes (curl, ftp, schtasks, powershell) ────────────────
	suspectCmds := extractSuspectCmdlines(results)
	if len(suspectCmds) > 0 {
		sb.WriteString("\n--- COMMANDES SUSPECTES (curl/ftp/schtasks détectées) ---\n")
		for _, cmd := range suspectCmds {
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", cmd.binary, truncateStr(cmd.cmdline, 150)))
		}
	}

	// ── KernelEvents critiques (file_create + net_connect filtrés) ──────────
	// Passer TOUS les events kernel à M1 — aucune troncature
	// M1 doit voir la timeline complète pour identifier famille/TTPs/C2
	criticalEvents := extractAllKernelEvents(results)
	if len(criticalEvents) > 0 {
		sb.WriteString("\n--- ÉVÉNEMENTS KERNEL CRITIQUES ---\n")
		for _, ev := range criticalEvents {
			// Format compact : timestamp, processus, action, cible
			// Ignorer les events sans cible ni action significative (bruit)
			if ev.Target == "" && ev.Action == "" {
				continue
			}
			action := ev.Action
			if len(action) > 20 {
				action = action[:20]
			}
			if ev.Target != "" {
				sb.WriteString(fmt.Sprintf("  [%dms] %s | %s → %s\n",
					ev.TimeMs, ev.Image, action, truncateStr(ev.Target, 100)))
			} else {
				sb.WriteString(fmt.Sprintf("  [%dms] %s | %s\n",
					ev.TimeMs, ev.Image, action))
			}
		}
	}

	// ── Fichiers déposés par le malware (payloads 2ème stage) ─────────────────
	for _, r := range results {
		if len(r.DroppedFiles) > 0 {
			sb.WriteString("\n--- FICHIERS DÉPOSÉS PAR LE MALWARE (payloads 2ème stage) ---\n")
			for i, df := range r.DroppedFiles {
				if i >= 8 {
					break
				}
				line := fmt.Sprintf("  [%s] %s (%d octets)", df.Kind, df.Name, df.Size)
				if df.SHA256 != "" {
					line += fmt.Sprintf(" SHA256=%s", df.SHA256[:16]+"...")
				}
				sb.WriteString(line + "\n")
				// Contenu des scripts (r.txt, 11.txt, commandes ftp/curl)
				if len(df.Content) > 0 && len(df.Content) <= 4096 {
					ext := strings.ToLower(filepath.Ext(df.Name))
					if ext == ".txt" || ext == ".bat" || ext == ".ps1" || ext == ".js" {
						sb.WriteString(fmt.Sprintf("    Contenu: %s\n", string(df.Content[:minExt(len(df.Content), 200)])))
					}
				}
			}
			break // une seule fois pour tous les résultats
		}
	}

	if enrichment != nil && len(enrichment.MitreTechniques) > 0 {
		sb.WriteString("\n--- ENRICHISSEMENT MITRE ---\n")
		for id, detail := range enrichment.MitreTechniques {
			sb.WriteString(fmt.Sprintf("  %s: %s (%s)\n", id, detail.Nom, detail.Tactique))
		}
	}
	return sb.String()
}

func minExt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─── Helpers extraction M1 ────────────────────────────────────────────────────

type netFlowSummary struct {
	dest    string
	domain  string
	country string
	txBytes uint64
}

type cmdlineSummary struct {
	binary  string
	cmdline string
}

// extractTopFlows retourne les N connexions réseau les plus significatives.
// Filtre les IPs privées et loopback, trie par volume de données envoyées.
func extractTopFlows(results []*models.AnalysisResult, n int) []netFlowSummary {
	var flows []netFlowSummary
	for _, r := range results {
		for _, nr := range r.Network {
			for _, f := range nr.Flows {
				if f.Dest == "" || isPrivateIPAddr(f.Dest) {
					continue
				}
				flows = append(flows, netFlowSummary{
					dest:    f.Dest,
					domain:  f.Domain,
					country: f.Country,
					txBytes: f.TxBytes,
				})
			}
		}
	}
	// Trier par volume envoyé décroissant
	for i := 0; i < len(flows)-1; i++ {
		for j := i + 1; j < len(flows); j++ {
			if flows[j].txBytes > flows[i].txBytes {
				flows[i], flows[j] = flows[j], flows[i]
			}
		}
	}
	if len(flows) > n {
		return flows[:n]
	}
	return flows
}

// extractSuspectCmdlines extrait les cmdlines suspectes (curl, ftp, schtasks, wscript...).
func extractSuspectCmdlines(results []*models.AnalysisResult) []cmdlineSummary {
	var cmds []cmdlineSummary
	suspectBinaries := []string{"curl", "ftp", "schtasks", "powershell", "wscript", "cscript",
		"mshta", "regsvr32", "rundll32", "certutil", "bitsadmin", "wget", "invoke-"}
	for _, r := range results {
		for _, p := range r.Processes {
			if p.Cmd == nil {
				continue
			}
			cmdline := ""
			switch v := p.Cmd.(type) {
			case string:
				cmdline = v
			case []interface{}:
				parts := make([]string, 0)
				for _, c := range v {
					if s, ok := c.(string); ok {
						parts = append(parts, s)
					}
				}
				cmdline = strings.Join(parts, " ")
			}
			if cmdline == "" {
				continue
			}
			lower := strings.ToLower(cmdline)
			for _, suspect := range suspectBinaries {
				if strings.Contains(lower, suspect) {
					parts := strings.Split(strings.ReplaceAll(p.Image, "\\", "/"), "/")
					binary := parts[len(parts)-1]
					cmds = append(cmds, cmdlineSummary{binary: binary, cmdline: cmdline})
					break
				}
			}
			if len(cmds) >= 10 {
				break
			}
		}
	}
	return cmds
}

// extractCriticalKernelEvents filtre les N events kernel les plus importants pour M1.
func extractCriticalKernelEvents(results []*models.AnalysisResult, n int) []models.KernelEvent {
	var critical []models.KernelEvent
	for _, r := range results {
		for _, ev := range r.KernelEvents {
			a := strings.ToLower(ev.Action)
			t := strings.ToLower(ev.Target)
			// Événements hautement significatifs
			if strings.Contains(a, "file") && strings.Contains(a, "create") &&
				(strings.Contains(t, ".exe") || strings.Contains(t, ".dll") ||
					strings.Contains(t, ".bat") || strings.Contains(t, ".ps1")) {
				critical = append(critical, ev) // Fichiers exécutables créés
			} else if strings.Contains(a, "net") || strings.Contains(a, "connect") {
				critical = append(critical, ev) // Connexions réseau
			} else if strings.Contains(a, "sched") || strings.Contains(t, "schtasks") {
				critical = append(critical, ev) // Tâches planifiées
			}
			if len(critical) >= n {
				break
			}
		}
	}
	return critical
}

// isPrivateIPAddr vérifie si une adresse IP est privée/loopback.
// extractAllKernelEvents retourne TOUS les events kernel sans limite.
// Contrairement à extractCriticalKernelEvents, aucun filtre n'est appliqué :
// tous les events sont nécessaires pour une timeline complète et un rapport exact.
func extractAllKernelEvents(results []*models.AnalysisResult) []models.KernelEvent {
	var all []models.KernelEvent
	for _, r := range results {
		all = append(all, r.KernelEvents...)
	}
	// Tri chronologique
	for i := 0; i < len(all)-1; i++ {
		for j := i + 1; j < len(all); j++ {
			if all[j].TimeMs < all[i].TimeMs {
				all[i], all[j] = all[j], all[i]
			}
		}
	}
	return all
}

// appendUniq ajoute s dans slice si absent.
func appendUniq(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

func isPrivateIPAddr(ip string) bool {
	private := []string{"127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
		"172.19.", "172.2", "172.3", "::1", "0.0.0.0", "localhost"}
	for _, p := range private {
		if strings.HasPrefix(ip, p) || ip == p {
			return true
		}
	}
	return false
}

// BuildSynthesisPrompt construit le prompt M2 à partir du résultat M1.
// M2 (Qwen 14B) reçoit l'extraction technique et produit le rapport JSON complet.
func BuildSynthesisPrompt(
	results []*models.AnalysisResult,
	extraction *TechExtraction,
	enrichment *EnrichmentData,
	similar []SimilarEntry,
	geoData map[string]GeoInfo,
) string {
	var sb strings.Builder

	sb.WriteString("Tu es un analyste senior CERT/CSIRT francophone. ")
	sb.WriteString("Un moteur IA spécialisé en cybersécurité a déjà effectué l'extraction technique.\n")
	sb.WriteString("Tu dois produire le rapport forensic complet au format JSON en exploitant ces données.\n\n")

	sb.WriteString("--- EXTRACTION TECHNIQUE (résultat moteur cyber spécialisé) ---\n")
	if b, err := json.Marshal(extraction); err == nil {
		sb.Write(b)
	}
	sb.WriteString("\n\n")

	// Contexte métier enrichi
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("Contexte: %s | Score sandbox: %d/10\n", r.Filename, r.Score))
	}

	// Données AbuseIPDB si disponibles
	if enrichment != nil && len(enrichment.IPReputations) > 0 {
		sb.WriteString("\n--- RÉPUTATION IPs (AbuseIPDB) ---\n")
		for ip, rep := range enrichment.IPReputations {
			if rep.EstMalveillant {
				sb.WriteString(fmt.Sprintf("  %s: score=%d/100, pays=%s, FAI=%s\n",
					ip, rep.Score, rep.Pays, rep.ISP))
			}
		}
	}

	// Analyses similaires depuis la base de connaissances
	if len(similar) > 0 {
		sb.WriteString("\n--- ANALYSES SIMILAIRES (base de connaissances) ---\n")
		for _, s := range similar {
			sb.WriteString(fmt.Sprintf("  Similarité %d%%: %s — %s\n",
				s.Score, s.Entry.Filename, s.Raison))
		}
	}

	// Schéma JSON de sortie attendu — M2 doit produire le ForensicReport complet
	// On lui demande exactement le même format que BuildForensicPrompt (mono-modèle)
	sb.WriteString("\nProduis le rapport forensic complet au format JSON valide, sans texte avant ni après.\n")
	sb.WriteString("Utilise l'extraction technique ci-dessus comme base factuelle — enrichis avec le contexte métier.\n")
	sb.WriteString("IMPORTANT : Si payload_stage2 contient NVIDIA.exe/libcef.dll → identifie T1574.002 DLL sideloading.\n")
	sb.WriteString("IMPORTANT : Si c2_infrastructure contient *.sharepoint.com ou *.microsoft.com → c'est une technique LOLBin (C2 via infra légitime).\n")
	sb.WriteString("IMPORTANT : Si persistance contient schtasks → identifie T1053.005 et décris la tâche planifiée.\n")
	sb.WriteString("IMPORTANT : Si exfiltration_tools contient curl/ftp → identifie T1041 et T1082 si ipinfo.io est mentionné.\n")
	sb.WriteString("Le JSON doit contenir tous les champs du ForensicReport : ")
	sb.WriteString("classification, score_global, resume_executif, pourquoi_malveillant, ")
	sb.WriteString("timeline_attaque, risque_lateralisation, etat_compromission, donnees_exposees, ")
	sb.WriteString("analyse_comportementale, analyse_reseau, techniques_mitre, iocs_critiques, ")
	sb.WriteString("attribution, posture_reponse, recommandations, niveau_confiance, conclusion.\n")
	// ── Données réseau brutes RF — transmises à M2 pour éviter les lacunes ─
	flowsM2 := extractTopFlows(results, 15)
	if len(flowsM2) > 0 {
		sb.WriteString("\n--- CONNEXIONS RÉSEAU OBSERVÉES EN SANDBOX ---\n")
		for _, f := range flowsM2 {
			line := fmt.Sprintf("  → %s", f.dest)
			if f.domain != "" {
				line += " (domaine: " + f.domain + ")"
			}
			if f.country != "" {
				line += " [" + f.country + "]"
			}
			sb.WriteString(line + "\n")
		}
	}
	cmdsM2 := extractSuspectCmdlines(results)
	if len(cmdsM2) > 0 {
		sb.WriteString("\n--- COMMANDES SUSPECTES (curl/ftp/schtasks) ---\n")
		for _, cmd := range cmdsM2 {
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", cmd.binary, truncateStr(cmd.cmdline, 120)))
		}
	}

	// Contrainte critique : rappel explicite des types tableaux
	// Qwen 2.5 14B retourne parfois {} au lieu de [] (observé en production)
	sb.WriteString(`

TYPES JSON OBLIGATOIRES — ces champs DOIVENT être des tableaux [] jamais des objets {} :
  timeline_attaque, techniques_mitre, iocs_critiques, recommandations, donnees_exposees
`)
	return sb.String()
}

func min8(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// BuildForensicPrompt construit le prompt management à partir des résultats sandbox.
// Accepte des donnees d'enrichissement externes (MITRE, AbuseIPDB) et la base de connaissances.
func BuildForensicPrompt(results []*models.AnalysisResult, enrichment *EnrichmentData, similar []SimilarEntry, geoData map[string]GeoInfo) string {
	data := buildCondensedData(results)
	dataJSON, _ := json.MarshalIndent(data, "", "  ")

	// ── Extraction IOCs factuels pour injection directe ──────────────────────
	// Ces données sont extraites des résultats RF Sandbox et DOIVENT être citées
	// exactement telles quelles dans le rapport — pas de "non spécifié"
	var factualIPs, factualDomains, factualHashes []string
	for _, r := range results {
		for _, ip := range r.IOCs.IPs {
			if ip != "" && !isPrivateIPAddr(ip) {
				factualIPs = appendUniq(factualIPs, ip)
			}
		}
		for _, d := range r.IOCs.Domains {
			if d != "" {
				factualDomains = appendUniq(factualDomains, d)
			}
		}
		for _, nr := range r.Network {
			for _, f := range nr.Flows {
				if f.Dest != "" && !isPrivateIPAddr(f.Dest) {
					factualIPs = appendUniq(factualIPs, f.Dest)
				}
				if f.Domain != "" {
					factualDomains = appendUniq(factualDomains, f.Domain)
				}
				if f.SNI != "" && f.SNI != f.Domain {
					factualDomains = appendUniq(factualDomains, f.SNI)
				}
			}
		}
		if r.Hashes.SHA256 != "" {
			factualHashes = appendUniq(factualHashes, r.Hashes.SHA256)
		}
		if r.Hashes.MD5 != "" {
			factualHashes = appendUniq(factualHashes, "MD5:"+r.Hashes.MD5)
		}
	}
	// Données factuelles à citer obligatoirement
	var factualBlock strings.Builder
	if len(factualIPs) > 0 || len(factualDomains) > 0 || len(factualHashes) > 0 {
		factualBlock.WriteString("\n⚠ DONNÉES FACTUELLES OBLIGATOIRES — CITE CES VALEURS EXACTES DANS LE RAPPORT :\n")
		if len(factualIPs) > 0 {
			factualBlock.WriteString(fmt.Sprintf("  IPs contactées : %s\n", strings.Join(factualIPs, ", ")))
		}
		if len(factualDomains) > 0 {
			factualBlock.WriteString(fmt.Sprintf("  Domaines contactés : %s\n", strings.Join(factualDomains, ", ")))
		}
		if len(factualHashes) > 0 {
			factualBlock.WriteString(fmt.Sprintf("  Hashes fichier : %s\n", strings.Join(factualHashes, " | ")))
		}
		factualBlock.WriteString("  → NE PAS écrire 'non spécifié' si une valeur figure ci-dessus\n")
	}

	// Contexte additionnel : enrichissement + historique
	extraContext := ""
	if enrichment != nil {
		extraContext += enrichment.FormatForPrompt()
	}
	if len(similar) > 0 {
		extraContext += FormatKnowledgeForPrompt(similar)
	}
	if len(geoData) > 0 {
		extraContext += FormatGeoForPrompt(geoData)
	}

	// Schéma JSON attendu de l'IA — chaque champ est une instruction de rédaction
	// Schéma JSON forensique — chaque champ guide la rédaction de l'IA
	// Injecter le bloc factuel dans extraContext si non vide
	if factualBlock.Len() > 0 {
		extraContext = factualBlock.String() + extraContext
	}
	schema := `{
  "classification": "CHOISIS UNE SEULE VALEUR parmi : CRITIQUE / ELEVE / MOYEN / FAIBLE / BENIN",
  "score_global": 7,
  "etat_compromission": "CONFIRME|PROBABLE|SUSPECTE — justifie en 1 phrase : quels elements observes en sandbox prouvent ou suggerent une infection reelle.",

  "resume_executif": "8 a 10 phrases pour le COMEX/PDG. Structure : (1) Nom et nature exacte de la menace identifiee. (2) Ce que ce malware fait concretement sur la machine infectee (actions observees, pas supposees). (3) Pourquoi c'est malveillant — la preuve : comportement anormal specifique constate en sandbox. (4) Quelles donnees ou systemes sont directement en danger. (5) Le risque de propagation a d'autres machines du reseau. (6) Les consequences financieres et operationnelles si aucune action. (7) Ce qui a ete fait ou doit etre fait en priorite. (8) Recommandation finale au dirigeant.",

  "pourquoi_malveillant": "Section cle pour le management : explique en 5 a 7 phrases POURQUOI ce fichier est definitvement malveillant et pas une fausse alerte. Cite les PREUVES concretes : (1) comportements observes impossibles pour un logiciel legitime (tentative d'evasion AV, connexion vers infrastructure malveillante connue, injection dans processus systeme, etc.), (2) techniques d'attaque identifiees et leur but reel, (3) correspondance avec une famille malware connue et ce que cette famille fait habituellement, (4) verdict : pourquoi on peut affirmer avec [niveau] de confiance que c'est une menace reelle.",

  "timeline_attaque": [
    {
      "phase": "Phase 1 : Activation initiale",
      "action": "Description precise de l'action observee en sandbox (ex: extraction archive 7z, execution WScript.exe)",
      "impact": "Ce que cela signifie pour la machine et l'entreprise",
      "detecte": true
    },
    {
      "phase": "Phase 2 : Etablissement de la persistance",
      "action": "Action de persistance observee ou probable selon la famille malware",
      "impact": "Le malware survit au redemarrage et reprend son activite",
      "detecte": false
    },
    {
      "phase": "Phase 3 : Communication C2",
      "action": "Cite EXACTEMENT les IPs et domaines des données factuelles ci-dessus — ex: connexion vers 150.171.28.10:443 et login.microsoftonline.com",
      "impact": "Lattaquant prend le controle et peut envoyer des ordres ou exfiltrer des donnees",
      "detecte": true
    }
  ],

  "risque_lateralisation": {
    "niveau": "CHOISIS UNE SEULE VALEUR parmi : CRITIQUE / ELEVE / MOYEN / FAIBLE",
    "vecteurs": [
      "Vecteur 1 : comment le malware pourrait se propager (partages reseau, credentials voles, exploit laterale)",
      "Vecteur 2 si applicable"
    ],
    "systemes_cibles": [
      "Type de systeme prioritairement vise : controleurs de domaine, serveurs de fichiers, postes admin",
      "Donnees sensibles accessibles depuis le poste infecte"
    ],
    "signes_detectes": [
      "Signe 1 observe en sandbox indiquant une tentative ou capacite de lateralisation",
      "Signe 2 si present"
    ],
    "action_urgente": "Action immediate specifique pour bloquer la propagation : isoler le segment reseau, changer les mots de passe de service, bloquer les partages SMB, etc."
  },

  "donnees_exposees": [
    {
      "type": "Identifiants Windows / Active Directory",
      "risque": "CRITIQUE",
      "explication": "Pourquoi ces donnees sont accessibles et ce que lattaquant peut en faire"
    },
    {
      "type": "Donnees metier / fichiers du poste",
      "risque": "ELEVE",
      "explication": "Quels fichiers sont accessibles depuis ce poste et le risque d'exfiltration"
    }
  ],

  "analyse_comportementale_intro": "OBLIGATOIRE — 1 phrase d'accroche specifique au malware analyse : annonce le comportement dominant observe. Ex: 'Ce dropper execute une sequence en 3 etapes qui lui permet de s'installer silencieusement et de contacter son operateur sans declencher les defenses.'",
  "analyse_comportementale": "5 a 7 phrases. Sequence chronologique des comportements observes en sandbox : actions fichiers (creation, modification, suppression), acces registre, tentatives de privilege, mecanismes de persistance. Chaque comportement est accompagne de son impact operationnel traduit pour un non-technicien.",
  "analyse_comportementale_conclusion": "OBLIGATOIRE — 2 phrases de synthese specifiques : (1) ce que l'ensemble des comportements confirme sur la nature et l'intention du malware (cite le nom de famille si connu), (2) recommandation operationnelle cle pour l'equipe IT basee sur ce qui a ete observe.",


  "analyse_reseau_intro": "OBLIGATOIRE — 1 phrase specifique : mentionne le nombre exact de connexions detectees et les destinations principales. Ex: 'Le malware a etabli 4 connexions vers des infrastructures exterieures localisees en Russie et aux Pays-Bas, suggerant un C2 actif.'",
  "analyse_reseau": "4 a 6 phrases. Liste exhaustive des connexions : chaque IP/domaine contacte avec son role presume. Integre les donnees de geolocalisation fournies dans le contexte (pays, FAI, ASN). Protocoles utilises et donnees potentiellement echangees.",
  "analyse_reseau_conclusion": "OBLIGATOIRE — 2 phrases specifiques : (1) synthese du risque reseau avec les IPs/domaines les plus dangereux nommes explicitement, (2) action SOC concrete et immediate (liste exacte des IPs a bloquer au firewall, requete proxy a executer).",


  "analyse_processus_intro": "OBLIGATOIRE — 1 phrase specifique : nomme les processus les plus suspects et le niveau de dangerosité. Ex: 'L'execution de WScript.exe puis PowerShell en tant qu'enfant d'EXCEL.EXE confirme une macro malveillante de niveau critique.'",
  "analyse_processus": "4 a 5 phrases. Pour chaque processus lance : nom exact, role legitime Windows, pourquoi son detournement est dangereux, actions executees (injection memoire, execution de code, contournement AV), impact sur le systeme.",
  "analyse_processus_conclusion": "OBLIGATOIRE — 2 phrases specifiques : (1) decris l'arbre de processus parent->enfant observe et ce qu'il revele de la strategie d'attaque, (2) Event ID Windows concret a surveiller pour detecter cette meme technique.",


  "analyse_statique_intro": "OBLIGATOIRE — 1 phrase specifique : nomme le type de fichier exact et le premier indicateur de malveillance. Ex: 'Ce fichier JavaScript obfusque de 45 Ko presente un ratio d'entropie de 7.8 caracteristique d'un packer ou d'un contenu chiffre.'",
  "analyse_statique": "3 a 4 phrases. Type de fichier et structure, presence d'obfuscation ou packing, langages de script detectes, indicateurs d'origine, niveau de sophistication.",
  "analyse_statique_conclusion": "OBLIGATOIRE — 2 phrases specifiques : (1) niveau de sophistication et ce que la structure revele sur les capacites techniques de l'attaquant, (2) ce que cela implique pour la detection par les outils de securite actuels.",


  "configs_malware": "Si des configurations sont extraites : serveurs C2 avec protocole et port, cles de chiffrement, identifiants de bot/campagne, chemins d'installation. Sinon : Donnees insuffisantes pour cette section.",

  "techniques_mitre": [
    {
      "id": "T1059.007",
      "nom": "Nom complet MITRE de la technique",
      "tactique": "Execution|Persistence|Defense Evasion|Discovery|Lateral Movement|Exfiltration|C2",
      "observation": "4 phrases : (1) ce que cette technique permet concretement a l'attaquant ici (base sur les donnees sandbox et la description MITRE fournie en contexte), (2) pourquoi elle est dangereuse dans ce contexte, (3) comment la detecter (Event ID Windows concret), (4) mitigation cle.",
      "description_officielle": "Resume en 2 phrases la description MITRE officielle si disponible en contexte.",
      "source_url": "https://attack.mitre.org/techniques/TXXX/ (remplace TXXX par l'ID reel)",
      "criticite": "CHOISIS UNE SEULE VALEUR : CRITIQUE / ELEVE / MOYEN / FAIBLE"
    }
  ],

  "iocs_critiques": [
    {
      "type": "IP|Domaine|Hash-MD5|Hash-SHA256|Mutex|Fichier",
      "valeur": "valeur exacte issue des donnees sandbox",
      "contexte": "2 phrases : (1) role precis dans l'attaque, (2) action immediate recommandee pour l'equipe SOC (bloquer au firewall, rechercher dans EDR, etc.).",
      "risque": "CHOISIS UNE SEULE VALEUR : CRITIQUE / ELEVE / MOYEN / FAIBLE"
    }
  ],

  "attribution": {
    "famille_presumee": "Nom precis ou Inconnue",
    "confiance": "CHOISIS UNE SEULE VALEUR : ELEVE / MOYEN / FAIBLE",
    "indicateurs": [
      "Indice 1 : element technique specifique qui identifie cette famille (mutex unique, domaine C2 repertorie, signature de code caracteristique)",
      "Indice 2 si present"
    ],
    "autres_hypotheses": ["Famille alternative plausible si ambiguite"]
  },

  "posture_reponse": {
    "phase": "CONFINEMENT — la priorite est d'empecher la propagation avant toute eradication",
    "actions_immediat": [
      "Action 1 immediate (0-1h) : tres concrete avec qui fait quoi et comment",
      "Action 2 immediate : isolation reseau, blocage IOCs, preservation des preuves",
      "Action 3 si applicable"
    ],
    "actions_24h": [
      "Action 1 dans les 24h : investigation forensique, recherche de lateralisation",
      "Action 2 : eradication sur le(s) poste(s) infecte(s)",
      "Action 3 : renforcement des defenses identifiees comme insuffisantes"
    ],
    "actions_72h": [
      "Action 1 dans les 72h : recouvrement et remise en service apres validation",
      "Action 2 : lecons apprises et corrections structurelles"
    ],
    "notification": "Qui notifier selon la reglementation : DPO si donnees personnelles exposees (RGPD 72h), ANSSI si OIV/OSE, assurance cyber, direction generale, clients si applicable.",
    "critere_retour": "Conditions pour reprendre les operations normalement : poste nettoye ou remplace, IOCs bloques en perimetre, absence de detection sur les autres postes, mots de passe de service reinitialises."
  },

  "recommandations": [
    {
      "priorite": "CRITIQUE",
      "categorie": "CONFINEMENT",
      "action": "Isoler immediatement le poste du reseau",
      "detail": "4 a 5 phrases tres concretes : (1) qui execute (nom du role : technicien reseau, SOC L1), (2) comment proceder techniquement (deconnecter le cable, desactiver le Wi-Fi, bloquer le port switch en VLAN quarantaine), (3) ce que ca empeche (propagation, exfiltration en cours), (4) comment confirmer l'isolation (perte de connectivite sur le poste), (5) ce qui ne doit PAS etre fait (eteindre le poste = perte des preuves en RAM).",
      "deadline": "Immediat"
    },
    {
      "priorite": "CRITIQUE",
      "categorie": "BLOCAGE",
      "action": "Bloquer les IOCs au niveau perimetre",
      "detail": "Instructions pour l'equipe reseau : ajouter les IPs et domaines identifies aux listes de blocage pare-feu et proxy, activer la journalisation de toute tentative de connexion vers ces destinations, verifier si d'autres postes ont deja contacte ces memes destinations.",
      "deadline": "Immediat"
    },
    {
      "priorite": "CRITIQUE",
      "categorie": "INVESTIGATION",
      "action": "Determiner l'ampleur de l'infection",
      "detail": "Instructions pour le SOC : requeter l'EDR sur tous les postes pour les hashs et noms de fichiers malveillants, analyser les logs proxy/firewall pour identifier d'autres connexions vers les C2 connus, verifier les logs d'authentification Active Directory pour des connexions anormales post-infection.",
      "deadline": "24h"
    },
    {
      "priorite": "ELEVE",
      "categorie": "ERADICATION",
      "action": "Nettoyer ou reinstaller le(s) poste(s) infecte(s)",
      "detail": "Procedure : capturer une image forensique du disque avant nettoyage (preservation des preuves), proceder a la reinstallation complete du systeme d'exploitation (le nettoyage seul est insuffisant pour ce type de menace), restaurer les donnees utilisateur depuis une sauvegarde anterieure a la date d'infection presumee, valider la proprete avant reconnexion au reseau.",
      "deadline": "72h"
    }
  ],

  "indicateurs_compromission": "Liste precise et exhaustive : adresses IP et domaines a bloquer au pare-feu/proxy, noms de fichiers suspects avec leurs chemins complets, cles de registre creees ou modifiees (HKLM/HKCU Run, services, etc.), noms de processus anormaux, hashs MD5/SHA256 a ajouter aux listes noires EDR/antivirus. Event IDs Windows specifiques a surveiller (4688 creation processus, 7045 service installe, 4625 echec auth, etc.).",

  "niveau_confiance": "CHOISIS UNE SEULE VALEUR : ELEVE / MOYEN / FAIBLE",
    "qualite_analyse": "UNIQUEMENT si meta_qualite.analyse_incomplete=true : expliquer clairement l'insuffisance des données (ex: analyse statique uniquement, fichier non-PE ou extension trompeuse). Recommander de resoumettre en renommant le fichier .exe. Si données comportementales présentes : omettre.",

  "conclusion": "4 a 5 phrases de synthese executive : (1) verdict definitif sur la nature et la gravite reelle de la menace, (2) etat actuel de la compromission et risque de propagation, (3) les deux actions les plus urgentes dans l'heure qui vient, (4) consequences concretes et chiffrees si aucune action dans les 24h (paralysie, vol de donnees, violation RGPD, etc.), (5) message au COMEX : ce que cet incident revele sur la posture de securite et ce qu'il faut corriger a long terme."
}`

	return fmt.Sprintf(`Tu es un analyste senior CERT/CSIRT qui redige un rapport forensique d'incident pour le management.
Tes lecteurs sont le RSSI, le DSI, le PDG et le Conseil d'Administration — ils ont besoin de comprendre la menace, pas juste de voir des donnees techniques.

RÈGLE ABSOLUE — INTÉGRITÉ DES DONNÉES :
  1. N'invente JAMAIS un comportement, IOC, domaine, IP, fichier ou technique non présent dans les données fournies.
  2. Si les données sandbox sont vides (0 signatures, 0 processus, 0 domaines) : indique-le EXPLICITEMENT dans qualite_analyse et ne génère PAS de timeline comportementale inventée.
  3. La timeline ne doit contenir que des phases "detecte": true basées sur des faits réels observés en sandbox.
  4. Si une section n'a pas de données, écris "Non observé en sandbox — données insuffisantes."
  5. Consulte le champ meta_qualite.analyse_incomplete : si true, adapter le niveau de certitude de l'ensemble du rapport.

MISSION : Analyser les donnees sandbox ci-dessous et produire un rapport qui repond aux 5 questions que pose TOUJOURS le management face a un incident :
  1. "Est-ce vraiment une attaque ou une fausse alerte ?" -> champ pourquoi_malveillant
  2. "Qu'est-ce qui s'est passe exactement et dans quel ordre ?" -> champ timeline_attaque
  3. "Est-ce que ca s'est propage a d'autres machines ?" -> champ risque_lateralisation
  4. "Quelles sont nos donnees en danger ?" -> champ donnees_exposees
  5. "Que fait-on maintenant, dans quelle ordre, et qui le fait ?" -> champs posture_reponse et recommandations

INSTRUCTIONS POUR LES FICHIERS DEPOSES (fichiers_deposes_malware) :
Si le champ "fichiers_deposes_malware" est present dans les donnees :
- Ces fichiers ont ete tele-charges ou crees par le malware pendant l'execution en sandbox RF.
- Analyse leur nom, extension, hash et contenu (si texte) pour enrichir l'analyse.
- Integre ces payloads dans la timeline_attaque (quelle etape de l'attaque les a crees).
- Mentionne les hashs de ces fichiers dans iocs_critiques (type "Hash-SHA256" ou "Fichier").
- Si un fichier .txt ou .bat contient du contenu : analyse et cite les commandes ou URL presentes.
- Si des executables (exe/dll) sont presents : note leur role presume dans la chaine d'infection.

REGLES ABSOLUES :
1. CITE les elements exacts des donnees sandbox (noms de processus, IPs, domaines, hashs) — ne generalise pas.
2. TRADUIS chaque terme technique en impact business :
   - "WScript.exe" => "le moteur de scripts Windows a ete detourne pour executer du code malveillant"
   - "connexion TLS vers IP tierce" => "communication chiffree avec un serveur controle par les attaquants"
   - "tag: rat" => "acces distant complet : lattaquant peut voir l'ecran, lire les fichiers, activer la webcam"
   - "signatures: trojan.dropper" => "le fichier installe d'autres logiciels malveillants en arriere-plan"
   - "tags: spygate" => "famille SpyGateRAT : specialisee dans la surveillance et le vol d'informations"
3. SOIS PRECIS sur le niveau de certitude : distingue ce qui est confirme (observe en sandbox) vs probable (comportement typique de cette famille).
4. NE FABRIQUE PAS d'informations : si une donnee n'est pas dans le JSON, ecris "Non determine a partir des donnees disponibles."
5. REPONDS UNIQUEMENT avec du JSON valide. Zero texte avant ou apres. Zero balise markdown.
6. INTRO ET CONCLUSION OBLIGATOIRES : les champs *_intro et *_conclusion sont OBLIGATOIRES dans chaque section. Ils doivent etre SPECIFIQUES aux donnees analysees — jamais generiques. Chaque intro nomme un element concret (processus, IP, fichier). Chaque conclusion donne une action concrete basee sur ce qui a ete observe. Un champ intro ou conclusion vide ou generique ("Cette section presente...") est une ERR
7. TECHNIQUE LOLBIN/LOLBAS : Si tu vois des connexions vers *.sharepoint.com, *.onedrive.com, *.microsoft.com, graph.microsoft.com ou login.microsoftonline.com dans les IOCs ou flows reseau, c'est le signe d'un C2 via infrastructure legitime (LOLBin). Indique explicitement : "Canal C2 via infrastructure Microsoft legitime (technique LOLBin/LOLBAS) — non bloquable directement, surveiller le domaine SNI dans les logs proxy."
8. DLL SIDELOADING : Si NVIDIA.exe, libcef.dll, ou tout exe+dll dans Users\Public sont presents dans les fichiers deposes, identifie T1574.002 (DLL Side-Loading) et explique : "Binaire NVIDIA legitime utilise comme vecteur pour executer une DLL malveillante libcef.dll via DLL sideloading."
9. PERSISTANCE SCHTASKS : Si schtasks ou une tache planifiee est mentionnee dans les events kernel ou les cmdlines, identifie T1053.005 (Scheduled Task) et decris la persistance.
10. EXFILTRATION FTP/CURL : Si curl.exe ou ftp.exe sont dans les cmdlines avec des arguments vers des URLs externes ou des fichiers .txt (r.txt, 11.txt), identifie T1041 (Exfiltration Over C2 Channel) et T1082 (System Information Discovery via ipinfo.io).EUR.

DONNEES D'ANALYSE SANDBOX :
%s%s

REMPLIS CE JSON avec l'analyse reelle (remplace les descriptions par le contenu) :
%s`, string(dataJSON), extraContext, schema)
}

// sanitizeForensicReport nettoie les champs où l'IA a retourné le template
// au lieu d'une vraie valeur. Typique de Mistral 7B sur les champs enum :
// l'IA copie "CRITIQUE|ELEVE|MOYEN|FAIBLE|BENIN" au lieu de choisir une valeur.
// On infère la valeur correcte depuis le score ou les autres champs.
func sanitizeForensicReport(r *ForensicReport) {
	validLevels := map[string]bool{
		"CRITIQUE": true, "ELEVE": true, "MOYEN": true, "FAIBLE": true, "BENIN": true,
		"ÉLEVÉ": true, "ÉLEVÉE": true,
	}
	validConfidence := map[string]bool{
		"ELEVE": true, "MOYEN": true, "FAIBLE": true,
		"ÉLEVÉ": true, "ÉLEVÉE": true,
	}

	// ── Classification principale ─────────────────────────────────────────
	// Si l'IA a retourné le template (contient "|") ou une valeur invalide,
	// on infère depuis le score_global.
	if strings.Contains(r.Classification, "|") || !validLevels[strings.ToUpper(r.Classification)] {
		switch {
		case r.ScoreGlobal >= 8:
			r.Classification = "CRITIQUE"
		case r.ScoreGlobal >= 6:
			r.Classification = "ELEVE"
		case r.ScoreGlobal >= 4:
			r.Classification = "MOYEN"
		case r.ScoreGlobal >= 2:
			r.Classification = "FAIBLE"
		default:
			r.Classification = "MOYEN"
		}
	}
	r.Classification = strings.ToUpper(r.Classification)

	// ── Niveau de confiance global ────────────────────────────────────────
	if strings.Contains(r.NiveauConfiance, "|") || !validConfidence[strings.ToUpper(r.NiveauConfiance)] {
		r.NiveauConfiance = "MOYEN"
	}

	// ── Risque de latéralisation ──────────────────────────────────────────
	if strings.Contains(r.RisqueLateralisation.Niveau, "|") ||
		!validLevels[strings.ToUpper(r.RisqueLateralisation.Niveau)] {
		r.RisqueLateralisation.Niveau = r.Classification
	}

	// ── Priorité des recommandations ─────────────────────────────────────
	for i, rec := range r.Recommandations {
		crit := strings.ToUpper(rec.Priorite)
		if strings.Contains(crit, "|") || !validLevels[crit] {
			r.Recommandations[i].Priorite = r.Classification
		}
	}

	// ── Risque des IOCs ───────────────────────────────────────────────────
	for i, ioc := range r.IOCsCritiques {
		risk := strings.ToUpper(ioc.Risque)
		if strings.Contains(risk, "|") || !validLevels[risk] {
			r.IOCsCritiques[i].Risque = "CRITIQUE"
		}
	}

	// ── Données exposées ──────────────────────────────────────────────────
	for i, d := range r.DonneesExposees {
		risk := strings.ToUpper(d.Risque)
		if strings.Contains(risk, "|") || !validLevels[risk] {
			r.DonneesExposees[i].Risque = "ELEVE"
		}
	}

	// ── État de compromission ─────────────────────────────────────────────
	// Nettoyage si l'IA a laissé le template
	validEtats := map[string]bool{"CONFIRME": true, "PROBABLE": true, "SUSPECTE": true}
	etatUpper := strings.ToUpper(strings.Split(r.EtatCompromission, " ")[0])
	if strings.Contains(r.EtatCompromission, "|") || (!validEtats[etatUpper] && r.EtatCompromission != "") {
		if r.ScoreGlobal >= 7 {
			r.EtatCompromission = "CONFIRME — comportements malveillants actifs détectés en sandbox."
		} else {
			r.EtatCompromission = "PROBABLE — indicateurs suspects détectés, analyse approfondie recommandée."
		}
	}

	// ── Textes template non substitués ────────────────────────────────────
	// Remplacer les phrases génériques copiées du schéma par une valeur neutre.
	templatePhrases := []string{
		"Vecteur 1 :", "Vecteur 2 si applicable",
		"Signe 1 observe", "Signe 2 si present",
		"Indice 2 si présent", "Famille alternative plausible si ambiguité",
		"Type de systeme prioritairement vise",
		"Donnees sensibles accessibles depuis le poste infecte",
	}
	cleanTemplateSlice := func(s []string) []string {
		out := s[:0]
		for _, v := range s {
			isTemplate := false
			for _, tmpl := range templatePhrases {
				if strings.HasPrefix(v, tmpl) {
					isTemplate = true
					break
				}
			}
			if !isTemplate && strings.TrimSpace(v) != "" {
				out = append(out, v)
			}
		}
		return out
	}
	r.RisqueLateralisation.Vecteurs = cleanTemplateSlice(r.RisqueLateralisation.Vecteurs)
	r.RisqueLateralisation.SystemesCibles = cleanTemplateSlice(r.RisqueLateralisation.SystemesCibles)
	r.RisqueLateralisation.SignesDetectes = cleanTemplateSlice(r.RisqueLateralisation.SignesDetectes)
	r.Attribution.Indicateurs = cleanTemplateSlice(r.Attribution.Indicateurs)
}

// DataBudget définit les limites adaptatives selon la richesse des données RF sandbox.
// Un fichier .exe bien exécuté retourne 400 events, 20+ procs, 18 IPs — budget élevé.
// Un fichier .cer statique retourne 0 events, 0 procs — budget standard.
type DataBudget struct {
	MaxSigs    int // max signatures à inclure
	MaxFlows   int // max flux réseau
	MaxProcs   int // max processus
	MaxKernel  int // max kernel events
	MaxDropped int // max dropped files
	MaxURLs    int // max URLs
}

// getRichnessBudget calcule le budget données selon la richesse de l'analyse sandbox.
func getRichnessBudget(results []*models.AnalysisResult) DataBudget {
	var totalSigs, totalDomains, totalProcs, totalKernel int
	for _, r := range results {
		totalSigs += len(r.Signatures)
		totalDomains += len(r.IOCs.Domains) + len(r.IOCs.IPs)
		totalProcs += len(r.Processes)
		totalKernel += len(r.KernelEvents)
	}
	// MaxKernel = 0 signifie AUCUNE LIMITE — tous les events sont passés au modèle.
	// 400 events × ~123 chars/event ≈ 49 Ko — rentre dans le contexte 32k tokens (114 Ko).
	// Supprimer des events kernel = rapport incomplet : NVIDIA.exe, libcef.dll,
	// schtasks, curl, FTP peuvent être dans les events 50-400 et sont critiques.
	switch {
	case totalSigs >= 10 || totalDomains >= 10 || totalKernel >= 200:
		// Analyse riche
		return DataBudget{MaxSigs: 20, MaxFlows: 30, MaxProcs: 30, MaxKernel: 0, MaxDropped: 12, MaxURLs: 25}
	case totalSigs >= 3 || totalDomains >= 4 || totalKernel >= 50:
		// Analyse moyenne
		return DataBudget{MaxSigs: 15, MaxFlows: 25, MaxProcs: 25, MaxKernel: 0, MaxDropped: 10, MaxURLs: 20}
	default:
		// Analyse pauvre ou statique uniquement
		return DataBudget{MaxSigs: 10, MaxFlows: 20, MaxProcs: 20, MaxKernel: 0, MaxDropped: 8, MaxURLs: 15}
	}
}

func buildCondensedData(results []*models.AnalysisResult) map[string]interface{} {
	budget := getRichnessBudget(results) // limites adaptatives selon richesse données RF
	data := map[string]interface{}{
		"nb_echantillons": len(results),
		"echantillons":    make([]interface{}, 0, len(results)),
	}

	for _, r := range results {
		sample := map[string]interface{}{
			"fichier": r.Filename,
			"score":   r.Score,
			"statut":  r.Status,
		}

		if r.Family != "" {
			sample["famille_malware"] = r.Family
		}
		if len(r.Tags) > 0 {
			sample["tags"] = uniqueStrings(r.Tags)
		}
		// Hashes complets (md5 + sha1 + sha256) — IOCs réels pour EDR/SIEM
		if r.Hashes.MD5 != "" {
			sample["md5"] = r.Hashes.MD5
		}
		if r.Hashes.SHA1 != "" {
			sample["sha1"] = r.Hashes.SHA1
		}
		if r.Hashes.SHA256 != "" {
			sample["sha256"] = r.Hashes.SHA256
		}

		// ── Signatures avec indicateurs factuels ─────────────────────────
		// On expose désormais les Indicators[] de chaque signature : ce sont les
		// preuves concrètes (IOC exact, horodatage, PID source/cible, fichier dumpé)
		// qui permettent à l'IA de produire une timeline précise et des IOCs réels.
		if len(r.Signatures) > 0 {
			sigs := make([]map[string]interface{}, 0, 10)
			for _, sig := range r.Signatures {
				if len(sigs) >= budget.MaxSigs {
					break
				}
				if sig.Score == 0 {
					continue
				}
				s := map[string]interface{}{
					"nom":   sig.Name,
					"score": sig.Score,
				}
				if len(sig.TTP) > 0 {
					s["ttp"] = sig.TTP
				}
				if sig.Desc != "" {
					s["description"] = sig.Desc
				}
				// Indicateurs factuels : IOC exact + timestamp + PIDs
				// Limité à 5 indicateurs par signature pour ne pas saturer le contexte
				if len(sig.Indicators) > 0 {
					indicators := make([]map[string]interface{}, 0, 5)
					for i, ind := range sig.Indicators {
						if i >= 5 {
							break
						}
						indEntry := map[string]interface{}{}
						if ind.IOC != "" {
							indEntry["ioc"] = ind.IOC
						}
						if ind.Description != "" {
							indEntry["description"] = ind.Description
						}
						if ind.At > 0 {
							indEntry["t_ms"] = ind.At // timestamp en ms depuis le début de l'analyse
						}
						if ind.DumpFile != "" {
							indEntry["fichier_dump"] = ind.DumpFile
						}
						if len(indEntry) > 0 {
							indicators = append(indicators, indEntry)
						}
					}
					if len(indicators) > 0 {
						s["indicateurs"] = indicators
					}
				}
				sigs = append(sigs, s)
			}
			if len(sigs) > 0 {
				sample["signatures"] = sigs
			}
		}

		// ── IOCs complets : IPs, domaines, URLs, hashes ───────────────────
		if hasIOCs(r.IOCs) {
			iocs := map[string]interface{}{}
			if len(r.IOCs.IPs) > 0 {
				iocs["ips"] = r.IOCs.IPs
			}
			if len(r.IOCs.Domains) > 0 {
				iocs["domaines"] = r.IOCs.Domains
			}
			// URLs : limitées à 15 pour ne pas exploser le contexte (curl, ftp, C2, etc.)
			if len(r.IOCs.URLs) > 0 {
				urls := r.IOCs.URLs
				if len(urls) > budget.MaxURLs {
					urls = urls[:budget.MaxURLs]
				}
				iocs["urls"] = urls
			}
			if len(r.IOCs.Mutexes) > 0 {
				iocs["mutexes"] = r.IOCs.Mutexes
			}
			// Hashes des fichiers malveillants identifiés (MD5/SHA256)
			if len(r.IOCs.Hashes) > 0 {
				iocs["hashes"] = r.IOCs.Hashes
			}
			// Infra légitime utilisée comme C2 (SharePoint, OneDrive, Azure...)
			// Mention explicite pour l'IA : ces IPs ne doivent PAS être bloquées
			// mais les DOMAINES associés (SNI) sont les vrais IOCs réseau
			if len(r.IOCs.LegitInfraIPs) > 0 {
				iocs["infra_legit_utilisee_c2"] = r.IOCs.LegitInfraIPs
			}
			sample["iocs"] = iocs
		}

		// ── Configurations malware extraites (C2, clés, botnet…) ─────────
		if len(r.Extracted) > 0 {
			configs := buildExtractedData(r.Extracted)
			if len(configs) > 0 {
				sample["configs_extraites"] = configs
			}
		}

		// ── Fichiers déposés par le malware ───────────────────────────────
		// Inclut maintenant SHA1 + SHA256 complets pour les IOCs réels.
		// Pour les fichiers texte ≤ 8Ko : contenu inclus (sortie curl/ftp, commandes).
		if len(r.DroppedFiles) > 0 {
			dropped := make([]map[string]interface{}, 0, len(r.DroppedFiles))
			for _, df := range r.DroppedFiles {
				entry := map[string]interface{}{
					"nom":    df.Name,
					"tache":  df.TaskID,
					"kind":   df.Kind,
					"taille": df.Size,
				}
				if df.MD5 != "" {
					entry["md5"] = df.MD5
				}
				if df.SHA1 != "" {
					entry["sha1"] = df.SHA1
				}
				if df.SHA256 != "" {
					entry["sha256"] = df.SHA256
				}
				// Contenu des fichiers texte ≤ 8Ko (ex: 11.txt avec sortie ipinfo.io,
				// r.txt avec commandes ftp, scripts .bat/.ps1 déposés par le malware)
				if len(df.Content) > 0 && len(df.Content) <= 8192 {
					ext := strings.ToLower(filepath.Ext(df.Name))
					if ext == ".txt" || ext == ".bat" || ext == ".ps1" || ext == ".vbs" ||
						ext == ".js" || ext == ".sh" || ext == ".hta" || ext == ".wsf" ||
						ext == ".jse" || ext == ".cmd" {
						entry["contenu"] = string(df.Content)
					}
				}
				dropped = append(dropped, entry)
			}
			if len(dropped) > 0 {
				sample["fichiers_deposes_malware"] = dropped
			}
		}

		// ── Arbre de processus avec commandes et timestamps ───────────────
		// AVANT : seulement les noms binaires (liste de strings)
		// MAINTENANT : arbre parent→enfant avec cmdline complète + horodatage
		// Ceci permet à l'IA de reconstruire une timeline précise et d'identifier
		// les arguments curl/ftp/powershell contenant des URLs C2.
		if len(r.Processes) > 0 {
			procs := make([]map[string]interface{}, 0, 20)
			for _, p := range r.Processes {
				if len(procs) >= budget.MaxProcs {
					break
				}
				if p.Image == "" {
					continue
				}
				// Extraire le nom du binaire depuis le chemin complet
				parts := strings.Split(strings.ReplaceAll(p.Image, "\\", "/"), "/")
				binName := parts[len(parts)-1]

				proc := map[string]interface{}{
					"binaire":   binName,
					"image":     p.Image,
					"pid":       p.PID,
					"ppid":      p.PPID,
					"procid":    p.ProcID,
					"parent_id": p.ParentProcID,
					"original":  p.Orig, // true = processus soumis directement
				}
				// Timestamp de démarrage en ms (depuis début de l'analyse sandbox)
				if p.Started > 0 {
					proc["demarrage_ms"] = p.Started
				}
				if p.Terminated > 0 {
					proc["fin_ms"] = p.Terminated
				}
				// Cmdline complète — contient les arguments curl, ftp, powershell, etc.
				if p.Cmd != nil {
					switch v := p.Cmd.(type) {
					case string:
						if v != "" {
							proc["cmdline"] = v
						}
					case []interface{}:
						parts := make([]string, 0, len(v))
						for _, c := range v {
							if s, ok := c.(string); ok && s != "" {
								parts = append(parts, s)
							}
						}
						if len(parts) > 0 {
							proc["cmdline"] = strings.Join(parts, " ")
						}
					}
				}
				procs = append(procs, proc)
			}
			if len(procs) > 0 {
				sample["arbre_processus"] = procs
			}
		}

		// ── Réseau enrichi avec géolocalisation native RF ─────────────────
		// AVANT : seulement protocoles + SNI/JA3 des connexions chiffrées
		// MAINTENANT : tous les flows avec pays/ASN/org depuis les champs RF natifs
		// (NetworkFlow.Country, .AS, .Org) + volume de données échangées
		// + requêtes HTTP/DNS détaillées pour identifier les URLs C2 exactes.
		netSummary := buildNetworkSummary(r)
		if len(netSummary) > 0 {
			sample["reseau"] = netSummary
		}

		// ── Analyse statique ──────────────────────────────────────────────
		if r.Static != nil {
			staticSummary := map[string]interface{}{}
			if len(r.Static.Analysis.Tags) > 0 {
				staticSummary["tags"] = r.Static.Analysis.Tags
			}
			if len(r.Static.Signatures) > 0 {
				sigNames := make([]string, 0, 5)
				for i, s := range r.Static.Signatures {
					if i >= 5 {
						break
					}
					sigNames = append(sigNames, s.Name)
				}
				staticSummary["signatures"] = sigNames
			}
			if r.Static.UnpackCount > 0 {
				staticSummary["nb_fichiers_extraits"] = r.Static.UnpackCount
			}
			if len(staticSummary) > 0 {
				sample["analyse_statique"] = staticSummary
			}
		}

		// ── Événements kernel horodatés (onemon.json) ─────────────────────
		// Permet à l'IA de reconstruire une timeline précise comme HarfangLab :
		// création de fichiers, accès registre, connexions réseau avec timestamps.
		// Limité à 50 événements les plus significatifs pour ne pas saturer le contexte.
		if len(r.KernelEvents) > 0 {
			evs := r.KernelEvents
			// Tri chronologique pur (TimeMs croissant) — tous les events étant passés,
			// la timeline complète est plus importante que la priorité par type.
			// L'IA voit les actions dans l'ordre réel d'exécution.
			sortedEvs := make([]models.KernelEvent, len(evs))
			copy(sortedEvs, evs)
			for i := 0; i < len(sortedEvs)-1; i++ {
				for j := i + 1; j < len(sortedEvs); j++ {
					if sortedEvs[j].TimeMs < sortedEvs[i].TimeMs {
						sortedEvs[i], sortedEvs[j] = sortedEvs[j], sortedEvs[i]
					}
				}
			}
			evs = sortedEvs
			// MaxKernel = 0 → aucune limite : tous les events sont passés au modèle
			// Supprimer des events = risque de manquer NVIDIA.exe, libcef.dll, schtasks, curl
			if budget.MaxKernel > 0 && len(evs) > budget.MaxKernel {
				evs = evs[:budget.MaxKernel]
			}
			kernelList := make([]map[string]interface{}, 0, len(evs))
			for _, ev := range evs {
				entry := map[string]interface{}{}
				if ev.TimeMs > 0 {
					entry["t_ms"] = ev.TimeMs
				}
				if ev.Image != "" {
					entry["processus"] = ev.Image
				}
				if ev.Action != "" {
					entry["action"] = ev.Action
				}
				if ev.Target != "" {
					entry["cible"] = ev.Target
				}
				if ev.Details != "" {
					entry["detail"] = ev.Details
				}
				if len(entry) > 0 {
					kernelList = append(kernelList, entry)
				}
			}
			if len(kernelList) > 0 {
				sample["evenements_kernel"] = kernelList
			}
		}

		data["echantillons"] = append(data["echantillons"].([]interface{}), sample)
	}

	// ── Méta-qualité de l'analyse ────────────────────────────────────
	// Indique au modèle si les données sont suffisantes pour des conclusions fiables.
	// Permet de prévenir les hallucinations sur analyses avec données pauvres.
	nbSigs := 0
	nbDomains := 0
	nbProcesses := 0
	nbKernelEvents := 0
	for _, r := range results {
		nbSigs += len(r.Signatures)
		nbDomains += len(r.IOCs.Domains)
		nbProcesses += len(r.Processes)
		nbKernelEvents += len(r.KernelEvents)
	}

	analyseIncomplete := nbSigs == 0 && nbDomains == 0 && nbProcesses == 0
	data["meta_qualite"] = map[string]interface{}{
		"nb_signatures":        nbSigs,
		"nb_domaines_iocs":     nbDomains,
		"nb_processus":         nbProcesses,
		"nb_evenements_kernel": nbKernelEvents,
		"analyse_incomplete":   analyseIncomplete,
		"avertissement": func() string {
			if analyseIncomplete {
				return "DONNÉES INSUFFISANTES — 0 signatures comportementales, 0 domaines, 0 processus. " +
					"Le fichier n'a probablement pas été exécuté en sandbox (extension trompeuse, fichier non-PE, " +
					"ou sandbox non compatible). NE PAS inférer de comportements non observés. " +
					"Baser toutes les conclusions uniquement sur les données statiques disponibles."
			}
			return "Données sandbox disponibles — baser les conclusions sur les faits observés."
		}(),
	}

	// ── Budget token adaptatif ──────────────────────────────────────────────
	// Si les données dépassent ~18k chars JSON, réduire les sections secondaires.
	// Objectif : maintenir le prompt final sous ~24k chars pour Foundation-Sec-8B.
	if rawSize, err := json.Marshal(data); err == nil && len(rawSize) > 18000 {
		for _, echo := range data["echantillons"].([]interface{}) {
			if m, ok := echo.(map[string]interface{}); ok {
				// KernelEvents : NE PAS tronquer — tous les events sont nécessaires
				// pour reconstruire la timeline complète (NVIDIA.exe, libcef.dll, schtasks, curl)
				// Réduire URLs à 8
				if iocs, ok2 := m["iocs"].(map[string]interface{}); ok2 {
					if urls, ok3 := iocs["urls"].([]string); ok3 && len(urls) > 8 {
						iocs["urls"] = urls[:8]
					}
				}
				// Réduire processus à 10
				if procs, ok2 := m["arbre_processus"].([]map[string]interface{}); ok2 && len(procs) > 10 {
					m["arbre_processus"] = procs[:10]
				}
			}
		}
	}
	return data
}

// buildNetworkSummary construit un résumé réseau enrichi.
// Exploite les champs natifs RF Sandbox : Country, AS, Org (géolocalisation intégrée),
// RxBytes/TxBytes (volume exfiltré), Domain, SNI, JA3, et les requêtes HTTP/DNS complètes.
func buildNetworkSummary(r *models.AnalysisResult) map[string]interface{} {
	net := map[string]interface{}{}

	// ── Protocoles utilisés ───────────────────────────────────────────────
	protoCount := map[string]int{}
	for _, nr := range r.Network {
		for _, f := range nr.Flows {
			for _, p := range f.Protocols {
				protoCount[p]++
			}
		}
	}
	if len(protoCount) > 0 {
		protos := make([]string, 0, len(protoCount))
		for p := range protoCount {
			protos = append(protos, p)
		}
		net["protocoles"] = protos
	}

	// ── Flows réseau enrichis ─────────────────────────────────────────────
	// Inclut géolocalisation native (Country/AS/Org), volume de données,
	// et JA3/SNI pour les connexions TLS. Max 20 flows.
	// Tous les flows réseau — pas de limite pour capturer tous les domaines C2
	allFlows := make([]map[string]interface{}, 0, 50)
	for _, nr := range r.Network {
		for _, f := range nr.Flows {
			if len(allFlows) >= 50 { // 50 flows max pour éviter de saturer le contexte
				break
			}
			flow := map[string]interface{}{
				"dest":       f.Dest,
				"protocoles": f.Protocols,
			}
			if f.Domain != "" {
				flow["domaine"] = f.Domain
			}
			// Géolocalisation native RF — pas besoin d'ip-api.com
			if f.Country != "" {
				flow["pays"] = f.Country
			}
			if f.AS != "" {
				flow["asn"] = f.AS
			}
			if f.Org != "" {
				flow["organisation"] = f.Org
			}
			// Volume de données échangées — indicateur d'exfiltration
			if f.TxBytes > 0 {
				flow["octets_envoyes"] = f.TxBytes
			}
			if f.RxBytes > 0 {
				flow["octets_recus"] = f.RxBytes
			}
			// Horodatage relatif (ms depuis début de l'analyse)
			if f.FirstSeen > 0 {
				flow["premier_contact_ms"] = f.FirstSeen
			}
			// TLS : JA3 fingerprint + SNI (identifie le client malware + serveur ciblé)
			if f.JA3 != "" {
				flow["ja3"] = f.JA3
			}
			if f.SNI != "" {
				flow["sni"] = f.SNI
			}
			allFlows = append(allFlows, flow)
		}
	}
	if len(allFlows) > 0 {
		net["flows"] = allFlows
	}

	// ── Requêtes HTTP détaillées (méthode + URL complète) ─────────────────
	// Contient les URLs exactes contactées par curl, powershell, etc.
	// Limité à 15 requêtes pour ne pas saturer le contexte IA.
	httpReqs := make([]map[string]interface{}, 0, 15)
	for _, nr := range r.Network {
		for _, req := range nr.Requests {
			if len(httpReqs) >= 15 {
				break
			}
			if req.WebReq != nil && req.WebReq.URL != "" {
				entry := map[string]interface{}{
					"url":    req.WebReq.URL,
					"method": req.WebReq.Method,
				}
				if req.At > 0 {
					entry["t_ms"] = req.At
				}
				httpReqs = append(httpReqs, entry)
			}
		}
	}
	if len(httpReqs) > 0 {
		net["requetes_http"] = httpReqs
	}

	// ── Résolutions DNS (domaine → IPs résolues) ─────────────────────────
	// Révèle l'infrastructure C2 réelle derrière les domaines
	dnsResolutions := make([]map[string]interface{}, 0, 10)
	for _, nr := range r.Network {
		for _, req := range nr.Requests {
			if len(dnsResolutions) >= 10 {
				break
			}
			if req.DomainReq != nil && req.DomainResp != nil {
				domains := req.DomainReq.Domains
				if len(domains) == 0 {
					for _, q := range req.DomainReq.Questions {
						if q.Name != "" {
							domains = append(domains, q.Name)
						}
					}
				}
				if len(domains) > 0 && len(req.DomainResp.IP) > 0 {
					dnsResolutions = append(dnsResolutions, map[string]interface{}{
						"domaine": strings.Join(domains, ", "),
						"ips":     req.DomainResp.IP,
					})
				}
			}
		}
	}
	if len(dnsResolutions) > 0 {
		net["resolutions_dns"] = dnsResolutions
	}

	return net
}

// uniqueStrings déduplique une liste de chaînes.
func uniqueStrings(s []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(s))
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func buildExtractedData(extracted []models.ExtractWithTask) []map[string]interface{} {
	var configs []map[string]interface{}
	for _, ex := range extracted {
		if ex.Config == nil {
			continue
		}
		cfg := map[string]interface{}{}
		if ex.Config.Family != "" {
			cfg["famille"] = ex.Config.Family
		}
		if len(ex.Config.C2) > 0 {
			cfg["c2"] = ex.Config.C2
		}
		if ex.Config.Botnet != "" {
			cfg["botnet_id"] = ex.Config.Botnet
		}
		if ex.Config.Version != "" {
			cfg["version"] = ex.Config.Version
		}
		if ex.Config.Campaign != "" {
			cfg["campagne"] = ex.Config.Campaign
		}
		if len(ex.Config.Mutex) > 0 {
			cfg["mutex"] = ex.Config.Mutex
		}
		if len(ex.Config.DNS) > 0 {
			cfg["dns_hardcodes"] = ex.Config.DNS
		}
		if len(ex.Config.Keys) > 0 {
			keys := make([]string, 0, len(ex.Config.Keys))
			for _, k := range ex.Config.Keys {
				keys = append(keys, fmt.Sprintf("%s:%s", k.Kind, k.Key))
			}
			cfg["cles_crypto"] = keys
		}
		if len(cfg) > 0 {
			configs = append(configs, cfg)
		}
	}
	return configs
}

// ─── Parsing de la réponse ────────────────────────────────────────────────────

// ParseForensicResponse extrait le JSON de la réponse IA (gère le markdown éventuel).
// Gère tous les formats de sortie de Mistral : JSON brut, blocs ```json```, texte parasite avant/après,
// cleanInvalidEscapes supprime les séquences d'échappement JSON invalides produites
// par certains LLMs (Mistral notamment) : \_ \. \: \! \- etc.
// En JSON, seuls \\ \" \/ \b \f \n \r \t \uXXXX sont valides.
func cleanInvalidEscapes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inStr := false
	i := 0
	for i < len(s) {
		ch := s[i]
		if ch == '"' && (i == 0 || s[i-1] != '\\') {
			inStr = !inStr
			b.WriteByte(ch)
			i++
			continue
		}
		if inStr && ch == '\\' && i+1 < len(s) {
			next := s[i+1]
			switch next {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				// Séquences valides — conserver
				b.WriteByte(ch)
				b.WriteByte(next)
				i += 2
			case 'u':
				// \uXXXX — conserver
				b.WriteByte(ch)
				b.WriteByte(next)
				i += 2
			default:
				// Séquence invalide (\_ \. \: \! etc.) — supprimer le backslash
				b.WriteByte(next)
				i += 2
			}
			continue
		}
		b.WriteByte(ch)
		i++
	}
	return b.String()
}

// ParseForensicResponse parse la réponse brute de l'IA en ForensicReport.
// et JSON tronqué (tente une réparation des accolades manquantes).
// normalizeJSONArrayFields corrige les champs qui devraient être des tableaux []
// mais que le modèle a retournés comme objets {}.
// Observé avec Qwen 2.5 14B pour timeline_attaque, techniques_mitre, etc.
func normalizeJSONArrayFields(raw string) string {
	arrayFields := []string{
		"timeline_attaque", "techniques_mitre", "iocs_critiques",
		"recommandations", "donnees_exposees", "ttps_confirmes", "iocs_nets",
		"comportements_cles", "vecteurs", "systemes_cibles", "signes_detectes",
		"actions_immediat", "actions_24h", "actions_72h",
	}
	for _, field := range arrayFields {
		marker := `"` + field + `": {`
		if !strings.Contains(raw, marker) {
			continue
		}
		idx := strings.Index(raw, marker)
		start := idx + len(`"`) + len(field) + len(`": `)
		depth, end := 0, start
		for end < len(raw) {
			if raw[end] == '{' {
				depth++
			} else if raw[end] == '}' {
				depth--
				if depth == 0 {
					end++
					break
				}
			}
			end++
		}
		if depth == 0 && end > start {
			objContent := raw[start:end]
			raw = strings.Replace(raw,
				`"`+field+`": `+objContent,
				`"`+field+`": [`+objContent+`]`, 1)
		}
	}
	return raw
}

// ParseExtractionResponse parse la réponse JSON partielle de M1 (extraction technique).
// Plus tolérant que ParseForensicResponse — le JSON partiel de M1 est moins strict.
func ParseExtractionResponse(raw string) (*TechExtraction, error) {
	// Même nettoyage que ParseForensicResponse
	// Nettoyer les escapes JSON invalides
	raw = strings.NewReplacer(`\_`, `_`, `\.`, `.`, `\:`, `:`).Replace(raw)
	raw = strings.TrimSpace(raw)

	// Extraire le premier objet JSON
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start < 0 || end <= start {
		return nil, fmt.Errorf("aucun objet JSON trouvé dans la réponse M1")
	}
	raw = raw[start : end+1]

	var extraction TechExtraction
	if err := json.Unmarshal([]byte(raw), &extraction); err != nil {
		return nil, fmt.Errorf("parsing extraction M1: %w", err)
	}

	// Valeurs par défaut si vides
	if extraction.Famille == "" {
		extraction.Famille = "Inconnue"
	}
	if extraction.Confiance == "" {
		extraction.Confiance = "FAIBLE"
	}
	if extraction.Propagation == "" {
		extraction.Propagation = "MOYEN"
	}
	return &extraction, nil
}

func ParseForensicResponse(raw string) (*ForensicReport, error) {
	// Mistral génère parfois des séquences d'échappement JSON invalides (\_ \. \: etc.)
	// On les nettoie avant tout parsing
	raw = cleanInvalidEscapes(raw)
	raw = normalizeJSONArrayFields(raw) // Corriger {} → [] (bug Qwen 2.5 14B)

	candidates := extractJSONCandidates(raw)
	var lastErr error
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		var report ForensicReport
		if err := json.Unmarshal([]byte(candidate), &report); err == nil {
			if report.Classification != "" {
				sanitizeForensicReport(&report)
				return &report, nil
			}
		} else {
			lastErr = err
		}
		// Tentative de réparation : fermer les accolades/crochets manquants
		if repaired := repairJSON(candidate); repaired != "" && repaired != candidate {
			var report2 ForensicReport
			if err := json.Unmarshal([]byte(repaired), &report2); err == nil {
				if report2.Classification != "" {
					sanitizeForensicReport(&report2)
					return &report2, nil
				}
			}
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("parsing JSON echoue: %w", lastErr)
	}
	return nil, fmt.Errorf("aucun JSON trouvé dans la réponse IA")
}

// extractJSONCandidates retourne une liste ordonnée de candidats JSON à essayer.
func extractJSONCandidates(raw string) []string {
	var results []string

	// 1. Blocs ```json ... ```
	s := raw
	for {
		idx := strings.Index(s, "```json")
		if idx < 0 {
			break
		}
		rest := s[idx+7:]
		end := strings.Index(rest, "```")
		if end < 0 {
			results = append(results, extractBalanced(rest))
			break
		}
		results = append(results, extractBalanced(rest[:end]))
		s = rest[end+3:]
	}

	// 2. Blocs ``` ... ``` génériques
	s = raw
	for {
		idx := strings.Index(s, "```")
		if idx < 0 {
			break
		}
		rest := s[idx+3:]
		// Sauter si c'est "```json" (déjà traité)
		if strings.HasPrefix(rest, "json") {
			s = rest
			continue
		}
		end := strings.Index(rest, "```")
		if end < 0 {
			results = append(results, extractBalanced(rest))
			break
		}
		candidate := extractBalanced(rest[:end])
		if strings.Contains(candidate, "{") {
			results = append(results, candidate)
		}
		s = rest[end+3:]
	}

	// 3. Premier objet JSON équilibré dans le texte brut
	if candidate := extractBalanced(raw); candidate != "" {
		results = append(results, candidate)
	}

	// 4. Fallback : entre première { et dernière }
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start >= 0 && end > start {
		results = append(results, raw[start:end+1])
	}

	return results
}

// extractBalanced extrait le premier objet JSON { ... } équilibré dans s.
func extractBalanced(s string) string {
	start := strings.Index(s, "{")
	if start < 0 {
		return ""
	}
	depth := 0
	inStr := false
	escape := false
	for i := start; i < len(s); i++ {
		ch := s[i]
		if escape {
			escape = false
			continue
		}
		if ch == '\\' && inStr {
			escape = true
			continue
		}
		if ch == '"' {
			inStr = !inStr
			continue
		}
		if inStr {
			continue
		}
		if ch == '{' {
			depth++
		} else if ch == '}' {
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

// repairJSON tente de fermer les accolades/crochets non fermés dans un JSON tronqué.
func repairJSON(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, " \t\r\n")

	// Supprimer une virgule trailing
	if strings.HasSuffix(s, ",") {
		s = s[:len(s)-1]
	}

	// Analyser caractère par caractère pour détecter l'état exact
	depth := 0
	arrDepth := 0
	inStr := false
	escape := false
	lastKeyEnd := -1 // position après la dernière clé JSON complète
	_ = lastKeyEnd

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escape {
			escape = false
			continue
		}
		if ch == '\\' && inStr {
			escape = true
			continue
		}
		if ch == '"' {
			inStr = !inStr
			continue
		}
		if inStr {
			continue
		}
		switch ch {
		case '{':
			depth++
		case '}':
			depth--
		case '[':
			arrDepth++
		case ']':
			arrDepth--
		}
	}

	// Si on est encore dans une string, la fermer proprement
	if inStr {
		s += "\""
	}

	// Supprimer une clé ou valeur incomplète en fin (ex: ,"recommandations": [)
	// En remontant jusqu'à un point de structure JSON valide
	s = strings.TrimRight(s, " \t\r\n,:")

	// Fermer les tableaux ouverts
	closing := ""
	for arrDepth > 0 {
		closing += "]"
		arrDepth--
	}
	// Fermer les objets ouverts
	for depth > 0 {
		closing += "}"
		depth--
	}
	return s + closing
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func hasIOCs(iocs models.IOCBundle) bool {
	return len(iocs.IPs) > 0 || len(iocs.Domains) > 0 ||
		len(iocs.URLs) > 0 || len(iocs.Mutexes) > 0
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
