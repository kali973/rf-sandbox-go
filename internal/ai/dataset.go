package ai

// dataset.go - Génération du dataset d'entraînement LoRA depuis analyses.db
//
// Convertit chaque entrée de la base SQLite en paire (instruction → réponse)
// au format Alpaca JSONL, utilisable directement par Unsloth pour fine-tuner
// Mistral 7B (ou tout modèle compatible HuggingFace).
//
// Format de sortie (une ligne JSON par exemple) :
//   {"instruction": "...", "input": "...", "output": "..."}
//
// L'instruction est fixe (rôle CERT/CSIRT FR), l'input est le contexte sandbox
// brut, l'output est le JSON ForensicReport tel qu'il a été validé et stocké.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ─── Structures dataset ───────────────────────────────────────────────────────

// TrainingExample est une paire d'entraînement au format Alpaca.
type TrainingExample struct {
	Instruction string `json:"instruction"`
	Input       string `json:"input"`
	Output      string `json:"output"`
}

// DatasetStats contient les métriques de génération du dataset.
type DatasetStats struct {
	Total      int
	Exported   int
	Skipped    int
	OutputPath string
	Duration   time.Duration
}

// ─── Instruction système fixe ─────────────────────────────────────────────────

// systemInstruction est l'instruction invariante pour tous les exemples.
// Elle définit le rôle, le vocabulaire attendu, et le format de sortie.
// C'est exactement cette instruction que le modèle doit apprendre à suivre.
const systemInstruction = `Tu es un analyste senior CERT/CSIRT francophone spécialisé en forensique malware.
Tu rédiges des rapports d'analyse de menaces destinés au management (RSSI, DSI, COMEX).

STYLE ET VOCABULAIRE ATTENDUS :
- Français technique CERT/CSIRT : "dropper", "payload", "C2", "TTPs", "latéralisation", "IOC", "persistence", "DLL sideloading", "RAT", "exfiltration"
- Traduction systématique des termes techniques en impact business
- Niveau de certitude explicite : distinguer "observé en sandbox" vs "comportement typique de la famille"
- Recommandations concrètes et actionnables avec délais précis

FORMAT DE RÉPONSE : JSON valide uniquement, sans texte avant ni après, sans balises markdown.`

// ─── Export principal ─────────────────────────────────────────────────────────

// ExportTrainingDataset exporte toutes les entrées de analyses.db
// vers un fichier JSONL prêt pour l'entraînement Unsloth/LoRA.
// outputPath : chemin du fichier .jsonl à créer (créé/écrasé)
// minScore   : score minimum pour inclure une entrée (qualité du dataset)
func ExportTrainingDataset(outputPath string, minScore int) (*DatasetStats, error) {
	start := time.Now()
	stats := &DatasetStats{OutputPath: outputPath}

	db, err := openDB()
	if err != nil {
		return nil, fmt.Errorf("openDB: %w", err)
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT id, date, filename, famille, classification, score,
		       ttps, ips, domaines, hashes, resume, recommandations, confiance,
		       COALESCE(mitre_details, '{}'), COALESCE(abuse_scores, '{}')
		FROM analyses
		WHERE score >= ?
		ORDER BY date DESC`, minScore)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	// Créer le dossier parent si nécessaire
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	for rows.Next() {
		stats.Total++

		var e KnowledgeEntry
		var tJ, iJ, dJ, hJ, rJ, mitreJ, abuseJ string
		if err := rows.Scan(
			&e.ID, &e.Date, &e.Filename, &e.FamillePresumee,
			&e.Classification, &e.ScoreGlobal,
			&tJ, &iJ, &dJ, &hJ, &e.ResumeExecutif, &rJ, &e.NiveauConfiance,
			&mitreJ, &abuseJ,
		); err != nil {
			stats.Skipped++
			continue
		}
		e.TTPs = unmarshalSlice(tJ)
		e.IPs = unmarshalSlice(iJ)
		e.Domaines = unmarshalSlice(dJ)
		e.Hashes = unmarshalSlice(hJ)
		e.Recommandations = unmarshalSlice(rJ)
		// Désérialiser les enrichissements MITRE + AbuseIPDB
		if mitreJ != "" && mitreJ != "{}" {
			json.Unmarshal([]byte(mitreJ), &e.MitreDetails)
		}
		if abuseJ != "" && abuseJ != "{}" {
			json.Unmarshal([]byte(abuseJ), &e.AbuseScores)
		}

		// Construire l'input (contexte sandbox brut que le modèle recevra)
		inputText := buildTrainingInput(e)

		// Construire l'output (réponse JSON parfaite que le modèle doit produire)
		outputJSON, err := buildTrainingOutput(e)
		if err != nil {
			stats.Skipped++
			continue
		}

		example := TrainingExample{
			Instruction: systemInstruction,
			Input:       inputText,
			Output:      outputJSON,
		}

		line, err := json.Marshal(example)
		if err != nil {
			stats.Skipped++
			continue
		}

		if _, err := fmt.Fprintf(f, "%s\n", line); err != nil {
			return nil, fmt.Errorf("write: %w", err)
		}
		stats.Exported++
	}

	stats.Duration = time.Since(start)
	return stats, rows.Err()
}

// ─── Construction de l'input ──────────────────────────────────────────────────

// buildTrainingInput construit le contexte sandbox brut (ce que le modèle reçoit).
// C'est intentionnellement minimal : on simule ce que le prompt réel enverrait
// pour une analyse similaire — TTPs, IOCs, famille connue.
// Le modèle apprend à partir de ce contexte réduit → produire le rapport complet.
func buildTrainingInput(e KnowledgeEntry) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("FICHIER ANALYSE : %s\n", e.Filename))
	sb.WriteString(fmt.Sprintf("SCORE SANDBOX   : %d/10\n", e.ScoreGlobal))

	if len(e.TTPs) > 0 {
		sb.WriteString(fmt.Sprintf("TTPS DETECTES   : %s\n", strings.Join(e.TTPs, ", ")))
	}
	if len(e.IPs) > 0 {
		max := 10
		if len(e.IPs) < max {
			max = len(e.IPs)
		}
		sb.WriteString(fmt.Sprintf("IPS CONTACTEES  : %s\n", strings.Join(e.IPs[:max], ", ")))
	}
	if len(e.Domaines) > 0 {
		sb.WriteString(fmt.Sprintf("DOMAINES C2     : %s\n", strings.Join(e.Domaines, ", ")))
	}
	if len(e.Hashes) > 0 {
		sb.WriteString(fmt.Sprintf("HASH SHA256     : %s\n", e.Hashes[0]))
	}
	if e.FamillePresumee != "" && e.FamillePresumee != "Inconnue" {
		sb.WriteString(fmt.Sprintf("FAMILLE CONNUE  : %s\n", e.FamillePresumee))
	}

	// ── Enrichissement MITRE ATT&CK (descriptions stockées depuis l'API) ────────
	if len(e.MitreDetails) > 0 {
		sb.WriteString("\nTECHNIQUES MITRE ATT&CK OBSERVEES :\n")
		for ttpID, detail := range e.MitreDetails {
			line := fmt.Sprintf("  [%s] %s", ttpID, detail.Nom)
			if detail.Tactique != "" {
				line += fmt.Sprintf(" | Tactique: %s", detail.Tactique)
			}
			if detail.Description != "" {
				desc := detail.Description
				if len(desc) > 200 {
					desc = desc[:200] + "..."
				}
				line += fmt.Sprintf(" | %s", desc)
			}
			if len(detail.Mitigations) > 0 {
				line += fmt.Sprintf(" | Mitigations: %s", strings.Join(detail.Mitigations[:minInt(2, len(detail.Mitigations))], "; "))
			}
			sb.WriteString(line + "\n")
		}
	}

	// ── Réputation AbuseIPDB (scores et catégories d'abus) ───────────────────────
	if len(e.AbuseScores) > 0 {
		maliciousCount := 0
		for _, rep := range e.AbuseScores {
			if rep.EstMalveillant {
				maliciousCount++
			}
		}
		sb.WriteString(fmt.Sprintf("\nREPUTATION IPs (AbuseIPDB) : %d IPs enrichies, %d confirmées malveillantes\n",
			len(e.AbuseScores), maliciousCount))
		for ip, rep := range e.AbuseScores {
			statut := "légitime"
			if rep.EstMalveillant {
				statut = fmt.Sprintf("MALVEILLANTE score=%d/100", rep.Score)
			}
			line := fmt.Sprintf("  %s : %s", ip, statut)
			if rep.Pays != "" {
				line += fmt.Sprintf(" | Pays=%s", rep.Pays)
			}
			if rep.ISP != "" {
				line += fmt.Sprintf(" | FAI=%s", rep.ISP)
			}
			if len(rep.Categories) > 0 {
				line += fmt.Sprintf(" | Types=%s", strings.Join(rep.Categories, ","))
			}
			sb.WriteString(line + "\n")
		}
	}

	return sb.String()
}

// min helper pour dataset.go (Go < 1.21 compat)
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─── Construction de l'output ─────────────────────────────────────────────────

// buildTrainingOutput construit le JSON ForensicReport de référence.
// C'est la "bonne réponse" que le modèle doit apprendre à produire.
// On reconstruit un ForensicReport partiel mais cohérent depuis les données stockées.
func buildTrainingOutput(e KnowledgeEntry) (string, error) {

	// Reconstruire les recommandations depuis le format "[PRIORITE] Action"
	var recs []Recommandation
	for _, r := range e.Recommandations {
		priorite := "ELEVE"
		action := r
		if strings.HasPrefix(r, "[") {
			end := strings.Index(r, "]")
			if end > 0 {
				priorite = strings.TrimPrefix(r[:end+1], "[")
				priorite = strings.TrimSuffix(priorite, "]")
				action = strings.TrimSpace(r[end+1:])
			}
		}
		if action != "" {
			recs = append(recs, Recommandation{
				Priorite:  priorite,
				Categorie: inferCategorie(action),
				Action:    action,
				Deadline:  inferDeadline(priorite),
			})
		}
	}

	// Reconstruire les IOCs critiques depuis les hashes
	var iocs []IOCEntry
	for _, h := range e.Hashes {
		if h != "" {
			iocs = append(iocs, IOCEntry{
				Type:     "Hash-SHA256",
				Valeur:   h,
				Contexte: fmt.Sprintf("Hash du fichier malveillant %s. À bloquer immédiatement dans l'EDR et l'antivirus.", e.Filename),
				Risque:   "CRITIQUE",
			})
		}
	}
	// IOCs réseau
	for i, ip := range e.IPs {
		if i >= 3 {
			break
		}
		iocs = append(iocs, IOCEntry{
			Type:     "IP",
			Valeur:   ip,
			Contexte: "Serveur contacté par le malware. À bloquer au pare-feu périmètre.",
			Risque:   "CRITIQUE",
		})
	}
	for i, d := range e.Domaines {
		if i >= 3 {
			break
		}
		iocs = append(iocs, IOCEntry{
			Type:     "Domaine",
			Valeur:   d,
			Contexte: "Domaine C2 contacté par le malware. À bloquer au proxy et DNS.",
			Risque:   "CRITIQUE",
		})
	}

	// Reconstruire les techniques MITRE depuis les TTPs
	var mitre []MitreEntry
	for _, ttp := range e.TTPs {
		if ttp == "" {
			continue
		}
		mitre = append(mitre, MitreEntry{
			ID:          ttp,
			Nom:         inferMitreName(ttp),
			Tactique:    inferMitreTactique(ttp),
			Observation: fmt.Sprintf("Technique %s détectée lors de l'analyse du fichier %s.", ttp, e.Filename),
			SourceURL:   fmt.Sprintf("https://attack.mitre.org/techniques/%s/", strings.ReplaceAll(ttp, ".", "/")),
			Criticite:   inferCriticiteFromScore(e.ScoreGlobal),
		})
	}

	// Posture de réponse standard selon classification
	posture := buildPostureFromClassification(e.Classification)

	// Construire le rapport complet
	report := map[string]interface{}{
		"classification":     e.Classification,
		"score_global":       e.ScoreGlobal,
		"etat_compromission": inferEtat(e.ScoreGlobal),
		"resume_executif":    e.ResumeExecutif,
		"pourquoi_malveillant": fmt.Sprintf(
			"Le fichier %s est définitivement malveillant. "+
				"Score sandbox : %d/10. Famille identifiée : %s. "+
				"Techniques d'attaque détectées : %s. "+
				"Ces comportements sont impossibles pour un logiciel légitime.",
			e.Filename, e.ScoreGlobal, e.FamillePresumee,
			strings.Join(e.TTPs, ", "),
		),
		"timeline_attaque": buildDefaultTimeline(e),
		"risque_lateralisation": map[string]interface{}{
			"niveau":   inferNiveauLateral(e.ScoreGlobal),
			"vecteurs": []string{"Propagation via partages réseau", "Utilisation d'identifiants volés"},
			"systemes_cibles": []string{
				"Contrôleurs de domaine Active Directory",
				"Serveurs de fichiers accessibles depuis le poste infecté",
			},
			"signes_detectes": inferSignesLateral(e),
			"action_urgente":  "Isoler immédiatement le poste infecté du réseau.",
		},
		"donnees_exposees": []map[string]interface{}{
			{
				"type":        "Identifiants Windows / Active Directory",
				"risque":      "CRITIQUE",
				"explication": "Les identifiants présents sur le poste peuvent être volés et réutilisés pour un mouvement latéral.",
			},
			{
				"type":        "Données métier / fichiers locaux",
				"risque":      "ELEVE",
				"explication": "Les fichiers accessibles depuis le poste infecté sont exposés à l'exfiltration.",
			},
		},
		"analyse_comportementale_intro": fmt.Sprintf(
			"Le fichier %s a été analysé en sandbox avec un score de %d/10.",
			e.Filename, e.ScoreGlobal,
		),
		"analyse_comportementale": fmt.Sprintf(
			"Le malware %s utilise les techniques suivantes : %s. "+
				"Il établit des communications avec des serveurs externes via les domaines : %s.",
			e.Filename,
			strings.Join(e.TTPs, ", "),
			strings.Join(e.Domaines, ", "),
		),
		"analyse_comportementale_conclusion": "L'équipe IT doit isoler le poste et bloquer les IOCs au périmètre.",
		"analyse_reseau_intro": fmt.Sprintf(
			"Le malware a contacté %d IP(s) et %d domaine(s) externes.",
			len(e.IPs), len(e.Domaines),
		),
		"analyse_reseau": fmt.Sprintf(
			"Connexions établies vers : %s. Domaines C2 : %s.",
			strings.Join(e.IPs, ", "),
			strings.Join(e.Domaines, ", "),
		),
		"analyse_reseau_conclusion": "Bloquer immédiatement ces destinations au pare-feu et proxy. Journaliser toute tentative de connexion.",
		"techniques_mitre":          mitre,
		"iocs_critiques":            iocs,
		"attribution": map[string]interface{}{
			"famille_presumee": e.FamillePresumee,
			"confiance":        e.NiveauConfiance,
			"indicateurs":      inferIndicateurs(e),
		},
		"posture_reponse":           posture,
		"recommandations":           recs,
		"indicateurs_compromission": buildIOCString(e),
		"niveau_confiance":          e.NiveauConfiance,
		"conclusion": fmt.Sprintf(
			"Menace %s confirmée — score %d/10. "+
				"Actions immédiates : isolation du poste et blocage des IOCs. "+
				"Risque de propagation %s. "+
				"Notification DPO requise si données personnelles exposées (RGPD 72h).",
			e.Classification, e.ScoreGlobal, inferNiveauLateral(e.ScoreGlobal),
		),
	}

	b, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ─── Helpers d'inférence ──────────────────────────────────────────────────────

func inferCategorie(action string) string {
	action = strings.ToLower(action)
	switch {
	case strings.Contains(action, "isol") || strings.Contains(action, "déconnect"):
		return "CONFINEMENT"
	case strings.Contains(action, "bloqu") || strings.Contains(action, "ioc"):
		return "BLOCAGE"
	case strings.Contains(action, "investig") || strings.Contains(action, "analys"):
		return "INVESTIGATION"
	case strings.Contains(action, "nettoy") || strings.Contains(action, "réinstall") || strings.Contains(action, "éradiqu"):
		return "ERADICATION"
	case strings.Contains(action, "durciss") || strings.Contains(action, "configur"):
		return "DURCISSEMENT"
	default:
		return "REMEDIATION"
	}
}

func inferDeadline(priorite string) string {
	switch strings.ToUpper(priorite) {
	case "CRITIQUE":
		return "Immediat"
	case "ELEVE":
		return "24h"
	case "MOYEN":
		return "72h"
	default:
		return "7 jours"
	}
}

func inferEtat(score int) string {
	switch {
	case score >= 8:
		return "CONFIRME — comportements malveillants actifs détectés en sandbox."
	case score >= 5:
		return "PROBABLE — indicateurs suspects confirmés, investigation complémentaire recommandée."
	default:
		return "SUSPECTE — comportements anormaux détectés, analyse approfondie nécessaire."
	}
}

func inferNiveauLateral(score int) string {
	switch {
	case score >= 8:
		return "CRITIQUE"
	case score >= 6:
		return "ELEVE"
	case score >= 4:
		return "MOYEN"
	default:
		return "FAIBLE"
	}
}

func inferCriticiteFromScore(score int) string {
	switch {
	case score >= 8:
		return "CRITIQUE"
	case score >= 5:
		return "ELEVE"
	default:
		return "MOYEN"
	}
}

func inferMitreName(ttp string) string {
	// Noms courants pour les TTPs fréquents en forensique malware
	names := map[string]string{
		"T1059":     "Command and Scripting Interpreter",
		"T1059.001": "PowerShell",
		"T1059.003": "Windows Command Shell",
		"T1059.005": "Visual Basic",
		"T1059.007": "JavaScript",
		"T1547":     "Boot or Logon Autostart Execution",
		"T1547.001": "Registry Run Keys / Startup Folder",
		"T1053":     "Scheduled Task/Job",
		"T1053.005": "Scheduled Task",
		"T1055":     "Process Injection",
		"T1071":     "Application Layer Protocol",
		"T1071.001": "Web Protocols",
		"T1105":     "Ingress Tool Transfer",
		"T1140":     "Deobfuscate/Decode Files or Information",
		"T1027":     "Obfuscated Files or Information",
		"T1082":     "System Information Discovery",
		"T1083":     "File and Directory Discovery",
		"T1016":     "System Network Configuration Discovery",
		"T1041":     "Exfiltration Over C2 Channel",
		"T1567":     "Exfiltration Over Web Service",
		"T1574":     "Hijack Execution Flow",
		"T1574.002": "DLL Side-Loading",
	}
	if name, ok := names[ttp]; ok {
		return name
	}
	return fmt.Sprintf("Technique %s", ttp)
}

func inferMitreTactique(ttp string) string {
	prefix := strings.Split(ttp, ".")[0]
	tactics := map[string]string{
		"T1059": "Execution",
		"T1547": "Persistence",
		"T1053": "Persistence",
		"T1055": "Defense Evasion",
		"T1071": "C2",
		"T1105": "C2",
		"T1140": "Defense Evasion",
		"T1027": "Defense Evasion",
		"T1082": "Discovery",
		"T1083": "Discovery",
		"T1016": "Discovery",
		"T1041": "Exfiltration",
		"T1567": "Exfiltration",
		"T1574": "Defense Evasion",
	}
	if t, ok := tactics[prefix]; ok {
		return t
	}
	return "Execution"
}

func inferSignesLateral(e KnowledgeEntry) []string {
	var signes []string
	for _, d := range e.Domaines {
		if strings.Contains(strings.ToLower(d), "sharepoint") ||
			strings.Contains(strings.ToLower(d), "onedrive") ||
			strings.Contains(strings.ToLower(d), "microsoft") {
			signes = append(signes, "Connexion vers infrastructure Microsoft Cloud (potentiel C2 via SharePoint/OneDrive)")
			break
		}
	}
	for _, ttp := range e.TTPs {
		if strings.HasPrefix(ttp, "T1055") {
			signes = append(signes, "Injection de processus détectée (T1055) — vecteur de propagation latérale")
		}
	}
	if len(signes) == 0 {
		signes = append(signes, "Communications réseau vers serveurs externes établies")
	}
	return signes
}

func inferIndicateurs(e KnowledgeEntry) []string {
	var ind []string
	if len(e.TTPs) > 0 {
		ind = append(ind, fmt.Sprintf("TTPs identifiés : %s — caractéristiques de cette famille malware", strings.Join(e.TTPs, ", ")))
	}
	for _, d := range e.Domaines {
		if strings.Contains(strings.ToLower(d), "sharepoint") {
			ind = append(ind, "Utilisation de SharePoint comme C2 — technique caractéristique de certains RATs modernes")
			break
		}
	}
	if len(ind) == 0 {
		ind = append(ind, "Aucun indicateur d'attribution distinctive identifié avec certitude")
	}
	return ind
}

func buildIOCString(e KnowledgeEntry) string {
	var parts []string
	if len(e.IPs) > 0 {
		parts = append(parts, fmt.Sprintf("IPs à bloquer : %s", strings.Join(e.IPs, ", ")))
	}
	if len(e.Domaines) > 0 {
		parts = append(parts, fmt.Sprintf("Domaines à bloquer : %s", strings.Join(e.Domaines, ", ")))
	}
	if len(e.Hashes) > 0 {
		parts = append(parts, fmt.Sprintf("Hashes à ajouter EDR : %s", strings.Join(e.Hashes, ", ")))
	}
	parts = append(parts, "Event IDs Windows à surveiller : 4688 (création processus), 7045 (service installé), 4625 (échec auth)")
	return strings.Join(parts, ". ")
}

func buildDefaultTimeline(e KnowledgeEntry) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"phase":   "Phase 1 : Activation initiale",
			"action":  fmt.Sprintf("Exécution de %s — déclenchement du comportement malveillant.", e.Filename),
			"impact":  "La machine est compromise, le malware prend le contrôle du système.",
			"detecte": true,
		},
		{
			"phase":  "Phase 2 : Établissement de la persistance",
			"action": "Mise en place d'un mécanisme de persistance pour survivre au redémarrage.",
			"impact": "Le malware redémarre automatiquement et reprend son activité après un reboot.",
			"detecte": len(e.TTPs) > 0 && func() bool {
				for _, t := range e.TTPs {
					if strings.HasPrefix(t, "T1547") || strings.HasPrefix(t, "T1053") {
						return true
					}
				}
				return false
			}(),
		},
		{
			"phase":   "Phase 3 : Communication C2",
			"action":  fmt.Sprintf("Connexions vers : %s", strings.Join(append(e.Domaines, e.IPs...), ", ")),
			"impact":  "L'attaquant peut envoyer des ordres, exfiltrer des données ou déployer d'autres payloads.",
			"detecte": len(e.IPs) > 0 || len(e.Domaines) > 0,
		},
	}
}

func buildPostureFromClassification(classification string) map[string]interface{} {
	phase := "CONFINEMENT — la priorité est d'empêcher la propagation avant toute éradication"
	immediat := []string{"Isoler immédiatement le poste du réseau.", "Bloquer les IOCs au niveau périmètre."}
	h24 := []string{"Investigation forensique et recherche de latéralisation.", "Éradication sur le(s) poste(s) infecté(s)."}
	h72 := []string{"Recouvrement et remise en service après validation.", "Leçons apprises et corrections structurelles."}

	if classification == "CRITIQUE" {
		immediat = append(immediat, "Déclencher la cellule de crise cyber.")
		h24 = append(h24, "Notification ANSSI si OIV/OSE.")
	}

	return map[string]interface{}{
		"phase":            phase,
		"actions_immediat": immediat,
		"actions_24h":      h24,
		"actions_72h":      h72,
		"notification":     "Notifier le DPO si données personnelles exposées (RGPD 72h). Notifier l'assurance cyber.",
		"critere_retour":   "Poste nettoyé ou remplacé, IOCs bloqués en périmètre, absence de détection sur autres postes.",
	}
}

// DatasetPath retourne le chemin par défaut du dataset JSONL dans le dossier knowledge/.
func DatasetPath() string {
	return filepath.Join(knowledgeDir(), "training_dataset.jsonl")
}
