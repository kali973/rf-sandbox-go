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

// BuildForensicPrompt construit le prompt management à partir des résultats sandbox.
// Accepte des donnees d'enrichissement externes (MITRE, AbuseIPDB) et la base de connaissances.
func BuildForensicPrompt(results []*models.AnalysisResult, enrichment *EnrichmentData, similar []SimilarEntry, geoData map[string]GeoInfo) string {
	data := buildCondensedData(results)
	dataJSON, _ := json.MarshalIndent(data, "", "  ")

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
      "action": "Domaines et IPs contactes, protocoles utilises",
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
  "conclusion": "4 a 5 phrases de synthese executive : (1) verdict definitif sur la nature et la gravite reelle de la menace, (2) etat actuel de la compromission et risque de propagation, (3) les deux actions les plus urgentes dans l'heure qui vient, (4) consequences concretes et chiffrees si aucune action dans les 24h (paralysie, vol de donnees, violation RGPD, etc.), (5) message au COMEX : ce que cet incident revele sur la posture de securite et ce qu'il faut corriger a long terme."
}`

	return fmt.Sprintf(`Tu es un analyste senior CERT/CSIRT qui redige un rapport forensique d'incident pour le management.
Tes lecteurs sont le RSSI, le DSI, le PDG et le Conseil d'Administration — ils ont besoin de comprendre la menace, pas juste de voir des donnees techniques.

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
6. INTRO ET CONCLUSION OBLIGATOIRES : les champs *_intro et *_conclusion sont OBLIGATOIRES dans chaque section. Ils doivent etre SPECIFIQUES aux donnees analysees — jamais generiques. Chaque intro nomme un element concret (processus, IP, fichier). Chaque conclusion donne une action concrete basee sur ce qui a ete observe. Un champ intro ou conclusion vide ou generique ("Cette section presente...") est une ERREUR.

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

func buildCondensedData(results []*models.AnalysisResult) map[string]interface{} {
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
				if len(sigs) >= 10 {
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
				if len(urls) > 15 {
					urls = urls[:15]
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
				if len(procs) >= 20 {
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
			if len(evs) > 50 {
				evs = evs[:50]
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
	allFlows := make([]map[string]interface{}, 0, 20)
	for _, nr := range r.Network {
		for _, f := range nr.Flows {
			if len(allFlows) >= 20 {
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
func ParseForensicResponse(raw string) (*ForensicReport, error) {
	// Mistral génère parfois des séquences d'échappement JSON invalides (\_ \. \: etc.)
	// On les nettoie avant tout parsing
	raw = cleanInvalidEscapes(raw)

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
