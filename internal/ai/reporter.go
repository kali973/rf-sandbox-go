package ai

import (
	"fmt"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
	"rf-sandbox-go/internal/models"
)

// ─── Palette ──────────────────────────────────────────────────────────────────

type color struct{ r, g, b int }

var (
	colDark   = color{18, 24, 38}
	colNavy   = color{20, 30, 58}
	colBlue   = color{37, 99, 235}
	colSteel  = color{71, 85, 105}
	colAccent = color{239, 68, 68}
	colRed    = color{220, 38, 38}
	colRedBg  = color{254, 242, 242}
	colOrange = color{234, 88, 12}
	colOrgBg  = color{255, 247, 237}
	colYellow = color{202, 138, 4}
	colYelBg  = color{254, 252, 232}
	colGreen  = color{22, 163, 74}
	colGrnBg  = color{240, 253, 244}
	colGrey   = color{100, 116, 139}
	colBg     = color{248, 250, 252}
	colBg2    = color{241, 245, 249}
	colBorder = color{203, 213, 225}
	colText   = color{15, 23, 42}
	colText2  = color{71, 85, 105}
	colWhite  = color{255, 255, 255}
)

func classColor(c string) color {
	switch strings.ToUpper(c) {
	case "CRITIQUE":
		return colRed
	case "ÉLEVÉ", "ELEVE":
		return colOrange
	case "MOYEN":
		return colYellow
	case "FAIBLE", "BENIN":
		return colGreen
	default:
		return colGrey
	}
}

func classBg(c string) color {
	switch strings.ToUpper(c) {
	case "CRITIQUE":
		return colRedBg
	case "ÉLEVÉ", "ELEVE":
		return colOrgBg
	case "MOYEN":
		return colYelBg
	case "FAIBLE", "BENIN":
		return colGrnBg
	default:
		return colBg
	}
}

func prioColor(p string) color { return classColor(p) }

// ─── AIReporter ───────────────────────────────────────────────────────────────

type AIReporter struct {
	pdf            *gofpdf.Fpdf
	outputPath     string
	classification string
	tlpLabel       string // TLP dynamique selon la gravité
	reportDate     string
	pageW, pageH   float64
	mL, mR, mT     float64
	cW             float64
	geoData        map[string]GeoInfo
	enrichData     *EnrichmentData
	engineName     string
	results        []*models.AnalysisResult // données brutes pour sections avancées
	generationSecs int                      // durée génération IA (secondes) pour pied de page
}

// tlpFromClassification détermine le niveau TLP selon la classification de la menace.
// CRITIQUE/ÉLEVÉ → TLP:RED (ne pas partager)
// MOYEN → TLP:AMBER (partage restreint)
// FAIBLE/INCONNU → TLP:WHITE (partage libre)
func tlpFromClassification(classification string) (string, string) {
	switch strings.ToUpper(strings.TrimSpace(classification)) {
	case "CRITIQUE", "CRITICAL", "TRES ELEVE", "TRÈS ÉLEVÉ":
		return "TLP:RED", "Ce document est confidentiel - ne pas diffuser en dehors de l'organisation"
	case "ELEVE", "ÉLEVÉ", "HIGH":
		return "TLP:AMBER", "Diffusion restreinte - partager uniquement avec les equipes autorisees"
	case "MOYEN", "MEDIUM", "MODERATE":
		return "TLP:AMBER", "Diffusion restreinte - partager uniquement avec les equipes autorisees"
	default:
		return "TLP:WHITE", "Ce document peut etre partage librement"
	}
}

func NewAIReporter(outputPath, classification string, geoData map[string]GeoInfo) *AIReporter {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetAuthor("CCM de Bercy - Ministere de l'Economie et des Finances", true)
	pdf.SetCreator("Analyseur Forensic IA - CCM Bercy", true)
	pdf.SetTitle(toL1("Rapport d'Analyse Forensic IA — CCM de Bercy"), true)

	r := &AIReporter{
		pdf:            pdf,
		outputPath:     outputPath,
		classification: classification,
		tlpLabel:       "TLP:WHITE",
		reportDate:     time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		mL:             16,
		mR:             16,
		mT:             14,
		geoData:        geoData,
	}
	r.pageW, r.pageH = pdf.GetPageSize()
	r.cW = r.pageW - r.mL - r.mR

	pdf.SetMargins(r.mL, r.mT, r.mR)
	pdf.SetAutoPageBreak(true, 20)

	pdf.SetHeaderFuncMode(func() { r.drawHeader() }, true)
	pdf.SetFooterFunc(func() { r.drawFooter() })

	return r
}

// SetEngine définit le nom du moteur IA ayant produit ce rapport.
func (r *AIReporter) SetEngine(name string) {
	r.engineName = name
}

// SetGenerationDuration définit la durée de génération IA (secondes) pour affichage PDF.
func (r *AIReporter) SetGenerationDuration(secs int) {
	r.generationSecs = secs
}

// SetEnrichment injecte les données d'enrichissement MITRE ATT&CK et AbuseIPDB dans le rapport.
func (r *AIReporter) SetEnrichment(data *EnrichmentData) {
	r.enrichData = data
}

// Generate génère le rapport PDF complet à partir des résultats d'analyse.
func (r *AIReporter) Generate(results []*models.AnalysisResult, report *ForensicReport) error {
	r.results = results // sauvegarder pour les sections avancées (LegitInfra, etc.)
	// Déterminer le TLP dynamiquement selon la gravité réelle du rapport
	tlpLabel, _ := tlpFromClassification(report.Classification)
	r.tlpLabel = tlpLabel
	r.classification = report.Classification

	r.coverPage(results, report)
	r.tocPage(results, report)
	r.resumeExecutifPage(results, report)

	// ── Section forensique clé : pourquoi c'est malveillant ──────────────────
	if report.PourquoiMalveillant != "" {
		r.malveillanceSection(report)
	}

	// ── Timeline de l'attaque ─────────────────────────────────────────────────
	if len(report.TimelineAttaque) > 0 {
		r.timelineSection(report)
	}

	// ── Risque de latéralisation ──────────────────────────────────────────────
	r.lateralisationSection(report)

	// ── Données exposées ──────────────────────────────────────────────────────
	if len(report.DonneesExposees) > 0 || report.AnalyseComportementale != "" {
		r.donneesExpoSeesSection(report)
	}

	// ── Analyses techniques ───────────────────────────────────────────────────
	if report.AnalyseComportementale != "" {
		r.genericSectionWithConcl("ANALYSE COMPORTEMENTALE",
			"Comportements observes traduits en impact operationnel pour l'organisation.",
			report.AnalyseComportementaleIntro,
			report.AnalyseComportementale,
			report.AnalyseComportementaleConclusion, "")
	}
	if report.AnalyseReseau != "" || len(report.IOCsCritiques) > 0 || len(r.geoData) > 0 {
		r.reseauSection(report)
	}
	if report.AnalyseProcessus != "" {
		r.genericSectionWithConcl("ACTIVITE DES PROCESSUS",
			"Programmes lances par le malware et leurs actions sur le systeme.",
			report.AnalyseProcessusIntro,
			report.AnalyseProcessus,
			report.AnalyseProcessusConclusion, "")
	}
	// ── Preuves kernel : fichiers créés + connexions (données brutes RF) ──────
	// Affichées uniquement si r.results contient des KernelEvents significatifs
	if r.results != nil {
		criticalEvs := extractKernelEventsForPDF(r.results, 60)
		if len(criticalEvs) > 0 {
			r.kernelEvidenceSection(criticalEvs)
		}
		// Fichiers déposés par le malware (payloads 2ème stage)
		var allDropped []models.DroppedFileInfo
		for _, res := range r.results {
			allDropped = append(allDropped, res.DroppedFiles...)
		}
		if len(allDropped) > 0 {
			r.droppedFilesSection(allDropped)
		}
		// Commandes suspectes (curl, ftp, schtasks, powershell...)
		allProcs := make([]models.ProcessWithTask, 0)
		for _, res := range r.results {
			allProcs = append(allProcs, res.Processes...)
		}
		r.cmdlineSection(allProcs)
	}

	if report.AnalyseStatique != "" {
		r.genericSectionWithConcl("ANALYSE DU FICHIER",
			"Structure, caracteristiques techniques et indicateurs d'origine du fichier malveillant.",
			report.AnalyseStatiqueIntro,
			report.AnalyseStatique,
			report.AnalyseStatiqueConclusion, "")
	}
	if report.ConfigsMalware != "" &&
		!strings.Contains(strings.ToLower(report.ConfigsMalware), "insuffisantes") {
		r.genericSectionWithConcl("INFRASTRUCTURE C2 IDENTIFIEE",
			"Serveurs de commandement et parametres de configuration extraits du malware.",
			"",
			report.ConfigsMalware,
			"", "")
	}
	if len(report.TechniquesMitre) > 0 {
		r.mitreSection(report)
	}
	r.attributionSection(report)

	// ── Posture de réponse à incident ─────────────────────────────────────────
	r.postureSection(report)

	r.recommendationsSection(report)
	r.conclusionSection(report)

	return r.pdf.OutputFileAndClose(r.outputPath)
}

// ─── Header / Footer ──────────────────────────────────────────────────────────

func (r *AIReporter) drawHeader() {
	if r.pdf.PageNo() == 1 {
		return
	}
	pdf := r.pdf
	// Barre supérieure fine
	pdf.SetFillColor(colNavy.r, colNavy.g, colNavy.b)
	pdf.Rect(0, 0, r.pageW, 9, "F")
	// Ligne accent couleur classification
	cc := classColor(r.classification)
	pdf.SetFillColor(cc.r, cc.g, cc.b)
	pdf.Rect(0, 9, r.pageW, 1.5, "F")

	pdf.SetFont("Helvetica", "B", 7)
	pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
	pdf.SetXY(r.mL, 2)
	pdf.CellFormat(r.cW/2, 5, toL1("Analyseur Forensic IA  |  CCM de Bercy"), "", 0, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 7)
	pdf.SetTextColor(148, 163, 184)
	pdf.CellFormat(r.cW/2, 5, toL1(r.reportDate+"  |  "+strings.ToUpper(r.classification)), "", 0, "R", false, 0, "")
	pdf.SetTextColor(0, 0, 0)
}

func (r *AIReporter) drawFooter() {
	pdf := r.pdf
	y := r.pageH - 8
	pdf.SetFillColor(colBg2.r, colBg2.g, colBg2.b)
	pdf.Rect(0, y, r.pageW, 8, "F")
	pdf.SetDrawColor(colBorder.r, colBorder.g, colBorder.b)
	pdf.Line(0, y, r.pageW, y)

	pdf.SetFont("Helvetica", "", 7)
	pdf.SetTextColor(colGrey.r, colGrey.g, colGrey.b)
	pdf.SetXY(r.mL, y+1.5)
	pdf.CellFormat(r.cW/2, 4,
		toL1("Analyseur Forensic IA  |  CCM de Bercy"), "", 0, "L", false, 0, "")
	pdf.SetFont("Helvetica", "B", 7)
	pdf.SetTextColor(colNavy.r, colNavy.g, colNavy.b)
	pdf.CellFormat(r.cW/2, 4,
		toL1(fmt.Sprintf("%s  |  Page %d", r.tlpLabel, pdf.PageNo())), "", 0, "R", false, 0, "")
	pdf.SetTextColor(0, 0, 0)
}

// ─── Page de garde ─────────────────────────────────────────────────────────

func (r *AIReporter) coverPage(results []*models.AnalysisResult, report *ForensicReport) {
	pdf := r.pdf
	pdf.AddPage()

	cc := classColor(report.Classification)
	cbg := classBg(report.Classification)

	// Fond noir haut (60%)
	pdf.SetFillColor(colDark.r, colDark.g, colDark.b)
	pdf.Rect(0, 0, r.pageW, 170, "F")

	// Fond clair bas (40%)
	pdf.SetFillColor(cbg.r, cbg.g, cbg.b)
	pdf.Rect(0, 170, r.pageW, r.pageH-170, "F")

	// Barre latérale gauche couleur classification (toute la hauteur)
	pdf.SetFillColor(cc.r, cc.g, cc.b)
	pdf.Rect(0, 0, 5, r.pageH, "F")

	// Ligne horizontale séparatrice sur fond sombre
	pdf.SetFillColor(cc.r, cc.g, cc.b)
	pdf.Rect(5, 62, r.pageW-5, 0.5, "F")

	// ── Logo / Titre ──────────────────────────────────────────────────────────
	pdf.SetXY(r.mL+4, 14)
	pdf.SetFont("Helvetica", "", 7.5)
	pdf.SetTextColor(100, 130, 180)
	pdf.CellFormat(120, 4, toL1("CCM de Bercy"), "", 1, "L", false, 0, "")

	pdf.SetXY(r.mL+4, 18)
	pdf.SetFont("Helvetica", "I", 7)
	pdf.SetTextColor(80, 110, 160)
	pdf.CellFormat(120, 4, toL1("Ministere de l'Economie et des Finances"), "", 1, "L", false, 0, "")

	pdf.SetXY(r.mL+4, 26)
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(148, 163, 184)
	pdf.CellFormat(120, 5, "RAPPORT FORENSIC IA", "", 1, "L", false, 0, "")

	pdf.SetXY(r.mL+4, 30)
	pdf.SetFont("Helvetica", "B", 32)
	pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
	pdf.CellFormat(150, 14, "ANALYSE", "", 1, "L", false, 0, "")

	pdf.SetXY(r.mL+4, 47)
	pdf.SetFont("Helvetica", "", 12)
	pdf.SetTextColor(191, 201, 215)
	pdf.CellFormat(150, 6, toL1("Rapport d'Analyse Forensic"), "", 1, "L", false, 0, "")

	// ── Badge classification ──────────────────────────────────────────────────
	pdf.SetXY(r.mL+4, 68)
	pdf.SetFillColor(cc.r, cc.g, cc.b)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
	label := "MENACE : " + strings.ToUpper(report.Classification)
	pdf.CellFormat(60, 8, toL1(label), "0", 1, "L", true, 0, "")

	// ── KPIs ──────────────────────────────────────────────────────────────────
	maxScore := 0
	totalSigs := 0
	for _, res := range results {
		if res.Score > maxScore {
			maxScore = res.Score
		}
		totalSigs += len(res.Signatures)
	}
	if report.ScoreGlobal > 0 {
		maxScore = report.ScoreGlobal
	}

	// Compter les domaines C2 (IOCs + SNI issus des flows TLS)
	totalDomains := 0
	for _, res := range results {
		totalDomains += len(res.IOCs.Domains)
	}
	kpis := []struct{ val, label string }{
		{fmt.Sprintf("%d", len(results)), "Echantillons"},
		{fmt.Sprintf("%d/10", maxScore), "Score"},
		{fmt.Sprintf("%d", totalSigs), "Signatures"},
		{fmt.Sprintf("%d", len(report.TechniquesMitre)), "MITRE ATT&CK"},
		{fmt.Sprintf("%d", totalDomains), "Domaines C2"},
		{fmt.Sprintf("%d", len(report.IOCsCritiques)), "IOCs"},
	}

	kpiX := r.mL + 4
	kpiY := 85.0
	kpiW := (r.cW - 4) / float64(len(kpis))

	// Fond KPI
	pdf.SetFillColor(25, 35, 65)
	pdf.Rect(r.mL+4, kpiY-3, r.cW-4, 25, "F")
	pdf.SetDrawColor(cc.r, cc.g, cc.b)
	pdf.SetLineWidth(0.3)
	pdf.Line(r.mL+4, kpiY-3, r.mL+4+r.cW-4, kpiY-3)

	for i, kpi := range kpis {
		x := kpiX + float64(i)*kpiW
		// Séparateur vertical
		if i > 0 {
			pdf.SetDrawColor(60, 70, 100)
			pdf.SetLineWidth(0.2)
			pdf.Line(x, kpiY, x, kpiY+18)
		}
		pdf.SetXY(x+2, kpiY+1)
		pdf.SetFont("Helvetica", "B", 16)
		pdf.SetTextColor(cc.r, cc.g, cc.b)
		pdf.CellFormat(kpiW-4, 9, toL1(kpi.val), "", 1, "C", false, 0, "")
		pdf.SetXY(x+2, kpiY+10)
		pdf.SetFont("Helvetica", "", 7)
		pdf.SetTextColor(148, 163, 184)
		pdf.CellFormat(kpiW-4, 4, toL1(kpi.label), "", 0, "C", false, 0, "")
	}

	// ── Métadonnées ───────────────────────────────────────────────────────────
	pdf.SetXY(r.mL+4, 118)
	// Score brut RF sandbox pour comparaison avec score IA
	rfScoreCover := 0
	for _, res := range results {
		if res.Score > rfScoreCover {
			rfScoreCover = res.Score
		}
	}
	engineDisplayCover := "Analyseur Forensic IA - CCM Bercy"
	if r.engineName != "" {
		engineDisplayCover = r.engineName
	}
	scoreDisplayCover := fmt.Sprintf("%d/10", report.ScoreGlobal)
	if rfScoreCover > 0 && rfScoreCover != report.ScoreGlobal {
		scoreDisplayCover = fmt.Sprintf("%d/10 (IA) | RF Sandbox: %d/10", report.ScoreGlobal, rfScoreCover)
	}
	metas := []struct{ k, v string }{
		{"Date d'analyse", r.reportDate},
		{"Classification", r.classification},
		{"Moteur d'analyse", engineDisplayCover},
		{"Score de menace", scoreDisplayCover},
		{"Niveau de confiance", report.NiveauConfiance},
	}
	for _, m := range metas {
		pdf.SetX(r.mL + 4)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetTextColor(148, 163, 184)
		pdf.CellFormat(52, 5.5, toL1(m.k)+" :", "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
		pdf.CellFormat(r.cW-56, 5.5, toL1(m.v), "", 1, "L", false, 0, "")
	}

	// ── Séparateur ────────────────────────────────────────────────────────────
	pdf.SetDrawColor(cc.r, cc.g, cc.b)
	pdf.SetLineWidth(0.4)
	pdf.Line(r.mL+4, 146, r.pageW-r.mR, 146)

	// ── Échantillons ──────────────────────────────────────────────────────────
	pdf.SetXY(r.mL+4, 150)
	pdf.SetFont("Helvetica", "B", 8)
	pdf.SetTextColor(148, 163, 184)
	pdf.CellFormat(r.cW, 5, toL1("FICHIERS ANALYSES"), "", 1, "L", false, 0, "")
	pdf.Ln(1)

	for _, res := range results {
		name := res.Filename
		if len(name) > 55 {
			name = "..." + name[len(name)-52:]
		}
		sc, lbl := scoreLabel(res.Score)
		pdf.SetX(r.mL + 4)

		// Ligne fond alterné
		pdf.SetFillColor(28, 38, 65)
		pdf.Rect(r.mL+4, pdf.GetY(), r.cW-4, 6.5, "F")

		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(220, 225, 235)
		pdf.CellFormat(r.cW-55, 6.5, toL1(name), "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 7)
		pdf.SetTextColor(148, 163, 184)
		pdf.CellFormat(18, 6.5, toL1(fmt.Sprintf("%d/10", res.Score)), "", 0, "C", false, 0, "")
		// Badge score
		pdf.SetFillColor(sc.r, sc.g, sc.b)
		pdf.SetFont("Helvetica", "B", 7)
		pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
		pdf.CellFormat(34, 6.5, toL1(lbl), "0", 1, "C", true, 0, "")
	}

	// ── Famille / Attribution bas de page ─────────────────────────────────────
	if report.Attribution.FamillePresumee != "" && report.Attribution.FamillePresumee != "Inconnue" {
		pdf.SetXY(r.mL+4, 175)
		// Boite
		pdf.SetFillColor(cc.r, cc.g, cc.b)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
		pdf.CellFormat(40, 6, "FAMILLE IDENTIFIEE", "0", 0, "C", true, 0, "")
		pdf.SetFillColor(30, 40, 70)
		pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
		pdf.CellFormat(r.cW-44, 6,
			toL1(report.Attribution.FamillePresumee+" — Confiance : "+report.Attribution.Confiance),
			"0", 1, "L", true, 0, "")
	}

	// TLP bas de page
	pdf.SetXY(r.mL+4, r.pageH-18)
	pdf.SetFont("Helvetica", "B", 8)
	pdf.SetTextColor(colGrey.r, colGrey.g, colGrey.b)
	tlpLabel, tlpDesc := tlpFromClassification(report.Classification)
	pdf.CellFormat(r.cW, 5, toL1(tlpLabel+" - "+tlpDesc+"."), "", 0, "C", false, 0, "")

	pdf.SetTextColor(0, 0, 0)
}

// ─── Table des matières ───────────────────────────────────────────────────────

func (r *AIReporter) tocPage(results []*models.AnalysisResult, report *ForensicReport) {
	pdf := r.pdf
	pdf.AddPage()

	r.pageTitle("TABLE DES MATIÈRES", "")

	sections := []struct{ num, title, note string }{
		{"1.", "Sommaire exécutif", "Classification, score global, KPIs, résumé direction"},
		{"2.", "Analyse comportementale", "Actions du malware sur le système hôte"},
		{"3.", "Communications réseau", "Connexions, IOCs, infrastructure C2"},
		{"4.", "Activité des processus", "Programmes suspects et leurs rôles"},
		{"5.", "Analyse du fichier", "Structure, obfuscation, origine"},
		{"6.", "Techniques MITRE ATT&CK", "Tactiques et méthodes d'attaque identifiées"},
		{"7.", "Attribution", "Famille et acteur présumés"},
		{"8.", "Plan d'action", "Recommandations classées par priorité"},
		{"9.", "Conclusion", "Synthèse et urgence"},
	}

	pdf.Ln(4)
	for i, s := range sections {
		y := pdf.GetY()
		// Fond alterné
		if i%2 == 0 {
			pdf.SetFillColor(colBg.r, colBg.g, colBg.b)
		} else {
			pdf.SetFillColor(colWhite.r, colWhite.g, colWhite.b)
		}
		pdf.Rect(r.mL, y, r.cW, 9, "F")
		// Barre gauche couleur
		pdf.SetFillColor(colBlue.r, colBlue.g, colBlue.b)
		pdf.Rect(r.mL, y, 2, 9, "F")

		pdf.SetXY(r.mL+5, y+1.5)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetTextColor(colNavy.r, colNavy.g, colNavy.b)
		pdf.CellFormat(12, 6, toL1(s.num), "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetTextColor(colText.r, colText.g, colText.b)
		pdf.CellFormat(70, 6, toL1(s.title), "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(colGrey.r, colGrey.g, colGrey.b)
		pdf.CellFormat(r.cW-90, 6, toL1(s.note), "", 0, "L", false, 0, "")
		pdf.Ln(9)
	}

	// Bloc résumé menace
	pdf.Ln(6)
	cc := classColor(report.Classification)
	pdf.SetFillColor(cc.r, cc.g, cc.b)
	pdf.Rect(r.mL, pdf.GetY(), r.cW, 0.5, "F")
	pdf.Ln(4)

	pdf.SetFillColor(classBg(report.Classification).r, classBg(report.Classification).g, classBg(report.Classification).b)
	pdf.Rect(r.mL, pdf.GetY(), r.cW, 20, "F")
	pdf.SetFillColor(cc.r, cc.g, cc.b)
	pdf.Rect(r.mL, pdf.GetY(), 3, 20, "F")

	pdf.SetXY(r.mL+7, pdf.GetY()+3)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(cc.r, cc.g, cc.b)
	pdf.CellFormat(r.cW-10, 5, toL1("VERDICT : MENACE "+strings.ToUpper(report.Classification)), "", 1, "L", false, 0, "")
	pdf.SetX(r.mL + 7)
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(colText2.r, colText2.g, colText2.b)
	fam := report.Attribution.FamillePresumee
	if fam == "" {
		fam = "Non determinee"
	}
	pdf.CellFormat(r.cW-10, 5,
		toL1(fmt.Sprintf("Famille : %s  |  Score : %d/10  |  %d techniques MITRE  |  %d recommandations",
			fam, report.ScoreGlobal, len(report.TechniquesMitre), len(report.Recommandations))),
		"", 0, "L", false, 0, "")

	pdf.SetTextColor(0, 0, 0)
}

// ─── Résumé exécutif ──────────────────────────────────────────────────────────

func (r *AIReporter) resumeExecutifPage(results []*models.AnalysisResult, report *ForensicReport) {
	pdf := r.pdf
	pdf.AddPage()
	r.pageTitle("SOMMAIRE EXÉCUTIF", "1.")

	cc := classColor(report.Classification)
	cbg := classBg(report.Classification)

	// ── Tableau métriques clés ────────────────────────────────────────────────
	r.subSection("Métriques de l'analyse")

	rows := [][]string{
		{"Classification", strings.ToUpper(report.Classification)},
		{"Score de menace global", fmt.Sprintf("%d / 10", report.ScoreGlobal)},
		{"Niveau de confiance de l'analyse", report.NiveauConfiance},
		{"Échantillons soumis", fmt.Sprintf("%d fichier(s)", len(results))},
		{"Signatures comportementales", fmt.Sprintf("%d détectée(s)", totalSignatures(results))},
		{"Techniques MITRE ATT&CK", fmt.Sprintf("%d identifiée(s)", len(report.TechniquesMitre))},
		{"Indicateurs de compromission (IOC)", fmt.Sprintf("%d critique(s)", len(report.IOCsCritiques))},
		{"Actions de remédiation recommandées", fmt.Sprintf("%d action(s) planifiée(s)", len(report.Recommandations))},
	}
	if report.Attribution.FamillePresumee != "" {
		rows = append(rows, []string{"Famille malware identifiée", report.Attribution.FamillePresumee})
	}
	r.metricTable(rows, cc)

	// ── Résumé IA ─────────────────────────────────────────────────────────────
	r.subSection("Analyse de direction")
	r.richParagraph(report.ResumeExecutif)

	// ── IOCs rapides ──────────────────────────────────────────────────────────
	if len(report.IOCsCritiques) > 0 {
		r.subSection(fmt.Sprintf("Indicateurs de compromission critiques (%d)", len(report.IOCsCritiques)))
		iocRows := make([][]string, 0, len(report.IOCsCritiques))
		for _, ioc := range report.IOCsCritiques {
			iocRows = append(iocRows, []string{ioc.Type, ioc.Valeur, ioc.Contexte, ioc.Risque})
		}
		r.iocTable(iocRows)
	}

	// ── Attribution rapide ────────────────────────────────────────────────────
	if report.Attribution.FamillePresumee != "" {
		pdf.Ln(3)
		// Boite d'attribution
		pdf.SetFillColor(cbg.r, cbg.g, cbg.b)
		bY := pdf.GetY()
		pdf.Rect(r.mL, bY, r.cW, 18, "F")
		pdf.SetFillColor(cc.r, cc.g, cc.b)
		pdf.Rect(r.mL, bY, 3, 18, "F")

		pdf.SetXY(r.mL+7, bY+2)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetTextColor(colGrey.r, colGrey.g, colGrey.b)
		pdf.CellFormat(r.cW-10, 5, "ATTRIBUTION", "", 1, "L", false, 0, "")
		pdf.SetX(r.mL + 7)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetTextColor(cc.r, cc.g, cc.b)
		pdf.CellFormat(r.cW-10, 5,
			toL1("Famille : "+report.Attribution.FamillePresumee+
				"   |   Confiance : "+report.Attribution.Confiance), "", 1, "L", false, 0, "")
		if len(report.Attribution.Indicateurs) > 0 {
			pdf.SetX(r.mL + 7)
			pdf.SetFont("Helvetica", "", 8)
			pdf.SetTextColor(colText2.r, colText2.g, colText2.b)
			ind := report.Attribution.Indicateurs[0]
			if len(ind) > 120 {
				ind = ind[:117] + "..."
			}
			pdf.CellFormat(r.cW-10, 4, toL1(ind), "", 0, "L", false, 0, "")
		}
		pdf.Ln(20)
	}
	pdf.SetTextColor(0, 0, 0)
}

// ─── Section générique ────────────────────────────────────────────────────────

func (r *AIReporter) genericSection(title string, subtitle string, content string, _ color, num string) {
	r.genericSectionWithConcl(title, subtitle, "", content, "", num)
}

func (r *AIReporter) genericSectionWithConcl(title, subtitle, intro, content, conclusion, num string) {
	r.pdf.AddPage()
	r.pageTitle(title, num)
	if intro != "" {
		r.chapIntro(intro)
	} else if subtitle != "" {
		r.chapIntro(subtitle)
	}
	r.richParagraph(content)
	if conclusion != "" {
		r.sectionConclusion(conclusion)
	}
}

// ─── Section reseau ──────────────────────────────────────────────────────────

func (r *AIReporter) reseauSection(report *ForensicReport) {
	r.pdf.AddPage()
	r.pageTitle("COMMUNICATIONS RESEAU", "4.")

	intro := report.AnalyseReseauIntro
	if intro == "" {
		intro = "Connexions sortantes, domaines et IPs contactes, donnees potentiellement exfiltrees."
	}
	r.chapIntro(intro)

	if report.AnalyseReseau != "" {
		r.subSection("Analyse des flux reseau")
		r.richParagraph(report.AnalyseReseau)
	}

	// Tableau de geolocalisation si des donnees sont disponibles
	if len(r.geoData) > 0 {
		r.subSection("Geolocalisation des serveurs contactes")
		geoRows := [][]string{}
		for ip, info := range r.geoData {
			if !info.Disponible || info.EstPrivee {
				continue
			}
			// Exclure les IPs d'infrastructure légitime connue du tableau GeoIP :
			// elles ne constituent pas des IOCs malveillants, inutile de les afficher.
			fai := strings.ToLower(info.FAI)
			skipOrgs := []string{"google", "microsoft", "amazon", "cloudflare", "akamai", "fastly", "cdn"}
			skip := false
			for _, o := range skipOrgs {
				if strings.Contains(fai, o) {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
			geoRows = append(geoRows, []string{ip, info.Pays, info.Ville, info.FAI, info.ASN})
		}
		if len(geoRows) > 0 {
			r.geoTable(geoRows)
		}
	}

	if report.IndicateursCompromission != "" {
		r.subSection("Indicateurs de compromission reseau")
		r.richParagraph(report.IndicateursCompromission)
	}

	if len(report.IOCsCritiques) > 0 {
		r.subSection(fmt.Sprintf("IOCs detailles — %d indicateur(s) identifie(s)", len(report.IOCsCritiques)))
		iocRows := make([][]string, 0, len(report.IOCsCritiques))
		for _, ioc := range report.IOCsCritiques {
			iocRows = append(iocRows, []string{ioc.Type, ioc.Valeur, ioc.Contexte, ioc.Risque})
		}
		r.iocTable(iocRows)
	}

	if report.AnalyseReseauConclusion != "" {
		r.sectionConclusion(report.AnalyseReseauConclusion)
	}

	// Tableau AbuseIPDB si des données d'enrichissement sont disponibles
	if r.enrichData != nil && len(r.enrichData.IPReputations) > 0 {
		r.subSection(fmt.Sprintf("Reputation des IPs (AbuseIPDB) — %d IP(s) verifiees", len(r.enrichData.IPReputations)))
		r.abuseIPDBTable(r.enrichData.IPReputations)
	}

	// Tableau infrastructure légitime utilisée comme C2 (technique LOLBin)
	// SharePoint, OneDrive, Azure : IPs non bloquables mais SNI = vrais IOCs
	if r.results != nil {
		legitIPs := make([]string, 0)
		for _, res := range r.results {
			legitIPs = append(legitIPs, res.IOCs.LegitInfraIPs...)
		}
		legitIPs = uniqueStringsAI(legitIPs)
		if len(legitIPs) > 0 {
			r.subSection(fmt.Sprintf("Infrastructure legitime utilisee comme C2 — %d IP(s) LOLBin", len(legitIPs)))
			r.richParagraph(toL1(
				"Ces adresses appartiennent a des hebergeurs legitimes (Microsoft Azure, SharePoint, OneDrive) " +
					"utilises comme canal C2 par le malware (technique LOLBin/LOLBAS). " +
					"NE PAS bloquer ces IPs au pare-feu — les domaines SNI associes (ex: 0bgtr-my.sharepoint.com) " +
					"sont les vrais indicateurs a surveiller dans les logs proxy et DNS."))
			loBRows := make([][]string, 0)
			for _, ip := range legitIPs {
				loBRows = append(loBRows, []string{ip, "Microsoft / Azure", "C2 via infra legitime", "SURVEILLER"})
			}
			r.iocTable(loBRows)
		}
	}
}

// uniqueStringsAI déduplique une slice de strings.
func uniqueStringsAI(s []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, v := range s {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// ─── Section "Pourquoi c'est malveillant" ────────────────────────────────────

func (r *AIReporter) malveillanceSection(report *ForensicReport) {
	r.pdf.AddPage()
	r.pageTitle("POURQUOI C'EST UNE MENACE REELLE", "")

	cc := classColor(report.Classification)
	cbg := classBg(report.Classification)

	// Verdict d'etat de compromission
	etat := report.EtatCompromission
	if etat == "" {
		etat = "A determiner"
	}
	pdf := r.pdf
	pdf.Ln(2)
	y := pdf.GetY()
	pdf.SetFillColor(cbg.r, cbg.g, cbg.b)
	pdf.Rect(r.mL, y, r.cW, 14, "F")
	pdf.SetFillColor(cc.r, cc.g, cc.b)
	pdf.Rect(r.mL, y, 5, 14, "F")
	pdf.SetXY(r.mL+9, y+2)
	pdf.SetFont("Helvetica", "B", 7)
	pdf.SetTextColor(colGrey.r, colGrey.g, colGrey.b)
	pdf.CellFormat(r.cW-12, 4, "ETAT DE LA COMPROMISSION", "", 1, "L", false, 0, "")
	pdf.SetX(r.mL + 9)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(cc.r, cc.g, cc.b)
	pdf.CellFormat(r.cW-12, 5, toL1(strings.ToUpper(etat)), "", 0, "L", false, 0, "")
	pdf.Ln(18)

	r.chapIntro(toL1("Cette section repond a la question du management : \"Est-ce vraiment une attaque ou une fausse alerte ?\""))
	r.richParagraph(report.PourquoiMalveillant)

	pdf.SetTextColor(0, 0, 0)
}

// ─── Section Timeline ─────────────────────────────────────────────────────────

func (r *AIReporter) timelineSection(report *ForensicReport) {
	pdf := r.pdf
	pdf.AddPage()
	r.pageTitle("CHRONOLOGIE DE L'ATTAQUE", "")
	r.chapIntro("Sequence des actions du malware observees en sandbox, de l'activation initiale jusqu'aux communications avec l'attaquant.")

	for i, evt := range report.TimelineAttaque {
		if pdf.GetY() > r.pageH-55 {
			pdf.AddPage()
		}

		y := pdf.GetY()
		// Calculer la hauteur de carte en fonction du contenu réel
		pdf.SetFont("Helvetica", "", 8.5)
		actionLines := pdf.SplitLines([]byte(toL1(evt.Action)), r.cW-25)
		pdf.SetFont("Helvetica", "I", 8)
		impactLines := pdf.SplitLines([]byte(toL1("Impact : "+evt.Impact)), r.cW-40)
		cardH := float64(len(actionLines))*5.0 + float64(len(impactLines))*4.0 + 14
		if cardH < 26 {
			cardH = 26
		}
		// Connecteur vertical (sauf premier)
		if i > 0 {
			pdf.SetDrawColor(colBorder.r, colBorder.g, colBorder.b)
			pdf.SetLineWidth(0.8)
			pdf.Line(r.mL+10, y-4, r.mL+10, y)
		}

		// Cercle numerote
		pdf.SetFillColor(colNavy.r, colNavy.g, colNavy.b)
		pdf.Circle(r.mL+10, y+6, 5, "F")
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
		pdf.SetXY(r.mL+7, y+3.5)
		pdf.CellFormat(6, 5, toL1(fmt.Sprintf("%d", i+1)), "", 0, "C", false, 0, "")

		// Fond carte
		pdf.SetFillColor(colBg.r, colBg.g, colBg.b)
		pdf.Rect(r.mL+19, y, r.cW-19, cardH, "F")
		pdf.SetDrawColor(colBorder.r, colBorder.g, colBorder.b)
		pdf.SetLineWidth(0.1)
		pdf.Rect(r.mL+19, y, r.cW-19, cardH, "D")

		// Phase
		pdf.SetXY(r.mL+22, y+2)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetTextColor(colNavy.r, colNavy.g, colNavy.b)
		pdf.CellFormat(r.cW-25, 5, toL1(evt.Phase), "", 1, "L", false, 0, "")

		// Action
		pdf.SetX(r.mL + 22)
		pdf.SetFont("Helvetica", "", 8.5)
		pdf.SetTextColor(colText.r, colText.g, colText.b)
		// Action complete (MultiCell pour ne pas tronquer)
		pdf.SetXY(r.mL+22, pdf.GetY())
		pdf.SetFont("Helvetica", "", 8.5)
		pdf.SetTextColor(colText.r, colText.g, colText.b)
		pdf.MultiCell(r.cW-25, 5, toL1(evt.Action), "", "L", false)

		// Impact complet
		pdf.SetX(r.mL + 22)
		pdf.SetFont("Helvetica", "I", 8)
		pdf.SetTextColor(colGrey.r, colGrey.g, colGrey.b)
		pdf.MultiCell(r.cW-40, 4, toL1("Impact : "+evt.Impact), "", "L", false)

		// Badge detecte / non detecte
		if evt.Detecte {
			pdf.SetFillColor(colGreen.r, colGreen.g, colGreen.b)
			pdf.SetFont("Helvetica", "B", 6.5)
			pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
			pdf.CellFormat(18, 4, "DETECTE", "0", 0, "C", true, 0, "")
		} else {
			pdf.SetFillColor(colOrange.r, colOrange.g, colOrange.b)
			pdf.SetFont("Helvetica", "B", 6.5)
			pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
			pdf.CellFormat(22, 4, "NON DETECT.", "0", 0, "C", true, 0, "")
		}

		pdf.SetXY(r.mL, y+cardH+4)
	}
	pdf.SetTextColor(0, 0, 0)
}

// ─── Section Risque de latéralisation ────────────────────────────────────────

func (r *AIReporter) lateralisationSection(report *ForensicReport) {
	pdf := r.pdf
	pdf.AddPage()
	lat := report.RisqueLateralisation
	r.pageTitle("RISQUE DE PROPAGATION AU RESEAU", "")
	r.chapIntro("Evaluation du risque que le malware se propage a d'autres machines de l'entreprise — question prioritaire pour le management.")

	// Jauge de risque visuelle
	cc := classColor(lat.Niveau)
	cbg := classBg(lat.Niveau)
	pdf.Ln(2)
	y := pdf.GetY()

	// Calculer la hauteur dynamique selon le texte de l'action urgente
	actionH := 0.0
	if lat.ActionUrgente != "" {
		pdf.SetFont("Helvetica", "", 8)
		lines := pdf.SplitLines([]byte(toL1("Action immediate : "+lat.ActionUrgente)), r.cW-14)
		actionH = float64(len(lines)) * 4.0
	}
	boxH := 16.0 + actionH
	if boxH < 18 {
		boxH = 18
	}

	pdf.SetFillColor(cbg.r, cbg.g, cbg.b)
	pdf.Rect(r.mL, y, r.cW, boxH, "F")
	pdf.SetFillColor(cc.r, cc.g, cc.b)
	pdf.Rect(r.mL, y, 6, boxH, "F")

	niv := lat.Niveau
	if niv == "" {
		niv = "A EVALUER"
	}
	pdf.SetXY(r.mL+10, y+2)
	pdf.SetFont("Helvetica", "B", 7)
	pdf.SetTextColor(colGrey.r, colGrey.g, colGrey.b)
	pdf.CellFormat(r.cW-14, 4, "NIVEAU DE RISQUE DE PROPAGATION", "", 1, "L", false, 0, "")
	pdf.SetX(r.mL + 10)
	pdf.SetFont("Helvetica", "B", 14)
	pdf.SetTextColor(cc.r, cc.g, cc.b)
	pdf.CellFormat(r.cW-14, 8, toL1(strings.ToUpper(niv)), "", 1, "L", false, 0, "")
	pdf.SetX(r.mL + 10)
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(colText2.r, colText2.g, colText2.b)
	if lat.ActionUrgente != "" {
		pdf.MultiCell(r.cW-14, 4, toL1("Action immediate : "+lat.ActionUrgente), "", "L", false)
	}
	pdf.SetXY(r.mL, y+boxH+4)

	// Tableau 2 colonnes : Vecteurs | Systemes cibles
	if len(lat.Vecteurs) > 0 || len(lat.SystemesCibles) > 0 {
		colW := r.cW / 2

		// En-têtes
		pdf.SetFillColor(colNavy.r, colNavy.g, colNavy.b)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
		pdf.SetX(r.mL)
		pdf.CellFormat(colW, 7, "VECTEURS DE PROPAGATION", "1", 0, "C", true, 0, "")
		pdf.CellFormat(colW, 7, "SYSTEMES ET DONNEES A RISQUE", "1", 1, "C", true, 0, "")

		maxRows := len(lat.Vecteurs)
		if len(lat.SystemesCibles) > maxRows {
			maxRows = len(lat.SystemesCibles)
		}
		for i := 0; i < maxRows; i++ {
			if pdf.GetY() > r.pageH-25 {
				break
			}
			v := ""
			if i < len(lat.Vecteurs) {
				v = lat.Vecteurs[i]
			}
			s := ""
			if i < len(lat.SystemesCibles) {
				s = lat.SystemesCibles[i]
			}

			// Calculer la hauteur réelle nécessaire pour les deux cellules
			pdf.SetFont("Helvetica", "", 8)
			linesV := pdf.SplitLines([]byte(toL1(v)), colW-4)
			pdf.SetFont("Helvetica", "B", 7.5)
			linesS := pdf.SplitLines([]byte(toL1(s)), colW-4)
			lineH := 4.5
			nLines := len(linesV)
			if len(linesS) > nLines {
				nLines = len(linesS)
			}
			rowH := float64(nLines)*lineH + 3
			if rowH < 8 {
				rowH = 8
			}

			rowY := pdf.GetY()
			// Fond gauche
			if i%2 == 0 {
				pdf.SetFillColor(colBg.r, colBg.g, colBg.b)
			} else {
				pdf.SetFillColor(colWhite.r, colWhite.g, colWhite.b)
			}
			pdf.Rect(r.mL, rowY, colW, rowH, "F")
			pdf.SetDrawColor(colBorder.r, colBorder.g, colBorder.b)
			pdf.SetLineWidth(0.1)
			pdf.Rect(r.mL, rowY, colW, rowH, "D")
			// Fond droit (orange pâle pour les systèmes cibles)
			pdf.SetFillColor(colOrgBg.r, colOrgBg.g, colOrgBg.b)
			pdf.Rect(r.mL+colW, rowY, colW, rowH, "F")
			pdf.Rect(r.mL+colW, rowY, colW, rowH, "D")

			// Texte colonne gauche (vecteurs)
			pdf.SetXY(r.mL+2, rowY+1.5)
			pdf.SetFont("Helvetica", "", 8)
			pdf.SetTextColor(colText.r, colText.g, colText.b)
			pdf.MultiCell(colW-4, lineH, toL1(v), "", "L", false)

			// Texte colonne droite (systèmes cibles)
			pdf.SetXY(r.mL+colW+2, rowY+1.5)
			pdf.SetFont("Helvetica", "B", 7.5)
			pdf.SetTextColor(colOrange.r, colOrange.g, colOrange.b)
			pdf.MultiCell(colW-4, lineH, toL1(s), "", "L", false)

			pdf.SetXY(r.mL, rowY+rowH)
		}
		pdf.Ln(5)
	}

	// Signes detectes
	if len(lat.SignesDetectes) > 0 {
		r.subSection("Signes de lateralisation observes en sandbox")
		for _, signe := range lat.SignesDetectes {
			if pdf.GetY() > r.pageH-25 {
				pdf.AddPage()
			}
			pdf.SetFont("Helvetica", "", 8.5)
			lines := pdf.SplitLines([]byte(toL1(signe)), r.cW-10)
			signeH := float64(len(lines))*4.5 + 4
			if signeH < 8 {
				signeH = 8
			}
			y2 := pdf.GetY()
			pdf.SetFillColor(colRedBg.r, colRedBg.g, colRedBg.b)
			pdf.Rect(r.mL, y2, r.cW, signeH, "F")
			pdf.SetFillColor(colRed.r, colRed.g, colRed.b)
			pdf.Rect(r.mL, y2, 2.5, signeH, "F")
			pdf.SetXY(r.mL+5, y2+1.5)
			pdf.SetFont("Helvetica", "", 8.5)
			pdf.SetTextColor(colRed.r, colRed.g, colRed.b)
			pdf.MultiCell(r.cW-7, 4.5, toL1(signe), "", "L", false)
			pdf.SetXY(r.mL, y2+signeH+1)
		}
	}
	pdf.SetTextColor(0, 0, 0)
}

// ─── Section Données exposées ─────────────────────────────────────────────────

func (r *AIReporter) donneesExpoSeesSection(report *ForensicReport) {
	pdf := r.pdf
	pdf.AddPage()
	r.pageTitle("DONNEES ET SYSTEMES EXPOSES", "")
	r.chapIntro("Inventaire des categories de donnees menacees par cette attaque — base pour evaluer l'obligation de notification RGPD.")

	if len(report.DonneesExposees) > 0 {
		for _, d := range report.DonneesExposees {
			if pdf.GetY() > r.pageH-40 {
				pdf.AddPage()
			}
			dc := classColor(d.Risque)
			dbg := classBg(d.Risque)
			y := pdf.GetY()

			cardH := 20.0
			expl := d.Explication
			lines := pdf.SplitLines([]byte(toL1(expl)), r.cW-35)
			if len(lines) > 2 {
				cardH = float64(len(lines))*4.5 + 12
			}

			pdf.SetFillColor(dbg.r, dbg.g, dbg.b)
			pdf.Rect(r.mL, y, r.cW, cardH, "F")
			pdf.SetFillColor(dc.r, dc.g, dc.b)
			pdf.Rect(r.mL, y, 5, cardH, "F")

			// Badge risque
			pdf.SetXY(r.pageW-r.mR-22, y+2)
			pdf.SetFillColor(dc.r, dc.g, dc.b)
			pdf.SetFont("Helvetica", "B", 7)
			pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
			pdf.CellFormat(20, 5, toL1(d.Risque), "0", 0, "C", true, 0, "")

			pdf.SetXY(r.mL+8, y+2)
			pdf.SetFont("Helvetica", "B", 9)
			pdf.SetTextColor(dc.r, dc.g, dc.b)
			pdf.CellFormat(r.cW-30, 5, toL1(d.Type), "", 1, "L", false, 0, "")
			pdf.SetX(r.mL + 8)
			pdf.SetFont("Helvetica", "", 8.5)
			pdf.SetTextColor(colText.r, colText.g, colText.b)
			pdf.MultiCell(r.cW-14, 4.5, toL1(expl), "", "L", false)

			pdf.SetXY(r.mL, y+cardH+4)
		}
	} else if report.AnalyseComportementale != "" {
		r.chapIntro("Analyse des donnees a risque basee sur les comportements observes.")
		r.richParagraph(report.AnalyseComportementale)
	}
	pdf.SetTextColor(0, 0, 0)
}

// ─── Section Posture de réponse à incident ────────────────────────────────────

func (r *AIReporter) postureSection(report *ForensicReport) {
	posture := report.PostureReponse
	if posture.Phase == "" && len(posture.ActionsImmediat) == 0 {
		return
	}

	pdf := r.pdf
	pdf.AddPage()
	r.pageTitle("POSTURE DE REPONSE A L'INCIDENT", "")
	r.chapIntro("Plan de reponse structure en 3 phases : Confinement -> Eradication -> Recouvrement.")

	// Phase actuelle
	if posture.Phase != "" {
		pdf.Ln(2)
		y := pdf.GetY()
		pdf.SetFillColor(colNavy.r, colNavy.g, colNavy.b)
		pdf.Rect(r.mL, y, r.cW, 10, "F")
		pdf.SetXY(r.mL+6, y+2)
		pdf.SetFont("Helvetica", "B", 7)
		pdf.SetTextColor(148, 163, 184)
		pdf.CellFormat(30, 4, "PHASE RECOMMANDEE", "", 1, "L", false, 0, "")
		pdf.SetX(r.mL + 6)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
		pdf.CellFormat(r.cW-10, 4, toL1(strings.ToUpper(posture.Phase)), "", 0, "L", false, 0, "")
		pdf.Ln(16)
	}

	// 3 colonnes de temps
	type actionCol struct {
		title   string
		actions []string
		col     color
		bg      color
	}
	cols := []actionCol{
		{"IMMEDIAT (0-1h)", posture.ActionsImmediat, colRed, colRedBg},
		{"24 HEURES", posture.Actions24h, colOrange, colOrgBg},
		{"72 HEURES", posture.Actions72h, colGreen, colGrnBg},
	}
	colW := r.cW / 3
	yStart := pdf.GetY()

	// En-tetes
	for _, col := range cols {
		pdf.SetFillColor(col.col.r, col.col.g, col.col.b)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
		pdf.CellFormat(colW, 7, toL1(col.title), "1", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)

	// Lignes d'actions
	maxActions := 0
	for _, col := range cols {
		if len(col.actions) > maxActions {
			maxActions = len(col.actions)
		}
	}
	for i := 0; i < maxActions && i < 6; i++ {
		rowY := pdf.GetY()
		x := r.mL
		rowH := 12.0
		for _, col := range cols {
			pdf.SetXY(x, rowY)
			if i < len(col.actions) {
				pdf.SetFillColor(col.bg.r, col.bg.g, col.bg.b)
				pdf.SetFont("Helvetica", "", 7.5)
				pdf.SetTextColor(colText.r, colText.g, colText.b)
				// Bullet
				pdf.SetFillColor(col.col.r, col.col.g, col.col.b)
				pdf.Circle(x+3.5, rowY+4, 1.5, "F")
				pdf.SetXY(x+7, rowY+0.5)
				pdf.SetFillColor(col.bg.r, col.bg.g, col.bg.b)
				pdf.MultiCell(colW-8, 4, toL1(col.actions[i]), "1", "L", true)
				newY := pdf.GetY()
				if newY-rowY > rowH {
					rowH = newY - rowY
				}
			} else {
				pdf.SetFillColor(colBg.r, colBg.g, colBg.b)
				pdf.CellFormat(colW, rowH, "", "1", 0, "L", true, 0, "")
			}
			x += colW
		}
		pdf.SetXY(r.mL, rowY+rowH)
	}
	_ = yStart

	// Notification
	if posture.Notification != "" {
		pdf.Ln(6)
		r.subSection("Obligations de notification")
		if pdf.GetY() > r.pageH-30 {
			pdf.AddPage()
		}
		y := pdf.GetY()
		// Hauteur dynamique selon le texte
		pdf.SetFont("Helvetica", "", 8.5)
		notifLines := pdf.SplitLines([]byte(toL1(posture.Notification)), r.cW-11)
		notifH := float64(len(notifLines))*5.0 + 8
		if notifH < 16 {
			notifH = 16
		}
		pdf.SetFillColor(colYelBg.r, colYelBg.g, colYelBg.b)
		pdf.Rect(r.mL, y, r.cW, notifH, "F")
		pdf.SetFillColor(colYellow.r, colYellow.g, colYellow.b)
		pdf.Rect(r.mL, y, 4, notifH, "F")
		pdf.SetXY(r.mL+7, y+3)
		pdf.SetFont("Helvetica", "", 8.5)
		pdf.SetTextColor(colText.r, colText.g, colText.b)
		pdf.MultiCell(r.cW-11, 5, toL1(posture.Notification), "", "L", false)
		pdf.SetXY(r.mL, y+notifH+2)
		pdf.Ln(4)
	}

	// Critère de retour
	if posture.CritereRetour != "" {
		r.subSection("Criteres de retour a la normale")
		r.richParagraph(posture.CritereRetour)
	}

	pdf.SetTextColor(0, 0, 0)
}

// ─── Section MITRE ATT&CK ─────────────────────────────────────────────────────

func (r *AIReporter) mitreSection(report *ForensicReport) {
	r.pdf.AddPage()
	r.pageTitle("TECHNIQUES MITRE ATT&CK", "8.")
	r.chapIntro(fmt.Sprintf(
		"%d technique(s) d'attaque identifiée(s), classées selon le référentiel international MITRE ATT&CK v14.",
		len(report.TechniquesMitre)))

	byTactic := map[string][]MitreEntry{}
	order := []string{}
	for _, t := range report.TechniquesMitre {
		tac := t.Tactique
		if tac == "" {
			tac = "Non classifie"
		}
		if _, ok := byTactic[tac]; !ok {
			order = append(order, tac)
		}
		byTactic[tac] = append(byTactic[tac], t)
	}

	for _, tactic := range order {
		techs := byTactic[tactic]
		r.subSection(fmt.Sprintf("Tactique : %s (%d technique(s))", tactic, len(techs)))

		for _, t := range techs {
			if r.pdf.GetY() > r.pageH-55 {
				r.pdf.AddPage()
			}
			yStart := r.pdf.GetY()
			cc := classColor(t.Criticite)

			// Bandeau technique
			r.pdf.SetFillColor(colNavy.r, colNavy.g, colNavy.b)
			r.pdf.Rect(r.mL, yStart, r.cW, 8, "F")
			r.pdf.SetFillColor(cc.r, cc.g, cc.b)
			r.pdf.Rect(r.mL, yStart, 3, 8, "F")

			r.pdf.SetXY(r.mL+6, yStart+1.5)
			r.pdf.SetFont("Helvetica", "B", 8)
			r.pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
			r.pdf.CellFormat(22, 5, toL1(t.ID), "", 0, "L", false, 0, "")
			r.pdf.SetFont("Helvetica", "B", 8)
			r.pdf.CellFormat(r.cW-60, 5, toL1(t.Nom), "", 0, "L", false, 0, "")
			// Badge criticité
			r.pdf.SetFillColor(cc.r, cc.g, cc.b)
			r.pdf.CellFormat(28, 5, toL1(t.Criticite), "0", 0, "C", true, 0, "")
			r.pdf.Ln(10)

			// Corps : description officielle MITRE
			// Priorité : enrichData (API MITRE live) > DescriptionOfficielle (IA)
			descOff := t.DescriptionOfficielle
			detectionOff := ""
			if r.enrichData != nil {
				if detail, ok := r.enrichData.MitreTechniques[t.ID]; ok {
					if detail.Description != "" {
						descOff = detail.Description
					}
					if detail.Detection != "" {
						detectionOff = detail.Detection
					}
					// Enrichir le nom et la tactique si l'IA ne les a pas bien remplis
					if detail.Nom != "" && t.Nom == t.ID {
						// on garde le nom de l'IA si il est plus précis
					}
				}
			}
			if descOff != "" {
				r.pdf.SetX(r.mL)
				r.pdf.SetFont("Helvetica", "B", 7)
				r.pdf.SetTextColor(colSteel.r, colSteel.g, colSteel.b)
				r.pdf.MultiCell(r.cW, 4, toL1("Description MITRE : "+descOff), "", "L", false)
				r.pdf.Ln(1)
			}
			if detectionOff != "" {
				r.pdf.SetX(r.mL)
				r.pdf.SetFont("Helvetica", "I", 7)
				r.pdf.SetTextColor(colBlue.r, colBlue.g, colBlue.b)
				r.pdf.MultiCell(r.cW, 4, toL1("Detection : "+detectionOff), "", "L", false)
				r.pdf.Ln(1)
			}
			// Corps observation
			if t.Observation != "" {
				r.pdf.SetFillColor(colBg.r, colBg.g, colBg.b)
				yObs := r.pdf.GetY()
				r.pdf.SetX(r.mL + 3)
				r.pdf.SetFont("Helvetica", "", 8.5)
				r.pdf.SetTextColor(colText.r, colText.g, colText.b)
				r.pdf.MultiCell(r.cW-6, 5, toL1(t.Observation), "", "L", true)
				_ = yObs
			}
			// Source URL MITRE
			if t.SourceURL != "" && t.SourceURL != "https://attack.mitre.org/techniques/TXXX/" {
				r.pdf.SetX(r.mL + 3)
				r.pdf.SetFont("Helvetica", "I", 7)
				r.pdf.SetTextColor(colBlue.r, colBlue.g, colBlue.b)
				r.pdf.MultiCell(r.cW-6, 4, toL1("Reference : "+t.SourceURL), "", "L", false)
			}
			r.pdf.Ln(3)
		}
	}
}

// ─── Section attribution ──────────────────────────────────────────────────────

func (r *AIReporter) attributionSection(report *ForensicReport) {
	r.pdf.AddPage()
	r.pageTitle("IDENTIFICATION DE LA MENACE", "7.")
	r.chapIntro("Attribution du malware à une famille connue, groupe d'attaquants et niveau de confiance de l'analyse.")

	attr := report.Attribution
	cc := classColor(report.Classification)

	rows := [][]string{
		{"Famille de malware identifiée", attr.FamillePresumee},
		{"Niveau de confiance", attr.Confiance},
	}
	if attr.GroupePresume != "" {
		rows = append(rows, []string{"Groupe / Acteur menaçant présumé", attr.GroupePresume})
	}
	if len(attr.AutresHypotheses) > 0 {
		rows = append(rows, []string{"Hypothèses alternatives", strings.Join(attr.AutresHypotheses, " | ")})
	}
	r.metricTable(rows, cc)

	if len(attr.Indicateurs) > 0 {
		r.subSection("Indicateurs d'attribution")
		for i, ind := range attr.Indicateurs {
			y := r.pdf.GetY()
			r.pdf.SetFillColor(colBg.r, colBg.g, colBg.b)
			r.pdf.SetXY(r.mL, y)
			r.pdf.SetFont("Helvetica", "B", 8)
			r.pdf.SetTextColor(cc.r, cc.g, cc.b)
			r.pdf.CellFormat(8, 5.5, toL1(fmt.Sprintf("%d.", i+1)), "", 0, "L", false, 0, "")
			r.pdf.SetFont("Helvetica", "", 9)
			r.pdf.SetTextColor(colText.r, colText.g, colText.b)
			r.pdf.MultiCell(r.cW-8, 5, toL1(ind), "", "L", false)
			r.pdf.Ln(1)
		}
	}
}

// ─── Section recommandations ──────────────────────────────────────────────────

func (r *AIReporter) recommendationsSection(report *ForensicReport) {
	r.pdf.AddPage()
	r.pageTitle("PLAN D'ACTION RECOMMANDÉ", "8.")
	r.chapIntro(fmt.Sprintf(
		"%d action(s) de remédiation classées par priorité. Chaque action inclut un délai recommandé et des instructions concrètes.",
		len(report.Recommandations)))

	for idx, rec := range report.Recommandations {
		if r.pdf.GetY() > r.pageH-55 {
			r.pdf.AddPage()
		}

		cc := prioColor(rec.Priorite)
		cbg := classBg(rec.Priorite)
		r.pdf.Ln(2)
		yStart := r.pdf.GetY()

		// Calcul hauteur totale de la carte
		r.pdf.SetFont("Helvetica", "", 8.5)
		detailLines := r.pdf.SplitLines([]byte(toL1(rec.Detail)), r.cW-12)
		cardH := 10.0 + float64(len(detailLines))*4.8 + 8

		if yStart+cardH > r.pageH-22 {
			r.pdf.AddPage()
			yStart = r.pdf.GetY()
		}

		// Fond carte
		r.pdf.SetFillColor(cbg.r, cbg.g, cbg.b)
		r.pdf.Rect(r.mL, yStart, r.cW, cardH, "F")
		r.pdf.SetDrawColor(cc.r, cc.g, cc.b)
		r.pdf.SetLineWidth(0.2)
		r.pdf.Rect(r.mL, yStart, r.cW, cardH, "D")
		// Barre gauche
		r.pdf.SetFillColor(cc.r, cc.g, cc.b)
		r.pdf.Rect(r.mL, yStart, 4, cardH, "F")

		// Numéro de l'action
		r.pdf.SetXY(r.mL+7, yStart+2)
		r.pdf.SetFont("Helvetica", "B", 7)
		r.pdf.SetTextColor(colGrey.r, colGrey.g, colGrey.b)
		r.pdf.CellFormat(12, 4, toL1(fmt.Sprintf("ACTION %d", idx+1)), "", 0, "L", false, 0, "")

		// Badges priorité + catégorie + deadline
		r.pdf.SetFont("Helvetica", "B", 7)
		r.pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
		r.pdf.SetFillColor(cc.r, cc.g, cc.b)
		r.pdf.CellFormat(24, 4, toL1(rec.Priorite), "0", 0, "C", true, 0, "")
		r.pdf.SetFillColor(colNavy.r, colNavy.g, colNavy.b)
		r.pdf.CellFormat(28, 4, toL1(rec.Categorie), "0", 0, "C", true, 0, "")
		if rec.Deadline != "" {
			r.pdf.SetFillColor(colSteel.r, colSteel.g, colSteel.b)
			r.pdf.CellFormat(26, 4, toL1(rec.Deadline), "0", 0, "C", true, 0, "")
		}

		// Titre action
		r.pdf.SetXY(r.mL+7, yStart+7.5)
		r.pdf.SetFont("Helvetica", "B", 9)
		r.pdf.SetTextColor(cc.r, cc.g, cc.b)
		r.pdf.MultiCell(r.cW-11, 5, toL1(rec.Action), "", "L", false)

		// Détail
		if rec.Detail != "" {
			r.pdf.SetX(r.mL + 7)
			r.pdf.SetFont("Helvetica", "", 8.5)
			r.pdf.SetTextColor(colText.r, colText.g, colText.b)
			r.pdf.MultiCell(r.cW-11, 4.8, toL1(rec.Detail), "", "L", false)
		}

		r.pdf.SetXY(r.mL, yStart+cardH+2)
	}
	r.pdf.SetTextColor(0, 0, 0)
}

// ─── Section conclusion ───────────────────────────────────────────────────────

func (r *AIReporter) conclusionSection(report *ForensicReport) {
	r.pdf.AddPage()
	r.pageTitle("CONCLUSION ET SYNTHÈSE", "9.")

	cc := classColor(report.Classification)
	cbg := classBg(report.Classification)

	// Grande boite de verdict
	pdf := r.pdf
	pdf.Ln(4)
	bY := pdf.GetY()
	pdf.SetFillColor(cbg.r, cbg.g, cbg.b)
	pdf.Rect(r.mL, bY, r.cW, 28, "F")
	pdf.SetFillColor(cc.r, cc.g, cc.b)
	pdf.Rect(r.mL, bY, 5, 28, "F")
	pdf.SetDrawColor(cc.r, cc.g, cc.b)
	pdf.SetLineWidth(0.3)
	pdf.Rect(r.mL, bY, r.cW, 28, "D")

	pdf.SetXY(r.mL+9, bY+4)
	pdf.SetFont("Helvetica", "B", 7)
	pdf.SetTextColor(colGrey.r, colGrey.g, colGrey.b)
	pdf.CellFormat(r.cW-12, 4, "VERDICT FINAL", "", 1, "L", false, 0, "")
	pdf.SetX(r.mL + 9)
	pdf.SetFont("Helvetica", "B", 13)
	pdf.SetTextColor(cc.r, cc.g, cc.b)
	pdf.CellFormat(r.cW-12, 8,
		toL1("MENACE "+strings.ToUpper(report.Classification)+" — Confiance : "+report.NiveauConfiance),
		"", 1, "L", false, 0, "")
	pdf.SetX(r.mL + 9)
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(colText2.r, colText2.g, colText2.b)
	fam := report.Attribution.FamillePresumee
	if fam == "" {
		fam = "Non determinee"
	}
	pdf.CellFormat(r.cW-12, 5,
		toL1(fmt.Sprintf("Famille : %s  |  Score : %d/10  |  %d techniques  |  %d actions requises",
			fam, report.ScoreGlobal, len(report.TechniquesMitre), len(report.Recommandations))),
		"", 0, "L", false, 0, "")
	pdf.Ln(36)

	// Texte conclusion IA
	r.subSection("Analyse de risque globale")
	r.richParagraph(report.Conclusion)

	// Prochaines étapes urgentes
	if len(report.Recommandations) > 0 {
		pdf.Ln(3)
		r.subSection("Actions immédiates à prendre")
		for _, rec := range report.Recommandations {
			if strings.ToUpper(rec.Priorite) != "CRITIQUE" {
				continue
			}
			if pdf.GetY() > r.pageH-30 {
				break
			}
			c := classColor(rec.Priorite)
			pdf.SetX(r.mL)
			pdf.SetFillColor(c.r, c.g, c.b)
			pdf.SetFont("Helvetica", "B", 7)
			pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
			pdf.CellFormat(22, 5, "CRITIQUE", "0", 0, "C", true, 0, "")
			pdf.SetFont("Helvetica", "", 8.5)
			pdf.SetTextColor(colText.r, colText.g, colText.b)
			pdf.MultiCell(r.cW-22, 5, toL1("  "+rec.Action), "", "L", false)
		}
	}

	pdf.SetTextColor(0, 0, 0)

	// ── Pied de page : métadonnées de génération ────────────────────────────────
	if r.generationSecs > 0 {
		pdf.SetY(r.pageH - 22)
		pdf.SetFont("Helvetica", "", 7)
		pdf.SetTextColor(120, 130, 150)
		durLabel := fmt.Sprintf("Durée analyse IA : %dm%02ds", r.generationSecs/60, r.generationSecs%60)
		if r.engineName != "" {
			durLabel += " — " + r.engineName
		}
		pdf.CellFormat(r.cW, 4, toL1(durLabel), "", 1, "C", false, 0, "")
		pdf.SetFont("Helvetica", "", 6.5)
		pdf.SetTextColor(150, 160, 175)
		pdf.CellFormat(r.cW, 4,
			toL1("Généré par Analyseur Forensic IA CCM Bercy — modèle local llama.cpp — aucune donnée transmise à un tiers"),
			"", 1, "C", false, 0, "")
	}
}

// ─── Primitives de mise en page ───────────────────────────────────────────────

// pageTitle : titre principal de section avec numérotation
func (r *AIReporter) pageTitle(title, num string) {
	pdf := r.pdf
	pdf.Ln(4)
	y := pdf.GetY()

	// Fond du titre
	pdf.SetFillColor(colNavy.r, colNavy.g, colNavy.b)
	pdf.Rect(r.mL, y, r.cW, 9, "F")
	// Accent gauche
	cc := classColor(r.classification)
	pdf.SetFillColor(cc.r, cc.g, cc.b)
	pdf.Rect(r.mL, y, 3, 9, "F")

	// Numéro
	if num != "" {
		pdf.SetXY(r.mL+5, y+1.5)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetTextColor(cc.r, cc.g, cc.b)
		pdf.CellFormat(10, 6, toL1(num), "", 0, "L", false, 0, "")
	}

	// Titre
	xTitle := r.mL + 5
	if num != "" {
		xTitle = r.mL + 16
	}
	pdf.SetXY(xTitle, y+1.5)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
	pdf.CellFormat(r.cW-20, 6, toL1(title), "", 0, "L", false, 0, "")

	pdf.SetTextColor(0, 0, 0)
	pdf.Ln(13)
}

// chapIntro : texte d'introduction italique sous le titre
func (r *AIReporter) sectionConclusion(text string) {
	if text == "" {
		return
	}
	pdf := r.pdf
	pdf.Ln(4)

	// Calculer la hauteur réelle du texte AVANT de dessiner le fond
	// pour éviter que le texte déborde hors du rectangle de fond.
	pdf.SetFont("Helvetica", "I", 8.5)
	lineH := 5.0
	lines := pdf.SplitLines([]byte(toL1(text)), r.cW-12)
	textH := float64(len(lines))*lineH + 2
	boxH := textH + 8 // 4 pour "SYNTHESE" + 4 de marge haut/bas
	if boxH < 14 {
		boxH = 14
	}

	y := pdf.GetY()
	// Vérifier qu'il y a assez de place sur la page
	if y+boxH > r.pageH-22 {
		pdf.AddPage()
		y = pdf.GetY()
	}

	pdf.SetFillColor(colNavy.r, colNavy.g, colNavy.b)
	pdf.Rect(r.mL, y, 3, boxH, "F")
	pdf.SetFillColor(colBg.r, colBg.g, colBg.b)
	pdf.Rect(r.mL+3, y, r.cW-3, boxH, "F")

	pdf.SetXY(r.mL+8, y+1.5)
	pdf.SetFont("Helvetica", "B", 7)
	pdf.SetTextColor(colNavy.r, colNavy.g, colNavy.b)
	pdf.CellFormat(r.cW-12, 4, "SYNTHESE", "", 1, "L", false, 0, "")
	pdf.SetX(r.mL + 8)
	pdf.SetFont("Helvetica", "I", 8.5)
	pdf.SetTextColor(colText.r, colText.g, colText.b)
	pdf.MultiCell(r.cW-12, lineH, toL1(text), "", "L", false)
	pdf.Ln(4)
	pdf.SetTextColor(0, 0, 0)
}

func (r *AIReporter) chapIntro(text string) {
	r.pdf.SetFont("Helvetica", "I", 8.5)
	r.pdf.SetTextColor(colGrey.r, colGrey.g, colGrey.b)
	r.pdf.SetX(r.mL)
	r.pdf.MultiCell(r.cW, 4.5, toL1(text), "", "L", false)
	r.pdf.SetTextColor(0, 0, 0)
	r.pdf.Ln(3)
}

// subSection : sous-titre avec barre bleue
func (r *AIReporter) subSection(title string) {
	r.pdf.Ln(2)
	y := r.pdf.GetY()
	r.pdf.SetFillColor(colBg2.r, colBg2.g, colBg2.b)
	r.pdf.Rect(r.mL, y, r.cW, 6.5, "F")
	r.pdf.SetFillColor(colBlue.r, colBlue.g, colBlue.b)
	r.pdf.Rect(r.mL, y, 2.5, 6.5, "F")
	r.pdf.SetXY(r.mL+5, y+0.5)
	r.pdf.SetFont("Helvetica", "B", 8.5)
	r.pdf.SetTextColor(colNavy.r, colNavy.g, colNavy.b)
	r.pdf.CellFormat(r.cW-8, 5.5, toL1(title), "", 1, "L", false, 0, "")
	r.pdf.SetTextColor(0, 0, 0)
	r.pdf.Ln(3)
}

// richParagraph : texte riche multi-paragraphes avec détection de listes
func (r *AIReporter) richParagraph(text string) {
	if text == "" || strings.Contains(strings.ToLower(text), "insuffisante") {
		r.pdf.SetFont("Helvetica", "I", 8.5)
		r.pdf.SetTextColor(colGrey.r, colGrey.g, colGrey.b)
		r.pdf.SetX(r.mL)
		r.pdf.MultiCell(r.cW, 5, toL1("Donnees insuffisantes pour cette section."), "", "L", false)
		r.pdf.SetTextColor(0, 0, 0)
		return
	}

	paragraphs := strings.Split(text, "\n")
	r.pdf.SetTextColor(colText.r, colText.g, colText.b)

	for _, p := range paragraphs {
		p = strings.TrimSpace(p)
		if p == "" {
			r.pdf.Ln(2)
			continue
		}
		// Titre inline (**...**)
		if strings.HasPrefix(p, "**") {
			p = strings.Trim(p, "*# ")
			r.pdf.SetFont("Helvetica", "B", 9)
			r.pdf.SetTextColor(colNavy.r, colNavy.g, colNavy.b)
			r.pdf.SetX(r.mL)
			r.pdf.MultiCell(r.cW, 5, toL1(p), "", "L", false)
			r.pdf.SetFont("Helvetica", "", 9)
			r.pdf.SetTextColor(colText.r, colText.g, colText.b)
			continue
		}
		// Élément de liste
		if strings.HasPrefix(p, "- ") || strings.HasPrefix(p, "• ") || strings.HasPrefix(p, "* ") {
			bullet := strings.TrimLeft(p, "-•* ")
			y := r.pdf.GetY()
			r.pdf.SetFillColor(colBlue.r, colBlue.g, colBlue.b)
			r.pdf.Circle(r.mL+2.8, y+2.5, 1, "F")
			r.pdf.SetXY(r.mL+6, y)
			r.pdf.SetFont("Helvetica", "", 8.5)
			r.pdf.SetTextColor(colText.r, colText.g, colText.b)
			r.pdf.MultiCell(r.cW-6, 4.8, toL1(bullet), "", "L", false)
			continue
		}
		// Paragraphe normal
		r.pdf.SetFont("Helvetica", "", 9)
		r.pdf.SetX(r.mL)
		r.pdf.MultiCell(r.cW, 5, toL1(p), "", "J", false)
	}
	r.pdf.Ln(2)
	r.pdf.SetTextColor(0, 0, 0)
}

// metricTable : tableau indicateurs 2 colonnes stylé
func (r *AIReporter) metricTable(rows [][]string, hdrColor color) {
	pdf := r.pdf
	w1, w2 := 80.0, r.cW-80

	for i, row := range rows {
		if len(row) < 2 {
			continue
		}
		y := pdf.GetY()
		if y > r.pageH-28 {
			pdf.AddPage()
		}
		// Fond alterné
		if i%2 == 0 {
			pdf.SetFillColor(colBg.r, colBg.g, colBg.b)
		} else {
			pdf.SetFillColor(colWhite.r, colWhite.g, colWhite.b)
		}
		pdf.Rect(r.mL, pdf.GetY(), r.cW, 7, "F")
		pdf.SetDrawColor(colBorder.r, colBorder.g, colBorder.b)
		pdf.SetLineWidth(0.1)
		pdf.Line(r.mL, pdf.GetY(), r.mL+r.cW, pdf.GetY())

		pdf.SetXY(r.mL+3, pdf.GetY()+1)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetTextColor(colText2.r, colText2.g, colText2.b)
		pdf.CellFormat(w1, 5, toL1(row[0]), "", 0, "L", false, 0, "")

		// Valeur avec couleur selon contenu
		valColor := hdrColor
		val := row[1]
		if strings.Contains(strings.ToUpper(val), "CRITIQUE") {
			valColor = colRed
		} else if strings.Contains(strings.ToUpper(val), "ÉLEVÉ") || strings.Contains(strings.ToUpper(val), "ELEVE") {
			valColor = colOrange
		} else if strings.Contains(strings.ToUpper(val), "MOYEN") {
			valColor = colYellow
		} else if strings.Contains(strings.ToUpper(val), "FAIBLE") || strings.Contains(strings.ToUpper(val), "BENIN") {
			valColor = colGreen
		}
		pdf.SetFont("Helvetica", "B", 8.5)
		pdf.SetTextColor(valColor.r, valColor.g, valColor.b)
		// MultiCell pour ne jamais tronquer (hash SHA256, URLs, etc.)
		pdf.MultiCell(w2-3, 4.5, toL1(val), "", "L", false)
	}
	// Ligne basse
	pdf.SetDrawColor(colBorder.r, colBorder.g, colBorder.b)
	pdf.Line(r.mL, pdf.GetY(), r.mL+r.cW, pdf.GetY())
	pdf.Ln(5)
	pdf.SetTextColor(0, 0, 0)
}

// iocTable : tableau IOC avec en-tete colore, valeurs jamais tronquees
func (r *AIReporter) iocTable(rows [][]string) {
	pdf := r.pdf
	// Colonne "Type"   : 22mm — "Hash-SHA256", "Domaine", "IP", "Fichier" tiennent
	// Colonne "Valeur" : 75mm — SHA256 (64 chars à 6pt ≈ 70mm) avec un léger retrait
	// Colonne "Contexte": espace restant
	// Colonne "Risque" : 22mm — badge de criticité
	widths := []float64{22, 75, r.cW - 119, 22}
	headers := []string{"Type", "Valeur / IOC", "Contexte", "Risque"}

	drawHdr := func() {
		pdf.SetFillColor(colNavy.r, colNavy.g, colNavy.b)
		pdf.SetFont("Helvetica", "B", 7.5)
		pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
		pdf.SetX(r.mL)
		for i, h := range headers {
			pdf.CellFormat(widths[i], 6, toL1(h), "1", 0, "C", true, 0, "")
		}
		pdf.Ln(-1)
	}
	drawHdr()

	for ri, row := range rows {
		// Calculer la hauteur réelle de chaque cellule (font 6.5pt pour les hashes longs)
		lineH := 4.5
		maxCellH := lineH + 2
		for i, cell := range row {
			if i >= len(widths) {
				break
			}
			// Hashes et URLs : police plus petite pour tenir dans la colonne
			fs := 7.5
			if i == 1 && (strings.HasPrefix(row[0], "Hash") || len(cell) > 40) {
				fs = 6.5
			}
			pdf.SetFont("Helvetica", "", fs)
			ls := pdf.SplitLines([]byte(toL1(cell)), widths[i]-3)
			h := float64(len(ls))*lineH + 2
			if h > maxCellH {
				maxCellH = h
			}
		}
		if maxCellH < 7 {
			maxCellH = 7
		}
		if pdf.GetY()+maxCellH > r.pageH-22 {
			pdf.AddPage()
			drawHdr()
		}

		rowY := pdf.GetY()
		x := r.mL
		// Dessiner les fonds d'abord
		for i := range row {
			if i >= len(widths) {
				break
			}
			if i == 3 {
				rc := classColor(row[3])
				pdf.SetFillColor(rc.r, rc.g, rc.b)
			} else if ri%2 == 0 {
				pdf.SetFillColor(colBg.r, colBg.g, colBg.b)
			} else {
				pdf.SetFillColor(colWhite.r, colWhite.g, colWhite.b)
			}
			pdf.Rect(x, rowY, widths[i], maxCellH, "F")
			pdf.SetDrawColor(colBorder.r, colBorder.g, colBorder.b)
			pdf.SetLineWidth(0.1)
			pdf.Rect(x, rowY, widths[i], maxCellH, "D")
			x += widths[i]
		}
		// Écrire le texte par-dessus
		x = r.mL
		for i, cell := range row {
			if i >= len(widths) {
				break
			}
			pdf.SetXY(x+1, rowY+1)
			if i == 3 {
				pdf.SetFont("Helvetica", "B", 7)
				pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
				pdf.MultiCell(widths[i]-2, lineH, toL1(cell), "", "C", false)
			} else if i == 1 && (strings.HasPrefix(row[0], "Hash") || len(cell) > 40) {
				// Hashes et longues valeurs : police réduite pour tenir sur 2 lignes max
				pdf.SetFont("Helvetica", "", 6.5)
				pdf.SetTextColor(colText.r, colText.g, colText.b)
				pdf.MultiCell(widths[i]-2, lineH, toL1(cell), "", "L", false)
			} else {
				pdf.SetFont("Helvetica", "", 7.5)
				pdf.SetTextColor(colText.r, colText.g, colText.b)
				pdf.MultiCell(widths[i]-2, lineH, toL1(cell), "", "L", false)
			}
			x += widths[i]
		}
		pdf.SetXY(r.mL, rowY+maxCellH)
	}
	pdf.SetTextColor(0, 0, 0)
	pdf.SetFillColor(colWhite.r, colWhite.g, colWhite.b)
	pdf.Ln(4)
}

// geoTable : tableau de geolocalisation des IPs
func (r *AIReporter) geoTable(rows [][]string) {
	pdf := r.pdf
	// Largeurs adaptees : IP | Pays | Ville | FAI | ASN
	widths := []float64{28, 35, 30, r.cW - 120, 27}
	headers := []string{"IP", "Pays", "Ville", "FAI / Operateur", "ASN"}

	drawHdr := func() {
		pdf.SetFillColor(colNavy.r, colNavy.g, colNavy.b)
		pdf.SetFont("Helvetica", "B", 7.5)
		pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
		pdf.SetX(r.mL)
		for i, h := range headers {
			pdf.CellFormat(widths[i], 6, toL1(h), "1", 0, "C", true, 0, "")
		}
		pdf.Ln(-1)
	}
	drawHdr()

	for ri, row := range rows {
		// Calcul hauteur necessaire pour chaque cellule
		maxLines := 1
		for i, cell := range row {
			if i < len(widths) {
				ls := pdf.SplitLines([]byte(toL1(cell)), widths[i]-2)
				if len(ls) > maxLines {
					maxLines = len(ls)
				}
			}
		}
		cellH := float64(maxLines)*4.5 + 2
		if cellH < 7 {
			cellH = 7
		}

		if pdf.GetY()+cellH > r.pageH-22 {
			pdf.AddPage()
			drawHdr()
		}
		rowY := pdf.GetY()
		x := r.mL
		for i, cell := range row {
			if i >= len(widths) {
				break
			}
			if ri%2 == 0 {
				pdf.SetFillColor(colBg.r, colBg.g, colBg.b)
			} else {
				pdf.SetFillColor(colWhite.r, colWhite.g, colWhite.b)
			}
			pdf.SetFont("Helvetica", "", 7.5)
			pdf.SetTextColor(colText.r, colText.g, colText.b)
			pdf.SetXY(x, rowY)
			// Utiliser MultiCell pour ne jamais tronquer
			pdf.MultiCell(widths[i], cellH/float64(maxLines), toL1(cell), "1", "L", true)
			x += widths[i]
		}
		pdf.SetXY(r.mL, rowY+cellH)
	}
	pdf.SetTextColor(0, 0, 0)
	pdf.Ln(4)
}

// abuseIPDBTable : tableau de réputation AbuseIPDB
func (r *AIReporter) abuseIPDBTable(reps map[string]IPReputation) {
	pdf := r.pdf
	widths := []float64{30, 22, 35, r.cW - 118, 15, 16}
	headers := []string{"IP", "Score", "Pays / FAI", "Categories d'abus", "Signalements", "Statut"}

	drawHdr := func() {
		pdf.SetFillColor(colNavy.r, colNavy.g, colNavy.b)
		pdf.SetFont("Helvetica", "B", 7)
		pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
		pdf.SetX(r.mL)
		for i, h := range headers {
			pdf.CellFormat(widths[i], 6, toL1(h), "1", 0, "C", true, 0, "")
		}
		pdf.Ln(-1)
	}
	drawHdr()

	// Trier les IPs par score décroissant
	type ipScore struct {
		ip  string
		rep IPReputation
	}
	sorted := make([]ipScore, 0, len(reps))
	for ip, rep := range reps {
		sorted = append(sorted, ipScore{ip, rep})
	}
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].rep.Score > sorted[i].rep.Score {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	for ri, item := range sorted {
		rep := item.rep
		if pdf.GetY() > r.pageH-22 {
			pdf.AddPage()
			drawHdr()
		}
		rowY := pdf.GetY()
		x := r.mL
		// Fond selon malveillance
		var rowBg color
		if rep.EstMalveillant {
			rowBg = colRedBg
		} else if ri%2 == 0 {
			rowBg = colBg
		} else {
			rowBg = colWhite
		}

		cellH := 7.0
		cells := []string{
			rep.IP,
			fmt.Sprintf("%d/100", rep.Score),
			rep.Pays + "\n" + truncate(rep.ISP, 20),
			strings.Join(rep.Categories, ", "),
			fmt.Sprintf("%d", rep.TotalReports),
			func() string {
				if rep.EstMalveillant {
					return "MALVEIL."
				}
				return "OK"
			}(),
		}

		// Fond
		for i, w := range widths {
			_ = cells[i]
			if i == 5 {
				if rep.EstMalveillant {
					pdf.SetFillColor(colRed.r, colRed.g, colRed.b)
				} else {
					pdf.SetFillColor(colGreen.r, colGreen.g, colGreen.b)
				}
			} else {
				pdf.SetFillColor(rowBg.r, rowBg.g, rowBg.b)
			}
			pdf.Rect(x, rowY, w, cellH, "F")
			pdf.SetDrawColor(colBorder.r, colBorder.g, colBorder.b)
			pdf.SetLineWidth(0.1)
			pdf.Rect(x, rowY, w, cellH, "D")
			x += w
		}
		// Texte
		x = r.mL
		for i, cell := range cells {
			pdf.SetXY(x+1, rowY+1.5)
			if i == 5 {
				pdf.SetFont("Helvetica", "B", 6.5)
				pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
				pdf.CellFormat(widths[i]-2, cellH-3, toL1(cell), "", 0, "C", false, 0, "")
			} else if i == 1 {
				// Score coloré
				scoreC := colGreen
				if rep.Score >= 75 {
					scoreC = colRed
				} else if rep.Score >= 25 {
					scoreC = colOrange
				}
				pdf.SetFont("Helvetica", "B", 8)
				pdf.SetTextColor(scoreC.r, scoreC.g, scoreC.b)
				pdf.CellFormat(widths[i]-2, cellH-3, toL1(cell), "", 0, "C", false, 0, "")
			} else {
				pdf.SetFont("Helvetica", "", 7)
				pdf.SetTextColor(colText.r, colText.g, colText.b)
				pdf.MultiCell(widths[i]-2, 3.5, toL1(cell), "", "L", false)
			}
			x += widths[i]
		}
		pdf.SetXY(r.mL, rowY+cellH)
	}
	pdf.SetTextColor(0, 0, 0)
	pdf.Ln(4)
}

// ─── Section preuves kernel ───────────────────────────────────────────────────

// kernelEvidenceSection affiche les événements kernel les plus significatifs.
// Montre les preuves concrètes : fichiers créés, connexions réseau, tâches planifiées.
// ─── Section cmdlines suspectes ──────────────────────────────────────────────

func (r *AIReporter) cmdlineSection(processes []models.ProcessWithTask) {
	if len(processes) == 0 {
		return
	}
	// Filtrer les cmdlines suspectes (curl, ftp, schtasks, powershell, wscript...)
	suspectKeywords := []string{"curl", "ftp", "schtasks", "powershell", "invoke-",
		"wscript", "cscript", "mshta", "regsvr32", "rundll32", "certutil", "bitsadmin"}
	type suspectCmd struct {
		binary  string
		cmdline string
		taskID  string
	}
	var cmds []suspectCmd
	for _, p := range processes {
		if p.Cmd == nil {
			continue
		}
		cmdStr := ""
		switch v := p.Cmd.(type) {
		case string:
			cmdStr = v
		case []interface{}:
			parts := make([]string, 0)
			for _, c := range v {
				if s, ok := c.(string); ok {
					parts = append(parts, s)
				}
			}
			cmdStr = strings.Join(parts, " ")
		}
		if cmdStr == "" {
			continue
		}
		lower := strings.ToLower(cmdStr)
		for _, kw := range suspectKeywords {
			if strings.Contains(lower, kw) {
				parts := strings.Split(strings.ReplaceAll(p.Image, "\\", "/"), "/")
				binary := parts[len(parts)-1]
				cmds = append(cmds, suspectCmd{binary: binary, cmdline: cmdStr, taskID: p.TaskID})
				break
			}
		}
		if len(cmds) >= 10 {
			break
		}
	}
	if len(cmds) == 0 {
		return
	}
	r.pdf.AddPage()
	r.pageTitle("COMMANDES SUSPECTES DÉTECTÉES", "")
	r.chapIntro(fmt.Sprintf(
		"%d commande(s) suspecte(s) identifiee(s) — curl, ftp, schtasks, PowerShell, WScript. "+
			"Ces commandes indiquent des capacites de telechargement, d'exfiltration et de persistance.",
		len(cmds)))
	r.subSection(fmt.Sprintf("Cmdlines suspectes — %d detectee(s)", len(cmds)))
	rows := make([][]string, 0, len(cmds))
	for _, cmd := range cmds {
		display := cmd.cmdline
		if len(display) > 120 {
			display = display[:120] + "..."
		}
		rows = append(rows, []string{
			cmd.binary,
			display,
			"SUSPECT",
		})
	}
	// Table avec 3 colonnes : Binaire | Cmdline | Risque
	colW := []float64{30, r.cW - 50, 20}
	headers := []string{"Binaire", "Ligne de commande", "Risque"}
	r.pdf.SetFont("Helvetica", "B", 7.5)
	r.pdf.SetFillColor(20, 30, 60)
	r.pdf.SetTextColor(255, 255, 255)
	x := r.mL
	for i, h := range headers {
		r.pdf.SetXY(x, r.pdf.GetY())
		r.pdf.CellFormat(colW[i], 7, toL1(h), "0", 0, "L", true, 0, "")
		x += colW[i]
	}
	r.pdf.Ln(7)
	r.pdf.SetFont("Helvetica", "", 7)
	alt := false
	for _, row := range rows {
		if alt {
			r.pdf.SetFillColor(240, 244, 255)
		} else {
			r.pdf.SetFillColor(255, 255, 255)
		}
		r.pdf.SetTextColor(20, 30, 60)
		x = r.mL
		for i, cell := range row {
			r.pdf.SetXY(x, r.pdf.GetY())
			fill := i < 2
			r.pdf.CellFormat(colW[i], 6.5, toL1(cell), "0", 0, "L", fill, 0, "")
			x += colW[i]
		}
		r.pdf.Ln(6.5)
		alt = !alt
	}
}

func (r *AIReporter) kernelEvidenceSection(evs []models.KernelEvent) {
	r.pdf.AddPage()
	r.pageTitle("PREUVES KERNEL — TIMELINE TECHNIQUE", "")
	r.chapIntro(toL1("Evenements observes directement par le moniteur kernel de RF Sandbox. " +
		"Ces donnees constituent les preuves techniques de l'activite malveillante."))

	r.subSection(fmt.Sprintf("Evenements significatifs detectes (%d)", len(evs)))

	rows := make([][]string, 0, len(evs))
	for _, ev := range evs {
		t := ""
		if ev.TimeMs > 0 {
			t = fmt.Sprintf("+%ds", ev.TimeMs/1000)
		}
		img := ev.Image
		if len(img) > 20 {
			parts := strings.Split(strings.ReplaceAll(img, "\\", "/"), "/")
			img = parts[len(parts)-1]
		}
		target := ev.Target
		if len(target) > 50 {
			target = "..." + target[len(target)-47:]
		}
		rows = append(rows, []string{t, img, ev.Action, target})
	}

	// Tableau compact: temps | processus | action | cible
	pdf := r.pdf
	pdf.SetFont("Helvetica", "B", 7)
	pdf.SetFillColor(30, 40, 70)
	pdf.SetTextColor(255, 255, 255)
	headers := []string{"T+", "Processus", "Action", "Cible"}
	widths := []float64{12, 32, 28, r.cW - 76}
	for i, h := range headers {
		pdf.CellFormat(widths[i], 5.5, h, "0", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", 6.5)
	for i, row := range rows {
		if pdf.GetY() > r.pageH-25 {
			pdf.AddPage()
			r.drawHeader()
		}
		bg := i%2 == 0
		if bg {
			pdf.SetFillColor(245, 247, 250)
		} else {
			pdf.SetFillColor(255, 255, 255)
		}
		pdf.SetTextColor(30, 41, 59)
		for j, cell := range row {
			pdf.CellFormat(widths[j], 5, toL1(cell), "0", 0, "L", bg, 0, "")
		}
		pdf.Ln(-1)
	}
}

// extractKernelEventsForPDF sélectionne les N événements les plus significatifs pour le PDF.
func extractKernelEventsForPDF(results []*models.AnalysisResult, n int) []models.KernelEvent {
	// Pour le PDF, on filtre les events les plus significatifs mais sans limite stricte.
	// n est utilisé comme guide si > 0, mais tous les events significatifs sont inclus.
	var critical []models.KernelEvent
	for _, r := range results {
		for _, ev := range r.KernelEvents {
			a := strings.ToLower(ev.Action)
			t := strings.ToLower(ev.Target)
			if (strings.Contains(a, "file") && strings.Contains(a, "create") &&
				(strings.Contains(t, ".exe") || strings.Contains(t, ".dll") || strings.Contains(t, ".bat") ||
					strings.Contains(t, ".ps1") || strings.Contains(t, ".vbs") || strings.Contains(t, ".js"))) ||
				strings.Contains(a, "file_delete") ||
				strings.Contains(a, "net") || strings.Contains(a, "connect") ||
				strings.Contains(a, "sched") || strings.Contains(t, "schtasks") ||
				strings.Contains(a, "reg") ||
				strings.Contains(t, "users\\public") || strings.Contains(t, "users/public") {
				critical = append(critical, ev)
			}
		}
	}
	// Tri chronologique
	for i := 0; i < len(critical)-1; i++ {
		for j := i + 1; j < len(critical); j++ {
			if critical[j].TimeMs < critical[i].TimeMs {
				critical[i], critical[j] = critical[j], critical[i]
			}
		}
	}
	// Appliquer la limite n uniquement si > 0
	if n > 0 && len(critical) > n {
		return critical[:n]
	}
	return critical
}

// ─── Section fichiers déposés ──────────────────────────────────────────────────

// droppedFilesSection affiche les fichiers déposés par le malware (payloads 2ème stage).
func (r *AIReporter) droppedFilesSection(files []models.DroppedFileInfo) {
	r.pdf.AddPage()
	r.pageTitle("FICHIERS DEPOSES PAR LE MALWARE", "")
	r.chapIntro(toL1("Payloads de 2eme stage telecharges et executes par le malware initial. " +
		"Ces fichiers constituent des IOCs supplementaires a bloquer dans l'EDR et l'antivirus."))

	r.subSection(fmt.Sprintf("Payloads detectes (%d fichier(s))", len(files)))

	pdf := r.pdf
	pdf.SetFont("Helvetica", "B", 7.5)
	pdf.SetFillColor(30, 40, 70)
	pdf.SetTextColor(255, 255, 255)
	headers := []string{"Nom", "Type", "Taille", "SHA256 (partiel)"}
	widths := []float64{60, 18, 18, r.cW - 100}
	for i, h := range headers {
		pdf.CellFormat(widths[i], 6, h, "0", 0, "L", true, 0, "")
	}
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", 7)
	for i, f := range files {
		if pdf.GetY() > r.pageH-25 {
			pdf.AddPage()
			r.drawHeader()
		}
		bg := i%2 == 0
		if bg {
			pdf.SetFillColor(245, 247, 250)
		} else {
			pdf.SetFillColor(255, 255, 255)
		}
		pdf.SetTextColor(30, 41, 59)
		sha := f.SHA256
		if len(sha) > 20 {
			sha = sha[:20] + "..."
		}
		sizeFmt := fmt.Sprintf("%d B", f.Size)
		if f.Size > 1024*1024 {
			sizeFmt = fmt.Sprintf("%.1f Mo", float64(f.Size)/1024/1024)
		} else if f.Size > 1024 {
			sizeFmt = fmt.Sprintf("%.1f Ko", float64(f.Size)/1024)
		}
		row := []string{toL1(f.Name), f.Kind, sizeFmt, sha}
		for j, cell := range row {
			pdf.CellFormat(widths[j], 5.5, cell, "0", 0, "L", bg, 0, "")
		}
		pdf.Ln(-1)
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func totalSignatures(results []*models.AnalysisResult) int {
	n := 0
	for _, r := range results {
		n += len(r.Signatures)
	}
	return n
}

func scoreLabel(score int) (color, string) {
	switch {
	case score >= 9:
		return colRed, "CRITIQUE"
	case score >= 7:
		return colOrange, "ELEVE"
	case score >= 4:
		return colYellow, "MOYEN"
	case score >= 1:
		return colGreen, "FAIBLE"
	default:
		return colGrey, "INCONNU"
	}
}

// toL1 convertit UTF-8 en Latin-1 pour gofpdf.
func toL1(s string) string {
	buf := make([]byte, 0, len(s))
	for _, r := range s {
		switch {
		case r < 0x80:
			buf = append(buf, byte(r))
		case r <= 0xFF:
			buf = append(buf, byte(r))
		case r == '\u2013' || r == '\u2014':
			buf = append(buf, '-')
		case r == '\u2018' || r == '\u2019':
			buf = append(buf, '\'')
		case r == '\u201C' || r == '\u201D':
			buf = append(buf, '"')
		case r == '\u2022', r == '\u25CF':
			buf = append(buf, '*')
		case r == '\u25B6':
			buf = append(buf, '>')
		case r == '\u2026':
			buf = append(buf, '.', '.', '.')
		case r == '\u2192':
			buf = append(buf, '-', '>')
		case r == '\u2264':
			buf = append(buf, '<', '=')
		case r == '\u2265':
			buf = append(buf, '>', '=')
		case r == '\u00AE':
			buf = append(buf, '(', 'R', ')')
		default:
			buf = append(buf, '?')
		}
	}
	return string(buf)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// sumW not used but kept for compat
func sumW(ws []float64) float64 {
	s := 0.0
	for _, w := range ws {
		s += w
	}
	return s
}
