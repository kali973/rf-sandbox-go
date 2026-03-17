package reporter

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
	"rf-sandbox-go/internal/ai"
	"rf-sandbox-go/internal/models"
)

// toL1 convertit une chaîne UTF-8 en Latin-1 (ISO-8859-1) attendu par gofpdf.
// Les caractères Unicode dans U+0000–U+00FF correspondent directement aux octets Latin-1.
// Les caractères hors de cette plage sont remplacés par '?'.
func toL1(s string) string {
	buf := make([]byte, 0, len(s))
	for _, r := range s {
		switch {
		case r < 0x80:
			buf = append(buf, byte(r))
		case r <= 0xFF:
			buf = append(buf, byte(r))
		case r == '\u2013' || r == '\u2014': // tirets longs → -
			buf = append(buf, '-')
		case r == '\u2018' || r == '\u2019': // guillemets simples → '
			buf = append(buf, '\'')
		case r == '\u201C' || r == '\u201D': // guillemets doubles → "
			buf = append(buf, '"')
		case r == '\u2022': // bullet •  → *
			buf = append(buf, '*')
		case r == '\u25CF': // ● (BLACK CIRCLE) → o
			buf = append(buf, 'o')
		case r == '\u25B6': // ▶ (BLACK RIGHT-POINTING TRIANGLE) → >
			buf = append(buf, '>')
		case r == '\u2026': // ellipsis → ...
			buf = append(buf, '.', '.', '.')
		case r == '\u2192': // → arrow
			buf = append(buf, '-', '>')
		case r == '\u2264': // ≤
			buf = append(buf, '<', '=')
		case r == '\u2265': // ≥
			buf = append(buf, '>', '=')
		default:
			buf = append(buf, '?')
		}
	}
	return string(buf)
}

// ─── Palette couleurs RF ───────────────────────────────────────────────────

type color struct{ r, g, b int }

var (
	colDark    = color{26, 26, 46}
	colNavy    = color{22, 33, 62}
	colBlue    = color{15, 52, 96}
	colAccent  = color{233, 69, 96}
	colRed     = color{211, 47, 47}
	colYellow  = color{245, 166, 35}
	colGreen   = color{39, 174, 96}
	colGrey    = color{108, 117, 125}
	colLight   = color{248, 249, 250}
	colWhite   = color{255, 255, 255}
	colDivider = color{222, 226, 230}
	colGold    = color{200, 168, 75}
)

func scoreColor(score int) (color, string) {
	switch {
	case score >= 9:
		return colRed, "CRITIQUE"
	case score >= 7:
		return colAccent, "ÉLEVÉ"
	case score >= 4:
		return colYellow, "MOYEN"
	case score >= 1:
		return colGreen, "FAIBLE"
	default:
		return colGrey, "INCONNU"
	}
}

// ─── Générateur PDF ────────────────────────────────────────────────────────

// Generator produit le rapport PDF professionnel
type Generator struct {
	pdf            *gofpdf.Fpdf
	outputPath     string
	classification string
	reportDate     string
	pageW, pageH   float64
	marginL        float64
	marginR        float64
	marginT        float64
	contentW       float64
	enrichment     *ai.EnrichmentData // données d'enrichissement MITRE + AbuseIPDB
}

// New crée un nouveau générateur
func New(outputPath, classification string) *Generator {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetAuthor("Recorded Future Sandbox Analyser", true)
	pdf.SetCreator("RF Sandbox Go Reporter", true)
	pdf.SetTitle("Recorded Future Sandbox — Rapport d'Analyse", true)

	g := &Generator{
		pdf:            pdf,
		outputPath:     outputPath,
		classification: classification,
		reportDate:     time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		marginL:        15,
		marginR:        15,
		marginT:        15,
	}
	g.pageW, g.pageH = pdf.GetPageSize()
	g.contentW = g.pageW - g.marginL - g.marginR

	pdf.SetMargins(g.marginL, g.marginT, g.marginR)
	pdf.SetAutoPageBreak(true, 18)

	pdf.SetHeaderFuncMode(func() {
		g.drawHeader()
	}, true)
	pdf.SetFooterFunc(func() {
		g.drawFooter()
	})

	return g
}

// ─── Header / Footer ──────────────────────────────────────────────────────

func (g *Generator) drawHeader() {
	pdf := g.pdf
	if pdf.PageNo() == 1 {
		return
	}
	// Ligne bleue fine en haut
	pdf.SetFillColor(colBlue.r, colBlue.g, colBlue.b)
	pdf.Rect(0, 0, g.pageW, 8, "F")
	pdf.SetFont("Helvetica", "B", 8)
	pdf.SetTextColor(colWhite.r, colWhite.g, colWhite.b)
	pdf.SetXY(g.marginL, 2)
	pdf.CellFormat(g.contentW/2, 4, toL1("RECORDED FUTURE SANDBOX — Rapport d'Analyse"), "", 0, "L", false, 0, "")
	pdf.CellFormat(g.contentW/2, 4, toL1(g.reportDate), "", 0, "R", false, 0, "")
	pdf.SetTextColor(0, 0, 0)
}

func (g *Generator) drawFooter() {
	pdf := g.pdf
	pdf.SetY(-12)
	pdf.SetFillColor(colNavy.r, colNavy.g, colNavy.b)
	pdf.Rect(0, g.pageH-10, g.pageW, 10, "F")
	pdf.SetFont("Helvetica", "", 7)
	pdf.SetTextColor(140, 150, 170)
	pdf.SetXY(g.marginL, g.pageH-8)
	pdf.CellFormat(g.contentW/2, 4,
		toL1("Recorded Future Sandbox — Rapport confidentiel — "+g.reportDate),
		"", 0, "L", false, 0, "")
	pdf.CellFormat(g.contentW/2, 4,
		toL1(fmt.Sprintf("%s  |  Page %d", g.classification, pdf.PageNo())),
		"", 0, "R", false, 0, "")
	pdf.SetTextColor(0, 0, 0)
}

// ─── Helpers mise en page ──────────────────────────────────────────────────

func (g *Generator) setFont(family, style string, size float64) {
	g.pdf.SetFont(family, style, size)
}

func (g *Generator) setColor(c color) {
	g.pdf.SetTextColor(c.r, c.g, c.b)
}

func (g *Generator) fillColor(c color) {
	g.pdf.SetFillColor(c.r, c.g, c.b)
}

func (g *Generator) drawColor(c color) {
	g.pdf.SetDrawColor(c.r, c.g, c.b)
}

func (g *Generator) x() float64   { return g.marginL }
func (g *Generator) y() float64   { return g.pdf.GetY() }
func (g *Generator) nl(h float64) { g.pdf.Ln(h) }

func (g *Generator) sectionTitle(title string) {
	g.pdf.Ln(6)
	g.fillColor(colBlue)
	g.pdf.Rect(g.marginL, g.y(), g.contentW, 7, "F")
	g.setFont("Helvetica", "B", 10)
	g.setColor(colWhite)
	g.pdf.SetXY(g.marginL+3, g.y())
	g.pdf.CellFormat(g.contentW-6, 7, toL1(title), "", 1, "L", false, 0, "")
	g.setColor(color{0, 0, 0})
	g.pdf.Ln(3)
}

func (g *Generator) subTitle(title string) {
	g.pdf.Ln(3)
	g.setFont("Helvetica", "B", 9)
	g.setColor(colBlue)
	g.pdf.SetX(g.marginL)
	g.pdf.CellFormat(g.contentW, 5, toL1("▶  "+title), "", 1, "L", false, 0, "")
	g.setColor(color{0, 0, 0})
	g.pdf.Ln(1)
}

func (g *Generator) bodyText(text string) {
	g.setFont("Helvetica", "", 9)
	g.setColor(color{28, 28, 28})
	g.pdf.SetX(g.marginL)
	g.pdf.MultiCell(g.contentW, 4.5, toL1(text), "", "J", false)
	g.pdf.Ln(1)
}

// sectionIntro : paragraphe d'introduction italique sous le titre de section
func (g *Generator) sectionIntro(text string) {
	if text == "" {
		return
	}
	g.setFont("Helvetica", "I", 8.5)
	g.setColor(colGrey)
	g.pdf.SetX(g.marginL)
	g.pdf.MultiCell(g.contentW, 4.5, toL1(text), "", "L", false)
	g.setColor(color{0, 0, 0})
	g.pdf.Ln(3)
}

// sectionConclusion : bloc de synthèse en bas de section
func (g *Generator) sectionConclusion(text string) {
	if text == "" {
		return
	}
	g.pdf.Ln(3)
	y := g.pdf.GetY()
	g.fillColor(color{235, 240, 250})
	g.pdf.Rect(g.marginL, y, g.contentW, 2, "F")
	g.pdf.Ln(3)
	g.setFont("Helvetica", "B", 7.5)
	g.setColor(colNavy)
	g.pdf.SetX(g.marginL)
	g.pdf.CellFormat(g.contentW, 4.5, toL1("SYNTHESE"), "", 1, "L", false, 0, "")
	g.setFont("Helvetica", "I", 8.5)
	g.setColor(color{28, 28, 28})
	g.pdf.SetX(g.marginL)
	g.pdf.MultiCell(g.contentW, 4.5, toL1(text), "", "J", false)
	g.pdf.Ln(3)
	g.setColor(color{0, 0, 0})
}

// Tableau générique avec header coloré
func (g *Generator) table(headers []string, rows [][]string, colWidths []float64, headerBg color) {
	pdf := g.pdf

	drawHeader := func() {
		g.fillColor(headerBg)
		g.setFont("Helvetica", "B", 8)
		g.setColor(colWhite)
		pdf.SetX(g.marginL)
		for i, h := range headers {
			pdf.CellFormat(colWidths[i], 6, toL1(h), "1", 0, "L", true, 0, "")
		}
		pdf.Ln(-1)
	}

	drawHeader()

	g.setFont("Helvetica", "", 8)
	for ri, row := range rows {
		// Calculer la hauteur max de la ligne AVANT de dessiner
		maxLines := 1
		for i, cell := range row {
			if i < len(colWidths) && colWidths[i] > 2 && cell != "" {
				lines := pdf.SplitLines([]byte(toL1(cell)), colWidths[i]-2)
				if len(lines) > maxLines {
					maxLines = len(lines)
				}
			}
		}
		cellH := float64(maxLines) * 4.2
		if cellH < 5.5 {
			cellH = 5.5
		}

		// Saut de page si nécessaire (avant de commencer la ligne)
		if pdf.GetY()+cellH > g.pageH-25 {
			pdf.AddPage()
			drawHeader()
			g.setFont("Helvetica", "", 8)
		}

		rowY := pdf.GetY()

		if ri%2 == 0 {
			g.fillColor(colWhite)
		} else {
			g.fillColor(colLight)
		}
		g.setColor(color{28, 28, 28})

		// Dessiner chaque cellule de la ligne à la même hauteur
		curX := g.marginL
		for i, cell := range row {
			if i >= len(colWidths) {
				break
			}
			w := colWidths[i]
			if w <= 0 {
				w = 10
			}
			fill := ri%2 != 0
			// Utiliser CellFormat pour les cellules simples, MultiCell sinon
			lineCount := 1
			if w > 2 && cell != "" {
				lines := pdf.SplitLines([]byte(toL1(cell)), w-2)
				lineCount = len(lines)
			}
			if lineCount <= 1 {
				pdf.SetXY(curX, rowY)
				pdf.CellFormat(w, cellH, toL1(cell), "1", 0, "L", fill, 0, "")
			} else {
				// MultiCell pour les cellules multi-lignes
				// On doit simuler la hauteur fixe avec MultiCell
				pdf.SetXY(curX, rowY)
				lineH := cellH / float64(maxLines)
				pdf.MultiCell(w, lineH, toL1(cell), "1", "L", fill)
				// Compléter avec des cellules vides si besoin
				linesDrawn := pdf.SplitLines([]byte(toL1(cell)), w-2)
				if len(linesDrawn) < maxLines {
					remaining := maxLines - len(linesDrawn)
					for k := 0; k < remaining; k++ {
						pdf.SetXY(curX, rowY+float64(len(linesDrawn)+k)*lineH)
						pdf.CellFormat(w, lineH, "", "LR", 0, "L", fill, 0, "")
					}
				}
			}
			curX += w
		}
		// Ligne de fermeture en bas
		pdf.SetXY(g.marginL, rowY+cellH)
	}
	g.setColor(color{0, 0, 0})
	g.fillColor(colWhite)
	pdf.Ln(3)
}

func sumWidths(ws []float64) float64 {
	s := 0.0
	for _, w := range ws {
		s += w
	}
	return s
}

// Badge coloré
func (g *Generator) badge(text string, bg color, x, y, w, h float64) {
	g.fillColor(bg)
	g.drawColor(bg)
	g.pdf.RoundedRect(x, y, w, h, 2, "1234", "FD")
	g.setFont("Helvetica", "B", 8)
	g.setColor(colWhite)
	g.pdf.SetXY(x, y)
	g.pdf.CellFormat(w, h, toL1(text), "", 0, "C", false, 0, "")
	g.setColor(color{0, 0, 0})
}

// Barre de score (gauge)
func (g *Generator) scoreBar(score int, x, y, w float64) {
	h := 5.0
	// Fond gris
	g.fillColor(color{230, 230, 235})
	g.pdf.Rect(x, y, w, h, "F")
	// Remplissage coloré
	pct := float64(score) / 10.0
	col, _ := scoreColor(score)
	g.fillColor(col)
	g.pdf.Rect(x, y, w*pct, h, "F")
	// Texte
	g.setFont("Helvetica", "B", 7.5)
	g.setColor(colWhite)
	g.pdf.SetXY(x+w*pct-8, y)
}

// ─── Page de garde ─────────────────────────────────────────────────────────

func (g *Generator) coverPage(results []*models.AnalysisResult) {
	pdf := g.pdf
	pdf.AddPage()

	// Fond sombre
	g.fillColor(colDark)
	pdf.Rect(0, 0, g.pageW, g.pageH, "F")

	// Barre rouge gauche
	g.fillColor(colAccent)
	pdf.Rect(0, 0, 6, g.pageH, "F")

	// Bande bleue bas
	g.fillColor(colNavy)
	pdf.Rect(0, g.pageH-20, g.pageW, 20, "F")

	// Titre principal
	pdf.SetXY(g.marginL+8, 35)
	g.setFont("Helvetica", "", 9)
	g.setColor(color{140, 153, 170})
	pdf.CellFormat(100, 5, toL1("● RECORDED FUTURE"), "", 1, "L", false, 0, "")

	pdf.SetXY(g.marginL+8, 42)
	g.setFont("Helvetica", "B", 28)
	g.setColor(colWhite)
	pdf.CellFormat(150, 12, toL1("SANDBOX"), "", 1, "L", false, 0, "")

	pdf.SetXY(g.marginL+8, 56)
	g.setFont("Helvetica", "", 14)
	g.setColor(color{191, 201, 209})
	pdf.CellFormat(150, 7, toL1("Rapport d'Analyse Malware"), "", 1, "L", false, 0, "")

	// Ligne séparatrice rouge
	g.fillColor(colAccent)
	pdf.Rect(g.marginL+8, 66, g.contentW-8, 1, "F")

	// KPIs
	maxScore := 0
	allTags := make(map[string]bool)
	totalIPs := 0
	for _, r := range results {
		if r.Score > maxScore {
			maxScore = r.Score
		}
		for _, t := range r.Tags {
			allTags[t] = true
		}
		totalIPs += len(r.IOCs.IPs)
	}

	kpis := []struct{ val, label string }{
		{fmt.Sprintf("%d", len(results)), "Échantillons analysés"},
		{fmt.Sprintf("%d/10", maxScore), "Score maximal"},
		{fmt.Sprintf("%d", len(allTags)), "Tags détectés"},
		{fmt.Sprintf("%d", totalIPs), "IPs uniques"},
	}

	pdf.SetXY(g.marginL+8, 75)
	for _, kpi := range kpis {
		g.setFont("Helvetica", "B", 20)
		g.setColor(colAccent)
		pdf.CellFormat(40, 9, toL1(kpi.val), "", 0, "L", false, 0, "")
	}
	pdf.Ln(10)
	pdf.SetX(g.marginL + 8)
	for _, kpi := range kpis {
		g.setFont("Helvetica", "", 8)
		g.setColor(color{140, 153, 170})
		pdf.CellFormat(40, 5, toL1(kpi.label), "", 0, "L", false, 0, "")
	}

	// Métadonnées
	pdf.SetXY(g.marginL+8, 108)
	metaStyle := []struct{ k, v string }{
		{"Date de génération", g.reportDate},
		{"Classification", g.classification},
		{"Analyste", "Recorded Future Sandbox API"},
		{"Outil", "RF Sandbox Analyser — Go Edition"},
	}
	for _, m := range metaStyle {
		g.setFont("Helvetica", "B", 8)
		g.setColor(color{140, 153, 170})
		pdf.CellFormat(45, 5, toL1(m.k)+" :", "", 0, "L", false, 0, "")
		g.setFont("Helvetica", "", 8)
		g.setColor(colWhite)
		pdf.CellFormat(100, 5, toL1(m.v), "", 1, "L", false, 0, "")
		pdf.SetX(g.marginL + 8)
	}

	// Jauges de score pour chaque sample
	pdf.SetXY(g.marginL+8, 145)
	g.setFont("Helvetica", "B", 9)
	g.setColor(colWhite)
	pdf.CellFormat(g.contentW, 5, toL1("Scores par échantillon :"), "", 1, "L", false, 0, "")
	pdf.Ln(2)

	for _, r := range results {
		name := r.Filename
		if len(name) > 45 {
			name = "…" + name[len(name)-44:]
		}
		col, label := scoreColor(r.Score)
		yPos := pdf.GetY()
		pdf.SetX(g.marginL + 8)
		g.setFont("Helvetica", "", 8)
		g.setColor(colWhite)
		pdf.CellFormat(80, 5, toL1(name), "", 0, "L", false, 0, "")
		g.scoreBar(r.Score, g.marginL+8+80, yPos, 50)
		g.badge(label, col, g.marginL+8+80+52, yPos, 22, 5)
		pdf.Ln(7)
	}

	// Footer couverture
	pdf.SetXY(g.marginL+8, g.pageH-15)
	g.setFont("Helvetica", "", 7)
	g.setColor(color{100, 110, 130})
	pdf.CellFormat(g.contentW, 4,
		toL1("Ce rapport est confidentiel. Distribution limitée aux personnes autorisées."),
		"", 1, "L", false, 0, "")

	g.setColor(color{0, 0, 0})
}

// ─── Sommaire exécutif ─────────────────────────────────────────────────────

func (g *Generator) executiveSummary(results []*models.AnalysisResult) {
	g.pdf.AddPage()
	g.sectionTitle("1. SOMMAIRE EXÉCUTIF")

	maxScore := 0
	allTags := make(map[string]bool)
	totalSigs := 0
	totalIPs := 0
	totalDoms := 0
	families := []string{}

	for _, r := range results {
		if r.Score > maxScore {
			maxScore = r.Score
		}
		for _, t := range r.Tags {
			allTags[t] = true
		}
		totalSigs += len(r.Signatures)
		totalIPs += len(r.IOCs.IPs)
		totalDoms += len(r.IOCs.Domains)
		if r.Family != "" {
			families = append(families, r.Family)
		}
	}
	_, scLabel := scoreColor(maxScore)

	// Tableau de synthèse
	headers := []string{"Indicateur", "Valeur", "Évaluation"}
	rows := [][]string{
		{"Score global (max)", fmt.Sprintf("%d/10", maxScore), scLabel},
		{"Échantillons analysés", fmt.Sprintf("%d", len(results)), "—"},
		{"Signatures comportementales", fmt.Sprintf("%d", totalSigs), "Voir section Signatures"},
		{"IPs contactées", fmt.Sprintf("%d", totalIPs), "Voir section IOCs"},
		{"Domaines contactés", fmt.Sprintf("%d", totalDoms), "Voir section IOCs"},
		{"Tags uniques", fmt.Sprintf("%d", len(allTags)), strings.Join(sortedTags(allTags, 6), ", ")},
	}
	if len(families) > 0 {
		rows = append(rows, []string{"Familles malware", strings.Join(uniqueStrs(families), ", "), "Confirmé"})
	}
	g.table(headers, rows, []float64{55, 30, 95}, colBlue)

	// Graphe ASCII des scores
	g.subTitle("Distribution des scores par échantillon")
	for _, r := range results {
		name := r.Filename
		if len(name) > 40 {
			name = "…" + name[len(name)-39:]
		}
		col, label := scoreColor(r.Score)
		yPos := g.pdf.GetY()
		g.pdf.SetX(g.marginL)
		g.setFont("Helvetica", "", 8)
		g.setColor(color{28, 28, 28})
		g.pdf.CellFormat(55, 5.5, toL1(name), "", 0, "L", false, 0, "")
		g.scoreBar(r.Score, g.marginL+55, yPos, 80)
		g.badge(fmt.Sprintf("%d/10 %s", r.Score, label), col, g.marginL+55+82, yPos, 32, 5.5)
		g.pdf.Ln(7)
	}

	// Analyse narrative
	g.pdf.Ln(3)
	g.bodyText(g.buildNarrative(results, maxScore, scLabel, totalSigs, totalIPs, totalDoms, families))

	// Tags visuels
	if len(allTags) > 0 {
		g.subTitle("Tags de menace détectés")
		g.pdf.SetX(g.marginL)
		for tag := range allTags {
			g.pdf.SetX(g.pdf.GetX())
			yb := g.pdf.GetY()
			xb := g.pdf.GetX()
			tw := g.pdf.GetStringWidth(tag) + 8
			g.badge(tag, colNavy, xb, yb, tw, 5)
			g.pdf.SetXY(xb+tw+2, yb)
			if g.pdf.GetX() > g.marginL+g.contentW-30 {
				g.pdf.SetXY(g.marginL, g.pdf.GetY()+7)
			}
		}
		g.pdf.Ln(8)
	}
}

func (g *Generator) buildNarrative(results []*models.AnalysisResult,
	maxScore int, label string, sigs, ips, doms int, families []string) string {

	n := fmt.Sprintf("L'analyse sandbox de %d échantillon(s) révèle un niveau de menace "+
		"%s avec un score maximal de %d/10. ", len(results), label, maxScore)

	if len(families) > 0 {
		n += fmt.Sprintf("Les familles de malwares identifiées incluent : %s. ",
			strings.Join(families, ", "))
	}
	if sigs > 0 {
		n += fmt.Sprintf("%d signatures comportementales ont été déclenchées. ", sigs)
	}
	if ips > 0 || doms > 0 {
		n += fmt.Sprintf("L'activité réseau inclut %d adresses IP et %d domaines contactés. ",
			ips, doms)
	}
	n += "Ce rapport détaille les comportements observés, les IOCs, les techniques " +
		"MITRE ATT&CK identifiées et les recommandations de remédiation."
	return n
}

// ─── Détails par sample ────────────────────────────────────────────────────

func (g *Generator) sampleDetail(result *models.AnalysisResult, idx int) {
	g.pdf.AddPage()
	g.sectionTitle(fmt.Sprintf("%d. ANALYSE — %s", idx, truncate(result.Filename, 55)))

	// Informations générales
	col, label := scoreColor(result.Score)
	rows := [][]string{
		{"Fichier / URL", result.Filename},
		{"Sample ID", result.SampleID},
		{"Statut final", strings.ToUpper(result.Status)},
		{"Score sandbox", fmt.Sprintf("%d/10 — %s", result.Score, label)},
	}
	if result.Family != "" {
		rows = append(rows, []string{"Famille malware", result.Family})
	}
	if result.Hashes.SHA256 != "" {
		rows = append(rows, []string{"SHA-256", result.Hashes.SHA256})
	}
	if result.Hashes.MD5 != "" {
		rows = append(rows, []string{"MD5", result.Hashes.MD5})
	}
	if result.Hashes.SHA1 != "" {
		rows = append(rows, []string{"SHA-1", result.Hashes.SHA1})
	}
	if result.Overview != nil && result.Overview.Sample.Filetype != "" {
		rows = append(rows, []string{"Type de fichier", result.Overview.Sample.Filetype})
	}
	if result.Overview != nil && result.Overview.Sample.Size > 0 {
		rows = append(rows, []string{"Taille", fmt.Sprintf("%d octets", result.Overview.Sample.Size)})
	}
	if len(result.Tags) > 0 {
		rows = append(rows, []string{"Tags", strings.Join(result.Tags, ", ")})
	}
	if result.Error != "" {
		rows = append(rows, []string{"Erreur", result.Error})
	}

	g.table([]string{"Propriété", "Valeur"}, rows, []float64{40, 140}, colBlue)

	// Badge score visuel
	yb := g.pdf.GetY()
	g.badge(fmt.Sprintf("SCORE : %d/10 — %s", result.Score, label), col,
		g.pageW-g.marginR-50, yb, 50, 7)
	g.pdf.Ln(10)

	// Tâches d'analyse
	if len(result.Tasks) > 0 {
		g.subTitle("Tâches d'analyse")
		taskRows := [][]string{}
		for tid, td := range result.Tasks {
			platform := td.Platform
			if platform == "" {
				platform = td.Resource
			}
			taskRows = append(taskRows, []string{
				truncate(tid, 28),
				platform,
				fmt.Sprintf("%d", td.Score),
				strings.Join(td.Tags, ", "),
			})
		}
		sort.Slice(taskRows, func(i, j int) bool { return taskRows[i][0] < taskRows[j][0] })
		g.table([]string{"Tâche ID", "Plateforme", "Score", "Tags"},
			taskRows, []float64{60, 40, 15, 65}, colNavy)
	}
}

// ─── Signatures ────────────────────────────────────────────────────────────

func (g *Generator) signaturesSection(results []*models.AnalysisResult) {
	var allSigs []models.AggregatedSignature
	for _, r := range results {
		allSigs = append(allSigs, r.Signatures...)
	}
	if len(allSigs) == 0 {
		return
	}
	sort.Slice(allSigs, func(i, j int) bool {
		return allSigs[i].Score > allSigs[j].Score
	})

	g.pdf.AddPage()
	g.sectionTitle("SIGNATURES COMPORTEMENTALES")
	g.sectionIntro("Analyse des comportements suspects détectés en sandbox. Chaque signature correspond à un comportement observé, corrélé avec les techniques d'attaque MITRE ATT&CK. Les signatures de score élevé constituent des preuves directes de malveillance.")
	g.subTitle(fmt.Sprintf("Top signatures (%d détectées)", len(allSigs)))
	topN := allSigs
	if len(topN) > 15 {
		topN = topN[:15]
	}
	maxSc := topN[0].Score
	if maxSc == 0 {
		maxSc = 1
	}
	barW := 60.0

	for _, sig := range topN {
		name := sig.Label
		if name == "" {
			name = sig.Name
		}
		name = truncate(name, 42)
		col, _ := scoreColor(sig.Score)
		yPos := g.pdf.GetY()
		g.pdf.SetX(g.marginL)
		g.setFont("Helvetica", "", 7.5)
		g.setColor(color{28, 28, 28})
		g.pdf.CellFormat(60, 5, toL1(name), "", 0, "L", false, 0, "")
		// Barre de score
		pct := float64(sig.Score) / 10.0
		g.fillColor(color{230, 232, 238})
		g.pdf.Rect(g.marginL+60, yPos, barW, 5, "F")
		g.fillColor(col)
		g.pdf.Rect(g.marginL+60, yPos, barW*pct, 5, "F")
		// Score
		g.setFont("Helvetica", "B", 7.5)
		g.setColor(col)
		g.pdf.SetXY(g.marginL+60+barW+2, yPos)
		g.pdf.CellFormat(10, 5, fmt.Sprintf("%d", sig.Score), "", 0, "L", false, 0, "")
		// Tags
		g.setFont("Helvetica", "", 7)
		g.setColor(colGrey)
		g.pdf.CellFormat(40, 5, toL1(strings.Join(sig.Tags, " ")), "", 0, "L", false, 0, "")
		g.pdf.Ln(6)
	}
	g.pdf.Ln(2)

	// Table détaillée
	g.subTitle("Table complète des signatures")
	sigRows := [][]string{}
	for _, sig := range allSigs {
		name := sig.Label
		if name == "" {
			name = sig.Name
		}
		ttp := strings.Join(sig.TTP, ", ")
		sigRows = append(sigRows, []string{
			name,
			fmt.Sprintf("%d", sig.Score),
			ttp,
			sig.Desc,
		})
	}
	g.table([]string{"Nom", "Score", "TTP", "Description"},
		sigRows, []float64{55, 10, 32, 81}, colBlue)
	g.sectionConclusion("Les signatures comportementales confirment la nature malveillante du fichier analysé. Les techniques identifiées doivent être corrélées avec les logs SIEM et EDR pour déterminer si des comportements similaires ont été observés sur d'autres postes du réseau.")
}

// ─── IOCs ──────────────────────────────────────────────────────────────────

func (g *Generator) iocSection(results []*models.AnalysisResult) {
	allIPs := uniqueStrs(flatIPs(results))
	allDomains := uniqueStrs(flatDomains(results))
	allURLs := uniqueStrs(flatURLs(results))
	allMutexes := uniqueStrs(flatMutexes(results))

	if len(allIPs)+len(allDomains)+len(allURLs)+len(allMutexes) == 0 {
		return
	}

	g.pdf.AddPage()
	g.sectionTitle("INDICATEURS DE COMPROMISSION (IOCs)")
	g.sectionIntro(fmt.Sprintf("Liste exhaustive des %d adresse(s) IP, %d domaine(s), %d URL(s) et %d mutex identifiés lors de l'analyse. Ces IOCs doivent être immédiatement ajoutés aux listes de blocage pare-feu, proxy et EDR. Toute connexion vers ces destinations est une preuve de compromission.",
		len(allIPs), len(allDomains), len(allURLs), len(allMutexes)))

	// Résumé visuel
	g.subTitle("Vue d'ensemble des IOCs")
	cats := []struct {
		label string
		count int
		col   color
	}{
		{"IPs", len(allIPs), colAccent},
		{"Domaines", len(allDomains), colYellow},
		{"URLs", len(allURLs), colBlue},
		{"Mutexes", len(allMutexes), color{142, 68, 173}},
	}

	maxCount := 1
	for _, c := range cats {
		if c.count > maxCount {
			maxCount = c.count
		}
	}

	barW := 45.0
	barMaxH := 25.0
	startX := g.marginL + 10
	g.pdf.SetX(startX)
	for _, c := range cats {
		barH := math.Max(2, barMaxH*float64(c.count)/float64(maxCount))
		yBar := g.pdf.GetY() + 3 + (barMaxH - barH)
		g.fillColor(c.col)
		g.pdf.Rect(startX, yBar, barW-5, barH, "F")
		// Valeur
		g.setFont("Helvetica", "B", 9)
		g.setColor(c.col)
		g.pdf.SetXY(startX, yBar-6)
		g.pdf.CellFormat(barW-5, 5, fmt.Sprintf("%d", c.count), "", 0, "C", false, 0, "")
		// Label
		g.setFont("Helvetica", "", 7.5)
		g.setColor(color{28, 28, 28})
		g.pdf.SetXY(startX, yBar+barH+1)
		g.pdf.CellFormat(barW-5, 4, toL1(c.label), "", 0, "C", false, 0, "")
		startX += barW
	}
	g.pdf.SetY(g.pdf.GetY() + barMaxH + 12)
	g.pdf.Ln(2)

	g.iocBlock("Adresses IP contactées", allIPs)

	// Marquer les IPs malveillantes si enrichissement disponible
	if g.enrichment != nil && len(g.enrichment.IPReputations) > 0 {
		maliciousIPs := []string{}
		for _, ip := range allIPs {
			if rep, ok := g.enrichment.IPReputations[ip]; ok && rep.EstMalveillant {
				maliciousIPs = append(maliciousIPs, fmt.Sprintf("%s — score %d/100 (%s, %s)", ip, rep.Score, rep.Pays, rep.ISP))
			}
		}
		if len(maliciousIPs) > 0 {
			g.pdf.Ln(2)
			g.setFont("Helvetica", "B", 8.5)
			g.setColor(colAccent)
			g.pdf.SetX(g.marginL)
			g.pdf.CellFormat(g.contentW, 5, toL1(fmt.Sprintf("⚠  %d IP(s) confirmées malveillantes par AbuseIPDB :", len(maliciousIPs))), "", 1, "L", false, 0, "")
			for _, line := range maliciousIPs {
				g.setFont("Helvetica", "", 8)
				g.setColor(colRed)
				g.pdf.SetX(g.marginL + 4)
				g.pdf.CellFormat(g.contentW-4, 4.5, toL1("• "+line), "", 1, "L", false, 0, "")
			}
			g.setColor(color{0, 0, 0})
			g.pdf.Ln(2)
		}
	}
	g.iocBlock("Domaines DNS résolus", allDomains)
	g.iocBlock("URLs HTTP/S observées", allURLs)
	g.iocBlock("Mutexes / Artefacts", allMutexes)

	// Hashes
	g.subTitle("Empreintes cryptographiques")
	hashRows := [][]string{}
	for _, r := range results {
		for _, kv := range []struct{ k, v string }{
			{"MD5", r.Hashes.MD5},
			{"SHA-1", r.Hashes.SHA1},
			{"SHA-256", r.Hashes.SHA256},
			{"SHA-512", r.Hashes.SHA512},
		} {
			if kv.v != "" {
				hashRows = append(hashRows, []string{kv.k, kv.v})
			}
		}
	}
	if len(hashRows) > 0 {
		g.table([]string{"Type", "Valeur"}, hashRows, []float64{18, 162}, colNavy)
	}
	g.sectionConclusion("Bloquer immédiatement toutes les IPs et domaines listés au niveau pare-feu et proxy. Ajouter les hashes MD5/SHA-256 aux listes noires EDR et antivirus. Rechercher dans les logs si d'autres postes ont déjà contacté ces IOCs — chaque occurrence supplémentaire indique une propagation.")
}

func (g *Generator) iocBlock(title string, items []string) {
	if len(items) == 0 {
		return
	}
	g.subTitle(fmt.Sprintf("%s (%d)", title, len(items)))
	rows := [][]string{}
	for i, v := range items {
		if i >= 50 {
			rows = append(rows, []string{"…", fmt.Sprintf("+ %d entrées supplémentaires", len(items)-50)})
			break
		}
		rows = append(rows, []string{fmt.Sprintf("%d", i+1), v})
	}
	g.table([]string{"#", "Valeur"}, rows, []float64{10, 170}, colNavy)
}

// ─── Réseau ───────────────────────────────────────────────────────────────

// ─── Analyse Statique ─────────────────────────────────────────────────────

func (g *Generator) staticAnalysisSection(results []*models.AnalysisResult) {
	// Vérifier qu'au moins un sample a un rapport statique
	hasStatic := false
	for _, r := range results {
		if r.Static != nil && len(r.Static.Files) > 0 {
			hasStatic = true
			break
		}
	}
	if !hasStatic {
		return
	}

	g.pdf.AddPage()
	g.sectionTitle("ANALYSE STATIQUE")
	g.sectionIntro("Résultats de l'analyse statique des fichiers soumis : identification des composants, types MIME, hashes et indicateurs de packing ou d'obfuscation. L'analyse statique révèle la structure du fichier sans l'exécuter, permettant d'identifier les techniques d'évasion et les indicateurs d'origine.")

	for _, r := range results {
		if r.Static == nil {
			continue
		}
		sr := r.Static

		// En-tête par sample
		g.subTitle(fmt.Sprintf("Fichier : %s — %d fichier(s) extrait(s)", r.Filename, len(sr.Files)))

		// Méta globale
		metaRows := [][]string{}
		if sr.Analysis.Reported != "" {
			metaRows = append(metaRows, []string{"Date d'analyse", sr.Analysis.Reported})
		}
		if sr.UnpackCount > 0 {
			metaRows = append(metaRows, []string{"Fichiers dépaquetés", fmt.Sprintf("%d", sr.UnpackCount)})
		}
		if sr.ErrorCount > 0 {
			metaRows = append(metaRows, []string{"Erreurs d'extraction", fmt.Sprintf("%d", sr.ErrorCount)})
		}
		if len(sr.Analysis.Tags) > 0 {
			metaRows = append(metaRows, []string{"Tags statiques", strings.Join(sr.Analysis.Tags, ", ")})
		}
		if len(metaRows) > 0 {
			g.table([]string{"Propriété", "Valeur"}, metaRows, []float64{50, 130}, colNavy)
		}

		// Signatures statiques (packer, anti-debug, obfuscation…)
		if len(sr.Signatures) > 0 {
			g.subTitle(fmt.Sprintf("Signatures statiques (%d)", len(sr.Signatures)))
			sigRows := [][]string{}
			for _, sig := range sr.Signatures {
				ttps := strings.Join(sig.TTP, " ")
				sigRows = append(sigRows, []string{
					sig.Name,
					fmt.Sprintf("%d", sig.Score),
					ttps,
					truncate(sig.Desc, 60),
				})
			}
			g.table([]string{"Signature", "Score", "TTP", "Description"},
				sigRows, []float64{55, 12, 25, 88}, colNavy)
		}

		// Table des fichiers
		if len(sr.Files) > 0 {
			g.subTitle(fmt.Sprintf("Fichiers analysés (%d)", len(sr.Files)))
			fileRows := [][]string{}
			for _, f := range sr.Files {
				selected := ""
				if f.Selected {
					selected = "OUI"
				}
				tags := strings.Join(f.Tags, " ")
				fileRows = append(fileRows, []string{
					truncate(f.Name, 40),
					f.Filetype,
					fmt.Sprintf("%d o", f.Size),
					f.SHA256,
					selected,
					tags,
				})
			}
			g.table(
				[]string{"Fichier", "Type", "Taille", "SHA256", "Sélect.", "Tags"},
				fileRows, []float64{52, 28, 16, 50, 14, 20}, colBlue,
			)
		}
	}
	g.sectionConclusion("L'analyse statique permet d'identifier les composants malveillants sans risque d'exécution. Les fichiers marqués comme sélectionnés ont été soumis à l'analyse comportementale. Les hashes SHA-256 permettent une détection immédiate par les outils EDR et antivirus — les ajouter aux listes noires en priorité.")
}

// ─── Configurations Malware Extraites ────────────────────────────────────

func (g *Generator) malwareConfigSection(results []*models.AnalysisResult) {
	// Collecter toutes les configs extraites non-nulles
	type configEntry struct {
		filename string
		taskID   string
		cfg      *models.MalwareConfig
		ransom   *models.RansomNote
		creds    *models.Credentials
	}
	var entries []configEntry
	for _, r := range results {
		for _, ex := range r.Extracted {
			if ex.Config != nil {
				entries = append(entries, configEntry{filename: r.Filename, taskID: ex.TaskID, cfg: ex.Config})
			}
			if ex.RansomNote != nil {
				entries = append(entries, configEntry{filename: r.Filename, taskID: ex.TaskID, ransom: ex.RansomNote})
			}
			if ex.Credentials != nil {
				entries = append(entries, configEntry{filename: r.Filename, taskID: ex.TaskID, creds: ex.Credentials})
			}
		}
	}
	if len(entries) == 0 {
		return
	}

	g.pdf.AddPage()
	g.sectionTitle("CONFIGURATIONS MALWARE EXTRAITES")
	g.bodyText("Configurations statiques ou dynamiques extraites de la mémoire ou des fichiers analysés.")

	for _, e := range entries {
		name := truncate(e.filename, 50)
		if e.cfg != nil {
			cfg := e.cfg
			g.subTitle(fmt.Sprintf("Config : %s — Famille : %s", name, cfg.Family))
			rows := [][]string{}
			if cfg.Family != "" {
				rows = append(rows, []string{"Famille", cfg.Family})
			}
			if cfg.Rule != "" {
				rows = append(rows, []string{"Règle YARA", cfg.Rule})
			}
			if cfg.Version != "" {
				rows = append(rows, []string{"Version", cfg.Version})
			}
			if cfg.Botnet != "" {
				rows = append(rows, []string{"Botnet / Campaign ID", cfg.Botnet})
			}
			if cfg.Campaign != "" {
				rows = append(rows, []string{"Campagne", cfg.Campaign})
			}
			if cfg.ListenAddr != "" {
				rows = append(rows, []string{"Listen", fmt.Sprintf("%s:%d", cfg.ListenAddr, cfg.ListenPort)})
			}
			if len(cfg.Mutex) > 0 {
				rows = append(rows, []string{"Mutex", strings.Join(cfg.Mutex, ", ")})
			}
			if len(cfg.DNS) > 0 {
				rows = append(rows, []string{"DNS hardcodés", strings.Join(cfg.DNS, ", ")})
			}
			if len(rows) > 0 {
				g.table([]string{"Paramètre", "Valeur"}, rows, []float64{45, 135}, colNavy)
			}
			// C2 servers
			if len(cfg.C2) > 0 {
				g.subTitle(fmt.Sprintf("Serveurs C2 (%d)", len(cfg.C2)))
				c2rows := [][]string{}
				for _, c2 := range cfg.C2 {
					c2rows = append(c2rows, []string{c2})
				}
				g.table([]string{"Adresse C2"}, c2rows, []float64{180}, colAccent)
			}
		}
		if e.ransom != nil {
			rn := e.ransom
			g.subTitle(fmt.Sprintf("Note de rançon : %s — Famille : %s", name, rn.Family))
			rows := [][]string{}
			if len(rn.Emails) > 0 {
				rows = append(rows, []string{"Emails de contact", strings.Join(rn.Emails, ", ")})
			}
			if len(rn.Wallets) > 0 {
				rows = append(rows, []string{"Wallets crypto", strings.Join(rn.Wallets, ", ")})
			}
			if len(rn.URLs) > 0 {
				rows = append(rows, []string{"URLs paiement", strings.Join(rn.URLs, ", ")})
			}
			if len(rows) > 0 {
				g.table([]string{"Indicateur", "Valeur"}, rows, []float64{45, 135}, colAccent)
			}
		}
		if e.creds != nil {
			cr := e.creds
			g.subTitle(fmt.Sprintf("Credentials volés : %s", name))
			rows := [][]string{
				{"Protocole", cr.Protocol},
				{"Hôte", cr.Host},
				{"Utilisateur", cr.Username},
				{"Mot de passe", cr.Password},
			}
			g.table([]string{"Champ", "Valeur"}, rows, []float64{45, 135}, colAccent)
		}
	}
}

// ─── Réseau ────────────────────────────────────────────────────────────────

func (g *Generator) networkSection(results []*models.AnalysisResult) {
	allFlows := []models.NetworkFlow{}
	var allRequests []models.NetworkRequest
	for _, r := range results {
		for _, net := range r.Network {
			allFlows = append(allFlows, net.Flows...)
			allRequests = append(allRequests, net.Requests...)
		}
	}
	if len(allFlows) == 0 && len(allRequests) == 0 {
		return
	}

	g.pdf.AddPage()
	g.sectionTitle("ACTIVITÉ RÉSEAU")
	g.sectionIntro("Analyse exhaustive des communications réseau établies par le malware en sandbox. Les connexions vers des IPs et domaines externes peuvent indiquer une communication avec l'infrastructure de commande et contrôle (C2), de l'exfiltration de données ou le téléchargement de charges supplémentaires.")

	// Comptage protocoles
	protoCount := make(map[string]int)
	for _, f := range allFlows {
		if len(f.Protocols) > 0 {
			for _, p := range f.Protocols {
				protoCount[p]++
			}
		} else if f.Proto != "" {
			protoCount[f.Proto]++
		}
	}

	if len(protoCount) > 0 {
		g.subTitle("Protocoles détectés")
		type protoItem struct {
			p string
			n int
		}
		protoList := []protoItem{}
		for p, n := range protoCount {
			protoList = append(protoList, protoItem{p, n})
		}
		sort.Slice(protoList, func(i, j int) bool { return protoList[i].n > protoList[j].n })

		maxN := 1
		if len(protoList) > 0 {
			maxN = protoList[0].n
		}
		barW2 := 30.0
		protoColors := []color{colBlue, colAccent, colGreen, colYellow, color{142, 68, 173}}
		barMaxH2 := 20.0
		startX2 := g.marginL + 5
		baseY := g.pdf.GetY() + 3
		for i, p := range protoList {
			if i >= 8 {
				break
			}
			barH := math.Max(2, barMaxH2*float64(p.n)/float64(maxN))
			col := protoColors[i%len(protoColors)]
			g.fillColor(col)
			g.pdf.Rect(startX2, baseY+(barMaxH2-barH), barW2-4, barH, "F")
			g.setFont("Helvetica", "B", 8)
			g.setColor(col)
			g.pdf.SetXY(startX2, baseY+(barMaxH2-barH)-5)
			g.pdf.CellFormat(barW2-4, 4, fmt.Sprintf("%d", p.n), "", 0, "C", false, 0, "")
			g.setFont("Helvetica", "", 7)
			g.setColor(color{28, 28, 28})
			g.pdf.SetXY(startX2, baseY+barMaxH2+1)
			g.pdf.CellFormat(barW2-4, 4, toL1(p.p), "", 0, "C", false, 0, "")
			startX2 += barW2
		}
		g.pdf.SetY(baseY + barMaxH2 + 8)
		g.pdf.Ln(2)
	}

	// Table des connexions avec JA3/SNI/géoloc
	if len(allFlows) > 0 {
		g.subTitle(fmt.Sprintf("Connexions réseau (%d flows)", len(allFlows)))
		flowRows := [][]string{}
		for _, f := range allFlows {
			if len(flowRows) >= 50 {
				break
			}
			protos := strings.Join(f.Protocols, "/")
			if protos == "" {
				protos = f.Proto
			}
			// Géoloc enrichie : priorité EnrichmentData.GeoData, fallback données sandbox
			geo := f.Country
			if f.Org != "" {
				geo = f.Country + " / " + f.Org
			}
			if g.enrichment != nil && g.enrichment.GeoData != nil {
				ip := strings.Split(f.Dest, ":")[0]
				if info, ok := g.enrichment.GeoData[ip]; ok && info.Disponible && !info.EstPrivee {
					geo = info.FormatCourt()
				}
			}
			// Statut AbuseIPDB
			abuseStatus := ""
			if g.enrichment != nil && g.enrichment.IPReputations != nil {
				ip := strings.Split(f.Dest, ":")[0]
				if rep, ok := g.enrichment.IPReputations[ip]; ok {
					if rep.EstMalveillant {
						abuseStatus = fmt.Sprintf("⚠ Score:%d", rep.Score)
					}
				}
			}
			dest := f.Dest
			if abuseStatus != "" {
				dest = f.Dest + " " + abuseStatus
			}
			flowRows = append(flowRows, []string{
				dest,
				f.Domain,
				protos,
				geo,
				fmt.Sprintf("%d/%d Ko", f.RxBytes/1024, f.TxBytes/1024),
			})
		}
		g.table([]string{"Destination", "Domaine", "Protocoles", "Pays / Org", "Rx/Tx"},
			flowRows, []float64{42, 42, 22, 50, 22}, colBlue)

		// TLS — JA3 fingerprints
		ja3Rows := [][]string{}
		for _, f := range allFlows {
			if f.JA3 != "" || f.SNI != "" {
				ja3Rows = append(ja3Rows, []string{
					f.Dest,
					f.SNI,
					f.JA3,
					f.JA3S,
				})
			}
			if len(ja3Rows) >= 20 {
				break
			}
		}
		if len(ja3Rows) > 0 {
			g.subTitle(fmt.Sprintf("Empreintes TLS / JA3 (%d connexions chiffrées)", len(ja3Rows)))
			g.table([]string{"Destination", "SNI", "JA3 (client)", "JA3S (serveur)"},
				ja3Rows, []float64{38, 40, 44, 44}, colNavy)
		}
	}

	// Requêtes DNS
	dnsRows := [][]string{}
	for _, req := range allRequests {
		if req.DomainReq == nil {
			continue
		}
		// Domaines : priorité Domains[], fallback Questions[].Name
		domains := req.DomainReq.Domains
		if len(domains) == 0 {
			for _, q := range req.DomainReq.Questions {
				if q.Name != "" {
					domains = append(domains, q.Name)
				}
			}
		}
		if len(domains) == 0 {
			continue
		}
		// IPs résolues : priorité IP[], fallback Answers[].Value
		resolvedIPs := []string{}
		if req.DomainResp != nil {
			resolvedIPs = req.DomainResp.IP
			if len(resolvedIPs) == 0 {
				for _, a := range req.DomainResp.Answers {
					if a.Value != "" {
						resolvedIPs = append(resolvedIPs, a.Value)
					}
				}
			}
		}
		resolved := strings.Join(resolvedIPs, ", ")
		for _, d := range domains {
			if d == "" {
				continue
			}
			dnsRows = append(dnsRows, []string{d, resolved})
			if len(dnsRows) >= 30 {
				break
			}
		}
		if len(dnsRows) >= 30 {
			break
		}
	}
	if len(dnsRows) > 0 {
		g.subTitle(fmt.Sprintf("Requêtes DNS (%d)", len(dnsRows)))
		g.table([]string{"Domaine résolu", "IP retournée(s)"},
			dnsRows, []float64{90, 90}, colNavy)
	}

	// Requêtes HTTP/S
	httpRows := [][]string{}
	for _, req := range allRequests {
		if req.WebReq != nil && req.WebReq.URL != "" {
			status := ""
			if req.WebResp != nil {
				status = req.WebResp.Status
			}
			httpRows = append(httpRows, []string{
				req.WebReq.Method,
				truncate(req.WebReq.URL, 110),
				status,
			})
			if len(httpRows) >= 25 {
				break
			}
		}
	}
	if len(httpRows) > 0 {
		g.subTitle(fmt.Sprintf("Requêtes HTTP/S (%d)", len(httpRows)))
		g.table([]string{"Méthode", "URL", "Statut"},
			httpRows, []float64{18, 140, 22}, colNavy)
	}

	// ── Réputation des IPs (AbuseIPDB) ────────────────────────────────
	if g.enrichment != nil && len(g.enrichment.IPReputations) > 0 {
		g.pdf.Ln(4)
		g.subTitle(fmt.Sprintf("Réputation des IPs — AbuseIPDB (%d IPs enrichies)", len(g.enrichment.IPReputations)))
		abuseRows := [][]string{}
		// Trier : malveillantes en premier
		type ipEntry struct {
			ip  string
			rep ai.IPReputation
		}
		ipList := []ipEntry{}
		for ip, rep := range g.enrichment.IPReputations {
			ipList = append(ipList, ipEntry{ip, rep})
		}
		sort.Slice(ipList, func(i, j int) bool {
			if ipList[i].rep.EstMalveillant != ipList[j].rep.EstMalveillant {
				return ipList[i].rep.EstMalveillant
			}
			return ipList[i].rep.Score > ipList[j].rep.Score
		})
		for _, e := range ipList {
			rep := e.rep
			status := "Légitime"
			if rep.EstMalveillant {
				status = "⚠ MALVEILLANTE"
			}
			cats := strings.Join(rep.Categories, ", ")
			if cats == "" {
				cats = "-"
			}
			if len(cats) > 50 {
				cats = cats[:47] + "..."
			}
			abuseRows = append(abuseRows, []string{
				e.ip,
				fmt.Sprintf("%d/100", rep.Score),
				rep.Pays,
				rep.ISP,
				fmt.Sprintf("%d", rep.TotalReports),
				status,
				cats,
			})
		}
		g.table(
			[]string{"IP", "Score", "Pays", "FAI / Opérateur", "Signalements", "Statut", "Types d'abus"},
			abuseRows,
			[]float64{32, 16, 20, 36, 20, 24, 30},
			colAccent,
		)
	}
}

// ─── Processus ────────────────────────────────────────────────────────────

func (g *Generator) processSection(results []*models.AnalysisResult) {
	var allProcs []models.ProcessWithTask
	for _, r := range results {
		allProcs = append(allProcs, r.Processes...)
	}
	if len(allProcs) == 0 {
		return
	}

	g.pdf.AddPage()
	g.sectionTitle("ARBRE DES PROCESSUS")
	g.sectionIntro("Analyse de l'arbre de processus lancés par le malware en sandbox. Chaque processus enfant révèle une étape de l'attaque : exécution de commandes, modification du système, communication réseau ou tentative d'évasion. La relation parent-enfant permet de reconstituer la chaîne d'infection.")

	g.subTitle("Timeline des processus (ms depuis démarrage)")

	// Trouver la plage temporelle max
	maxT := uint32(1)
	for _, p := range allProcs {
		t := p.Terminated
		if t == 0 {
			t = p.Started + 1000
		}
		if t > maxT {
			maxT = t
		}
	}

	barW3 := g.contentW - 70
	for i, p := range allProcs {
		if i >= 25 {
			break
		}
		img := p.Image
		if img == "" {
			if p.Cmd != nil {
				img = fmt.Sprintf("%v", p.Cmd)
			}
		}
		img = truncate(lastPathElement(img), 38)
		s := float64(p.Started) / float64(maxT)
		t := float64(p.Terminated) / float64(maxT)
		if t == 0 || t < s {
			t = s + 0.05
		}
		if t > 1 {
			t = 1
		}

		yPos := g.pdf.GetY()
		g.pdf.SetX(g.marginL)
		g.setFont("Helvetica", "", 7.5)
		g.setColor(color{28, 28, 28})
		g.pdf.CellFormat(50, 5, toL1(img), "", 0, "L", false, 0, "")
		// Barre timeline
		col := protoColorByIdx(i)
		g.fillColor(color{230, 232, 238})
		g.pdf.Rect(g.marginL+50, yPos, barW3, 5, "F")
		g.fillColor(col)
		g.pdf.Rect(g.marginL+50+barW3*s, yPos, barW3*(t-s), 5, "F")
		// PID
		g.setFont("Helvetica", "", 7)
		g.setColor(colGrey)
		g.pdf.SetXY(g.marginL+50+barW3+2, yPos)
		g.pdf.CellFormat(20, 5, fmt.Sprintf("PID:%d", p.PID), "", 0, "L", false, 0, "")
		g.pdf.Ln(6)
	}
	g.pdf.Ln(2)

	// Table
	g.subTitle("Détail des processus")
	procRows := [][]string{}
	for _, p := range allProcs {
		if len(procRows) >= 35 {
			break
		}
		img := p.Image
		if img == "" && p.Cmd != nil {
			img = fmt.Sprintf("%v", p.Cmd)
		}
		dur := uint32(0)
		if p.Terminated > p.Started {
			dur = p.Terminated - p.Started
		}
		procRows = append(procRows, []string{
			fmt.Sprintf("%d", p.PID),
			fmt.Sprintf("%d", p.PPID),
			truncate(img, 65),
			fmt.Sprintf("%d ms", dur),
		})
	}
	g.table([]string{"PID", "PPID", "Image / Commande", "Durée"},
		procRows, []float64{14, 14, 130, 22}, colBlue)
}

// ─── MITRE ATT&CK ─────────────────────────────────────────────────────────

func (g *Generator) mitreSection(results []*models.AnalysisResult) {
	ttpSet := make(map[string]bool)
	for _, r := range results {
		for _, sig := range r.Signatures {
			for _, t := range sig.TTP {
				ttpSet[t] = true
			}
		}
		if r.Overview != nil {
			for _, task := range r.Overview.Tasks {
				for _, t := range task.TTP {
					ttpSet[t] = true
				}
			}
		}
	}
	if len(ttpSet) == 0 {
		return
	}

	g.pdf.AddPage()
	g.sectionTitle("TECHNIQUES MITRE ATT&CK")
	g.sectionIntro(fmt.Sprintf("%d technique(s) d'attaque identifiee(s) et classees selon le referentiel international MITRE ATT&CK. Chaque technique correspond a une methode d'attaque concrete observee en sandbox. Les references MITRE permettent de corréler avec votre SIEM et de déployer des règles de détection ciblées.", len(ttpSet)))
	g.pdf.Ln(2)

	ttps := sortedKeys(ttpSet)
	// Descriptions enrichies pour toutes les sous-techniques connues
	ttpDesc := map[string]string{
		"T1059":     "Command and Scripting Interpreter — Exécution de commandes via interpréteurs de scripts",
		"T1059.007": "JavaScript — Exécution de code malveillant via le moteur JavaScript (WScript, Node.js)",
		"T1055":     "Process Injection — Injection de code dans un processus légitime pour masquer l'activité",
		"T1082":     "System Information Discovery — Collecte d'informations sur le système cible",
		"T1083":     "File and Directory Discovery — Énumération des fichiers et dossiers du système",
		"T1547":     "Boot or Logon Autostart Execution — Persistance au démarrage ou à la connexion utilisateur",
		"T1037.004": "RC Scripts — Modification des scripts rc pour la persistance sur Linux/macOS",
		"T1071":     "Application Layer Protocol — Communication C2 via protocoles applicatifs (HTTP, DNS, SMTP)",
		"T1105":     "Ingress Tool Transfer — Téléchargement d'outils supplémentaires depuis l'infrastructure attaquant",
		"T1027":     "Obfuscated Files or Information — Obfuscation du code pour contourner la détection",
		"T1003":     "OS Credential Dumping — Extraction des identifiants stockés sur le système",
		"T1003.008": "Proc Filesystem — Dump des identifiants via /proc sur Linux pour une utilisation ultérieure",
		"T1486":     "Data Encrypted for Impact — Chiffrement des données à des fins d'extorsion (ransomware)",
		"T1490":     "Inhibit System Recovery — Suppression des sauvegardes et points de restauration",
		"T1562":     "Impair Defenses — Désactivation ou contournement des outils de sécurité",
		"T1021":     "Remote Services — Mouvement latéral via services distants (RDP, SMB, SSH, WMI)",
		"T1566":     "Phishing — Vecteur d'infection initial via email ou lien malveillant",
		"T1016":     "System Network Configuration Discovery — Reconnaissance de la topologie réseau de la cible",
		"T1053.003": "Cron — Persistance via tâches planifiées cron sur systèmes Linux/macOS",
		"T1070.004": "File Deletion — Suppression des traces et indicateurs de compromission après exécution",
		"T1072":     "Software Deployment Tools — Abus d'outils de déploiement légitimes pour exécuter du code",
		"T1102":     "Web Service — Utilisation de services web légitimes pour le C2 ou l'hébergement de charges",
		"T1129":     "Shared Modules — Chargement de bibliothèques partagées malveillantes (DLL hijacking Linux)",
		"T1222.002": "Linux and Mac File and Directory Permissions Modification — Modification des permissions pour l'évasion",
		"T1497.001": "System Checks — Détection d'environnement virtuel pour contourner l'analyse sandbox",
		"T1548.003": "Sudo and Sudo Caching — Abus de sudo ou du cache sudo pour l'escalade de privilèges",
		"T1556.003": "Network Device Authentication — Modification des mécanismes d'authentification pour la persistance",
		"T1574.006": "Dynamic Linker Hijacking — Détournement du linker dynamique pour charger des librairies malveillantes",
	}

	rows := [][]string{}
	for _, t := range ttps {
		desc := ttpDesc[t]
		// Priorité aux données d'enrichissement live (MITRE API)
		if g.enrichment != nil {
			if detail, ok := g.enrichment.MitreTechniques[t]; ok {
				live := detail.Nom
				if detail.Tactique != "" {
					live += " (" + detail.Tactique + ")"
				}
				if detail.Description != "" {
					live += " — " + detail.Description
				}
				if len(live) > 220 {
					live = live[:217] + "..."
				}
				desc = live
			}
		}
		if desc == "" {
			desc = "Technique identifiée par signature comportementale"
		}
		rows = append(rows, []string{t, desc, "https://attack.mitre.org/techniques/" + strings.ReplaceAll(t, ".", "/")})
	}
	g.table([]string{"Technique ID", "Description", "Référence"},
		rows, []float64{25, 100, 55}, colBlue)

	// Blocs détaillés enrichis (si MITRE API disponible)
	if g.enrichment != nil && len(g.enrichment.MitreTechniques) > 0 {
		g.pdf.Ln(4)
		g.subTitle("Détail des techniques — Données MITRE ATT&CK")
		for _, t := range ttps {
			detail, ok := g.enrichment.MitreTechniques[t]
			if !ok {
				continue
			}
			yT := g.pdf.GetY()
			// Bandeau ID + tactique
			g.fillColor(colBlue)
			g.pdf.Rect(g.marginL, yT, g.contentW, 7, "F")
			g.setFont("Helvetica", "B", 9)
			g.setColor(colWhite)
			g.pdf.SetXY(g.marginL+2, yT+1.5)
			g.pdf.CellFormat(g.contentW/2, 5, toL1(fmt.Sprintf("[%s] %s", t, detail.Nom)), "", 0, "L", false, 0, "")
			if detail.Tactique != "" {
				g.pdf.CellFormat(g.contentW/2-4, 5, toL1("Tactique : "+detail.Tactique), "", 0, "R", false, 0, "")
			}
			g.pdf.SetY(yT + 8)
			// Description
			if detail.Description != "" {
				g.setFont("Helvetica", "B", 7.5)
				g.setColor(colNavy)
				g.pdf.SetX(g.marginL + 2)
				g.pdf.CellFormat(g.contentW, 4, toL1("Description :"), "", 1, "L", false, 0, "")
				g.setFont("Helvetica", "", 7.5)
				g.setColor(color{40, 40, 40})
				g.pdf.SetX(g.marginL + 4)
				g.pdf.MultiCell(g.contentW-6, 3.8, toL1(detail.Description), "", "L", false)
			}
			// Détection
			if detail.Detection != "" {
				g.setFont("Helvetica", "B", 7.5)
				g.setColor(colGreen)
				g.pdf.SetX(g.marginL + 2)
				g.pdf.CellFormat(g.contentW, 4, toL1("Détection :"), "", 1, "L", false, 0, "")
				g.setFont("Helvetica", "", 7.5)
				g.setColor(color{40, 40, 40})
				g.pdf.SetX(g.marginL + 4)
				g.pdf.MultiCell(g.contentW-6, 3.8, toL1(detail.Detection), "", "L", false)
			}
			// Mitigations
			if len(detail.Mitigations) > 0 {
				g.setFont("Helvetica", "B", 7.5)
				g.setColor(colAccent)
				g.pdf.SetX(g.marginL + 2)
				g.pdf.CellFormat(g.contentW, 4, toL1("Mitigations :"), "", 1, "L", false, 0, "")
				g.setFont("Helvetica", "", 7.5)
				g.setColor(color{40, 40, 40})
				g.pdf.SetX(g.marginL + 4)
				g.pdf.MultiCell(g.contentW-6, 3.8, toL1(strings.Join(detail.Mitigations, " | ")), "", "L", false)
			}
			// Ligne séparatrice
			g.drawColor(colDivider)
			g.pdf.Line(g.marginL, g.pdf.GetY()+1, g.pageW-g.marginR, g.pdf.GetY()+1)
			g.pdf.Ln(3)
		}
	}
	g.sectionConclusion("Les techniques MITRE ATT&CK identifiées permettent de déployer des règles de détection ciblées dans votre SIEM (Splunk, Microsoft Sentinel, Elastic). Chaque technique correspond à des Event IDs Windows spécifiques et à des règles Sigma disponibles publiquement. Consulter attack.mitre.org pour les mitigations détaillées.")
}

// ─── Recommandations ──────────────────────────────────────────────────────

func (g *Generator) recommendationsSection(results []*models.AnalysisResult) {
	g.pdf.AddPage()
	g.sectionTitle("RECOMMANDATIONS")
	g.sectionIntro("Plan d'action priorisé pour répondre à l'incident. Les recommandations CRITIQUES doivent être exécutées dans l'heure. Les actions ÉLEVÉES dans les 24h. Les mesures de durcissement à planifier dans les 7 jours suivants.")

	maxScore := 0
	allIPs := uniqueStrs(flatIPs(results))
	allDoms := uniqueStrs(flatDomains(results))
	families := []string{}
	for _, r := range results {
		if r.Score > maxScore {
			maxScore = r.Score
		}
		if r.Family != "" {
			families = append(families, r.Family)
		}
	}

	type rec struct {
		priority string
		bg       color
		text     string
	}

	recs := []rec{}
	if maxScore >= 7 {
		recs = append(recs, rec{"CRITIQUE — BLOCAGE IMMÉDIAT", colRed,
			"Bloquer immédiatement les IOCs identifiés sur tous les équipements réseau " +
				"(pare-feu, proxy, DNS sinkhole). Isoler tout système ayant exécuté ces fichiers."})
	}
	if len(allIPs) > 0 {
		recs = append(recs, rec{"ÉLEVÉ — BLOCAGE IP", colAccent,
			fmt.Sprintf("Ajouter les %d adresses IP identifiées aux listes de blocage réseau. "+
				"Inspecter les logs pour détecter toute connexion antérieure.", len(allIPs))})
	}
	if len(allDoms) > 0 {
		recs = append(recs, rec{"ÉLEVÉ — BLOCAGE DOMAINES", colAccent,
			fmt.Sprintf("Configurer un sinkhole DNS pour les %d domaines identifiés. "+
				"Alerter le SOC sur toute résolution DNS vers ces domaines.", len(allDoms))})
	}
	if len(families) > 0 {
		recs = append(recs, rec{"MOYEN — MISE À JOUR SIGNATURES", colYellow,
			"Vérifier que les signatures antivirales couvrent les familles : " +
				strings.Join(uniqueStrs(families), ", ") + ". Forcer une mise à jour des bases."})
	}
	recs = append(recs,
		rec{"MOYEN — INVESTIGATION FORENSIQUE", colYellow,
			"Analyser les artefacts réseau (pcap) et processus suspects. " +
				"Comparer avec les logs SIEM sur la période concernée."},
		rec{"FAIBLE — DURCISSEMENT", colGreen,
			"Appliquer le principe du moindre privilège. " +
				"Activer AppLocker/WDAC pour bloquer les exécutables non signés."},
		rec{"INFO — THREAT INTELLIGENCE", color{15, 52, 96},
			"Partager les IOCs avec votre plateforme STIX/TAXII ou MISP. " +
				"Enrichir dans Recorded Future Intelligence pour une corrélation étendue."},
	)

	for _, r := range recs {
		yPos := g.pdf.GetY()
		// Colonne priorité
		g.fillColor(r.bg)
		g.pdf.Rect(g.marginL, yPos, 38, 14, "F")
		g.setFont("Helvetica", "B", 7)
		g.setColor(colWhite)
		g.pdf.SetXY(g.marginL+1, yPos+1)
		g.pdf.MultiCell(36, 3.5, toL1(r.priority), "", "C", false)
		// Colonne texte
		g.fillColor(colLight)
		g.pdf.Rect(g.marginL+38, yPos, g.contentW-38, 14, "F")
		g.setFont("Helvetica", "", 8)
		g.setColor(color{28, 28, 28})
		g.pdf.SetXY(g.marginL+40, yPos+1)
		g.pdf.MultiCell(g.contentW-42, 3.8, toL1(r.text), "", "L", false)
		g.pdf.SetY(yPos + 15)
		g.pdf.Ln(1)
	}
	g.sectionConclusion("Prioriser les actions CRITIQUES et ÉLEVÉES avant toute autre démarche. Ne pas éteindre le poste infecté (perte des preuves en RAM). Documenter chaque action entreprise avec horodatage pour la conformité RGPD et les assurances cyber. Contacter votre RSSI et votre DPO dans les 24h si des données personnelles sont potentiellement exposées.")
}

// ─── Point d'entrée ────────────────────────────────────────────────────────

// Generate produit le rapport PDF complet
func (g *Generator) Generate(results []*models.AnalysisResult, enrichment *ai.EnrichmentData) error {
	g.enrichment = enrichment
	g.coverPage(results)
	g.executiveSummary(results)

	for i, r := range results {
		g.sampleDetail(r, i+2)
	}

	g.signaturesSection(results)
	g.attackTimelineSection(results)
	g.propagationRiskSection(results)
	g.staticAnalysisSection(results)
	g.malwareConfigSection(results)
	g.iocSection(results)
	g.networkSection(results)
	g.processSection(results)
	g.mitreSection(results)
	g.incidentResponseSection(results)
	g.recommendationsSection(results)

	return g.pdf.OutputFileAndClose(g.outputPath)
}

// ─── Chronologie d'attaque ─────────────────────────────────────────────────

func (g *Generator) attackTimelineSection(results []*models.AnalysisResult) {
	// Collecter les événements depuis les signatures et processus
	type phase struct {
		num     int
		label   string
		detail  string
		status  string
		statCol color
	}
	var phases []phase

	for _, r := range results {
		// Phase 1 — Activation initiale (toujours)
		phases = append(phases, phase{1, "Activation initiale",
			fmt.Sprintf("Exécution de %s et déclenchement du code malveillant embarqué.", r.Filename),
			"DÉTECTÉ", colAccent})

		// Phase 2 — Persistance (chercher dans signatures)
		hasPersist := false
		persistDetail := "Installation probable dans le registre pour survivre au redémarrage."
		for _, sig := range r.Signatures {
			for _, tag := range sig.Tags {
				if strings.Contains(strings.ToLower(tag), "persist") || strings.Contains(strings.ToLower(tag), "autostart") {
					hasPersist = true
					if sig.Desc != "" {
						persistDetail = sig.Desc
					}
					break
				}
			}
			for _, t := range sig.TTP {
				if strings.HasPrefix(t, "T1547") || strings.HasPrefix(t, "T1053") {
					hasPersist = true
					break
				}
			}
		}
		statusPersist := "NON DÉTECTÉ"
		colPersist := colGrey
		if hasPersist {
			statusPersist = "DÉTECTÉ"
			colPersist = colAccent
		}
		phases = append(phases, phase{2, "Établissement de la persistance", persistDetail, statusPersist, colPersist})

		// Phase 3 — C2 (depuis les IPs)
		if len(r.IOCs.IPs) > 0 {
			ips := r.IOCs.IPs
			if len(ips) > 3 {
				ips = ips[:3]
			}
			detail := fmt.Sprintf("Connexion chiffrée vers l'infrastructure C2 : %s.", strings.Join(ips, ", "))
			phases = append(phases, phase{3, "Communication C2", detail, "DÉTECTÉ", colAccent})
		}

		// Phase 4 — Latéralisation (chercher dans signatures)
		hasLateral := false
		for _, sig := range r.Signatures {
			for _, t := range sig.TTP {
				if strings.HasPrefix(t, "T1021") || strings.HasPrefix(t, "T1078") || strings.HasPrefix(t, "T1550") {
					hasLateral = true
					break
				}
			}
		}
		statusLat := "NON DÉTECTÉ"
		colLat := colGrey
		if hasLateral {
			statusLat = "DÉTECTÉ"
			colLat = colRed
		}
		phases = append(phases, phase{4, "Tentative de latéralisation réseau",
			"Tentative de propagation vers d'autres systèmes du réseau via partages ou services distants.",
			statusLat, colLat})

		// Phase 5 — Exfiltration ou payload
		hasExfil := len(r.DroppedFiles) > 0 || len(r.IOCs.URLs) > 0
		statusExfil := "NON DÉTECTÉ"
		colExfil := colGrey
		detailExfil := "Aucune exfiltration de données confirmée lors de l'analyse."
		if hasExfil {
			statusExfil = "DÉTECTÉ"
			colExfil = colRed
			if len(r.DroppedFiles) > 0 {
				detailExfil = fmt.Sprintf("%d fichier(s) déposé(s) par le malware (payloads secondaires).", len(r.DroppedFiles))
			} else {
				detailExfil = "Connexions HTTP/S vers des URLs distantes — possible exfiltration ou téléchargement de payload."
			}
		}
		phases = append(phases, phase{5, "Exfiltration / Payload secondaire", detailExfil, statusExfil, colExfil})
		break // une seule fois pour le premier résultat significatif
	}

	if len(phases) == 0 {
		return
	}

	g.pdf.AddPage()
	g.sectionTitle("CHRONOLOGIE DE L'ATTAQUE")
	g.sectionIntro("Séquence des actions du malware observées en sandbox, de l'activation initiale jusqu'aux communications avec l'attaquant.")
	g.pdf.Ln(3)

	for _, p := range phases {
		yStart := g.pdf.GetY()
		// Numéro de phase
		g.fillColor(colNavy)
		g.pdf.Rect(g.marginL, yStart, 12, 16, "F")
		g.setFont("Helvetica", "B", 11)
		g.setColor(colWhite)
		g.pdf.SetXY(g.marginL, yStart+3)
		g.pdf.CellFormat(12, 8, fmt.Sprintf("%d", p.num), "", 0, "C", false, 0, "")

		// Étiquette de phase
		g.fillColor(colLight)
		g.pdf.Rect(g.marginL+12, yStart, g.contentW-70, 16, "F")
		g.setFont("Helvetica", "B", 9)
		g.setColor(colNavy)
		g.pdf.SetXY(g.marginL+14, yStart+1)
		g.pdf.CellFormat(g.contentW-72, 5, toL1(fmt.Sprintf("Phase %d : %s", p.num, p.label)), "", 1, "L", false, 0, "")
		g.setFont("Helvetica", "", 8)
		g.setColor(color{60, 60, 60})
		g.pdf.SetX(g.marginL + 14)
		g.pdf.MultiCell(g.contentW-72, 4, toL1(p.detail), "", "L", false)

		// Statut
		g.fillColor(p.statCol)
		g.pdf.Rect(g.pageW-g.marginR-54, yStart, 54, 16, "F")
		g.setFont("Helvetica", "B", 7.5)
		g.setColor(colWhite)
		g.pdf.SetXY(g.pageW-g.marginR-54, yStart+5)
		g.pdf.CellFormat(54, 6, toL1(p.status), "", 0, "C", false, 0, "")

		g.pdf.SetY(yStart + 18)
	}
	g.sectionConclusion("Cette chronologie permet d'identifier la séquence exacte de compromission et d'orienter les actions de réponse. Les phases marquées DÉTECTÉ sont confirmées ; les phases NON DÉTECTÉ restent probables selon le comportement typique de ce vecteur d'attaque.")
}

// ─── Risque de propagation ─────────────────────────────────────────────────

func (g *Generator) propagationRiskSection(results []*models.AnalysisResult) {
	maxScore := 0
	for _, r := range results {
		if r.Score > maxScore {
			maxScore = r.Score
		}
	}
	if maxScore < 4 {
		return // Pas de risque significatif
	}

	g.pdf.AddPage()
	g.sectionTitle("RISQUE DE PROPAGATION AU RÉSEAU")
	g.sectionIntro("Évaluation du risque que le malware se propage à d'autres machines de l'entreprise — question prioritaire pour le management.")
	g.pdf.Ln(2)

	// Niveau de risque global
	riskLabel := "MODÉRÉ"
	riskCol := colYellow
	if maxScore >= 8 {
		riskLabel = "CRITIQUE"
		riskCol = colRed
	} else if maxScore >= 6 {
		riskLabel = "ÉLEVÉ"
		riskCol = colAccent
	}

	g.fillColor(riskCol)
	g.pdf.Rect(g.marginL, g.pdf.GetY(), g.contentW, 14, "F")
	g.setFont("Helvetica", "B", 13)
	g.setColor(colWhite)
	g.pdf.SetXY(g.marginL, g.pdf.GetY()+3)
	g.pdf.CellFormat(g.contentW, 8, toL1("NIVEAU DE RISQUE DE PROPAGATION : "+riskLabel), "", 1, "C", false, 0, "")
	g.pdf.Ln(4)

	// Vecteurs de propagation + systèmes à risque
	g.subTitle("Vecteurs de propagation et systèmes exposés")

	// Collecter les vecteurs depuis les IOCs et signatures
	allIPs := uniqueStrs(flatIPs(results))
	allDoms := uniqueStrs(flatDomains(results))

	vectorRows := [][]string{}
	for _, r := range results {
		if len(r.IOCs.IPs) > 0 {
			vectorRows = append(vectorRows, []string{
				"Connexion réseau sortante",
				fmt.Sprintf("Contact avec %d adresse(s) IP externe(s)", len(r.IOCs.IPs)),
				"Contrôleurs de domaine, serveurs de fichiers",
			})
		}
		for _, sig := range r.Signatures {
			for _, t := range sig.TTP {
				if strings.HasPrefix(t, "T1021") {
					vectorRows = append(vectorRows, []string{"Mouvement latéral (T1021)", "Services distants (RDP/SMB/WMI)", "Tous postes du réseau local"})
					break
				}
			}
		}
	}
	if len(allDoms) > 0 {
		vectorRows = append(vectorRows, []string{
			"Résolution DNS malveillante",
			fmt.Sprintf("%d domaine(s) suspect(s) résolu(s)", len(allDoms)),
			"Tout poste utilisant le DNS interne",
		})
	}
	if len(allIPs) > 0 {
		vectorRows = append(vectorRows, []string{
			"Communication C2 chiffrée",
			fmt.Sprintf("Infrastructure attaquant contactée (%d IPs)", len(allIPs)),
			"Partage réseau ou accès distant",
		})
	}
	if len(vectorRows) > 0 {
		g.table([]string{"Vecteur", "Détail", "Systèmes ciblés"}, vectorRows, []float64{50, 70, 60}, colNavy)
	}

	// Données exposées
	g.pdf.Ln(3)
	g.subTitle("Données et systèmes exposés")
	exposedRows := [][]string{
		{"Identifiants Windows / Active Directory", "CRITIQUE", "Vol possible pour pivoter sur d'autres ressources réseau"},
		{"Données métier / fichiers du poste", "ÉLEVÉ", "Exfiltration potentielle des fichiers locaux"},
	}
	for _, r := range results {
		if len(r.DroppedFiles) > 0 {
			exposedRows = append(exposedRows, []string{"Fichiers déposés par le malware", "CRITIQUE", fmt.Sprintf("%d payload(s) secondaire(s) détecté(s)", len(r.DroppedFiles))})
		}
	}
	g.table([]string{"Type de donnée", "Risque", "Impact"}, exposedRows, []float64{60, 20, 100}, colAccent)

	g.pdf.Ln(3)
	g.sectionConclusion("Action immédiate : Isoler le segment réseau concerné. Changer les mots de passe des comptes administratifs. Surveiller les connexions anormales dans les logs AD et proxy.")
}

// ─── Plan de réponse à l'incident ─────────────────────────────────────────

func (g *Generator) incidentResponseSection(results []*models.AnalysisResult) {
	allIPs := uniqueStrs(flatIPs(results))

	g.pdf.AddPage()
	g.sectionTitle("POSTURE DE RÉPONSE À L'INCIDENT")
	g.sectionIntro("Plan de réponse structuré en 3 phases : Confinement → Éradication → Recouvrement.")
	g.pdf.Ln(2)

	// Bannière phase recommandée
	g.fillColor(colRed)
	g.pdf.Rect(g.marginL, g.pdf.GetY(), g.contentW, 10, "F")
	g.setFont("Helvetica", "B", 9)
	g.setColor(colWhite)
	g.pdf.SetXY(g.marginL+2, g.pdf.GetY()+2)
	g.pdf.CellFormat(g.contentW-4, 6, toL1("PHASE RECOMMANDÉE : CONFINEMENT — PRIORITÉ EMPÊCHER LA PROPAGATION AVANT TOUTE ÉRADICATION"), "", 1, "C", false, 0, "")
	g.pdf.Ln(4)

	// Tableau des 3 phases temporelles
	phases := [][]string{
		{"IMMÉDIAT (0-1h)", "Isoler le poste du réseau.\nBlocker les IOCs au niveau périmètre."},
		{"24 HEURES", "Investiguer la forensique et rechercher une latéralisation.\nÉradiquer le malware sur le poste infecté."},
		{"72 HEURES", "Recouvrir et remettre en service après validation.\nLeçons apprises et corrections structurelles."},
	}

	colW := (g.contentW - 6) / 3
	xStart := g.marginL
	yStart := g.pdf.GetY()
	phaseColors := []color{colRed, colAccent, colYellow}
	for i, p := range phases {
		g.fillColor(phaseColors[i])
		g.pdf.Rect(xStart+float64(i)*colW, yStart, colW-2, 6, "F")
		g.setFont("Helvetica", "B", 7.5)
		g.setColor(colWhite)
		g.pdf.SetXY(xStart+float64(i)*colW+1, yStart+1)
		g.pdf.CellFormat(colW-4, 4, toL1(p[0]), "", 0, "L", false, 0, "")
	}
	g.pdf.SetY(yStart + 7)
	yBody := g.pdf.GetY()
	for i, p := range phases {
		g.fillColor(colLight)
		g.pdf.Rect(xStart+float64(i)*colW, yBody, colW-2, 22, "F")
		g.setFont("Helvetica", "", 7.5)
		g.setColor(color{40, 40, 40})
		g.pdf.SetXY(xStart+float64(i)*colW+2, yBody+2)
		g.pdf.MultiCell(colW-6, 4, toL1(p[1]), "", "L", false)
	}
	g.pdf.SetY(yBody + 24)
	g.pdf.Ln(4)

	// Plan d'action détaillé
	g.subTitle("Plan d'action recommandé")

	type action struct {
		num      int
		priority string
		pCol     color
		category string
		delay    string
		detail   string
	}

	iocStr := "IOCs identifiés"
	if len(allIPs) > 0 {
		iocStr = strings.Join(allIPs[:min(3, len(allIPs))], ", ")
		if len(allIPs) > 3 {
			iocStr += fmt.Sprintf(" et %d autre(s)", len(allIPs)-3)
		}
	}

	actions := []action{
		{1, "CRITIQUE", colRed, "CONFINEMENT", "Immédiat", "Déconnecter le câble Ethernet et désactiver le Wi-Fi pour isoler le poste infecté."},
		{2, "CRITIQUE", colRed, "BLOCAGE", "Immédiat", fmt.Sprintf("Ajouter les IPs (%s) aux listes de blocage pare-feu et proxy.", iocStr)},
		{3, "CRITIQUE", colAccent, "INVESTIGATION", "24h", "Requêter l'EDR pour les fichiers malveillants. Analyser les logs proxy/firewall pour identifier d'autres connexions vers le C2. Vérifier les logs AD pour des connexions anormales."},
		{4, "ÉLEVÉ", colYellow, "ÉRADICATION", "72h", "Capturer une image forensique du disque avant nettoyage. Réinstaller le système d'exploitation. Restaurer les données depuis une sauvegarde antérieure à l'infection."},
	}

	for _, a := range actions {
		y := g.pdf.GetY()
		// Numéro
		g.fillColor(a.pCol)
		g.pdf.Rect(g.marginL, y, 10, 18, "F")
		g.setFont("Helvetica", "B", 10)
		g.setColor(colWhite)
		g.pdf.SetXY(g.marginL, y+4)
		g.pdf.CellFormat(10, 8, fmt.Sprintf("%d", a.num), "", 0, "C", false, 0, "")

		// Header
		g.fillColor(a.pCol)
		g.pdf.Rect(g.marginL+10, y, g.contentW-10, 7, "F")
		g.setFont("Helvetica", "B", 8)
		g.setColor(colWhite)
		g.pdf.SetXY(g.marginL+12, y+1)
		g.pdf.CellFormat(40, 5, toL1("ACTION "+fmt.Sprintf("%d", a.num)+" — "+a.priority), "", 0, "L", false, 0, "")
		g.pdf.CellFormat(30, 5, toL1(a.category), "", 0, "C", false, 0, "")
		g.pdf.CellFormat(30, 5, toL1(a.delay), "", 0, "R", false, 0, "")

		// Corps
		g.fillColor(colLight)
		g.pdf.Rect(g.marginL+10, y+7, g.contentW-10, 11, "F")
		g.setFont("Helvetica", "", 8)
		g.setColor(color{40, 40, 40})
		g.pdf.SetXY(g.marginL+12, y+8)
		g.pdf.MultiCell(g.contentW-14, 4, toL1(a.detail), "", "L", false)
		g.pdf.SetY(y + 20)
	}

	// Obligations de notification
	g.pdf.Ln(3)
	g.subTitle("Obligations de notification")
	g.setFont("Helvetica", "", 8.5)
	g.setColor(color{40, 40, 40})
	g.pdf.SetX(g.marginL)
	notifText := "Notifier le DPO si données personnelles exposées (RGPD 72h) | ANSSI si OIV/OSE | Assurance cyber | Direction générale | Clients si applicable."
	g.pdf.MultiCell(g.contentW, 4.5, toL1(notifText), "", "L", false)

	g.pdf.Ln(2)
	g.subTitle("Critères de retour à la normale")
	g.setFont("Helvetica", "", 8.5)
	g.setColor(color{40, 40, 40})
	g.pdf.SetX(g.marginL)
	criteriaText := "Poste nettoyé ou remplacé | IOCs bloqués en périmètre | Absence de détection sur d'autres postes | Mots de passe de service réinitialisés."
	g.pdf.MultiCell(g.contentW, 4.5, toL1(criteriaText), "", "L", false)
}

// ─── Helpers ──────────────────────────────────────────────────────────────

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n+1:]
}

func lastPathElement(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	parts := strings.Split(p, "/")
	return parts[len(parts)-1]
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedTags(m map[string]bool, max int) []string {
	keys := sortedKeys(m)
	if len(keys) > max {
		return keys[:max]
	}
	return keys
}

func uniqueStrs(s []string) []string {
	seen := make(map[string]bool, len(s))
	out := make([]string, 0, len(s))
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func flatIPs(results []*models.AnalysisResult) []string {
	var out []string
	for _, r := range results {
		out = append(out, r.IOCs.IPs...)
	}
	return out
}
func flatDomains(results []*models.AnalysisResult) []string {
	var out []string
	for _, r := range results {
		out = append(out, r.IOCs.Domains...)
	}
	return out
}
func flatURLs(results []*models.AnalysisResult) []string {
	var out []string
	for _, r := range results {
		out = append(out, r.IOCs.URLs...)
	}
	return out
}
func flatMutexes(results []*models.AnalysisResult) []string {
	var out []string
	for _, r := range results {
		out = append(out, r.IOCs.Mutexes...)
	}
	return out
}

func protoColorByIdx(i int) color {
	palette := []color{
		colBlue, colAccent, colGreen, colYellow,
		{142, 68, 173}, {22, 160, 133}, {211, 84, 0}, {52, 73, 94},
	}
	return palette[i%len(palette)]
}
