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
		case r == '\u25CF': // ● (BLACK CIRCLE) → (*)
			buf = append(buf, '(', '*', ')')
		case r == '\u25B6': // ▶ (BLACK RIGHT-POINTING TRIANGLE) → >>
			buf = append(buf, '>', '>')
		case r == '\u2026': // ellipsis → ...
			buf = append(buf, '.', '.', '.')
		case r == '\u2192': // → arrow
			buf = append(buf, '-', '>')
		case r == '\u2264': // ≤
			buf = append(buf, '<', '=')
		case r == '\u2265': // ≥
			buf = append(buf, '>', '=')
		case r == '\u26A0': // ⚠ WARNING SIGN → [!]
			buf = append(buf, '[', '!', ']')
		case r == '\u2713' || r == '\u2714': // ✓ CHECK MARK → [v]
			buf = append(buf, '[', 'v', ']')
		case r == '\u2717' || r == '\u2718': // ✗ CROSS → [x]
			buf = append(buf, '[', 'x', ']')
		case r == '\u00B7' || r == '\u2022' || r == '\u2023': // middle dots → -
			buf = append(buf, '-')
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
		lineH := 4.2 // hauteur d'une ligne de texte

		// Pré-remplir le fond de toute la ligne (fond uniforme avant dessin)
		// Calculer la largeur totale
		totalW := 0.0
		for ci, _ := range row {
			if ci < len(colWidths) {
				totalW += colWidths[ci]
			}
		}
		if ri%2 == 0 {
			g.fillColor(colWhite)
			pdf.Rect(g.marginL, rowY, totalW, cellH, "F")
		} else {
			g.fillColor(colLight)
			pdf.Rect(g.marginL, rowY, totalW, cellH, "F")
		}
		g.setColor(color{28, 28, 28})

		// CORRECTION BUG4: dessiner chaque cellule en forçant SetXY(curX, rowY)
		// avant chaque cellule. Ne JAMAIS appeler MultiCell qui déplace Y.
		// Pour les cellules multi-lignes, on dessine le texte ligne par ligne.
		curX := g.marginL
		for i, cell := range row {
			if i >= len(colWidths) {
				break
			}
			w := colWidths[i]
			if w <= 0 {
				w = 10
			}
			cellText := toL1(cell)

			// Toujours repositionner au début de la ligne courante
			pdf.SetXY(curX, rowY)

			// Calculer le nombre de lignes nécessaires pour cette cellule
			var splitLines [][]byte
			if w > 2 && cellText != "" {
				splitLines = pdf.SplitLines([]byte(cellText), w-2)
			}

			if len(splitLines) <= 1 {
				// Cellule mono-ligne: CellFormat simple, hauteur = cellH total
				pdf.CellFormat(w, cellH, cellText, "1", 0, "L", false, 0, "")
			} else {
				// Cellule multi-lignes: dessiner manuellement ligne par ligne
				// sans jamais laisser le curseur Y avancer automatiquement
				// 1. Dessiner le rectangle de bordure englobant
				g.drawColor(color{180, 185, 190})
				pdf.Rect(curX, rowY, w, cellH, "D")
				g.drawColor(color{0, 0, 0})
				// 2. Dessiner chaque ligne de texte à sa position Y exacte
				for li, lineBytes := range splitLines {
					if li >= maxLines {
						break
					}
					textY := rowY + float64(li)*lineH + 1.0
					pdf.SetXY(curX+1, textY)
					pdf.CellFormat(w-2, lineH, string(lineBytes), "", 0, "L", false, 0, "")
				}
			}
			curX += w
		}
		// Repositionner Y APRÈS toute la ligne (pas avant, pas entre cellules)
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
	pdf.CellFormat(100, 5, "[*] RECORDED FUTURE", "", 1, "L", false, 0, "")

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

	// BUG5 fix: largeur dynamique pour que les 4 KPIs tiennent tous
	kpiW := (g.contentW - 8) / float64(len(kpis))
	pdf.SetXY(g.marginL+8, 75)
	for _, kpi := range kpis {
		g.setFont("Helvetica", "B", 20)
		g.setColor(colAccent)
		pdf.CellFormat(kpiW, 9, toL1(kpi.val), "", 0, "L", false, 0, "")
	}
	pdf.Ln(10)
	pdf.SetX(g.marginL + 8)
	for _, kpi := range kpis {
		g.setFont("Helvetica", "", 8)
		g.setColor(color{140, 153, 170})
		pdf.CellFormat(kpiW, 5, toL1(kpi.label), "", 0, "L", false, 0, "")
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

	// Séparer domaines bloquables vs domaines Microsoft légitimes (LOLBin)
	legitDoms := []string{}
	blockDoms := []string{}
	for _, d := range allDomains {
		if isLegitMSDomain(d) {
			legitDoms = append(legitDoms, d)
		} else {
			blockDoms = append(blockDoms, d)
		}
	}

	g.pdf.AddPage()
	g.sectionTitle("INDICATEURS DE COMPROMISSION (IOCs)")

	// Intro adaptée selon présence LOLBin
	introText := fmt.Sprintf("Liste exhaustive des %d adresse(s) IP, %d domaine(s), %d URL(s) et %d mutex identifiés lors de l'analyse.",
		len(allIPs), len(allDomains), len(allURLs), len(allMutexes))
	if len(legitDoms) > 0 {
		introText += fmt.Sprintf(" ATTENTION : %d domaine(s) appartiennent à l'infrastructure Microsoft légitime (LOLBin) — NE PAS bloquer au pare-feu (casserait Office365/Teams/Azure AD). Surveiller via EDR/proxy uniquement.", len(legitDoms))
		if len(blockDoms) > 0 {
			introText += fmt.Sprintf(" Seuls %d domaine(s) sont réellement bloquables.", len(blockDoms))
		}
	} else {
		introText += " Ces IOCs doivent être immédiatement ajoutés aux listes de blocage pare-feu, proxy et EDR."
	}
	g.sectionIntro(introText)

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

	// Infrastructure légitime utilisée comme C2 (technique LOLBin)
	// Ces IPs ne sont pas bloquables mais les DOMAINES SNI associés le sont.
	allLegitIPs := uniqueStrs(flatLegitInfraIPs(results))
	if len(allLegitIPs) > 0 {
		g.pdf.Ln(3)
		g.subTitle(fmt.Sprintf("Infrastructure legitime utilisee comme C2 (LOLBin) — %d IP(s)", len(allLegitIPs)))
		// Note explicative
		g.setFont("Helvetica", "I", 8)
		g.setColor(color{100, 100, 100})
		g.pdf.SetX(g.marginL)
		g.pdf.MultiCell(g.contentW, 4.5, toL1(
			"Ces adresses appartiennent a Microsoft Azure / SharePoint / OneDrive — "+
				"infrastructure legitime utilisee comme canal C2 (technique LOLBin/LOLBAS). "+
				"NE PAS bloquer ces IPs au pare-feu — surveiller les domaines SNI dans les logs proxy/DNS."), "", "L", false)
		g.setColor(color{0, 0, 0})
		// Tableau des IPs avec note
		rows := make([][]string, 0)
		for _, ip := range allLegitIPs {
			rows = append(rows, []string{ip, "Microsoft / Azure", "LOLBin C2", "SURVEILLER — non bloquable"})
		}
		g.table([]string{"IP", "Org", "Technique", "Action"}, rows, []float64{40, 40, 30, 70}, colNavy)
	}

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

	// Conclusion adaptée LOLBin
	conclusionText := "Ajouter les hashes MD5/SHA-256 aux listes noires EDR et antivirus. Rechercher dans les logs si d'autres postes ont déjà contacté ces IOCs — chaque occurrence supplémentaire indique une propagation."
	if len(legitDoms) > 0 {
		conclusionText = "RÈGLE LOLBIN : NE PAS bloquer " + strings.Join(legitDoms, ", ") + " au pare-feu — ces domaines Microsoft sont partagés avec Office365, Teams et Azure AD. Action correcte : créer des alertes proxy/EDR sur ces domaines et corréler avec l'activité des postes infectés. " + conclusionText
	} else {
		conclusionText = "Bloquer immédiatement toutes les IPs et domaines listés au niveau pare-feu et proxy. " + conclusionText
	}
	g.sectionConclusion(conclusionText)

	// ── Infrastructure légitime utilisée comme C2 (LOLBin) ──────────────────────
	// Ces IPs ne peuvent pas être bloquées (SharePoint/OneDrive/Azure) mais
	// les domaines SNI TLS associés sont les vrais IOCs réseau.
	allegitIPs := make([]string, 0)
	allegitSNIs := make([]string, 0)
	for _, r := range results {
		allegitIPs = append(allegitIPs, r.IOCs.LegitInfraIPs...)
		for _, nr := range r.Network {
			for _, f := range nr.Flows {
				if f.SNI != "" && f.SNI != f.Domain {
					allegitSNIs = append(allegitSNIs, f.SNI)
				}
			}
		}
	}
	allegitIPs = uniqueStrs(allegitIPs)
	allegitSNIs = uniqueStrs(allegitSNIs)
	if len(allegitIPs) > 0 || len(allegitSNIs) > 0 {
		g.pdf.AddPage()
		g.sectionTitle("INFRASTRUCTURE LÉGITIME UTILISÉE COMME C2 (LOLBIN)")
		g.sectionIntro(
			"Ces adresses IP appartiennent à des hébergeurs légitimes (Microsoft Azure, SharePoint, OneDrive) " +
				"utilisés comme canal C2 par le malware via la technique LOLBAS/LOLBin. " +
				"NE PAS bloquer ces IPs au pare-feu — les serveurs légitimes hébergent aussi des services autorisés. " +
				"Les DOMAINES SNI ci-dessous sont les vrais indicateurs à surveiller dans les logs proxy et DNS.")
		if len(allegitIPs) > 0 {
			g.subTitle(fmt.Sprintf("IPs infrastructure légitime — %d adresse(s)", len(allegitIPs)))
			rows := make([][]string, 0)
			for _, ip := range allegitIPs {
				rows = append(rows, []string{ip, "Microsoft / Azure / SharePoint", "SURVEILLER — non bloquable"})
			}
			g.table([]string{"Adresse IP", "Organisation", "Action recommandée"},
				rows, []float64{50, 80, 60}, color{20, 30, 60})
		}
		if len(allegitSNIs) > 0 {
			g.subTitle(fmt.Sprintf("Domaines SNI TLS — %d domaine(s) (VRAIS IOCs réseau)", len(allegitSNIs)))
			g.bodyText("Ces domaines ont été contactés via TLS. Ils figurent dans le champ SNI des flux HTTPS capturés en sandbox. Les bloquer au niveau du proxy web ou du pare-feu HTTPS-inspection est la mesure corrective principale.")
			g.iocBlock("Domaines SNI à surveiller et bloquer proxy", allegitSNIs)
		}
	}
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
				// BUG6 fix: supprimer col Type vide, tronquer SHA256
				sha256Display := f.SHA256
				if len(sha256Display) > 40 {
					sha256Display = sha256Display[:40] + "..."
				}
				// Truncate du nom par la droite (garder début du chemin)
				name := f.Name
				if len(name) > 45 {
					name = name[:44] + "..."
				}
				fileRows = append(fileRows, []string{
					name,
					fmt.Sprintf("%d o", f.Size),
					sha256Display,
					selected,
					tags,
				})
			}
			g.table(
				// BUG6b: sans col Type, SHA256=72mm, total=180mm
				[]string{"Fichier", "Taille", "SHA256 (tronqué)", "Sel.", "Tags"},
				fileRows, []float64{52, 18, 72, 14, 24}, colBlue,
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

	// Injection des TTPs inférés depuis les données sandbox
	// (DLL sideloading, schtasks, curl/ftp, LOLBin, ipinfo.io...)
	inferredDescs := inferMitreTTPs(results)
	for id := range inferredDescs {
		ttpSet[id] = true
	}

	if len(ttpSet) == 0 {
		return
	}

	g.pdf.AddPage()
	g.sectionTitle("TECHNIQUES MITRE ATT&CK")
	g.sectionIntro(fmt.Sprintf("%d technique(s) d'attaque identifiee(s) et classees selon le referentiel international MITRE ATT&CK. Chaque technique correspond a une methode d'attaque concrete observee en sandbox. Les references MITRE permettent de corréler avec votre SIEM et de déployer des règles de détection ciblées.", len(ttpSet)))
	g.pdf.Ln(2)

	ttps := sortedKeys(ttpSet)
	// Descriptions enrichies — base statique complétée par inférences dynamiques
	ttpDesc := map[string]string{
		"T1059":     "Command and Scripting Interpreter — Exécution de commandes via interpréteurs de scripts",
		"T1059.007": "JavaScript — Exécution de code malveillant via le moteur JavaScript (WScript, Node.js)",
		"T1055":     "Process Injection — Injection de code dans un processus légitime pour masquer l'activité",
		"T1082":     "System Information Discovery — Collecte d'informations sur le système cible (ipinfo.io)",
		"T1083":     "File and Directory Discovery — Énumération des fichiers et dossiers du système",
		"T1547":     "Boot or Logon Autostart Execution — Persistance au démarrage ou à la connexion utilisateur",
		"T1071":     "Application Layer Protocol — Communication C2 via protocoles applicatifs (HTTP, DNS, SMTP)",
		"T1071.001": "Application Layer Protocol: Web Protocols — Communication C2 chiffrée via HTTPS/TLS",
		"T1105":     "Ingress Tool Transfer — Téléchargement d'outils supplémentaires depuis l'infrastructure attaquant",
		"T1027":     "Obfuscated Files or Information — Obfuscation du code pour contourner la détection",
		"T1003":     "OS Credential Dumping — Extraction des identifiants stockés sur le système",
		"T1486":     "Data Encrypted for Impact — Chiffrement des données à des fins d'extorsion (ransomware)",
		"T1490":     "Inhibit System Recovery — Suppression des sauvegardes et points de restauration",
		"T1562":     "Impair Defenses — Désactivation ou contournement des outils de sécurité",
		"T1021":     "Remote Services — Mouvement latéral via services distants (RDP, SMB, SSH, WMI)",
		"T1566":     "Phishing — Vecteur d'infection initial via email ou lien malveillant",
		"T1016":     "System Network Configuration Discovery — Reconnaissance de la topologie réseau de la cible",
		"T1053.003": "Cron — Persistance via tâches planifiées cron sur systèmes Linux/macOS",
		"T1053.005": "Scheduled Task/Job — Persistance via tâche planifiée Windows (schtasks.exe)",
		"T1041":     "Exfiltration Over C2 Channel — Exfiltration via curl.exe / ftp.exe vers infrastructure C2",
		"T1070.004": "File Deletion — Suppression des traces et indicateurs de compromission après exécution",
		"T1102":     "Web Service (LOLBin) — Canal C2 via services web légitimes (OneDrive, SharePoint, Graph API)",
		"T1574.002": "DLL Side-Loading — Binaire légitime (NVIDIA.exe) détourné pour charger une DLL malveillante (libcef.dll)",
		"T1497.001": "System Checks — Détection d'environnement virtuel pour contourner l'analyse sandbox",
	}
	// Priorité aux descriptions inférées dynamiquement (plus précises)
	for id, desc := range inferredDescs {
		ttpDesc[id] = desc
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
		// Marquer les techniques inférées (non remontées par les signatures)
		source := "Signature"
		if _, isInferred := inferredDescs[t]; isInferred {
			if !ttpSet[t] || inferredDescs[t] != "" {
				source = "Inféré"
			}
		}
		_ = source
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
	// BUG8 fix: recommandation CRITIQUE toujours présente (isolation)
	recs = append(recs, rec{"CRITIQUE — ISOLATION", colRed,
		"Isoler immédiatement tout système ayant exécuté ce fichier. " +
			"Déconnecter du réseau (câble ou VLAN quarantaine). " +
			"Ne pas éteindre la machine (perte de preuves RAM)."})
	if maxScore >= 4 {
		recs = append(recs, rec{"CRITIQUE — BLOCAGE IOCs", colRed,
			"Bloquer immédiatement les IOCs identifiés sur tous les équipements réseau " +
				"(pare-feu, proxy, EDR, DNS sinkhole). Forcer une analyse complète de l'infra."})
	}
	if len(allIPs) > 0 {
		// Séparer IPs bloquables vs infra légitime Microsoft/Google
		blockableIPs, legitIPs := buildBlockableIPs(results)
		if len(blockableIPs) > 0 {
			recs = append(recs, rec{"ÉLEVÉ — BLOCAGE IP", colAccent,
				fmt.Sprintf("Ajouter les %d adresses IP bloquables aux listes de blocage réseau. "+
					"Inspecter les logs pour détecter toute connexion antérieure.", len(blockableIPs))})
		}
		if len(legitIPs) > 0 {
			recs = append(recs, rec{"ÉLEVÉ — SURVEILLANCE LOLBIN", colAccent,
				fmt.Sprintf("%d IP(s) Microsoft/Azure utilisées comme canal C2 (LOLBin) ne peuvent PAS être bloquées au pare-feu. "+
					"Créer des alertes EDR/proxy sur les domaines SNI associés (graph.microsoft.com, login.microsoftonline.com, *.sharepoint.com). "+
					"Corréler avec l'activité des postes infectés.", len(legitIPs))})
		}
	}
	// Domaines : séparer bloquables vs Microsoft LOLBin
	legitDomsList := []string{}
	blockDomsList := []string{}
	for _, d := range allDoms {
		if isLegitMSDomain(d) {
			legitDomsList = append(legitDomsList, d)
		} else {
			blockDomsList = append(blockDomsList, d)
		}
	}
	if len(blockDomsList) > 0 {
		recs = append(recs, rec{"ÉLEVÉ — BLOCAGE DOMAINES", colAccent,
			fmt.Sprintf("Configurer un sinkhole DNS pour les %d domaines non-Microsoft identifiés. "+
				"Alerter le SOC sur toute résolution DNS vers ces domaines.", len(blockDomsList))})
	}
	if len(legitDomsList) > 0 {
		recs = append(recs, rec{"MOYEN — ALERTES PROXY LOLBin", colYellow,
			"NE PAS bloquer au DNS/pare-feu : " + strings.Join(uniqueStrs(legitDomsList), ", ") + ". " +
				"Ces domaines Microsoft sont légitimes et partagés avec Office365/Teams/Azure AD. " +
				"Créer des alertes proxy HTTPS-inspection sur ces destinations et surveiller l'activité anormale."})
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
		// BUG9 fix: label 50mm (était 38mm) pour éviter le wrapping
		g.pdf.Rect(g.marginL, yPos, 50, 14, "F")
		g.setFont("Helvetica", "B", 7)
		g.setColor(colWhite)
		g.pdf.SetXY(g.marginL+1, yPos+1)
		g.pdf.MultiCell(48, 3.5, toL1(r.priority), "", "C", false)
		// Colonne texte
		g.fillColor(colLight)
		g.pdf.Rect(g.marginL+50, yPos, g.contentW-50, 14, "F")
		g.setFont("Helvetica", "", 8)
		g.setColor(color{28, 28, 28})
		g.pdf.SetXY(g.marginL+52, yPos+1)
		g.pdf.MultiCell(g.contentW-54, 3.8, toL1(r.text), "", "L", false)
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
	g.grilleCompromissionSection(results) // Grille des 3 états — proche rapport manuel
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

// ─── Grille des 3 états de compromission ──────────────────────────────────

// grilleCompromissionSection affiche la grille de décision opérationnelle
// permettant aux équipes terrain de qualifier rapidement l'état de chaque poste.
// Reproduit fidèlement la grille du rapport manuel HarfangLab.
func (g *Generator) grilleCompromissionSection(results []*models.AnalysisResult) {
	// Construire la liste des fichiers IOCs à rechercher depuis les résultats
	iocFiles := []string{"Certificate.cer.exe", "nv.exe", "fs.zip", "ps.zip"}
	for _, r := range results {
		for _, df := range r.DroppedFiles {
			if df.Name != "" {
				iocFiles = append(iocFiles, df.Name)
			}
		}
	}
	iocFiles = uniqueStrs(iocFiles)

	g.pdf.AddPage()
	g.sectionTitle("FRISE DE COMPROMISSION — ETATS POSSIBLES")
	g.sectionIntro("Pour chaque poste ayant eu une connexion vers le portail ou la ressource compromise, " +
		"trois états sont possibles. Cette grille permet aux équipes terrain de qualifier " +
		"rapidement la situation et d'appliquer les actions adaptées.")
	g.pdf.Ln(4)

	type etat struct {
		num         int
		titre       string
		description string
		signes      string
		actions     []string
		urgence     string
		bg          color
		accent      color
	}

	iocFilesStr := strings.Join(iocFiles[:intMin(5, len(iocFiles))], ", ")

	etats := []etat{
		{
			num:         1,
			titre:       "Aucun fichier malveillant présent",
			description: "Le poste a eu une connexion vers le site compromis mais aucun téléchargement ni exécution n'a eu lieu.",
			signes:      "Absence de : " + iocFilesStr + " et fichiers dans Users\\Public (exe, dll, txt)",
			actions: []string{
				"Un scan antiviral avancé du poste peut être réalisé par prudence.",
				"Aucune action urgente requise.",
			},
			urgence: "FAIBLE",
			bg:      color{235, 250, 242},
			accent:  colGreen,
		},
		{
			num:         2,
			titre:       "Fichiers présents mais pas d'exécution",
			description: "Des fichiers malveillants ont été téléchargés mais le malware n'a pas été exécuté et aucune connexion C2 n'est établie.",
			signes:      "Présence de Certificate.cer.exe ou fichiers dans Users\\Public, mais aucune connexion sortante vers l'infra C2 et aucune tâche planifiée NVIDIA.",
			actions: []string{
				"1. Supprimer l'ensemble des fichiers présents.",
				"2. Réaliser un scan AV et confirmer l'absence des IOCs découverts à l'issue des actions.",
			},
			urgence: "MOYEN",
			bg:      color{255, 249, 235},
			accent:  colYellow,
		},
		{
			num:         3,
			titre:       "Exécution confirmée avec connexion C2",
			description: "Le poste est compromis : le malware a été exécuté et a établi une communication avec l'infrastructure attaquant (OneDrive/SharePoint Microsoft).",
			signes:      "Présence de tâche planifiée NVIDIA, connexions vers graph.microsoft.com / *.sharepoint.com, fichiers NVIDIA.exe + libcef.dll dans Users\\Public.",
			actions: []string{
				"1. Réinitialiser les identifiants de tous les comptes présents sur le poste lors de la compromission.",
				"2. Réinitialiser les sessions réseau actives.",
				"3. Réinstaller le poste après un formatage bas niveau.",
			},
			urgence: "CRITIQUE",
			bg:      color{255, 235, 235},
			accent:  colRed,
		},
	}

	for _, e := range etats {
		if g.pdf.GetY() > g.pageH-70 {
			g.pdf.AddPage()
			g.drawHeader()
		}

		yStart := g.pdf.GetY()
		blockH := 52.0

		// Fond du bloc
		g.fillColor(e.bg)
		g.pdf.Rect(g.marginL, yStart, g.contentW, blockH, "F")

		// Barre d'urgence gauche
		g.fillColor(e.accent)
		g.pdf.Rect(g.marginL, yStart, 5, blockH, "F")

		// Badge urgence (coin supérieur droit)
		badgeW := 25.0
		g.fillColor(e.accent)
		g.pdf.Rect(g.marginL+g.contentW-badgeW, yStart, badgeW, 8, "F")
		g.setFont("Helvetica", "B", 7)
		g.setColor(colWhite)
		g.pdf.SetXY(g.marginL+g.contentW-badgeW, yStart+1.5)
		g.pdf.CellFormat(badgeW-1, 5, toL1(e.urgence), "", 0, "C", false, 0, "")

		// Titre du cas
		g.pdf.SetXY(g.marginL+8, yStart+2)
		g.setFont("Helvetica", "B", 9)
		g.setColor(e.accent)
		g.pdf.CellFormat(g.contentW-badgeW-12, 6, toL1(fmt.Sprintf("CAS %d — %s", e.num, strings.ToUpper(e.titre))), "", 1, "L", false, 0, "")

		// Description
		g.pdf.SetX(g.marginL + 8)
		g.setFont("Helvetica", "I", 7.5)
		g.setColor(color{80, 90, 110})
		g.pdf.MultiCell(g.contentW-14, 3.8, toL1(e.description), "", "L", false)
		g.pdf.Ln(2)

		// Deux colonnes : Signes | Actions
		xL := g.marginL + 8
		xR := g.marginL + g.contentW/2 + 2
		colW := g.contentW/2 - 12
		yCol := g.pdf.GetY()

		// En-têtes
		g.setFont("Helvetica", "B", 7)
		g.setColor(color{100, 110, 130})
		g.pdf.SetXY(xL, yCol)
		g.pdf.CellFormat(colW, 4, "SIGNES A RECHERCHER", "", 0, "L", false, 0, "")
		g.pdf.SetXY(xR, yCol)
		g.pdf.CellFormat(colW, 4, "ACTIONS RECOMMANDEES", "", 1, "L", false, 0, "")
		yCol += 4.5

		// Contenu signes
		g.setFont("Helvetica", "", 7.5)
		g.setColor(color{40, 50, 60})
		g.pdf.SetXY(xL, yCol)
		g.pdf.MultiCell(colW, 3.8, toL1(e.signes), "", "L", false)
		yAfterLeft := g.pdf.GetY()

		// Contenu actions
		g.pdf.SetXY(xR, yCol)
		g.pdf.MultiCell(colW, 3.8, toL1(strings.Join(e.actions, "\n")), "", "L", false)
		yAfterRight := g.pdf.GetY()

		// Positionner après le plus bas des deux colonnes
		finalY := yAfterLeft
		if yAfterRight > finalY {
			finalY = yAfterRight
		}
		g.pdf.SetY(finalY + 6)
	}

	g.sectionConclusion("La présence de fichiers de type exe, dll, txt dans le dossier Users\\Public doit lever une alerte immédiate sur la compromission du poste. Chaque cas nécessite une réponse proportionnée — éviter l'over-réaction (formatage systématique) autant que la sous-réaction (ignorer les fichiers présents).")
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

		// BUG7 fix: Phase 3 toujours présente, statut adaptatif
		{
			var detail3 string
			var status3 string
			var col3 color
			if len(r.IOCs.IPs) > 0 {
				ips3 := r.IOCs.IPs
				if len(ips3) > 3 {
					ips3 = ips3[:3]
				}
				detail3 = fmt.Sprintf("Connexion chiffrée vers l'infrastructure C2 : %s.", strings.Join(ips3, ", "))
				status3 = "DÉTECTÉ"
				col3 = colAccent
			} else if len(r.IOCs.Domains) > 0 {
				detail3 = fmt.Sprintf("Contact DNS suspects vers : %s.", strings.Join(r.IOCs.Domains[:intMin(2, len(r.IOCs.Domains))], ", "))
				status3 = "DÉTECTÉ"
				col3 = colAccent
			} else {
				detail3 = "Aucune communication C2 confirmée lors de l'analyse sandbox."
				status3 = "NON DÉTECTÉ"
				col3 = colGrey
			}
			phases = append(phases, phase{3, "Communication C2", detail3, status3, col3})
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
		// Distinguer domaines LOLBin Microsoft vs domaines suspects réels
		blockDoms := []string{}
		for _, d := range allDoms {
			if !isLegitMSDomain(d) {
				blockDoms = append(blockDoms, d)
			}
		}
		if len(blockDoms) > 0 {
			vectorRows = append(vectorRows, []string{
				"Résolution DNS suspecte",
				fmt.Sprintf("%d domaine(s) non-Microsoft résolu(s)", len(blockDoms)),
				"Tout poste utilisant le DNS interne",
			})
		}
		legitDomCount := len(allDoms) - len(blockDoms)
		if legitDomCount > 0 {
			vectorRows = append(vectorRows, []string{
				"C2 via infra Microsoft (LOLBin)",
				fmt.Sprintf("%d domaine(s) Microsoft utilisé(s) comme C2 (non bloquable au DNS)", legitDomCount),
				"Surveillance proxy/EDR requise",
			})
		}
	}
	// Connexions C2 : distinguer IPs bloquables vs Microsoft
	blockableC2, legitC2 := buildBlockableIPs(results)
	if len(blockableC2) > 0 {
		vectorRows = append(vectorRows, []string{
			"Communication C2 externe",
			fmt.Sprintf("%d IP(s) externe(s) bloquables contactées", len(blockableC2)),
			"Partage réseau ou accès distant",
		})
	}
	if len(legitC2) > 0 {
		vectorRows = append(vectorRows, []string{
			"C2 via Azure/SharePoint",
			fmt.Sprintf("%d IP(s) Microsoft/Azure (LOLBin) — non bloquables", len(legitC2)),
			"Alertes proxy/EDR uniquement",
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

	// Séparer IPs bloquables vs infra Microsoft LOLBin (en utilisant org des flows)
	blockableIPsRI, legitIPsRI := buildBlockableIPs(results)

	iocStr := "IOCs identifiés"
	if len(blockableIPsRI) > 0 {
		iocStr = strings.Join(blockableIPsRI[:intMin(3, len(blockableIPsRI))], ", ")
		if len(blockableIPsRI) > 3 {
			iocStr += fmt.Sprintf(" et %d autre(s)", len(blockableIPsRI)-3)
		}
	}

	action2Detail := fmt.Sprintf("Ajouter les IPs bloquables (%s) aux listes de blocage pare-feu et proxy.", iocStr)
	if len(legitIPsRI) > 0 {
		action2Detail += fmt.Sprintf(" ATTENTION : %d IP(s) Microsoft/Azure (LOLBin) NE doivent PAS être bloquées — créer des alertes EDR/proxy sur graph.microsoft.com, login.microsoftonline.com, *.sharepoint.com.", len(legitIPsRI))
	}

	actions := []action{
		{1, "CRITIQUE", colRed, "CONFINEMENT", "Immédiat", "Déconnecter le câble Ethernet et désactiver le Wi-Fi pour isoler le poste infecté."},
		{2, "CRITIQUE", colRed, "BLOCAGE", "Immédiat", action2Detail},
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

// intMin retourne le minimum de deux entiers
func intMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

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

// ─── Helpers LOLBin et TTPs ────────────────────────────────────────────────

// isLegitMSOrg retourne true si l'organisation est Microsoft, Google ou autre
// infrastructure légitime non bloquable.
func isLegitMSOrg(org string) bool {
	org = strings.ToLower(org)
	legitOrgs := []string{
		"microsoft", "google", "amazon", "cloudflare",
		"akamai", "fastly", "azure", "office365",
	}
	for _, o := range legitOrgs {
		if strings.Contains(org, o) {
			return true
		}
	}
	return false
}

// isLegitMSDomain retourne true si le domaine appartient à l'infrastructure
// Microsoft légitime utilisée comme C2 (LOLBin) — ces domaines ne doivent
// jamais être bloqués au pare-feu car ils servent aussi à Office365/Teams/AAD.
func isLegitMSDomain(d string) bool {
	d = strings.ToLower(strings.TrimSpace(d))
	legitSuffixes := []string{
		"microsoft.com", "microsoftonline.com", "sharepoint.com",
		"windows.net", "onedrive.com", "live.com", "office.com",
		"office365.com", "azure.com", "azurewebsites.net",
		"bing.com", "msftconnecttest.com",
	}
	for _, s := range legitSuffixes {
		if d == s || strings.HasSuffix(d, "."+s) {
			return true
		}
	}
	return false
}

// isLegitMSIP retourne true si l'IP appartient à Microsoft/Google/infra légitime
// (plages ASN connues) — approximation basée sur les préfixes fréquents.
func isLegitMSIP(ip string) bool {
	// On se base sur LegitInfraIPs déjà classifiés par le client RF
	// Cette fonction est un filet de sécurité supplémentaire
	return false // délégué à LegitInfraIPs dans models
}

// inferMitreTTPs déduit les techniques MITRE ATT&CK depuis les données sandbox
// quand les signatures ne les ont pas remontées directement.
// Implémente les règles : DLL Sideloading, Scheduled Task, Exfiltration curl/ftp,
// LOLBin C2, System Info Discovery.
func inferMitreTTPs(results []*models.AnalysisResult) map[string]string {
	inferred := map[string]string{}

	for _, r := range results {
		// ── T1574.002 DLL Side-Loading ─────────────────────────────────────
		// Signal : NVIDIA.exe + libcef.dll dans Users\Public (dropped files)
		hasNVIDIA, hasLibcef := false, false
		for _, df := range r.DroppedFiles {
			nl := strings.ToLower(df.Name)
			if strings.Contains(nl, "nvidia") && strings.HasSuffix(nl, ".exe") {
				hasNVIDIA = true
			}
			if strings.Contains(nl, "libcef") && strings.HasSuffix(nl, ".dll") {
				hasLibcef = true
			}
		}
		if hasNVIDIA && hasLibcef {
			inferred["T1574.002"] = "DLL Side-Loading — Binaire NVIDIA légitime utilisé pour charger libcef.dll malveillante (Users\\Public)"
		}

		// ── T1053.005 Scheduled Task ────────────────────────────────────────
		// Signal : schtasks dans kernel events ou cmdlines
		for _, ev := range r.KernelEvents {
			tgt := strings.ToLower(ev.Target)
			act := strings.ToLower(ev.Action)
			if strings.Contains(tgt, "schtask") || strings.Contains(act, "schtask") ||
				strings.Contains(tgt, "task scheduler") || strings.Contains(ev.Details, "schtasks") {
				inferred["T1053.005"] = "Scheduled Task/Job — Tâche planifiée créée pour la persistance (ex: tâche NVIDIA, exécution quotidienne)"
				break
			}
		}
		for _, p := range r.Processes {
			cmdline := ""
			switch v := p.Cmd.(type) {
			case string:
				cmdline = strings.ToLower(v)
			}
			if strings.Contains(cmdline, "schtasks") || strings.Contains(strings.ToLower(p.Image), "schtasks") {
				inferred["T1053.005"] = "Scheduled Task/Job — Tâche planifiée créée pour la persistance (ex: tâche NVIDIA, exécution quotidienne)"
			}
		}

		// ── T1041 Exfiltration Over C2 Channel (curl/ftp) ──────────────────
		hasCurl, hasFTP := false, false
		for _, p := range r.Processes {
			img := strings.ToLower(p.Image)
			if strings.Contains(img, "curl") {
				hasCurl = true
			}
			if strings.Contains(img, "ftp") {
				hasFTP = true
			}
		}
		for _, ev := range r.KernelEvents {
			detail := strings.ToLower(ev.Details)
			img := strings.ToLower(ev.Image)
			if strings.Contains(img, "curl") || strings.Contains(detail, "curl") {
				hasCurl = true
			}
			if strings.Contains(img, "ftp.exe") || strings.Contains(detail, "ftp") {
				hasFTP = true
			}
		}
		if hasCurl || hasFTP {
			tools := []string{}
			if hasCurl {
				tools = append(tools, "curl.exe")
			}
			if hasFTP {
				tools = append(tools, "ftp.exe")
			}
			inferred["T1041"] = "Exfiltration Over C2 Channel — Exfiltration de données via " + strings.Join(tools, " et ") + " (r.txt, 11.txt)"
		}

		// ── T1082 System Information Discovery (ipinfo.io) ──────────────────
		for _, url := range r.IOCs.URLs {
			if strings.Contains(strings.ToLower(url), "ipinfo.io") {
				inferred["T1082"] = "System Information Discovery — Collecte d'informations système via ipinfo.io (IP publique, géolocalisation)"
				break
			}
		}
		for _, ev := range r.KernelEvents {
			if strings.Contains(strings.ToLower(ev.Target), "ipinfo.io") ||
				strings.Contains(strings.ToLower(ev.Details), "ipinfo.io") {
				inferred["T1082"] = "System Information Discovery — Collecte d'informations système via ipinfo.io (IP publique, géolocalisation)"
			}
		}

		// ── T1102 Web Service (LOLBin C2 via OneDrive/SharePoint) ──────────
		for _, nr := range r.Network {
			for _, f := range nr.Flows {
				sni := strings.ToLower(f.SNI)
				dom := strings.ToLower(f.Domain)
				if strings.Contains(sni, "sharepoint.com") || strings.Contains(dom, "sharepoint.com") ||
					strings.Contains(sni, "onedrive.com") || strings.Contains(dom, "onedrive.com") ||
					strings.Contains(sni, "graph.microsoft.com") {
					inferred["T1102"] = "Web Service (LOLBin) — Canal C2 via infrastructure Microsoft légitime (SharePoint/OneDrive/Graph API) — non bloquable au pare-feu"
				}
			}
		}
		for _, url := range r.IOCs.URLs {
			ul := strings.ToLower(url)
			if strings.Contains(ul, "graph.microsoft.com") || strings.Contains(ul, "sharepoint.com") {
				inferred["T1102"] = "Web Service (LOLBin) — Canal C2 via infrastructure Microsoft légitime (SharePoint/OneDrive/Graph API) — non bloquable au pare-feu"
			}
		}

		// ── T1059 Command and Scripting Interpreter ─────────────────────────
		for _, p := range r.Processes {
			img := strings.ToLower(p.Image)
			if strings.Contains(img, "powershell") || strings.Contains(img, "cmd.exe") ||
				strings.Contains(img, "wscript") || strings.Contains(img, "cscript") {
				inferred["T1059"] = "Command and Scripting Interpreter — Exécution de commandes via PowerShell ou interpréteurs Windows"
				break
			}
		}

		// ── T1071.001 Application Layer Protocol (HTTP/S C2) ────────────────
		hasHTTPS := false
		for _, nr := range r.Network {
			for _, f := range nr.Flows {
				for _, proto := range f.Protocols {
					if proto == "tls" || proto == "https" || proto == "http" {
						hasHTTPS = true
					}
				}
			}
		}
		if hasHTTPS {
			inferred["T1071.001"] = "Application Layer Protocol: Web Protocols — Communication C2 chiffrée via HTTPS/TLS"
		}
	}
	return inferred
}

// buildBlockableIPs retourne deux listes : IPs réellement bloquables et IPs infra légitime.
// Une IP est considérée "infra légitime" si :
//   - elle est dans r.IOCs.LegitInfraIPs (classifiée par le client RF via isLegitOrg)
//   - OU son organisation dans les flows réseau est Microsoft/Google/Amazon/etc.
//   - OU le domaine/SNI associé à cette IP dans les flows est un domaine Microsoft légitime
//     (cas fréquent : flow.Org vide mais flow.Domain = "login.microsoftonline.com")
func buildBlockableIPs(results []*models.AnalysisResult) (blockable, legit []string) {
	allIPs := uniqueStrs(flatIPs(results))
	legitSet := map[string]bool{}

	// 1. LegitInfraIPs déjà identifiées par le client RF (isLegitOrg non vide)
	for _, ip := range uniqueStrs(flatLegitInfraIPs(results)) {
		legitSet[ip] = true
	}

	// 2. Analyser chaque flow réseau : org ET domaine/SNI associé à l'IP
	for _, r := range results {
		for _, nr := range r.Network {
			for _, f := range nr.Flows {
				ipPart := strings.Split(f.Dest, ":")[0]
				if ipPart == "" {
					continue
				}
				// Critère A : organisation Microsoft/Google dans le flow
				if f.Org != "" && isLegitMSOrg(f.Org) {
					legitSet[ipPart] = true
					continue
				}
				// Critère B : domaine résolu associé à cette IP est Microsoft légitime
				// (couvre le cas org="" mais domain="login.microsoftonline.com")
				if f.Domain != "" && isLegitMSDomain(f.Domain) {
					legitSet[ipPart] = true
					continue
				}
				// Critère C : SNI TLS associé est Microsoft légitime
				if f.SNI != "" && isLegitMSDomain(f.SNI) {
					legitSet[ipPart] = true
				}
			}
		}
	}

	// 3. Enrichissement AbuseIPDB : même si l'IP est signalée "malveillante",
	// si son FAI est Microsoft/Google/Amazon, c'est de l'infra LOLBin — non bloquable.
	// AbuseIPDB remonte des IPs Microsoft avec des scores de 20-24/100 à cause de
	// partages d'infrastructure (CDN communs) et non d'activité malveillante directe.
	// Note: g.enrichment n'est pas accessible ici — on se base sur les flows uniquement.

	for _, ip := range allIPs {
		if legitSet[ip] {
			legit = append(legit, ip)
		} else {
			blockable = append(blockable, ip)
		}
	}
	return uniqueStrs(blockable), uniqueStrs(legit)
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
		// Inclure aussi les SNI TLS (domaines HTTPS non dans IOCs.Domains)
		for _, nr := range r.Network {
			for _, f := range nr.Flows {
				if f.SNI != "" {
					out = append(out, f.SNI)
				}
			}
		}
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

func flatLegitInfraIPs(results []*models.AnalysisResult) []string {
	var out []string
	for _, r := range results {
		out = append(out, r.IOCs.LegitInfraIPs...)
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
