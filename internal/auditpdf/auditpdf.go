// Package auditpdf génère un rapport PDF d'audit de sécurité
// à partir des résultats de gosec, govulncheck et gitleaks.
package auditpdf

import (
	"fmt"
	"strings"

	"github.com/jung-kurt/gofpdf"
)

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
		case r == '\u2713' || r == '\u2714':
			buf = append(buf, '[', 'O', 'K', ']')
		case r == '\u2717' || r == '\u2718':
			buf = append(buf, '[', 'X', ']')
		case r == '\u26A0':
			buf = append(buf, '[', '!', ']')
		case r == '\u2022':
			buf = append(buf, '*')
		case r == '\u2026':
			buf = append(buf, '.', '.', '.')
		case r == '\u2192':
			buf = append(buf, '-', '>')
		default:
			buf = append(buf, '?')
		}
	}
	return string(buf)
}

// AuditLigne représente une ligne de résultat.
type AuditLigne struct {
	Niveau string
	Texte  string
}

// AuditSection représente une section de l'audit.
type AuditSection struct {
	Titre  string
	Statut string
	Lignes []AuditLigne
}

// AuditReport est le rapport complet.
type AuditReport struct {
	Date     string
	Project  string
	Resultat string
	Sections []AuditSection
}

type color struct{ r, g, b int }

var (
	colorOK       = color{34, 139, 34}
	colorWarn     = color{255, 165, 0}
	colorCritique = color{200, 0, 0}
	colorInfo     = color{60, 60, 60}
	colorSkip     = color{128, 128, 128}
	colorHeader   = color{30, 30, 80}
	colorBg       = color{245, 245, 255}
	colorWhite    = color{255, 255, 255}
	colorBlack    = color{0, 0, 0}
)

func niveauColor(n string) color {
	switch strings.ToUpper(n) {
	case "OK":
		return colorOK
	case "WARN":
		return colorWarn
	case "CRITIQUE":
		return colorCritique
	case "SKIP":
		return colorSkip
	default:
		return colorInfo
	}
}

// GeneratePDF génère le rapport d'audit au format PDF dans outPath.
func GeneratePDF(report AuditReport, outPath string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.SetAutoPageBreak(true, 20)
	pdf.AddPage()

	pageW, _ := pdf.GetPageSize()
	cW := pageW - 30

	pdf.SetFillColor(colorHeader.r, colorHeader.g, colorHeader.b)
	pdf.SetTextColor(colorWhite.r, colorWhite.g, colorWhite.b)
	pdf.SetFont("Helvetica", "B", 16)
	pdf.CellFormat(cW, 12, toL1("RF Sandbox Go - Rapport d'Audit de Securite"), "", 1, "C", true, 0, "")
	pdf.Ln(3)

	pdf.SetFillColor(colorBg.r, colorBg.g, colorBg.b)
	pdf.SetTextColor(colorBlack.r, colorBlack.g, colorBlack.b)
	pdf.SetFont("Helvetica", "", 10)
	pdf.CellFormat(cW, 7, toL1(fmt.Sprintf("Projet : %s   |   Date : %s", report.Project, report.Date)), "", 1, "L", true, 0, "")

	rc := colorOK
	if strings.Contains(strings.ToUpper(report.Resultat), "CRITIQUE") {
		rc = colorCritique
	} else if strings.Contains(strings.ToUpper(report.Resultat), "WARN") {
		rc = colorWarn
	}
	pdf.SetFillColor(rc.r, rc.g, rc.b)
	pdf.SetTextColor(colorWhite.r, colorWhite.g, colorWhite.b)
	pdf.SetFont("Helvetica", "B", 11)
	pdf.CellFormat(cW, 8, toL1("Resultat global : "+report.Resultat), "", 1, "C", true, 0, "")
	pdf.Ln(5)

	for _, section := range report.Sections {
		sc := niveauColor(section.Statut)
		pdf.SetFillColor(sc.r, sc.g, sc.b)
		pdf.SetTextColor(colorWhite.r, colorWhite.g, colorWhite.b)
		pdf.SetFont("Helvetica", "B", 11)
		label := section.Titre
		if section.Statut != "" {
			label = fmt.Sprintf("[%s] %s", section.Statut, section.Titre)
		}
		pdf.CellFormat(cW, 8, toL1(label), "", 1, "L", true, 0, "")
		pdf.Ln(1)

		pdf.SetFont("Helvetica", "", 9)
		for _, ligne := range section.Lignes {
			lc := niveauColor(ligne.Niveau)
			pdf.SetTextColor(lc.r, lc.g, lc.b)
			pdf.SetFillColor(colorWhite.r, colorWhite.g, colorWhite.b)
			var prefix string
			switch strings.ToUpper(ligne.Niveau) {
			case "OK":
				prefix = "[OK] "
			case "WARN":
				prefix = "[!]  "
			case "CRITIQUE":
				prefix = "[X]  "
			case "SKIP":
				prefix = "  -  "
			default:
				prefix = "     "
			}
			pdf.MultiCell(cW, 5, toL1(prefix+ligne.Texte), "", "L", false)
		}
		pdf.Ln(4)
	}

	pdf.SetTextColor(colorSkip.r, colorSkip.g, colorSkip.b)
	pdf.SetFont("Helvetica", "I", 8)
	pdf.CellFormat(cW, 5, toL1("Genere automatiquement par RF Sandbox Go - audit de securite local"), "", 1, "C", false, 0, "")

	return pdf.OutputFileAndClose(outPath)
}
