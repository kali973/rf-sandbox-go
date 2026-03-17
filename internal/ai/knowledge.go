package ai

// knowledge.go - Base de connaissances locale (SQLite)
//
// Driver  : modernc.org/sqlite (pur Go, sans CGO)
// Fichier : GolandProjects/knowledge/analyses.db
// Migration automatique depuis analyses.json si present

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"rf-sandbox-go/internal/models"
)

// ─── Structures ───────────────────────────────────────────────────────────────

type KnowledgeEntry struct {
	ID              string
	Date            string
	Filename        string
	FamillePresumee string
	Classification  string
	ScoreGlobal     int
	TTPs            []string
	IPs             []string
	Domaines        []string
	Hashes          []string
	ResumeExecutif  string
	Recommandations []string
	NiveauConfiance string
}

type SimilarEntry struct {
	Entry  KnowledgeEntry
	Score  int
	Raison string
}

// ─── Chemins ──────────────────────────────────────────────────────────────────

func knowledgeDir() string {
	var workspaceDir string
	if exe, err := os.Executable(); err == nil {
		workspaceDir = filepath.Dir(filepath.Dir(exe))
	}
	if workspaceDir == "" {
		if cwd, err := os.Getwd(); err == nil {
			workspaceDir = filepath.Dir(cwd)
		}
	}
	dir := filepath.Join(workspaceDir, "knowledge")
	os.MkdirAll(dir, 0755)
	return dir
}

func knowledgeDBPath() string   { return filepath.Join(knowledgeDir(), "analyses.db") }
func knowledgeJSONPath() string { return filepath.Join(knowledgeDir(), "analyses.json") }

// ─── Connexion + schema ───────────────────────────────────────────────────────

func openDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite", knowledgeDBPath())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`
		PRAGMA journal_mode=WAL;
		PRAGMA synchronous=NORMAL;
		CREATE TABLE IF NOT EXISTS analyses (
			id              TEXT PRIMARY KEY,
			date            TEXT NOT NULL,
			filename        TEXT NOT NULL,
			famille         TEXT,
			classification  TEXT,
			score           INTEGER DEFAULT 0,
			ttps            TEXT,
			ips             TEXT,
			domaines        TEXT,
			hashes          TEXT,
			resume          TEXT,
			recommandations TEXT,
			confiance       TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_famille ON analyses(famille);
		CREATE INDEX IF NOT EXISTS idx_score   ON analyses(score DESC);
		CREATE INDEX IF NOT EXISTS idx_date    ON analyses(date DESC);
	`); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// ─── JSON helpers ─────────────────────────────────────────────────────────────

func marshalSlice(s []string) string {
	if len(s) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(s)
	return string(b)
}

func unmarshalSlice(s string) []string {
	if s == "" || s == "[]" {
		return nil
	}
	var r []string
	json.Unmarshal([]byte(s), &r)
	return r
}

// ─── Migration JSON → SQLite ──────────────────────────────────────────────────

func migrateFromJSON(db *sql.DB) {
	data, err := os.ReadFile(knowledgeJSONPath())
	if err != nil {
		return
	}
	var old struct {
		Entries []struct {
			ID              string   `json:"id"`
			Date            string   `json:"date"`
			Filename        string   `json:"filename"`
			FamillePresumee string   `json:"famille_presumee"`
			Classification  string   `json:"classification"`
			ScoreGlobal     int      `json:"score_global"`
			TTPs            []string `json:"ttps"`
			IPs             []string `json:"ips"`
			Domaines        []string `json:"domaines"`
			Hashes          []string `json:"hashes"`
			ResumeExecutif  string   `json:"resume_executif"`
			Recommandations []string `json:"recommandations"`
			NiveauConfiance string   `json:"niveau_confiance"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(data, &old); err != nil || len(old.Entries) == 0 {
		return
	}
	tx, err := db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	imported := 0
	for _, e := range old.Entries {
		_, err := tx.Exec(`INSERT OR IGNORE INTO analyses
			(id,date,filename,famille,classification,score,ttps,ips,domaines,hashes,resume,recommandations,confiance)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			e.ID, e.Date, e.Filename, e.FamillePresumee, e.Classification,
			e.ScoreGlobal, marshalSlice(e.TTPs), marshalSlice(e.IPs),
			marshalSlice(e.Domaines), marshalSlice(e.Hashes),
			e.ResumeExecutif, marshalSlice(e.Recommandations), e.NiveauConfiance,
		)
		if err == nil {
			imported++
		}
	}
	if tx.Commit() == nil {
		archive := knowledgeJSONPath() + ".migrated-" + time.Now().Format("20060102-150405")
		os.Rename(knowledgeJSONPath(), archive)
		fmt.Printf("[KNOWLEDGE] Migration JSON->SQLite : %d entrees. Archive : %s\n",
			imported, filepath.Base(archive))
	}
}

// ─── Sauvegarde ───────────────────────────────────────────────────────────────

func SaveAnalysis(results []*models.AnalysisResult, report *ForensicReport) error {
	db, err := openDB()
	if err != nil {
		return fmt.Errorf("openDB: %w", err)
	}
	defer db.Close()

	var count int
	db.QueryRow("SELECT COUNT(*) FROM analyses").Scan(&count)
	if count == 0 {
		migrateFromJSON(db)
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, r := range results {
		ttps := make([]string, 0)
		for _, sig := range r.Signatures {
			for _, ttp := range sig.TTP {
				if ttp != "" && !containsStr(ttps, ttp) {
					ttps = append(ttps, ttp)
				}
			}
		}
		for _, t := range report.TechniquesMitre {
			if t.ID != "" && !containsStr(ttps, t.ID) {
				ttps = append(ttps, t.ID)
			}
		}

		recoms := make([]string, 0)
		for _, rec := range report.Recommandations {
			if rec.Action != "" {
				recoms = append(recoms, fmt.Sprintf("[%s] %s", rec.Priorite, rec.Action))
			}
		}

		if r.Hashes.SHA256 != "" {
			var existing int
			tx.QueryRow("SELECT COUNT(*) FROM analyses WHERE hashes LIKE ?",
				"%"+r.Hashes.SHA256+"%").Scan(&existing)
			if existing > 0 {
				continue
			}
		}

		id := fmt.Sprintf("%d-%s", time.Now().UnixNano(), sanitizeID(r.Filename))
		_, err := tx.Exec(`INSERT OR IGNORE INTO analyses
			(id,date,filename,famille,classification,score,ttps,ips,domaines,hashes,resume,recommandations,confiance)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			id,
			time.Now().UTC().Format(time.RFC3339),
			r.Filename,
			report.Attribution.FamillePresumee,
			report.Classification,
			report.ScoreGlobal,
			marshalSlice(ttps),
			marshalSlice(dedup(r.IOCs.IPs)),
			marshalSlice(dedup(r.IOCs.Domains)),
			marshalSlice(dedup([]string{r.Hashes.SHA256})),
			truncate(report.ResumeExecutif, 500),
			marshalSlice(recoms),
			report.NiveauConfiance,
		)
		if err != nil {
			return fmt.Errorf("insert: %w", err)
		}
	}
	return tx.Commit()
}

// ─── Recherche de similarite ──────────────────────────────────────────────────

func FindSimilar(results []*models.AnalysisResult, maxResults int) []SimilarEntry {
	db, err := openDB()
	if err != nil {
		return nil
	}
	defer db.Close()

	var count int
	db.QueryRow("SELECT COUNT(*) FROM analyses").Scan(&count)
	if count == 0 {
		migrateFromJSON(db)
		db.QueryRow("SELECT COUNT(*) FROM analyses").Scan(&count)
		if count == 0 {
			return nil
		}
	}

	curTTPs := make(map[string]bool)
	curIPs := make(map[string]bool)
	curDomains := make(map[string]bool)
	curFams := make(map[string]bool)

	for _, r := range results {
		for _, sig := range r.Signatures {
			for _, ttp := range sig.TTP {
				if ttp != "" {
					curTTPs[strings.ToUpper(ttp)] = true
				}
			}
			if sig.Name != "" {
				parts := strings.Split(sig.Name, ".")
				if len(parts) >= 2 {
					curFams[strings.ToLower(parts[len(parts)-1])] = true
					curFams[strings.ToLower(parts[len(parts)-2])] = true
				}
			}
		}
		for _, ip := range r.IOCs.IPs {
			curIPs[ip] = true
		}
		for _, d := range r.IOCs.Domains {
			curDomains[strings.ToLower(d)] = true
		}
	}

	rows, err := db.Query(`
		SELECT id,date,filename,famille,classification,score,
		       ttps,ips,domaines,hashes,resume,recommandations,confiance
		FROM analyses ORDER BY date DESC LIMIT 200`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var similar []SimilarEntry
	for rows.Next() {
		var e KnowledgeEntry
		var tJ, iJ, dJ, hJ, rJ string
		if err := rows.Scan(&e.ID, &e.Date, &e.Filename, &e.FamillePresumee,
			&e.Classification, &e.ScoreGlobal,
			&tJ, &iJ, &dJ, &hJ, &e.ResumeExecutif, &rJ, &e.NiveauConfiance,
		); err != nil {
			continue
		}
		e.TTPs = unmarshalSlice(tJ)
		e.IPs = unmarshalSlice(iJ)
		e.Domaines = unmarshalSlice(dJ)
		e.Hashes = unmarshalSlice(hJ)
		e.Recommandations = unmarshalSlice(rJ)

		score := 0
		var raisons []string

		if e.FamillePresumee != "" {
			fam := strings.ToLower(e.FamillePresumee)
			for f := range curFams {
				if strings.Contains(fam, f) || strings.Contains(f, fam) {
					score += 40
					raisons = append(raisons, fmt.Sprintf("famille '%s'", e.FamillePresumee))
					break
				}
			}
		}
		ttpMatches := 0
		for _, t := range e.TTPs {
			if curTTPs[strings.ToUpper(t)] {
				ttpMatches++
			}
		}
		if ttpMatches > 0 {
			pts := ttpMatches * 5
			if pts > 30 {
				pts = 30
			}
			score += pts
			raisons = append(raisons, fmt.Sprintf("%d TTP(s) commun(s)", ttpMatches))
		}
		iocMatches := 0
		for _, ip := range e.IPs {
			if curIPs[ip] {
				iocMatches++
			}
		}
		for _, d := range e.Domaines {
			if curDomains[strings.ToLower(d)] {
				iocMatches++
			}
		}
		if iocMatches > 0 {
			pts := iocMatches * 10
			if pts > 30 {
				pts = 30
			}
			score += pts
			raisons = append(raisons, fmt.Sprintf("%d IOC(s) commun(s)", iocMatches))
		}

		if score >= 10 {
			similar = append(similar, SimilarEntry{
				Entry:  e,
				Score:  score,
				Raison: strings.Join(raisons, ", "),
			})
		}
	}

	sort.Slice(similar, func(i, j int) bool { return similar[i].Score > similar[j].Score })
	if len(similar) > maxResults {
		similar = similar[:maxResults]
	}
	return similar
}

// ─── Prompt ───────────────────────────────────────────────────────────────────

func FormatKnowledgeForPrompt(similar []SimilarEntry) string {
	if len(similar) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("\n\n=== HISTORIQUE D'ANALYSES SIMILAIRES ===\n")
	sb.WriteString("Utilise ces analyses precedentes pour enrichir ton analyse courante.\n")
	for i, s := range similar {
		date := s.Entry.Date
		if len(date) >= 10 {
			date = date[:10]
		}
		sb.WriteString(fmt.Sprintf("\n[Analyse %d - score %d%% - %s]\n", i+1, s.Score, s.Raison))
		sb.WriteString(fmt.Sprintf("  Fichier      : %s\n", s.Entry.Filename))
		sb.WriteString(fmt.Sprintf("  Date         : %s\n", date))
		sb.WriteString(fmt.Sprintf("  Famille      : %s (confiance: %s)\n", s.Entry.FamillePresumee, s.Entry.NiveauConfiance))
		sb.WriteString(fmt.Sprintf("  Classification: %s (score %d/10)\n", s.Entry.Classification, s.Entry.ScoreGlobal))
		if len(s.Entry.TTPs) > 0 {
			sb.WriteString(fmt.Sprintf("  TTPs         : %s\n", strings.Join(s.Entry.TTPs, ", ")))
		}
		if s.Entry.ResumeExecutif != "" {
			sb.WriteString(fmt.Sprintf("  Resume       : %s\n", s.Entry.ResumeExecutif))
		}
	}
	sb.WriteString("\n=== FIN HISTORIQUE ===\n")
	return sb.String()
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func KnowledgeStats() string {
	db, err := openDB()
	if err != nil {
		return "Base inaccessible : " + err.Error()
	}
	defer db.Close()

	var total, families int
	var lastDate string
	db.QueryRow("SELECT COUNT(*) FROM analyses").Scan(&total)
	if total == 0 {
		return "Base de connaissances vide."
	}
	db.QueryRow("SELECT COUNT(DISTINCT famille) FROM analyses WHERE famille != ''").Scan(&families)
	db.QueryRow("SELECT date FROM analyses ORDER BY date DESC LIMIT 1").Scan(&lastDate)
	if len(lastDate) >= 10 {
		lastDate = lastDate[:10]
	}
	return fmt.Sprintf("Base SQLite : %d analyses | %d familles | Derniere : %s | %s",
		total, families, lastDate, knowledgeDBPath())
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func dedup(slice []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range slice {
		if s != "" && !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

func sanitizeID(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' {
			b.WriteRune(c)
		}
	}
	r := b.String()
	if len(r) > 40 {
		r = r[:40]
	}
	return r
}
