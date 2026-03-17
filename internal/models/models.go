package models

import "encoding/json"

// ─── Structures de réponse API Recorded Future Sandbox ────────────────────

// Sample représente un échantillon soumis (réponse POST /samples)
type Sample struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Kind      string `json:"kind"`
	Filename  string `json:"filename,omitempty"`
	URL       string `json:"url,omitempty"`
	Private   bool   `json:"private"`
	Submitted string `json:"submitted,omitempty"`
	Completed string `json:"completed,omitempty"`
}

// Summary - GET /samples/{id}/summary
type Summary struct {
	Sample    string                 `json:"sample"`
	Status    string                 `json:"status"`
	Kind      string                 `json:"kind,omitempty"`
	Owner     string                 `json:"owner,omitempty"`
	Target    string                 `json:"target,omitempty"`
	Created   string                 `json:"created,omitempty"`
	Completed string                 `json:"completed,omitempty"`
	Score     int                    `json:"score"`
	SHA256    string                 `json:"sha256,omitempty"`
	Custom    string                 `json:"custom,omitempty"`
	Tasks     map[string]TaskSummary `json:"tasks"`
}

// TaskSummary - résumé d'une tâche d'analyse
type TaskSummary struct {
	Kind     string   `json:"kind"`
	Status   string   `json:"status"`
	Tags     []string `json:"tags,omitempty"`
	TTP      []string `json:"ttp,omitempty"`
	Score    int      `json:"score,omitempty"`
	Target   string   `json:"target,omitempty"`
	Backend  string   `json:"backend,omitempty"`
	Resource string   `json:"resource,omitempty"`
	Platform string   `json:"platform,omitempty"`
	TaskName string   `json:"task_name,omitempty"`
	QueueID  int      `json:"queue_id,omitempty"`
}

// Overview - GET /samples/{id}/overview.json
// NOTE: RF Sandbox renvoie parfois Tasks comme un objet {} au lieu d'un tableau [].
// On utilise un UnmarshalJSON custom pour gérer les deux formats.
type Overview struct {
	Version    string              `json:"version"`
	Sample     OverviewSample      `json:"sample"`
	Tasks      []OverviewTask      `json:"-"` // géré par UnmarshalJSON
	Analysis   OverviewAnalysis    `json:"analysis"`
	Targets    []OverviewTarget    `json:"targets"`
	Signatures []OverviewSignature `json:"signatures,omitempty"`
	Extracted  []OverviewExtracted `json:"extracted,omitempty"`
	Errors     []ReportedFailure   `json:"errors,omitempty"`
}

// UnmarshalJSON gère le fait que RF Sandbox renvoie parfois
// "tasks": {} (objet vide) au lieu de "tasks": [] (tableau).
func (o *Overview) UnmarshalJSON(data []byte) error {
	// Alias pour éviter la récursion infinie
	type OverviewAlias struct {
		Version    string              `json:"version"`
		Sample     OverviewSample      `json:"sample"`
		Tasks      json.RawMessage     `json:"tasks"`
		Analysis   OverviewAnalysis    `json:"analysis"`
		Targets    []OverviewTarget    `json:"targets"`
		Signatures []OverviewSignature `json:"signatures,omitempty"`
		Extracted  []OverviewExtracted `json:"extracted,omitempty"`
		Errors     []ReportedFailure   `json:"errors,omitempty"`
	}
	var alias OverviewAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	o.Version = alias.Version
	o.Sample = alias.Sample
	o.Analysis = alias.Analysis
	o.Targets = alias.Targets
	o.Signatures = alias.Signatures
	o.Extracted = alias.Extracted
	o.Errors = alias.Errors

	// Tasks : accepter tableau [] ET objet {} (RF renvoie les deux selon le statut)
	if len(alias.Tasks) > 0 && alias.Tasks[0] == '[' {
		json.Unmarshal(alias.Tasks, &o.Tasks) // tableau normal
	}
	// Si c'est un objet {} ou null → Tasks reste nil, pas d'erreur
	return nil
}

type OverviewAnalysis struct {
	Score  int      `json:"score"`
	Family []string `json:"family,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

type OverviewSample struct {
	ID        string        `json:"id"`
	Target    string        `json:"target"`
	Size      int64         `json:"size,omitempty"`
	MD5       string        `json:"md5,omitempty"`
	SHA1      string        `json:"sha1,omitempty"`
	SHA256    string        `json:"sha256,omitempty"`
	SHA512    string        `json:"sha512,omitempty"`
	Filetype  string        `json:"filetype,omitempty"`
	Score     int           `json:"score,omitempty"`
	Created   string        `json:"created,omitempty"`
	Completed string        `json:"completed,omitempty"`
	IOCs      *OverviewIOCs `json:"iocs,omitempty"`
}

type OverviewIOCs struct {
	URLs    []string `json:"urls,omitempty"`
	Domains []string `json:"domains,omitempty"`
	IPs     []string `json:"ips,omitempty"`
}

type OverviewTarget struct {
	Tasks      []string            `json:"tasks"`
	Target     string              `json:"target,omitempty"`
	Size       int64               `json:"size,omitempty"`
	MD5        string              `json:"md5,omitempty"`
	SHA1       string              `json:"sha1,omitempty"`
	SHA256     string              `json:"sha256,omitempty"`
	SHA512     string              `json:"sha512,omitempty"`
	Tags       []string            `json:"tags,omitempty"`
	Family     []string            `json:"family,omitempty"`
	Signatures []OverviewSignature `json:"signatures,omitempty"`
	IOCs       *OverviewIOCs       `json:"iocs,omitempty"`
}

// OverviewTask — élément de Overview.Tasks (spec officielle : slice, champ "sample" = taskID)
// Ex: {"sample": "260309-rwz69sbyvs-behavioral1", "kind": "behavioral", "status": "reported", ...}
type OverviewTask struct {
	Sample   string   `json:"sample"` // taskID complet, ex: "260309-rwz69sbyvs-behavioral1"
	Kind     string   `json:"kind,omitempty"`
	Name     string   `json:"name,omitempty"`
	Status   string   `json:"status,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	TTP      []string `json:"ttp,omitempty"`
	Score    int      `json:"score,omitempty"`
	Target   string   `json:"target,omitempty"`
	Backend  string   `json:"backend,omitempty"`
	Resource string   `json:"resource,omitempty"`
	Platform string   `json:"platform,omitempty"`
	TaskName string   `json:"task_name,omitempty"`
	Failure  string   `json:"failure,omitempty"`
	QueueID  int64    `json:"queue_id,omitempty"`
	Pick     string   `json:"pick,omitempty"`
}

type TaskIOC = OverviewIOCs

type OverviewSignature struct {
	Label      string      `json:"label,omitempty"`
	Name       string      `json:"name"`
	Score      int         `json:"score,omitempty"`
	Tags       []string    `json:"tags,omitempty"`
	TTP        []string    `json:"ttp,omitempty"`
	Indicators []Indicator `json:"indicators,omitempty"`
	Desc       string      `json:"desc,omitempty"`
	URL        string      `json:"url,omitempty"`
}

// OverviewExtracted expose la config extraite ainsi que les tâches associées
type OverviewExtracted struct {
	Tasks []string `json:"tasks"`
	Extract
}

// TriageReport - GET /samples/{id}/{task}/report_triage.json
type TriageReport struct {
	Version    string            `json:"version"`
	Sample     TargetDesc        `json:"sample"`
	Task       TargetDesc        `json:"task"`
	Errors     []ReportedFailure `json:"errors,omitempty"`
	Analysis   AnalysisInfo      `json:"analysis,omitempty"`
	Processes  []Process         `json:"processes,omitempty"`
	Signatures []Signature       `json:"signatures"`
	Network    NetworkReport     `json:"network"`
	Dumped     []Dump            `json:"dumped,omitempty"`
	Extracted  []Extract         `json:"extracted,omitempty"`
}

type TargetDesc struct {
	ID         string   `json:"id,omitempty"`
	Score      int      `json:"score,omitempty"`
	Submitted  string   `json:"submitted,omitempty"`
	Completed  string   `json:"completed,omitempty"`
	Target     string   `json:"target,omitempty"`
	Pick       string   `json:"pick,omitempty"`
	Type       string   `json:"type,omitempty"`
	Size       int64    `json:"size,omitempty"`
	MD5        string   `json:"md5,omitempty"`
	SHA1       string   `json:"sha1,omitempty"`
	SHA256     string   `json:"sha256,omitempty"`
	SHA512     string   `json:"sha512,omitempty"`
	Filetype   string   `json:"filetype,omitempty"`
	StaticTags []string `json:"static_tags,omitempty"`
}

type ReportedFailure struct {
	Task    string `json:"task,omitempty"`
	Backend string `json:"backend,omitempty"`
	Reason  string `json:"reason"`
}

type AnalysisInfo struct {
	Score          int      `json:"score,omitempty"`
	Tags           []string `json:"tags"`
	TTP            []string `json:"ttp,omitempty"`
	Features       []string `json:"features,omitempty"`
	Submitted      string   `json:"submitted,omitempty"`
	Reported       string   `json:"reported,omitempty"`
	MaxTimeNetwork int64    `json:"max_time_network,omitempty"`
	MaxTimeKernel  uint32   `json:"max_time_kernel,omitempty"`
	Backend        string   `json:"backend,omitempty"`
	Resource       string   `json:"resource,omitempty"`
	ResourceTags   []string `json:"resource_tags,omitempty"`
	Platform       string   `json:"platform,omitempty"`
}

type Process struct {
	ProcID       int32       `json:"procid,omitempty"`
	ParentProcID int32       `json:"procid_parent,omitempty"`
	PID          uint64      `json:"pid"`
	PPID         uint64      `json:"ppid"`
	Cmd          interface{} `json:"cmd"`
	Image        string      `json:"image,omitempty"`
	Orig         bool        `json:"orig"`
	Started      uint32      `json:"started"`
	Terminated   uint32      `json:"terminated,omitempty"`
}

type Signature struct {
	Label      string      `json:"label,omitempty"`
	Name       string      `json:"name"`
	Score      int         `json:"score,omitempty"`
	TTP        []string    `json:"ttp,omitempty"`
	Tags       []string    `json:"tags,omitempty"`
	Indicators []Indicator `json:"indicators,omitempty"`
	YaraRule   string      `json:"yara_rule,omitempty"`
	Desc       string      `json:"desc,omitempty"`
	URL        string      `json:"url,omitempty"`
}

type Indicator struct {
	IOC          string `json:"ioc,omitempty"`
	Description  string `json:"description,omitempty"`
	At           uint32 `json:"at,omitempty"`
	SourcePID    uint64 `json:"pid,omitempty"`
	SourceProcID int32  `json:"procid,omitempty"`
	TargetPID    uint64 `json:"pid_target,omitempty"`
	TargetProcID int32  `json:"procid_target,omitempty"`
	Flow         int    `json:"flow,omitempty"`
	DumpFile     string `json:"dump_file,omitempty"`
	Resource     string `json:"resource,omitempty"`
	YaraRule     string `json:"yara_rule,omitempty"`
}

type NetworkReport struct {
	Flows    []NetworkFlow    `json:"flows,omitempty"`
	Requests []NetworkRequest `json:"requests,omitempty"`
}

type NetworkFlow struct {
	ID        int      `json:"id,omitempty"`
	Source    string   `json:"src,omitempty"`
	Dest      string   `json:"dst,omitempty"`
	Proto     string   `json:"proto,omitempty"`
	PID       uint64   `json:"pid,omitempty"`
	ProcID    int32    `json:"procid,omitempty"`
	FirstSeen int64    `json:"first_seen,omitempty"`
	LastSeen  int64    `json:"last_seen,omitempty"`
	RxBytes   uint64   `json:"rx_bytes,omitempty"`
	TxBytes   uint64   `json:"tx_bytes,omitempty"`
	RxPackets uint64   `json:"rx_packets,omitempty"`
	TxPackets uint64   `json:"tx_packets,omitempty"`
	Protocols []string `json:"protocols,omitempty"`
	Domain    string   `json:"domain,omitempty"`
	JA3       string   `json:"tls_ja3,omitempty"`
	JA3S      string   `json:"tls_ja3s,omitempty"`
	SNI       string   `json:"tls_sni,omitempty"`
	Country   string   `json:"country,omitempty"`
	AS        string   `json:"as_num,omitempty"`
	Org       string   `json:"as_org,omitempty"`
}

type NetworkRequest struct {
	Flow       int                    `json:"flow,omitempty"`
	Index      int                    `json:"index,omitempty"`
	At         uint32                 `json:"at,omitempty"`
	DomainReq  *NetworkDomainRequest  `json:"dns_request,omitempty"`
	DomainResp *NetworkDomainResponse `json:"dns_response,omitempty"`
	WebReq     *NetworkWebRequest     `json:"http_request,omitempty"`
	WebResp    *NetworkWebResponse    `json:"http_response,omitempty"`
}

type NetworkDomainRequest struct {
	Domains   []string   `json:"domains,omitempty"`
	Questions []DNSEntry `json:"questions,omitempty"`
}

type NetworkDomainResponse struct {
	Domains []string   `json:"domains,omitempty"`
	IP      []string   `json:"ip,omitempty"`
	Answers []DNSEntry `json:"answers,omitempty"`
}

type DNSEntry struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
}

type NetworkWebRequest struct {
	Method  string   `json:"method,omitempty"`
	URL     string   `json:"url"`
	Request string   `json:"request,omitempty"`
	Headers []string `json:"headers,omitempty"`
}

type NetworkWebResponse struct {
	Status   string   `json:"status"`
	Response string   `json:"response,omitempty"`
	Headers  []string `json:"headers,omitempty"`
}

type Dump struct {
	At     uint32 `json:"at"`
	PID    uint64 `json:"pid,omitempty"`
	ProcID int32  `json:"procid,omitempty"`
	Path   string `json:"path,omitempty"`
	Name   string `json:"name,omitempty"`
	Kind   string `json:"kind,omitempty"`
	Addr   uint64 `json:"addr,omitempty"`
	Length uint64 `json:"length,omitempty"`
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

type Extract struct {
	DumpedFile  string         `json:"dumped_file,omitempty"`
	Resource    string         `json:"resource,omitempty"`
	Config      *MalwareConfig `json:"config,omitempty"`
	Path        string         `json:"path,omitempty"`
	RansomNote  *RansomNote    `json:"ransom_note,omitempty"`
	Credentials *Credentials   `json:"credentials,omitempty"`
	Dropper     *Dropper       `json:"dropper,omitempty"` // dropper avec URLs de téléchargement
}

// CryptoKey représente une clé cryptographique extraite d'un malware
type CryptoKey struct {
	Kind  string      `json:"kind,omitempty"` // ex: AES, RSA, XOR, ecc_pubkey.base64…
	Key   string      `json:"key,omitempty"`
	Value interface{} `json:"value,omitempty"` // valeur de la clé (string ou bytes selon le type)
}

type MalwareConfig struct {
	Family       string        `json:"family,omitempty"`
	Tags         []string      `json:"tags,omitempty"`
	Rule         string        `json:"rule,omitempty"`
	C2           []string      `json:"c2,omitempty"`
	Version      string        `json:"version,omitempty"`
	Botnet       string        `json:"botnet,omitempty"`
	Campaign     string        `json:"campaign,omitempty"`
	Mutex        []string      `json:"mutex,omitempty"`
	Decoy        []string      `json:"decoy,omitempty"`
	Wallet       []string      `json:"wallet,omitempty"`  // compat ancienne clé
	Wallets      []string      `json:"wallets,omitempty"` // clé officielle doc API
	DNS          []string      `json:"dns,omitempty"`
	Webinject    []string      `json:"webinject,omitempty"`
	CommandLines []string      `json:"command_lines,omitempty"` // commandes exécutées (persistance, curl, ftp…)
	ListenAddr   string        `json:"listen_addr,omitempty"`
	ListenPort   int           `json:"listen_port,omitempty"`
	ListenFor    []string      `json:"listen_for,omitempty"`
	ExtractedPE  []string      `json:"extracted_pe,omitempty"`
	Shellcode    [][]byte      `json:"shellcode,omitempty"` // shellcode extrait
	Keys         []CryptoKey   `json:"keys,omitempty"`
	Credentials  []Credentials `json:"credentials,omitempty"` // identifiants extraits (liste)
	Attributes   interface{}   `json:"attr,omitempty"`        // autorun, scheduled tasks, etc.
	Raw          string        `json:"raw,omitempty"`         // config brute non parsée
}

// Dropper représente un dropper avec ses URLs de téléchargement de payload
type Dropper struct {
	Family   string       `json:"family,omitempty"`
	Language string       `json:"language"`
	Source   string       `json:"source"`       // source déobfusquée (obligatoire dans spec)
	Deobf    string       `json:"deobfuscated"` // version déobfusquée du script
	URLs     []DropperURL `json:"urls"`
}

// DropperURL représente une URL de téléchargement d'un payload par un dropper
type DropperURL struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type RansomNote struct {
	Family  string   `json:"family,omitempty"`
	Target  string   `json:"target,omitempty"`
	Emails  []string `json:"emails,omitempty"`
	Wallets []string `json:"wallets,omitempty"`
	URLs    []string `json:"urls,omitempty"`
	Contact []string `json:"contact,omitempty"` // contacts supplémentaires (chat, etc.)
	Note    string   `json:"note"`              // texte brut de la note de rançon
}

type Credentials struct {
	Flow     int    `json:"flow,omitempty"` // ID du flux réseau associé
	Protocol string `json:"protocol"`       // http, ftp, smtp…
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Username string `json:"username"` // aussi mappé depuis "user" dans certaines versions
	Password string `json:"password"`
	EmailTo  string `json:"email_to,omitempty"` // destinataire mail (exfiltration)
	URL      string `json:"url,omitempty"`
}

// ─── Structure de résultat consolidé ──────────────────────────────────────

// AnalysisResult regroupe toutes les données d'un échantillon analysé
type AnalysisResult struct {
	SampleID     string
	Filename     string
	Status       string
	Score        int
	Family       string
	Tags         []string
	Hashes       Hashes
	Summary      *Summary
	Overview     *Overview
	Static       *StaticReport
	Tasks        map[string]TaskResult
	Signatures   []AggregatedSignature
	Network      map[string]NetworkReport
	Processes    []ProcessWithTask
	Extracted    []ExtractWithTask
	IOCs         IOCBundle
	DroppedFiles []DroppedFileInfo // fichiers déposés par le malware (payloads récupérés)
	KernelEvents []KernelEvent     // événements kernel horodatés (onemon.json) — timeline précise
	Error        string
}

// KernelEvent représente un événement du moniteur kernel (onemon.json).
// Chaque événement est horodaté en ms depuis le début de l'analyse,
// avec le processus source (PID/image) et le détail de l'action.
type KernelEvent struct {
	TimeMs  uint64 `json:"time_ms,omitempty"` // timestamp en ms depuis début analyse
	PID     uint64 `json:"pid,omitempty"`
	Image   string `json:"image,omitempty"`   // nom du processus (ex: "WScript.exe")
	Action  string `json:"action,omitempty"`  // type d'événement (file, reg, net, proc…)
	Target  string `json:"target,omitempty"`  // objet ciblé (chemin, clé registre, IP…)
	Details string `json:"details,omitempty"` // informations supplémentaires
}

// DroppedFileInfo contient les métadonnées et le contenu d'un fichier déposé par le malware.
type DroppedFileInfo struct {
	Name    string // nom du fichier dans la sandbox
	TaskID  string // tâche comportementale qui l'a généré
	Kind    string // kind (exe, dll, txt, etc.)
	MD5     string
	SHA1    string
	SHA256  string
	Size    uint64
	Content []byte // contenu brut (limité à 10 Mo par fichier)
}

type Hashes struct {
	MD5    string
	SHA1   string
	SHA256 string
	SHA512 string
}

type TaskResult struct {
	TaskSummary
	Report *TriageReport
}

type AggregatedSignature struct {
	TaskID string
	Signature
}

type ProcessWithTask struct {
	TaskID string
	Process
}

type ExtractWithTask struct {
	TaskID string
	Extract
}

// IOCBundle regroupe tous les IOCs extraits
type IOCBundle struct {
	IPs     []string
	Domains []string
	URLs    []string
	Hashes  []string
	Mutexes []string
}

// ─── Rapport Statique ─────────────────────────────────────────────────────

// StaticReport - GET /samples/{id}/reports/static
type StaticReport struct {
	Version     string             `json:"version"`
	Sample      StaticReportSample `json:"sample"`
	Task        StaticReportTask   `json:"task"`
	Analysis    StaticAnalysis     `json:"analysis"`
	Signatures  []Signature        `json:"signatures,omitempty"`
	Files       []FileReport       `json:"files"`
	UnpackCount int                `json:"unpack_count"`
	ErrorCount  int                `json:"error_count"`
	Errors      []ReportedFailure  `json:"errors,omitempty"`
	Extracted   []Extract          `json:"extracted,omitempty"`
}

type StaticReportSample struct {
	ID        string `json:"sample"`
	Kind      string `json:"kind,omitempty"`
	Size      uint64 `json:"size,omitempty"`
	Target    string `json:"target,omitempty"`
	Submitted string `json:"submitted,omitempty"`
}

type StaticReportTask struct {
	ID     string `json:"task"`
	Target string `json:"target,omitempty"`
}

type StaticAnalysis struct {
	Reported string   `json:"reported,omitempty"`
	Score    int      `json:"score,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

// FileReport décrit un fichier extrait lors de l'analyse statique
type FileReport struct {
	Name       string   `json:"filename"`
	RelPath    string   `json:"relpath,omitempty"`
	Size       uint64   `json:"filesize"`
	MD5        string   `json:"md5,omitempty"`
	SHA1       string   `json:"sha1,omitempty"`
	SHA256     string   `json:"sha256,omitempty"`
	SHA512     string   `json:"sha512,omitempty"`
	Filetype   string   `json:"filetype,omitempty"`
	Mime       string   `json:"mime,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Extensions []string `json:"exts,omitempty"`
	Depth      int      `json:"depth"`
	Kind       string   `json:"kind"`
	Selected   bool     `json:"selected"`
	RunAs      string   `json:"runas,omitempty"`
	Password   string   `json:"password,omitempty"`
	Error      string   `json:"error,omitempty"`
}
