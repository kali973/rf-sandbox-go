package ai

// colors.go — Codes ANSI pour la colorisation de la console.
// Compatible Windows 10+ (VT sequences activées automatiquement via os.Stdout),
// Linux et macOS. Sur les terminaux ne supportant pas ANSI, les codes sont ignorés.

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

// ─── Codes ANSI ───────────────────────────────────────────────────────────────

const (
	ansiReset      = "\033[0m"
	ansiGreen      = "\033[32m"
	ansiYellow     = "\033[33m"
	ansiRed        = "\033[31m"
	ansiCyan       = "\033[36m"
	ansiBoldWhite  = "\033[1;37m"
	ansiBoldGreen  = "\033[1;32m"
	ansiBoldYellow = "\033[1;33m"
	ansiBoldRed    = "\033[1;31m"
	ansiBoldCyan   = "\033[1;36m"
	ansiGrey       = "\033[90m"
)

// ─── Exports publics pour les autres packages (ui, cmd) ──────────────────────

// CInfo : message vert (info standard)
func CInfo(text string) string { return cInfo(text) }

// COK : message vert gras (succès)
func COK(text string) string { return cOK(text) }

// CWarn : message jaune (avertissement)
func CWarn(text string) string { return cWarn(text) }

// CErr : message rouge (erreur)
func CErr(text string) string { return cErr(text) }

// CGrey : message gris (secondaire)
func CGrey(text string) string { return cGrey(text) }

// CDetail : message cyan avec préfixe tag (détail technique)
func CDetail(tag, msg string) string { return logDetail(tag, msg) }

// CHeader : en-tête de section blanc gras
func CHeader(tag, msg string) string { return logHeader(tag, msg) }

// ansiEnabled indique si le terminal supporte les codes couleur.
var ansiEnabled = initAnsi()

func initAnsi() bool {
	if runtime.GOOS == "windows" {
		// Activer le mode VT sur Windows 10+ via kernel32
		return enableWindowsVT()
	}
	// Linux/macOS : vérifier que stdout est un TTY
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// enableWindowsVT active le mode Virtual Terminal Processing sur Windows.
// Nécessaire pour que les séquences ANSI soient interprétées dans cmd.exe / PowerShell.
func enableWindowsVT() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")

	stdout := syscall.Handle(os.Stdout.Fd())
	var mode uint32
	ret, _, _ := getConsoleMode.Call(uintptr(stdout), uintptr(unsafe.Pointer(&mode)))
	if ret == 0 {
		return false // pas une console (ex: redirigé vers fichier)
	}
	const enableVirtualTerminalProcessing = 0x0004
	mode |= enableVirtualTerminalProcessing
	ret, _, _ = setConsoleMode.Call(uintptr(stdout), uintptr(mode))
	return ret != 0
}

// ─── Fonctions de colorisation ────────────────────────────────────────────────

func colorize(code, text string) string {
	if !ansiEnabled {
		return text
	}
	return code + text + ansiReset
}

// Info : texte en vert (messages normaux / OK)
func cInfo(text string) string { return colorize(ansiGreen, text) }

// InfoBold : texte en vert gras (succès importants)
func cOK(text string) string { return colorize(ansiBoldGreen, text) }

// Warn : texte en jaune (avertissements non bloquants)
func cWarn(text string) string { return colorize(ansiBoldYellow, text) }

// Err : texte en rouge gras (erreurs)
func cErr(text string) string { return colorize(ansiBoldRed, text) }

// Detail : texte en cyan (détails techniques)
func cDetail(text string) string { return colorize(ansiCyan, text) }

// Header : texte en blanc gras (en-têtes de section)
func cHeader(tag, msg string) string { return logHeader(tag, msg) }

// Grey : texte gris (logs secondaires, attente)
func cGrey(text string) string { return colorize(ansiGrey, text) }

// ─── Helpers de log colorisé ─────────────────────────────────────────────────

// logInfo : message d'information standard (vert)
func logInfo(tag, msg string) string {
	return cInfo(fmt.Sprintf("[%s] %s", tag, msg))
}

// logOK : succès (vert gras + coche)
func logOK(tag, msg string) string {
	return cOK(fmt.Sprintf("[%s] ✓ %s", tag, msg))
}

// logWarn : avertissement (jaune)
func logWarn(tag, msg string) string {
	return cWarn(fmt.Sprintf("[%s] ⚠ %s", tag, msg))
}

// logErr : erreur (rouge)
func logErr(tag, msg string) string {
	return cErr(fmt.Sprintf("[%s] ✗ %s", tag, msg))
}

// logDetail : détail technique (cyan)
func logDetail(tag, msg string) string {
	return cDetail(fmt.Sprintf("[%s] │  %s", tag, msg))
}

// logHeader : en-tête de bloc (blanc gras)
func logHeader(tag, msg string) string {
	sep := strings.Repeat("═", 51)
	return colorize(ansiBoldWhite, fmt.Sprintf("[%s] %s\n[%s]  %s\n[%s] %s", tag, sep, tag, msg, tag, sep))
}
