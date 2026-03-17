@echo off
setlocal EnableDelayedExpansion
:: =============================================================================
:: bootstrap.bat - Lanceur unique RF Sandbox Go
:: Double-clic pour compiler et lancer
:: =============================================================================

pushd "%~dp0\.."
set "PROJ=%CD%"
popd

echo.
echo  ==========================================
echo    RF Sandbox Go - Bootstrap
echo  ==========================================
echo.

:: ── TEMP local : CMD set appelle SetEnvironmentVariable du kernel ─────────────
set "LOCALTMP=%PROJ%\.gotmp"
if not exist "%LOCALTMP%" mkdir "%LOCALTMP%"
set "TEMP=%LOCALTMP%"
set "TMP=%LOCALTMP%"
set "GOTMPDIR=%LOCALTMP%"
echo  [*] TEMP redirige : %LOCALTMP%

:: Exclusions antivirus si disponibles (ESET / Defender)
powershell -NonInteractive -Command "Add-MpPreference -ExclusionPath '%LOCALTMP%','%PROJ%' -ErrorAction SilentlyContinue" >nul 2>&1
if exist "%ProgramFiles%\ESET\ESET Security\ecls.exe" (
    "%ProgramFiles%\ESET\ESET Security\ecls.exe" /exclude "%LOCALTMP%" >nul 2>&1
    "%ProgramFiles%\ESET\ESET Security\ecls.exe" /exclude "%PROJ%" >nul 2>&1
)
echo  [*] Exclusions AV configurees

:: Tuer les processus qui verrouillent les fichiers
taskkill /F /IM rf-sandbox.exe >nul 2>&1
taskkill /F /IM go.exe          >nul 2>&1
timeout /t 1 /nobreak >nul

:: ── Ecrire et executer le script de compilation ───────────────────────────────
set "BUILD_BAT=%PROJ%\_build_tmp.bat"

(
    echo @echo off
    echo cd /d "%PROJ%"
    echo set "TEMP=%LOCALTMP%"
    echo set "TMP=%LOCALTMP%"
    echo set "GOTMPDIR=%LOCALTMP%"
    echo set "GOOS=windows"
    echo set "GOARCH=amd64"
    echo.
    echo go get github.com/Azure/go-ntlmssp@v0.0.0-20221128193559-754e69321358
    echo go get github.com/joho/godotenv@v1.5.1
    echo go mod tidy
    echo.
    echo go build -ldflags="-s -w" -o "%PROJ%\rf-sandbox.exe" ./cmd
    echo if errorlevel 1 ^( echo [ERREUR] rf-sandbox.exe ^& exit /b 1 ^)
    echo echo [OK] rf-sandbox.exe
    echo.
    echo go build -ldflags="-s -w" -o "%PROJ%\vault.exe" ./cmd/vault
    echo if errorlevel 1 ^( echo [ERREUR] vault.exe ^& exit /b 1 ^)
    echo echo [OK] vault.exe
    echo.
    echo go build -ldflags="-s -w" -o "%PROJ%\compilateur.exe" ./cmd/compilateur
    echo go build -ldflags="-s -w" -o "%PROJ%\audit.exe" ./cmd/audit
    echo go build -ldflags="-s -w" -o "%PROJ%\audit-securite.exe" ./cmd/audit-securite
    echo go build -ldflags="-s -w" -o "%PROJ%\setup-moteur.exe" ./cmd/setup-moteur
    echo go build -ldflags="-s -w" -o "%PROJ%\trainer.exe" ./cmd/trainer
    echo exit /b 0
) > "%BUILD_BAT%"

echo  [*] Compilation en cours...
call "%BUILD_BAT%"
set "ERR=%errorlevel%"
del "%BUILD_BAT%" >nul 2>&1
rmdir /S /Q "%LOCALTMP%" >nul 2>&1

if %ERR% neq 0 (
    echo.
    echo  [ERREUR] Compilation echouee - code %ERR%
    pause
    exit /b 1
)

echo  [OK] Compilation reussie
echo.

:: ── compilateur.exe : audit + vault + lancement UI ───────────────────────────
if exist "%PROJ%\compilateur.exe" (
    "%PROJ%\compilateur.exe"
) else (
    "%PROJ%\rf-sandbox.exe" -ui
)
