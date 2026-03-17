@echo off
setlocal EnableDelayedExpansion
title RF Sandbox Go - Compilateur

echo.
echo  ==========================================
echo    RF Sandbox Go - Compilation directe
echo  ==========================================
echo.

:: Dossier du projet = dossier de ce .bat
set "PROJDIR=%~dp0"
if "%PROJDIR:~-1%"=="\" set "PROJDIR=%PROJDIR:~0,-1%"

:: Dossier temp LOCAL pour contourner Windows Defender sur %TEMP% systeme
set "LOCALTMP=%PROJDIR%\.gotmp"
if not exist "%LOCALTMP%" mkdir "%LOCALTMP%"

:: Rediriger TEMP/TMP/GOTMPDIR vers le dossier local
:: CMD set modifie l'env via SetEnvironmentVariable — GetTempPath() verra ce dossier
set "TEMP=%LOCALTMP%"
set "TMP=%LOCALTMP%"
set "GOTMPDIR=%LOCALTMP%"

:: Tenter d'ajouter une exclusion Windows Defender (silencieux si non-admin)
powershell -NonInteractive -WindowStyle Hidden -Command ^
  "Add-MpPreference -ExclusionPath '%LOCALTMP%' -ErrorAction SilentlyContinue" 2>nul
powershell -NonInteractive -WindowStyle Hidden -Command ^
  "Add-MpPreference -ExclusionProcess 'go.exe' -ErrorAction SilentlyContinue" 2>nul
echo  [OK] Exclusions Defender configurees (ou ignorees si non-admin)

:: Tuer rf-sandbox.exe si en cours
taskkill /F /IM rf-sandbox.exe >nul 2>&1
taskkill /F /IM go.exe >nul 2>&1
timeout /t 1 /nobreak >nul
echo  [OK] Processus existants arretes

:: Detection de la cible OS
set "GOOS=windows"
set "GOARCH=amd64"
set "EXT=.exe"

echo.
echo === Installation des dependances Go ===
go get github.com/Azure/go-ntlmssp@v0.0.0-20221128193559-754e69321358
go get github.com/joho/godotenv@v1.5.1
go mod tidy
if errorlevel 1 (
    echo  [!] go mod tidy echoue - continuation quand meme
)

echo.
echo === Compilation en cours ^(windows/amd64^) ===
echo  Dossier temp : %LOCALTMP%
echo.

:: Compiler chaque binaire
set FAILURES=0

echo  -^> rf-sandbox.exe
go build -ldflags="-s -w" -o "%PROJDIR%\rf-sandbox.exe" "./cmd"
if errorlevel 1 (
    echo  [ERREUR] rf-sandbox.exe - ECHEC CRITIQUE
    set /a FAILURES+=1
    goto :compile_failed
) else (
    echo  [OK] rf-sandbox.exe
)

echo  -^> vault.exe
go build -ldflags="-s -w" -o "%PROJDIR%\vault.exe" "./cmd/vault"
if errorlevel 1 (echo  [ERREUR] vault.exe) else (echo  [OK] vault.exe)

echo  -^> audit.exe
go build -ldflags="-s -w" -o "%PROJDIR%\audit.exe" "./cmd/audit"
if errorlevel 1 (echo  [!] audit.exe - non bloquant) else (echo  [OK] audit.exe)

echo  -^> audit-securite.exe
go build -ldflags="-s -w" -o "%PROJDIR%\audit-securite.exe" "./cmd/audit-securite"
if errorlevel 1 (echo  [!] audit-securite.exe - non bloquant) else (echo  [OK] audit-securite.exe)

echo  -^> setup-moteur.exe
go build -ldflags="-s -w" -o "%PROJDIR%\setup-moteur.exe" "./cmd/setup-moteur"
if errorlevel 1 (echo  [!] setup-moteur.exe - non bloquant) else (echo  [OK] setup-moteur.exe)

echo  -^> compilateur.exe
go build -ldflags="-s -w" -o "%PROJDIR%\compilateur.exe" "./cmd/compilateur"
if errorlevel 1 (echo  [!] compilateur.exe - non bloquant) else (echo  [OK] compilateur.exe)

echo  -^> trainer.exe
go build -ldflags="-s -w" -o "%PROJDIR%\trainer.exe" "./cmd/trainer"
if errorlevel 1 (echo  [!] trainer.exe - non bloquant) else (echo  [OK] trainer.exe)

echo.
echo  ==========================================
echo   [OK] Compilation terminee avec succes !
echo  ==========================================
echo.

:: Nettoyage du dossier temp local
rmdir /S /Q "%LOCALTMP%" >nul 2>&1

:: Vault init + seal
if exist "%PROJDIR%\vault.exe" (
    "%PROJDIR%\vault.exe" init
    echo  Chiffrement du token...
    "%PROJDIR%\vault.exe" seal
    "%PROJDIR%\vault.exe" status
)

echo.
echo  Lancement de l'interface sur http://localhost:8766 ...
echo  (Ctrl+C pour arreter)
echo.
"%PROJDIR%\rf-sandbox.exe" -ui
goto :end

:compile_failed
echo.
echo  ==========================================
echo   [ERREUR] Compilation rf-sandbox.exe
echo  ==========================================
echo.
echo  Si Windows Defender bloque la compilation :
echo.
echo  1. Ouvrir Windows Security
echo  2. Virus and threat protection - Manage settings
echo  3. Exclusions - Add an exclusion - Folder
echo  4. Ajouter : %LOCALTMP%
echo  5. Ajouter : %PROJDIR%
echo  6. Relancer compile.bat
echo.

:end
rmdir /S /Q "%LOCALTMP%" >nul 2>&1
echo.
pause
