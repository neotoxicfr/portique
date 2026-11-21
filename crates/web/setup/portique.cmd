@echo off
setlocal
rem Portique : prepare ce PC Windows 10/11 Pro pour Portique. Relancable. "portique.cmd annuler" defait tout.
rem Sources : learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access
rem   Groupe de regles pare-feu "Bureau a distance" = @FirewallAPI.dll,-28752, independant de la langue :
rem   learn.microsoft.com/windows-hardware/customize/desktop/unattend/networking-mpssvc-svc-firewallgroups-firewallgroup-group
rem   powercfg : learn.microsoft.com/windows-hardware/design/device-experiences/powercfg-command-line-options
rem   (la page ecrit /deviceenableawake par erreur ; le commutateur reel est /deviceenablewake ;
rem   nom de peripherique via /devicequery wake_programmable ; verification : /devicequery wake_armed).
rem   HiberbootEnabled = 0 : demarrage rapide desactive (le reveil depuis l'arret en depend).
rem Les cles de registre sont dans portique.reg / annuler.reg, importes ici s'ils sont a cote.

rem fltmc demande les droits administrateur sans dependre du service Serveur (net session en depend).
fltmc >nul 2>&1
if errorlevel 1 (
  echo Lance ce fichier en administrateur : clic droit, "Executer en tant qu'administrateur".
  pause
  exit /b 1
)
cd /d "%~dp0"

if /i "%~1"=="annuler" goto annuler

if not exist portique.reg (echo portique.reg introuvable a cote de ce fichier. & pause & exit /b 1)
reg import portique.reg || (echo Echec de l'import de portique.reg. & pause & exit /b 1)
echo [ok] Registre : Bureau a distance, NLA, graphiques, redirections.

set "ECHEC="
netsh advfirewall firewall set rule group="@FirewallAPI.dll,-28752" new enable=Yes >nul
if errorlevel 1 (
  echo [!] Pare-feu : echec de netsh, regles "Bureau a distance" non activees.
  set "ECHEC=1"
) else (
  echo [ok] Pare-feu : regles "Bureau a distance" activees.
)

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f >nul
if errorlevel 1 (
  echo [!] Echec : demarrage rapide non desactive.
  set "ECHEC=1"
) else (
  echo [ok] Demarrage rapide desactive ^(necessaire au reveil depuis l'arret^).
)

rem Carte reseau active : autoriser le reveil par paquet magique, afficher l'adresse MAC.
set "NICDESC="
for /f "usebackq tokens=1,2,3 delims=|" %%a in (`powershell -NoProfile -Command "$a=Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1; if($a){$a.Name+'|'+$a.InterfaceDescription+'|'+$a.MacAddress}"`) do (
  set "NICDESC=%%b"
  set "NICNAME=%%a"
  call :reveil "%%a" "%%b" "%%c"
)
if not defined NICDESC echo [!] Aucune carte reseau physique active trouvee.
echo      Pense aussi a activer Wake-on-LAN dans le BIOS/UEFI.

gpupdate /force >nul
if errorlevel 1 (
  echo [!] Echec de gpupdate : strategies non appliquees ^(redemarrer ou relancer^).
  set "ECHEC=1"
) else (
  echo [ok] Strategies appliquees ^(gpupdate^).
)
echo [..] Empreinte du certificat RDP a comparer dans Portique :
rem Le certificat peut etre dans le magasin "Remote Desktop" (auto-signe) ou "My" (certificat personnalise).
powershell -NoProfile -Command "try { $ts = Get-CimInstance -Namespace root\cimv2\TerminalServices -ClassName Win32_TSGeneralSetting -Filter \"TerminalName='RDP-tcp'\"; $h = $ts.SSLCertificateSHA1Hash; $c = $null; if ($h) { $c = Get-Item ('Cert:\LocalMachine\Remote Desktop\' + $h), ('Cert:\LocalMachine\My\' + $h) -ErrorAction SilentlyContinue | Select-Object -First 1 }; if (-not $c) { throw 'absent' }; '     ' + ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($c.RawData)) -replace '-','').ToLower() } catch { '     (certificat pas encore cree : relance ce fichier apres une premiere connexion)' }"
echo.
if defined ECHEC (
  echo [!] Preparation INCOMPLETE : les etapes marquees [!] ci-dessus ont echoue ^(les autres sont appliquees^).
  pause
  exit /b 1
)
echo Termine. Relancer ce fichier est sans danger.
pause
exit /b 0

:reveil
rem %~1 nom de la carte, %~2 description (nom de peripherique de powercfg), %~3 adresse MAC.
rem PowerShell lit le nom dans NICNAME : une valeur, jamais du code (le nom d'une carte se renomme).
powercfg /deviceenablewake "%~2" >nul 2>&1
if errorlevel 1 (
  echo [!] Reveil : powercfg refuse la carte "%~2", reveil non autorise.
  set "ECHEC=1"
  goto :eof
)
rem Memorise la carte modifiee, une valeur par carte (adresse MAC) : l'annulation les retrouve toutes,
rem meme debranchees ou remplacees depuis par une autre carte.
reg add "HKLM\SOFTWARE\Portique" /v "Nic-%~3" /t REG_SZ /d "%~2" /f >nul
if errorlevel 1 (
  rem Sans memo, l'annulation viserait la carte active : on retire l'autorisation.
  powercfg /devicedisablewake "%~2" >nul 2>&1
  echo [!] Reveil : carte "%~2" non memorisee dans le registre, reveil non autorise.
  set "ECHEC=1"
  goto :eof
)
powershell -NoProfile -Command "try { Set-NetAdapterPowerManagement -Name $env:NICNAME -WakeOnMagicPacket Enabled -ErrorAction Stop } catch { exit 1 }" >nul 2>&1
if errorlevel 1 goto reveil_note
echo [ok] Reveil autorise pour : %~2
goto reveil_mac
:reveil_note
echo [!] Reveil autorise par powercfg pour "%~2", mais WakeOnMagicPacket non configure ^(pilote ?^) : a verifier dans les proprietes de la carte.
:reveil_mac
echo      Adresse MAC a recopier dans Portique : %~3
goto :eof

:annuler
if not exist annuler.reg (echo annuler.reg introuvable a cote de ce fichier. & pause & exit /b 1)
reg import annuler.reg || (echo Echec de l'import de annuler.reg. & pause & exit /b 1)
set "ECHEC="
netsh advfirewall firewall set rule group="@FirewallAPI.dll,-28752" new enable=No >nul
if errorlevel 1 (
  echo [!] Pare-feu : echec de netsh, regles non desactivees.
  set "ECHEC=1"
)
rem Cartes memorisees a la preparation (une valeur par carte). La carte active seulement SANS journal : un
rem journal vide est celui d'une annulation dont les cartes sont deja traitees (une autre etape a echoue).
set "JOURNAL="
reg query "HKLM\SOFTWARE\Portique" >nul 2>&1 && set "JOURNAL=1"
for /f "tokens=1,2,*" %%a in ('reg query "HKLM\SOFTWARE\Portique" 2^>nul ^| findstr /c:"REG_SZ"') do call :sans_reveil "%%c" "%%a"
if not defined JOURNAL for /f "usebackq delims=" %%a in (`powershell -NoProfile -Command "(Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1).InterfaceDescription"`) do call :sans_reveil "%%a" ""
gpupdate /force >nul
if errorlevel 1 (
  echo [!] Echec de gpupdate : strategies non appliquees ^(redemarrer ou relancer^).
  set "ECHEC=1"
)
rem Journal garde, meme vide, tant qu'une etape echoue : une nouvelle annulation ne vise que les cartes restantes.
if not defined ECHEC reg delete "HKLM\SOFTWARE\Portique" /f >nul 2>&1
if defined ECHEC (
  echo [!] Annulation INCOMPLETE : les etapes marquees [!] ont echoue.
  pause
  exit /b 1
)
echo Annule : Bureau a distance ferme, strategies retirees, pare-feu et reveil restaures.
pause
exit /b 0

:sans_reveil
rem %~1 description de la carte, %~2 nom de sa valeur memorisee (vide : carte active, rien a oublier).
powercfg /devicedisablewake "%~1" >nul 2>&1
if errorlevel 1 (
  echo [!] Reveil : powercfg n'a pas pu retirer l'autorisation de la carte "%~1".
  set "ECHEC=1"
  goto :eof
)
rem Carte traitee : oubliee, une nouvelle annulation ne vise que les cartes restantes.
if not "%~2"=="" reg delete "HKLM\SOFTWARE\Portique" /v "%~2" /f >nul 2>&1
goto :eof
