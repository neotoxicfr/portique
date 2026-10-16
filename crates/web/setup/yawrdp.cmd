@echo off
setlocal
rem yawrdp : prepare ce PC Windows 10/11 Pro pour yawrdp. Relancable. "yawrdp.cmd annuler" defait tout.
rem Sources : learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access
rem   Groupe de regles pare-feu "Bureau a distance" = @FirewallAPI.dll,-28752, independant de la langue :
rem   learn.microsoft.com/windows-hardware/customize/desktop/unattend/networking-mpssvc-svc-firewallgroups-firewallgroup-group
rem   powercfg : learn.microsoft.com/windows-hardware/design/device-experiences/powercfg-command-line-options
rem   (la page ecrit /deviceenableawake par erreur ; le commutateur reel est /deviceenablewake ;
rem   nom de peripherique via /devicequery wake_programmable ; verification : /devicequery wake_armed).
rem   HiberbootEnabled = 0 : demarrage rapide desactive (le reveil depuis l'arret en depend).
rem Les cles de registre sont dans yawrdp.reg / annuler.reg, importes ici s'ils sont a cote.

net session >nul 2>&1
if errorlevel 1 (
  echo Lance ce fichier en administrateur : clic droit, "Executer en tant qu'administrateur".
  pause
  exit /b 1
)
cd /d "%~dp0"

if /i "%~1"=="annuler" goto annuler

if not exist yawrdp.reg (echo yawrdp.reg introuvable a cote de ce fichier. & pause & exit /b 1)
reg import yawrdp.reg || (echo Echec de l'import de yawrdp.reg. & pause & exit /b 1)
echo [ok] Registre : Bureau a distance, NLA, graphiques, redirections.

netsh advfirewall firewall set rule group="@FirewallAPI.dll,-28752" new enable=Yes >nul
echo [ok] Pare-feu : regles "Bureau a distance" activees.

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f >nul
echo [ok] Demarrage rapide desactive (necessaire au reveil depuis l'arret).

rem Carte reseau active : autoriser le reveil par paquet magique, afficher l'adresse MAC.
for /f "usebackq tokens=1,* delims=|" %%a in (`powershell -NoProfile -Command "$a=Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1; if($a){$a.InterfaceDescription+'|'+$a.MacAddress}"`) do (
  powercfg /deviceenablewake "%%a" >nul 2>&1
  echo [ok] Reveil autorise pour : %%a
  echo      Adresse MAC a recopier dans yawrdp : %%b
)
echo      Pense aussi a activer Wake-on-LAN dans le BIOS/UEFI.

gpupdate /force >nul
echo [ok] Strategies appliquees (gpupdate).
echo [..] Empreinte du certificat RDP a comparer dans yawrdp :
powershell -NoProfile -Command "try { $ts = Get-CimInstance -Namespace root\cimv2\TerminalServices -ClassName Win32_TSGeneralSetting -Filter \"TerminalName='RDP-tcp'\"; $c = Get-Item ('Cert:\LocalMachine\Remote Desktop\' + $ts.SSLCertificateSHA1Hash); '     ' + ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($c.RawData)) -replace '-','').ToLower() } catch { '     (certificat pas encore cree : relance ce fichier apres une premiere connexion)' }"
echo.
echo Termine. Relancer ce fichier est sans danger.
pause
exit /b 0

:annuler
if not exist annuler.reg (echo annuler.reg introuvable a cote de ce fichier. & pause & exit /b 1)
reg import annuler.reg || (echo Echec de l'import de annuler.reg. & pause & exit /b 1)
netsh advfirewall firewall set rule group="@FirewallAPI.dll,-28752" new enable=No >nul
for /f "usebackq delims=" %%a in (`powershell -NoProfile -Command "(Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1).InterfaceDescription"`) do powercfg /devicedisablewake "%%a" >nul 2>&1
gpupdate /force >nul
echo Annule : Bureau a distance ferme, strategies retirees, pare-feu et reveil restaures.
pause
exit /b 0
