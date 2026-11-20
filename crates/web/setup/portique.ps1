#Requires -RunAsAdministrator
<#
 Portique : prepare ce PC Windows 10/11 Pro pour Portique, tout-en-un. Relancable.
 Usage : clic droit > Executer avec PowerShell (administrateur), ou  .\portique.ps1 [-Annuler]
 Sources : learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access
   learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-terminalserver
   learn.microsoft.com/powershell/module/netadapter/set-netadapterpowermanagement
   Groupe pare-feu "Bureau a distance" : @FirewallAPI.dll,-28752 (independant de la langue).
 Valeurs verifiees contre TerminalServer.admx (modeles Windows 11 25H2) et policy-csp-admx-terminalserver :
   ImageQuality 1 sans perte, 2 haute, 3 moyenne, 4 basse ; SecurityLayer 2 = TLS ; delais en ms, 0 = jamais.
   DWMFRAMEINTERVAL = 15 : learn.microsoft.com/troubleshoot/windows-server/remote/frame-rate-limited-to-30-fps
   powercfg : le commutateur reel est /deviceenablewake (la page Learn ecrit /deviceenableawake par erreur).
#>
param([switch]$Annuler)
$ErrorActionPreference = 'Stop'
$ts  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$grp = '@FirewallAPI.dll,-28752'

function Set-Dw($path, $name, $val) {
  if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
  New-ItemProperty -Path $path -Name $name -Value $val -PropertyType DWord -Force | Out-Null
}
function Get-ActiveNic { Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1 }

$polNames = 'UserAuthentication','SecurityLayer','AVC444ModePreferred','AVCHardwareEncodePreferred',
  'bEnumerateHWBeforeSW','fEnableWddmDriver','ImageQuality','fDisableClip','fDisableCdm',
  'fDisableCam','fDisableAudioCapture','MaxIdleTime','MaxDisconnectionTime','MaxConnectionTime'

if ($Annuler) {
  Set-Dw $ts 'fDenyTSConnections' 1
  Remove-ItemProperty -Path "$ts\WinStations" -Name DWMFRAMEINTERVAL -ErrorAction SilentlyContinue
  foreach ($n in $polNames) { Remove-ItemProperty -Path $pol -Name $n -ErrorAction SilentlyContinue }
  Set-Dw 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' 1
  netsh advfirewall firewall set rule group=$grp new enable=No | Out-Null
  $nic = Get-ActiveNic
  if ($nic) { powercfg /devicedisablewake $nic.InterfaceDescription 2>$null | Out-Null }
  gpupdate /force | Out-Null
  Write-Host 'Annule : Bureau a distance ferme, strategies retirees, pare-feu et reveil restaures.'
  return
}

# Bureau a distance (NLA et TLS imposes par les strategies ci-dessous)
Set-Dw $ts 'fDenyTSConnections' 0
Set-Dw "$ts\WinStations" 'DWMFRAMEINTERVAL' 15      # 60 i/s (15 decimal)
# Strategies : graphiques, redirections, delais
$vals = [ordered]@{
  UserAuthentication = 1; SecurityLayer = 2
  AVC444ModePreferred = 1; AVCHardwareEncodePreferred = 1; bEnumerateHWBeforeSW = 1; fEnableWddmDriver = 1
  ImageQuality = 2
  fDisableClip = 0; fDisableCdm = 0; fDisableCam = 0; fDisableAudioCapture = 0
  MaxIdleTime = 0; MaxDisconnectionTime = 0; MaxConnectionTime = 0
}
foreach ($k in $vals.Keys) { Set-Dw $pol $k $vals[$k] }
Write-Host '[ok] Registre : Bureau a distance, NLA, graphiques, redirections.'

netsh advfirewall firewall set rule group=$grp new enable=Yes | Out-Null
Write-Host '[ok] Pare-feu : regles "Bureau a distance" activees.'

Set-Dw 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' 0
Write-Host '[ok] Demarrage rapide desactive (necessaire au reveil depuis l''arret).'

$nic = Get-ActiveNic
if ($nic) {
  powercfg /deviceenablewake $nic.InterfaceDescription 2>$null | Out-Null
  try { Set-NetAdapterPowerManagement -Name $nic.Name -WakeOnMagicPacket Enabled -ErrorAction Stop } catch { Write-Host "     (WakeOnMagicPacket non gere par ce pilote : $($_.Exception.Message))" }
  Write-Host "[ok] Reveil autorise pour : $($nic.InterfaceDescription)"
  Write-Host "     Adresse MAC a recopier dans Portique : $($nic.MacAddress)"
} else { Write-Host '[!] Aucune carte reseau physique active trouvee.' }
Write-Host '     Pense aussi a activer Wake-on-LAN dans le BIOS/UEFI.'

gpupdate /force | Out-Null
Write-Host '[ok] Strategies appliquees (gpupdate). Relancer ce script est sans danger.'

# Empreinte du certificat RDP : Portique la montre a l'admin lors de la premiere connexion,
# elle doit etre IDENTIQUE (sinon quelqu'un s'interpose). Certificat designe par
# Win32_TSGeneralSetting.SSLCertificateSHA1Hash, empreinte = SHA-256 du certificat DER.
try {
  $tsg = Get-CimInstance -Namespace root\cimv2\TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'"
  $cert = Get-Item ("Cert:\LocalMachine\Remote Desktop\" + $tsg.SSLCertificateSHA1Hash)
  $sha = [System.Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData)
  $fp = ([System.BitConverter]::ToString($sha) -replace '-', '').ToLower()
  Write-Host "[ok] Empreinte du certificat RDP a comparer dans Portique :"
  Write-Host "     $fp"
} catch {
  Write-Host '[!] Certificat RDP pas encore cree : relance ce script apres une premiere tentative de connexion.'
}
