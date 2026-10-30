# Test de bout en bout de l'installateur, réservé au CI.
# Installe en silence, vérifie les fichiers, le PATH et la commande, puis désinstalle et vérifie le nettoyage.
# ATTENTION : ce script écrit dans %APPDATA%\Vault et dans le registre de l'utilisateur courant.
# Il refuse donc de tourner ailleurs que sur GitHub Actions, pour ne jamais toucher à un vrai coffre.
param([Parameter(Mandatory = $true)][string]$Setup)

$ErrorActionPreference = "Stop"
if ($env:GITHUB_ACTIONS -ne "true") {
    throw "Ce test modifie %APPDATA%\Vault et le registre : il ne tourne que sur GitHub Actions."
}

$installDir = Join-Path $env:LOCALAPPDATA "Programs\Vault"
$binDir = Join-Path $installDir "bin"
$log = Join-Path $env:TEMP "vault-setup.log"
$dataDir = Join-Path $env:APPDATA "Vault"
$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

function Assert-True($condition, $message) {
    if (-not $condition) { throw $message }
}

# 1. Installation silencieuse (tâches par défaut : le PATH est inclus).
$p = Start-Process -FilePath $Setup -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CURRENTUSER", "/LOG=$log" -Wait -PassThru
if ($p.ExitCode -ne 0) {
    Get-Content $log -Tail 40
    throw "L'installateur a quitté avec le code $($p.ExitCode)"
}
foreach ($f in "vault-gui.exe", "bin\vault.exe", "LICENSE") {
    Assert-True (Test-Path (Join-Path $installDir $f)) "Fichier manquant après installation : $f"
}
Write-Output "OK  installation : fichiers présents dans $installDir"

# 2. Le dossier de la commande est dans le PATH de l'utilisateur.
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
Assert-True ($userPath -like "*$binDir*") "Le PATH utilisateur ne contient pas $binDir"
Write-Output "OK  PATH utilisateur"

# 3. La commande installée fonctionne et affiche sa sortie (binaire en mode console).
$help = & (Join-Path $binDir "vault.exe") --help | Out-String
Assert-True ($LASTEXITCODE -eq 0 -and $help -match "Coffre de secrets") "vault --help a échoué : $help"
Write-Output "OK  vault --help"

# 4. Simule ce que fait l'application : démarrage automatique et coffre de l'utilisateur.
New-Item -Path $runKey -Force | Out-Null  # absente sur une machine neuve
Set-ItemProperty -Path $runKey -Name "Vault" -Value "`"$installDir\vault-gui.exe`""
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
Set-Content -Path (Join-Path $dataDir "vault.enc") -Value "donnees-utilisateur-a-conserver"

# 5. Désinstallation silencieuse. Le désinstalleur se relance depuis un dossier temporaire : on attend la fin.
Start-Process -FilePath (Join-Path $installDir "unins000.exe") -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART" -Wait
for ($i = 0; $i -lt 90 -and (Test-Path (Join-Path $installDir "vault-gui.exe")); $i++) { Start-Sleep -Seconds 1 }
Assert-True (-not (Test-Path (Join-Path $installDir "vault-gui.exe"))) "Désinstallation incomplète : vault-gui.exe est toujours là"
Write-Output "OK  désinstallation : fichiers retirés"

# 6. Nettoyage : PATH et démarrage automatique retirés, données de l'utilisateur conservées.
Start-Sleep -Seconds 2
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
Assert-True ($userPath -notlike "*$binDir*") "Le PATH utilisateur contient encore $binDir"
$run = Get-ItemProperty -Path $runKey -Name "Vault" -ErrorAction SilentlyContinue
Assert-True ($null -eq $run) "La valeur de démarrage automatique « Vault » est restée dans le registre"
Assert-True (Test-Path (Join-Path $dataDir "vault.enc")) "Le coffre de l'utilisateur a été supprimé : c'est interdit"
Write-Output "OK  PATH nettoyé, démarrage automatique retiré, coffre conservé"
