# CERBERUS-LOCAL — build del instalador .msi (M6 de campo, Windows real)
# Requiere: WiX Toolset (heat/candle/light), signtool, y opcionalmente cyclonedx-py para SBOM.
# Uso:  .\packaging\build_msi.ps1 -PythonExe "C:\Python311\python.exe" -CertThumbprint "<hash>"
param(
    [Parameter(Mandatory = $true)][string]$PythonExe,
    [string]$CertThumbprint = "",
    [string]$OutDir = "dist"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# 1) Cosechar (harvest) el payload del paquete -> HarvestedComponents
& heat dir "$root\cerberus" -cg HarvestedComponents -gg -scom -sreg -sfrag `
    -dr INSTALLFOLDER -var var.SourceDir -out "$OutDir\harvest.wxs"

# 2) Compilar (.wxs -> .wixobj). Define SourceDir y PythonExe para el .wxs.
& candle -dSourceDir="$root" -dPythonExe="$PythonExe" `
    "$root\packaging\cerberus.wxs" "$OutDir\harvest.wxs" -out "$OutDir\"

# 3) Enlazar (.wixobj -> .msi)
& light "$OutDir\cerberus.wixobj" "$OutDir\harvest.wixobj" -out "$OutDir\cerberus-local-0.6.0.msi"

# 4) Firmar (Authenticode) si se dio thumbprint
if ($CertThumbprint -ne "") {
    & signtool sign /sha1 $CertThumbprint /fd SHA256 /tr http://timestamp.digicert.com `
        /td SHA256 "$OutDir\cerberus-local-0.6.0.msi"
}

# 5) SBOM (CycloneDX) + hash SHA256 del .msi
try { & cyclonedx-py -o "$OutDir\sbom.json" } catch { Write-Warning "cyclonedx-py no disponible; omitiendo SBOM" }
Get-FileHash "$OutDir\cerberus-local-0.6.0.msi" -Algorithm SHA256 |
    Format-List | Out-File "$OutDir\cerberus-local-0.6.0.msi.sha256.txt"

Write-Host "Build .msi completo en $OutDir"
