# CERBERUS-LOCAL — registro manual del Windows Service (M6 de campo).
# Alternativa a la instalacion via .msi. Ejecutar como Administrador.
# Uso:  .\packaging\install_service.ps1 -PythonExe "C:\Python311\python.exe"
param(
    [Parameter(Mandatory = $true)][string]$PythonExe,
    [string]$ServiceName = "Cerberus"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$script = Join-Path $root "cerberus_service.py"

# 1) Crear el servicio (autoarranque)
& sc.exe create $ServiceName binPath= "`"$PythonExe`" `"$script`"" start= auto
& sc.exe description $ServiceName "EDR hibrido Windows con IA local (defensivo)."

# 2) Recovery: reinicio escalonado 10s -> 1min -> 5min (spec 7.2)
& sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/60000/restart/300000

# 3) Firmar el arbol con el manifest de integridad (anti-tampering)
& $PythonExe (Join-Path $root "cerberus_local.py") integrity snapshot

# 4) Arrancar
& sc.exe start $ServiceName

Write-Host "Servicio $ServiceName instalado y arrancado."
Write-Host "Modo por defecto: dry_run. Cambiar con: $PythonExe cerberus_local.py mode <modo>"
Write-Host "Parada de emergencia: crear C:\ProgramData\Cerberus\KILLSWITCH"
