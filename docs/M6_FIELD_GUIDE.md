# CERBERUS-LOCAL — Guía de campo M6 (pasos manuales en Windows real)

Estos pasos **no se automatizan en el entorno de desarrollo** (requieren admin, WiX,
Npcap, una VM aislada). Se ejecutan en un host/VM Windows real, sobre el código ya
construido y testeado en M1–M5. Cada apartado indica cómo verificarlo.

> **Regla de oro:** nunca habilitar modos `auto_*` ni probar acciones reales fuera de
> una VM aislada con snapshot/restore. El modo `dry_run` es el default obligatorio.

## 1. Windows Service (pywin32)

Envolver el bucle de `cerberus_local.py start` en un servicio:

- Implementar una subclase `win32serviceutil.ServiceFramework` (`CerberusService`) cuyo
  `SvcDoRun` invoque `asyncio.run(_run_loop(cfg))` y cuyo `SvcStop` señale el `stop_event`.
- Registrar: `python cerberus_service.py install` / `... start` (pywin32) o
  `sc create Cerberus binPath= "<python> <ruta>\cerberus_service.py" start= auto`.
- Recovery: `sc failure Cerberus reset= 86400 actions= restart/10000/restart/60000/restart/300000`
  (10s → 1min → 5min, alineado con el spec §7.2).
- La abstracción `ServiceController` (M5) define la interfaz; `ForegroundServiceController`
  es el modo dev. La impl `Win32ServiceController` (sc/pywin32) vive aquí.
- **Verificar:** el servicio arranca al boot, sobrevive logoff, y `services.msc` lo lista como
  "Running"; matar el proceso dispara el recovery.

## 2. Named pipe IPC real

- Con pywin32 instalado, `NamedPipeTransport.available()` debe ser `True`.
- El servidor del pipe corre **dentro del Service**: un hilo/loop que hace
  `win32pipe.CreateNamedPipe(\\.\pipe\cerberus, ...)`, `ConnectNamedPipe`, lee el request,
  llama al `IpcDispatcher`, escribe la respuesta.
- **ACL del pipe (crítico):** crear el pipe con un `SECURITY_ATTRIBUTES` que restrinja el
  acceso a `SYSTEM` + `Administrators` (evita que un usuario sin privilegios mande comandos).
- El cliente (`cerberus status`/`mode`/`rollback`) se conecta vía `NamedPipeTransport.round_trip`.
- **Verificar:** `cerberus status` con el Service corriendo devuelve datos vía pipe (no DB directa);
  un usuario estándar no puede abrir el pipe.

## 3. Anti-tampering (completar M5)

- Tras instalar, ejecutar `cerberus integrity snapshot` para firmar el árbol (`manifest.json`).
- El Service verifica al arrancar (`_startup_integrity_violation`); si hay mismatch → fuerza
  `dry_run` + log CRITICAL. Ya implementado en M5; aquí se valida en el host real.
- **ACL `SYSTEM:F`** sobre el directorio de instalación, `manifest.json`, `KILLSWITCH` y la
  cuarentena (`icacls <dir> /inheritance:r /grant:r SYSTEM:F Administrators:F`; considerar
  TakeOwnership para que admin no pueda alterar sin dejar rastro).
- **Verificar:** alterar un `.py` y reiniciar el Service → arranca en `dry_run` con
  `integrity_violation` en el log.

## 4. Npcap + pyshark / `dns_query` (NetCollector M6)

- Instalar Npcap (modo WinPcap-compatible) con privilegios.
- Añadir un `PySharkProbe` opcional a `NetCollector`: `pyshark.LiveCapture` sobre la interfaz
  default; emite `dns_query` (y enriquece `outbound_conn`). Import lazy; si Npcap/pyshark
  ausentes → el collector sigue en polling psutil (degradación, ya soportada por el diseño).
- Añadir reglas/policies que casen `dns_query` (p.ej. DNS a dominios de alto riesgo / DGA).
- **Verificar:** generar una consulta DNS y ver el evento `dns_query` en el reporte; sin Npcap,
  no rompe (solo polling).

## 5. Instalador `.msi` (WiX Toolset)

- `.wxs` con harvesting del paquete (`heat`), `candle` + `light`; instalar en
  `C:\Program Files\Cerberus`, datos en `C:\ProgramData\Cerberus`.
- Acciones de instalación: registrar el Service, crear dirs con ACL, ejecutar
  `integrity snapshot` post-install.
- **Firmar** el `.msi` (Authenticode); publicar **SBOM** (CycloneDX) + hashes SHA256.
- **Verificar:** instalación limpia + arranque del Service; **desinstalación limpia** (no deja
  servicios; la cuarentena se preserva) per spec §9.5.

## 6. Redteam simulado (VM aislada, sin red externa)

- TTPs MITRE (spec §9.4): T1059.001 (PowerShell), T1071.001 (DNS C2), T1486 (Ransomware),
  T1078 (Valid Accounts), T1543.003 (Service).
- Snapshot de la VM antes de cada caso; restore tras cada test. Probar en `dry_run` primero,
  luego `auto_critical` con confirmación.
- Métricas: % TTPs detectados, MTTD, tasa de falsos positivos en 24h baseline.
- Documentar por release en `tests/redteam_reports/`.

## 7. Checklist pre-release (spec §9.5)
- [ ] N1+N2 (unit+integración) verdes en CI (`windows-latest`): pytest, ruff, mypy, bandit
- [ ] N3 (funcionales) ejecutados en VM limpia
- [ ] Instalación `.msi` limpia + arranque del Service exitoso
- [ ] Killswitch verificado (crear `KILLSWITCH` detiene toda acción)
- [ ] Desinstalación limpia (sin servicios residuales; cuarentena preservada)
- [ ] Baseline 24h: CPU < 5%, RAM < 200MB en idle
- [ ] Auditoría `auditing-security` (OWASP/ASVS/ASI) sin hallazgos críticos
- [ ] `.msi` firmado + SBOM + hashes publicados
