@echo off
title DETENER CERBERUS EDR
echo [1/2] Localizando procesos de Cerberus...

:: Matar procesos de python que esten ejecutando cerberus_local.py
:: Usamos taskkill con filtro para ser precisos
wmic process where "commandline like '%%cerberus_local.py%%'" delete

:: Por seguridad, cerramos tambien cualquier instancia del dashboard que use python en el venv
taskkill /F /FI "WINDOWTITLE eq Cerberus Agent" /T 2>nul
taskkill /F /FI "WINDOWTITLE eq Cerberus Dashboard" /T 2>nul

echo [2/2] Limpiando sockets y recursos...
:: Cerramos el servidor IPC si quedo colgado
taskkill /F /IM cerberus.exe /T 2>nul

echo.
echo ======================================================
echo    CERBERUS LOCAL EDR HA SIDO DETENIDO
echo ======================================================
echo [OK] Todos los procesos han sido finalizados.
echo.
timeout /t 3

