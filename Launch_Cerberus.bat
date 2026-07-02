@echo off
title CERBERUS LOCAL - Lanzador Unificado
set PROJECT_DIR=%~dp0
cd /d %PROJECT_DIR%

echo [1/3] Verificando entorno...
set PYTHON_EXE=".venv\Scripts\python.exe"
if not exist %PYTHON_EXE% (
    echo [WARN] No se detecto el entorno virtual .venv, usando python global...
    set PYTHON_EXE=python
)

if not exist "cerberus_local.py" (
    echo [ERROR] No se encuentra cerberus_local.py en %PROJECT_DIR%
    pause
    exit /b
)

echo [2/3] Iniciando Agente Cerberus (Modo Dry-Run)...
start /min "Cerberus Agent" %PYTHON_EXE% cerberus_local.py start --dry-run

echo [3/3] Iniciando Dashboard de Operaciones...
echo El Dashboard se abrira en breve en http://localhost:5000
start /min "Cerberus Dashboard" %PYTHON_EXE% cerberus_local.py dashboard

timeout /t 3 /nobreak > nul
start http://localhost:5000

echo.
echo ======================================================
echo    CERBERUS LOCAL EDR ESTA CORRIENDO
echo ======================================================
echo [INFO] El Agente y el Dashboard estan en segundo plano.
echo [INFO] Cierra las ventanas minimizadas para detenerlos.
echo ======================================================
timeout /t 5
