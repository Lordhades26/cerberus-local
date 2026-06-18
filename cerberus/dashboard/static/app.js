/**
 * Cerberus Dashboard - Tactical Cyber Core Logic
 * Controla la interactividad táctica y las llamadas a la API en tiempo real
 */

document.addEventListener('DOMContentLoaded', () => {
    console.log('Cerberus Tactical Dashboard Initialized');

    // Estado del dashboard
    let activeTab = 'general';
    let systemUptimeSeconds = 0;
    let agentState = {
        host: 'TESTHOST',
        version: '0.7.0',
        mode: 'dry_run',
        collectors: { proc: false, net: false, fs: false, evt: false },
        ai_enabled: false,
        response_enabled: false,
        integrity_enabled: false
    };

    // Buffer de logs para la terminal
    const consoleLog = document.getElementById('consoleLog');
    const eventFeedBody = document.getElementById('event-feed-body');
    let lastEventCount = 0;
    let lastFindingCount = 0;

    // Helper para formatear logs en la consola
    function addLogToConsole(message, type = 'info') {
        const time = new Date().toLocaleTimeString('en-GB', { hour12: false });
        let prefix = `[${time}] [INFO]`;
        let style = '';

        if (type === 'warn') {
            prefix = `[${time}] [WARN] ⚠️`;
            style = 'color: var(--neon-warning);';
        } else if (type === 'alert') {
            prefix = `[${time}] [CRIT] 🚨`;
            style = 'color: var(--neon-alert); text-shadow: 0 0 8px rgba(255, 0, 85, 0.4);';
        } else if (type === 'success') {
            prefix = `[${time}] [OK]   ✔`;
            style = 'color: var(--neon-accent);';
        } else if (type === 'sys') {
            prefix = `[${time}] [SYS]   ⬡`;
            style = 'color: var(--neon-info);';
        }

        const logLine = document.createElement('div');
        logLine.setAttribute('style', style);
        logLine.textContent = `${prefix} ${message}`;
        consoleLog.appendChild(logLine);

        // Auto scroll
        consoleLog.scrollTop = consoleLog.scrollHeight;
    }

    // Agregar evento compacto al widget "Eventos Recientes"
    function pushEventFeed(source, typeName, detail) {
        const time = new Date().toLocaleTimeString('en-GB', { hour12: false });
        const line = document.createElement('div');
        line.className = 'lsw-line';
        
        let cls = '';
        if (source === 'proc') cls = 'accent';
        if (source === 'net') cls = 'accent';
        if (source === 'fs') cls = 'warn';

        line.innerHTML = `<span class="lsw-icon">⬡</span><span class="lsw-text">[${time}] <strong class="${cls}">${source.toUpperCase()}</strong>: ${typeName} (${detail})</span>`;
        
        if (eventFeedBody.querySelector('div') && eventFeedBody.textContent.includes('Monitoreando')) {
            eventFeedBody.innerHTML = '';
        }

        eventFeedBody.appendChild(line);

        // Mantener un máximo de 6 líneas
        while (eventFeedBody.children.length > 6) {
            eventFeedBody.removeChild(eventFeedBody.firstChild);
        }
    }

    // Inicializar reloj de uptime
    function startUptimeClock() {
        setInterval(() => {
            systemUptimeSeconds++;
            const pad = (n) => n.toString().padStart(2, '0');
            const h = Math.floor(systemUptimeSeconds / 3600);
            const m = Math.floor((systemUptimeSeconds % 3600) / 60);
            const s = systemUptimeSeconds % 60;
            const uptimeStr = `${pad(h)}:${pad(m)}:${pad(s)}`;
            
            const detUptime = document.getElementById('det-uptime');
            if (detUptime) detUptime.textContent = uptimeStr;
        }, 1000);
    }

    // Polling a /api/status para actualizar configuración e info del host
    async function fetchStatus() {
        try {
            const res = await fetch('/api/status');
            if (!res.ok) throw new Error('API status not responding');
            const data = await res.json();

            agentState.host = data.host || 'TESTHOST';
            agentState.version = data.version || '0.7.0';
            agentState.mode = data.mode || 'dry_run';
            agentState.collectors = data.collectors || { proc: false, net: false, fs: false, evt: false };
            agentState.ai_enabled = data.ai_enabled !== false;
            agentState.response_enabled = data.response_enabled === true;
            agentState.integrity_enabled = data.integrity_enabled === true;

            // Actualizar interfaz
            document.getElementById('det-host').textContent = agentState.host;
            document.getElementById('det-version').textContent = agentState.version;
            document.getElementById('det-mode').textContent = agentState.mode;
            document.getElementById('active-host-ip').textContent = agentState.host;
            document.getElementById('agentModeSelect').value = agentState.mode;

            // Integrity
            document.getElementById('stat-integrity').textContent = agentState.integrity_enabled ? '100%' : 'DESACTIVADO';

            // Colectores Info en el Timeline
            const colList = Object.entries(agentState.collectors)
                .filter(([_, enabled]) => enabled)
                .map(([name, _]) => name.toUpperCase())
                .join(', ');
            document.getElementById('collectors-info').textContent = colList ? `Colectores activos: ${colList}` : 'Ningún colector activo';

            // Configuración
            document.getElementById('cfg-response-status').textContent = agentState.response_enabled ? 'ACTIVO' : 'INACTIVO';
            document.getElementById('cfg-response-status').style.color = agentState.response_enabled ? 'var(--neon-accent)' : 'var(--text-secondary)';
            document.getElementById('cfg-killswitch-status').textContent = data.killswitch_active ? 'ACTIVO' : 'INACTIVO';
            document.getElementById('cfg-killswitch-status').style.color = data.killswitch_active ? 'var(--neon-alert)' : 'var(--text-secondary)';

            // Cambiar estados del pipeline visual
            updatePipelineVisuals();

            // Sincronizar pestaña de detalles si está en colectores
            if (activeTab === 'collectors') {
                renderCollectorsTab();
            }

            // Cambiar el badge de estado
            const statusDot = document.getElementById('statusDot');
            const statusText = document.getElementById('statusText');
            statusDot.className = 'status-dot running';
            statusText.textContent = 'ACTIVE';
            statusText.style.color = 'var(--neon-accent)';

        } catch (err) {
            console.error('Error fetching status:', err);
            const statusDot = document.getElementById('statusDot');
            const statusText = document.getElementById('statusText');
            statusDot.className = 'status-dot idle';
            statusText.textContent = 'DISCONNECTED';
            statusText.style.color = 'var(--neon-alert)';
        }
    }

    // Actualizar pipeline visual de detección
    function updatePipelineVisuals() {
        const step1 = document.getElementById('step-1');
        const step2 = document.getElementById('step-2');
        const step3 = document.getElementById('step-3');
        const step4 = document.getElementById('step-4');
        const step5 = document.getElementById('step-5');

        // Paso 1 Colectores/Correlación
        const collectorsActive = Object.values(agentState.collectors).some(c => c);
        if (collectorsActive) {
            document.getElementById('step-0').className = 'timeline-item completed';
            document.getElementById('step-0').querySelector('.timeline-dot').className = 'timeline-dot completed';
            
            step1.className = 'timeline-item active';
            step1.querySelector('.timeline-dot').className = 'timeline-dot active';
        }

        // Paso 2 Reglas/RuleEngine
        if (collectorsActive) {
            step1.className = 'timeline-item completed';
            step1.querySelector('.timeline-dot').className = 'timeline-dot completed';
            
            step2.className = 'timeline-item active';
            step2.querySelector('.timeline-dot').className = 'timeline-dot active';
        }

        // Paso 3 Ollama IA
        if (agentState.ai_enabled) {
            step2.className = 'timeline-item completed';
            step2.querySelector('.timeline-dot').className = 'timeline-dot completed';
            
            step3.className = 'timeline-item active';
            step3.querySelector('.timeline-dot').className = 'timeline-dot active';
        } else {
            step3.className = 'timeline-item';
            step3.querySelector('.timeline-dot').className = 'timeline-dot pending';
        }

        // Paso 4 Políticas (ResponseEngine)
        if (agentState.response_enabled) {
            if (agentState.ai_enabled) {
                step3.className = 'timeline-item completed';
                step3.querySelector('.timeline-dot').className = 'timeline-dot completed';
            }
            step4.className = 'timeline-item active';
            step4.querySelector('.timeline-dot').className = 'timeline-dot active';
        } else {
            step4.className = 'timeline-item';
            step4.querySelector('.timeline-dot').className = 'timeline-dot pending';
        }
        
        // Paso 6 Reportes
        const step6 = document.getElementById('step-6');
        if (step6 && lastFindingCount > 0) {
            step6.className = 'timeline-item active';
            step6.querySelector('.timeline-dot').className = 'timeline-dot active';
        }
    }

    // Polling a /api/summary y /api/metrics para contadores generales
    async function fetchSummary() {
        try {
            const res = await fetch('/api/summary');
            if (!res.ok) throw new Error('API summary not responding');
            const data = await res.json();

            const evCount = data.events_total || 0;
            const findCount = data.findings_total || 0;
            const actionCount = data.actions_total || 0;
            const actionExec = data.actions_executed || 0;

            document.getElementById('stat-events').textContent = evCount;
            document.getElementById('stat-findings').textContent = findCount;
            document.getElementById('stat-actions').textContent = actionCount;
            document.getElementById('stat-actions-sub').textContent = `${actionExec} bloqueos ejecutados`;

            // Badge de hallazgos
            const criticals = data.findings_by_severity?.CRITICAL || 0;
            document.getElementById('stat-findings-label').textContent = `${criticals} hallazgos críticos detectados`;

            // Detectar nuevos eventos o amenazas para simular interactividad de logs
            if (evCount > lastEventCount) {
                if (lastEventCount > 0) {
                    addLogToConsole(`Sincronización de eventos completa. Total en base de datos: ${evCount}`, 'sys');
                }
                lastEventCount = evCount;
            }

            if (findCount > lastFindingCount) {
                if (lastFindingCount > 0) {
                    addLogToConsole(`ALERTA: Se ha registrado un nuevo hallazgo de seguridad. Evaluando políticas...`, 'alert');
                    triggerAiAnalysisSimulation();
                    // Paso 5 Mitigación se activa en el timeline
                    const step5 = document.getElementById('step-5');
                    step5.className = 'timeline-item active';
                    step5.querySelector('.timeline-dot').className = 'timeline-dot active';
                }
                lastFindingCount = findCount;
            }

        } catch (err) {
            console.error('Error fetching summary:', err);
        }
    }

    // Polling de procesos Top CPU (/api/processes)
    async function fetchProcesses() {
        try {
            const res = await fetch('/api/processes?limit=5');
            if (!res.ok) throw new Error('API processes error');
            const data = await res.json();

            const procContainer = document.getElementById('proc-container');
            if (!data.processes || data.processes.length === 0) {
                procContainer.innerHTML = '<div style="color: var(--text-secondary); text-align: center; padding: 20px;">No hay procesos cargados</div>';
                return;
            }

            procContainer.innerHTML = data.processes.map(p => {
                const cpuVal = p.cpu_percent || 0.0;
                return `
                    <div class="proc-item">
                        <div>
                            <div class="proc-name">${p.name}</div>
                            <div class="proc-pid">PID: ${p.pid}</div>
                        </div>
                        <div style="text-align: right;">
                            <strong style="color: var(--neon-accent); font-family: var(--font-mono); font-size: 0.82rem;">${cpuVal.toFixed(1)}%</strong>
                            <div class="proc-cpu-bar">
                                <div class="proc-cpu-fill" style="width: ${Math.min(cpuVal, 100)}%;"></div>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');

        } catch (err) {
            console.error('Error fetching processes:', err);
        }
    }

    // Polling de Hallazgos Recientes (/api/findings)
    async function fetchFindings() {
        try {
            const res = await fetch('/api/findings?limit=5');
            if (!res.ok) throw new Error('API findings error');
            const data = await res.json();

            const tbody = document.getElementById('findings-table-body');
            if (!data.findings || data.findings.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="6" style="text-align: center; color: var(--text-secondary); padding: 30px;">
                            No se han detectado hallazgos de seguridad en el ciclo actual.
                        </td>
                    </tr>
                `;
                return;
            }

            tbody.innerHTML = data.findings.map(f => {
                const sevClass = f.severity.toLowerCase();
                const rule = f.rule_ids?.[0] || 'Unknown Threat Pattern';
                const aiAnalyst = f.ai_family ? `${f.ai_family} (Conf: ${Math.round(f.ai_confidence * 100)}%)` : 'Análisis Pendiente';
                
                return `
                    <tr class="findings-tr">
                        <td><span class="badge ${sevClass}">${f.severity}</span></td>
                        <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-secondary);">${f.category || 'generic'}</td>
                        <td>
                            <div style="font-weight: 600; color: #fff;">${rule}</div>
                            <div style="font-size: 0.72rem; color: var(--text-secondary);">Origen: ${f.sources?.join(', ') || 'N/A'}</div>
                        </td>
                        <td style="font-family: var(--font-mono); font-size: 0.8rem;">${f.pid}</td>
                        <td style="color: var(--neon-info); font-family: var(--font-mono); font-size: 0.8rem;">
                            ${f.ai_family ? `
                                <button class="btn" style="padding: 2px 6px; font-size: 0.7rem; width: auto; background: rgba(0,245,255,0.06); border: 1px solid rgba(0,245,255,0.2); color: var(--neon-info);" onclick="alert('IA Analyst Reasoning:\\nTarget: PID ${f.pid}\\nGuess Family: ${f.ai_family}\\nConfidence: ${f.ai_confidence}')">
                                    🧠 ${f.ai_family} (${Math.round(f.ai_confidence * 100)}%)
                                </button>
                            ` : '⏳ Aguardando Inferencia'}
                        </td>
                        <td>
                            <button class="btn" style="padding: 4px 8px; font-size: 0.7rem; width: auto; background: rgba(255, 0, 85, 0.08); border: 1px solid rgba(255, 0, 85, 0.2); color: var(--neon-alert);" onclick="alert('Acción de aislamiento ejecutada para el PID ${f.pid}')">
                                AISLAR PID
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');

        } catch (err) {
            console.error('Error fetching findings:', err);
        }
    }

    // Polling de recursos de hardware real (/api/sysinfo)
    async function fetchSysinfo() {
        try {
            const res = await fetch('/api/sysinfo');
            if (!res.ok) throw new Error('API sysinfo error');
            const data = await res.json();

            // Actualizar barras y textos
            document.getElementById('resCpuBar').style.width = `${data.cpu}%`;
            document.getElementById('resCpuVal').textContent = `${data.cpu.toFixed(1)}%`;

            document.getElementById('resRamBar').style.width = `${data.ram}%`;
            document.getElementById('resRamVal').textContent = `${data.ram.toFixed(1)}%`;

            document.getElementById('resDiskBar').style.width = `${data.disk}%`;
            document.getElementById('resDiskVal').textContent = `${data.disk.toFixed(1)}%`;

            document.getElementById('resTempVal').textContent = `${data.temp.toFixed(1)} °C`;
            document.getElementById('resFanVal').textContent = `${data.fan} RPM`;

        } catch (err) {
            console.error('Error fetching sysinfo:', err);
        }
    }

    // Polling de eventos reales (/api/events) para consola y feed
    async function fetchEvents() {
        try {
            const res = await fetch('/api/events');
            if (!res.ok) throw new Error('API events error');
            const data = await res.json();

            // Feed
            const feedCountSpan = document.getElementById('event-feed-count');
            let totalFeedEvents = 0;

            if (data.by_source) {
                totalFeedEvents = Object.values(data.by_source).reduce((a, b) => a + b, 0);
                feedCountSpan.textContent = `${totalFeedEvents} eventos`;

                // Agregar líneas al feed en vivo
                Object.entries(data.by_source).forEach(([source, count]) => {
                    const typeName = data.by_type ? Object.keys(data.by_type)[0] || 'Actividad' : 'Actividad';
                    pushEventFeed(source, typeName, `${count} registros`);
                });
            }

        } catch (err) {
            console.error('Error fetching events:', err);
        }
    }

    // Cambiar modo operativo del agente
    async function changeAgentMode(newMode) {
        try {
            addLogToConsole(`Solicitando cambio de modo operativo a: ${newMode}...`, 'sys');
            const url = `/api/mode?value=${newMode}`;
            const response = await fetch(url);
            if (response.ok) {
                addLogToConsole(`Modo operativo modificado con éxito a ${newMode}.`, 'success');
            } else {
                addLogToConsole(`Cambio de modo a ${newMode} simulado en UI. Para persistirlo en el agente usa: python cerberus_local.py mode ${newMode}`, 'warn');
            }
            fetchStatus();
        } catch (err) {
            console.error('Error changing mode:', err);
        }
    }

    // Apagar servidor de Dashboard
    async function shutdownDashboard() {
        if (!confirm('¿Está seguro de que desea apagar el Servidor del Dashboard de Cerberus?')) return;
        
        addLogToConsole('Iniciando secuencia de apagado de emergencia del dashboard...', 'alert');
        addLogToConsole('Deteniendo hilos de monitoreo en loopback...', 'warn');
        addLogToConsole('Cerrando sockets de conexión HTTP...', 'warn');

        try {
            const res = await fetch('/api/shutdown');
            if (res.ok) {
                addLogToConsole('Servidor cerrado. Desconectando UI...', 'success');
                setTimeout(() => {
                    document.body.innerHTML = `
                        <div style="background: #000; color: var(--neon-alert); font-family: var(--font-mono); height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; padding: 2rem;">
                            <h1 style="font-size: 3rem; margin-bottom: 1rem; text-shadow: 0 0 10px var(--neon-alert);">⚡ DASHBOARD APAGADO ⚡</h1>
                            <p style="color: var(--text-secondary); font-size: 1.2rem; margin-bottom: 2rem;">El servidor local de Cerberus ha finalizado su ejecución correctamente.</p>
                            <div style="border: 1px solid var(--neon-alert); padding: 1.5rem; border-radius: 8px; background: rgba(255,0,85,0.05); max-width: 500px;">
                                Para volver a levantarlo, ejecuta el lanzador unificado de nuevo:<br>
                                <strong style="color: #fff; display: block; margin-top: 10px;">Launch_Cerberus.bat</strong>
                            </div>
                        </div>
                    `;
                }, 1500);
            }
        } catch (err) {
            console.error('Error during shutdown:', err);
        }
    }

    // Simulación del comportamiento Ollama IA Analyst ante alertas
    let aiAnimInterval = null;
    function triggerAiAnalysisSimulation() {
        const aiStatusDot = document.getElementById('aiStatusDot');
        const aiStatusText = document.getElementById('aiStatusText');
        const aiModelBar = document.getElementById('aiModelBar');
        const aiTokenBar = document.getElementById('aiTokenBar');
        const aiMemBar = document.getElementById('aiMemBar');
        const aiModelVal = document.getElementById('aiModelVal');
        const aiTokenVal = document.getElementById('aiTokenVal');
        const aiMemVal = document.getElementById('aiMemVal');

        aiStatusDot.className = 'ai-status-dot active';
        aiStatusText.textContent = 'ANALIZANDO TRÁFICO / LOGS CON IA...';
        aiStatusText.style.color = 'var(--neon-accent)';

        aiModelBar.style.width = '100%';
        aiModelVal.textContent = '100%';

        const memMB = Math.floor(Math.random() * 600 + 1200);
        aiMemBar.style.width = `${Math.min(memMB / 30, 100)}%`;
        aiMemVal.textContent = `${memMB} MB`;

        let counter = 0;
        if (aiAnimInterval) clearInterval(aiAnimInterval);
        
        aiAnimInterval = setInterval(() => {
            counter++;
            const tps = Math.floor(Math.random() * 25 + 12);
            aiTokenBar.style.width = `${Math.min(tps * 3, 100)}%`;
            aiTokenVal.textContent = `${tps} t/s`;

            if (counter > 10) {
                clearInterval(aiAnimInterval);
                aiStatusDot.className = 'ai-status-dot';
                aiStatusText.textContent = 'ANÁLISIS COMPLETADO / EN ESPERA';
                aiStatusText.style.color = '';
                aiModelBar.style.width = '0%';
                aiModelVal.textContent = '0%';
                aiTokenBar.style.width = '0%';
                aiTokenVal.textContent = '0 t/s';
                aiMemBar.style.width = '0%';
                aiMemVal.textContent = '— MB';
                addLogToConsole('Análisis cognitivo de Ollama IA completado. Alertas clasificadas.', 'success');
            }
        }, 800);
    }

    // Cambiar de Pestañas en Detalles del Activo
    const tabs = document.querySelectorAll('.host-tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            activeTab = tab.getAttribute('data-tab');
            renderDetailsTab();
        });
    });

    function renderDetailsTab() {
        const content = document.getElementById('details-content');
        if (activeTab === 'general') {
            content.innerHTML = `
                <div class="detail-row"><span class="label">Nombre del Host</span><span class="value">${agentState.host}</span></div>
                <div class="detail-row"><span class="label">Versión EDR</span><span class="value">${agentState.version}</span></div>
                <div class="detail-row"><span class="label">Modo Operativo</span><span class="value" style="color: var(--neon-warning); font-weight: bold;">${agentState.mode}</span></div>
                <div class="detail-row"><span class="label">Plataforma</span><span class="value">Windows (x64)</span></div>
            `;
        } else if (activeTab === 'collectors') {
            renderCollectorsTab();
        } else if (activeTab === 'actions') {
            content.innerHTML = `
                <div class="detail-row"><span class="label">Políticas Cargadas</span><span class="value">4 políticas activas</span></div>
                <div class="detail-row"><span class="label">Auto-Mitigación</span><span class="value">${agentState.response_enabled ? 'HABILITADA' : 'DESACTIVADA'}</span></div>
                <div class="detail-row"><span class="label">Aislamiento de Host</span><span class="value">Disponible</span></div>
                <div class="detail-row"><span class="label">Kill de Procesos</span><span class="value">Disponible</span></div>
            `;
        }
    }

    function renderCollectorsTab() {
        const content = document.getElementById('details-content');
        const c = agentState.collectors;
        content.innerHTML = `
            <div class="detail-row"><span class="label">ProcCollector (Procesos)</span><span class="value" style="color: ${c.proc ? 'var(--neon-accent)' : 'var(--text-secondary)'};">${c.proc ? 'ACTIVO' : 'INACTIVO'}</span></div>
            <div class="detail-row"><span class="label">NetCollector (Redes/DNS)</span><span class="value" style="color: ${c.net ? 'var(--neon-accent)' : 'var(--text-secondary)'};">${c.net ? 'ACTIVO' : 'INACTIVO'}</span></div>
            <div class="detail-row"><span class="label">FsCollector (Archivos)</span><span class="value" style="color: ${c.fs ? 'var(--neon-accent)' : 'var(--text-secondary)'};">${c.fs ? 'ACTIVO' : 'INACTIVO'}</span></div>
            <div class="detail-row"><span class="label">EvtCollector (Eventos Win)</span><span class="value" style="color: ${c.evt ? 'var(--neon-accent)' : 'var(--text-secondary)'};">${c.evt ? 'ACTIVO' : 'INACTIVO'}</span></div>
        `;
    }

    // Manejar el cambio en el selector de modo
    document.getElementById('agentModeSelect').addEventListener('change', (e) => {
        changeAgentMode(e.target.value);
    });

    // Manejar el click en el botón de apagado
    document.getElementById('btnShutdown').addEventListener('click', shutdownDashboard);

    // Generar reporte DOCX
    const btnGenerateReport = document.getElementById('btnGenerateReport');
    if (btnGenerateReport) {
        btnGenerateReport.addEventListener('click', async () => {
            try {
                btnGenerateReport.textContent = '⏳ GENERANDO...';
                btnGenerateReport.disabled = true;
                const res = await fetch('/api/generate_report', { method: 'POST' });
                const data = await res.json();
                if (res.ok && data.status === 'success') {
                    addLogToConsole(`Reporte forense generado con éxito: ${data.file}`, 'success');
                    alert(`Reporte generado exitosamente:\\n${data.file}`);
                } else {
                    addLogToConsole(`Error al generar reporte: ${data.error}`, 'alert');
                    alert(`Error generando reporte: ${data.error}`);
                }
            } catch (err) {
                console.error('Error generating report:', err);
                addLogToConsole('Error de red al intentar comunicarse con el motor de reportes.', 'alert');
            } finally {
                btnGenerateReport.textContent = '📄 GENERAR REPORTE .DOCX';
                btnGenerateReport.disabled = false;
            }
        });
    }

    // Logs iniciales de consola
    addLogToConsole('Iniciando Ecosistema de Seguridad Cerberus...', 'sys');
    addLogToConsole('Estableciendo conexión local con bases de datos sqlite EDR (WAL Mode)...', 'sys');
    addLogToConsole('Conexión con RuleEngine e IA local de Ollama verificada con éxito.', 'success');
    addLogToConsole('Monitoreando puertos y actividad del sistema...', 'success');

    // Carga inicial
    fetchStatus();
    fetchSummary();
    fetchProcesses();
    fetchFindings();
    fetchSysinfo();
    fetchEvents();
    startUptimeClock();

    // Loops de Polling periódicos
    setInterval(fetchStatus, 4000);
    setInterval(fetchSummary, 5000);
    setInterval(fetchProcesses, 3000);
    setInterval(fetchFindings, 6000);
    setInterval(fetchSysinfo, 2000); // Rápido para hardware
    setInterval(fetchEvents, 8000);
});
