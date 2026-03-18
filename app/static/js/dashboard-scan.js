(() => {
    const form = document.getElementById('scanForm');
    if (!form) return;

    const protocoloInput = document.getElementById('protocoloInput');
    const urlInput = document.getElementById('urlInput');
    const urlFieldError = document.getElementById('urlFieldError');
    const urlFieldErrorText = document.getElementById('urlFieldErrorText');
    const urlPreview = document.getElementById('urlPreview');
    const scanButton = document.getElementById('scanButton');
    const alerts = document.getElementById('scanAlerts');
    const progressCard = document.getElementById('scanProgressCard');
    const progressBar = document.getElementById('scanProgressBar');
    const progressMessage = document.getElementById('scanProgressMessage');
    const scanStepList = document.getElementById('scanStepList');
    const resultUrl = document.getElementById('resultUrl');
    const resultProtocol = document.getElementById('resultProtocol');
    const resultsBody = document.getElementById('resultsBody');
    const totalVuln = document.getElementById('totalVuln');
    const summaryStatus = document.getElementById('summaryStatus');
    const statsTotalHallazgos = document.getElementById('statsTotalHallazgos');
    const statsCriticas = document.getElementById('statsCriticas');
    const statsTotalEscaneos = document.getElementById('statsTotalEscaneos');
    const statsEscaneosHoy = document.getElementById('statsEscaneosHoy');
    const sendReportButton = document.getElementById('sendReportButton');
    const sendReportStatus = document.getElementById('sendReportStatus');

    const steps = [
        { text: 'Comprobando inyeccion SQL (SQLi)...', target: 20 },
        { text: 'Analizando vectores XSS reflejado...', target: 40 },
        { text: 'Revisando formularios y parametros de entrada...', target: 60 },
        { text: 'Consultando reputacion de URL con VirusTotal...', target: 80 },
        { text: 'Consolidando resultados del escaneo...', target: 92 },
    ];

    let stepTimer = null;
    let progressTimer = null;
    let currentStepIndex = 0;
    let currentProgressTarget = 5;
    let ultimoEscaneoId = Number(sendReportButton?.dataset.escaneoId || 0) || null;

    function limpiarAlertas() {
        alerts.innerHTML = '';
    }

    function limpiarErrorCampoUrl() {
        if (urlFieldError) {
            urlFieldError.classList.add('hidden');
            urlFieldError.classList.remove('flex');
        }
        urlInput.classList.remove('ring-2', 'ring-rose-400/60', 'bg-rose-500/10');
    }

    function mostrarErrorCampoUrl(mensaje) {
        if (urlFieldError && urlFieldErrorText) {
            urlFieldErrorText.textContent = mensaje;
            urlFieldError.classList.remove('hidden');
            urlFieldError.classList.add('flex');
        }
        urlInput.classList.add('ring-2', 'ring-rose-400/60', 'bg-rose-500/10');
    }

    function mostrarAlerta(tipo, titulo, mensaje) {
        const estilos = tipo === 'error'
            ? 'border-rose-400/40 bg-rose-500/10 text-rose-100'
            : 'border-amber-400/40 bg-amber-500/10 text-amber-100';
        const icono = tipo === 'error' ? 'error' : 'timer';

        alerts.innerHTML = `
            <div class="max-w-4xl mx-auto w-full rounded-xl border ${estilos} px-5 py-4">
                <div class="flex items-start gap-3">
                    <span class="material-symbols-outlined ${tipo === 'error' ? 'text-rose-300' : 'text-amber-300'}">${icono}</span>
                    <div>
                        <p class="text-sm font-bold uppercase tracking-wide">${titulo}</p>
                        <p class="text-sm mt-1">${mensaje}</p>
                    </div>
                </div>
            </div>`;
    }

    function mostrarEstadoEnvio(texto, esError = false) {
        if (!sendReportStatus) return;
        sendReportStatus.textContent = texto;
        sendReportStatus.classList.remove('hidden', 'text-slate-300', 'text-green-300', 'text-rose-300');
        sendReportStatus.classList.add(esError ? 'text-rose-300' : 'text-green-300');
    }

    function renderStepList(activeIndex, completedIndex) {
        if (!scanStepList) return;

        scanStepList.innerHTML = steps.map((step, index) => {
            let icon = 'radio_button_unchecked';
            let iconClass = 'text-slate-500';
            let textClass = 'text-slate-400';

            if (index <= completedIndex) {
                icon = 'check_circle';
                iconClass = 'text-emerald-400';
                textClass = 'text-emerald-300';
            } else if (index === activeIndex) {
                icon = 'autorenew';
                iconClass = 'text-primary animate-spin';
                textClass = 'text-cyan-100';
            }

            return `
                <li class="flex items-center gap-2 ${textClass}">
                    <span class="material-symbols-outlined text-sm ${iconClass}">${icon}</span>
                    <span>${step.text}</span>
                </li>`;
        }).join('');
    }

    function iniciarAnimacion() {
        currentStepIndex = 0;
        currentProgressTarget = 5;

        progressCard.classList.remove('hidden');
        progressBar.style.width = '5%';
        progressMessage.textContent = steps[0].text;
        renderStepList(0, -1);

        stepTimer = setInterval(() => {
            if (currentStepIndex < steps.length - 1) {
                currentStepIndex += 1;
            }
            currentProgressTarget = steps[currentStepIndex].target;
            progressMessage.textContent = steps[currentStepIndex].text;
            renderStepList(currentStepIndex, currentStepIndex - 1);
        }, 1900);

        progressTimer = setInterval(() => {
            const width = Number((progressBar.style.width || '0').replace('%', '')) || 0;
            if (width < currentProgressTarget) {
                progressBar.style.width = `${Math.min(width + 3, currentProgressTarget)}%`;
            }
        }, 180);
    }

    function finalizarAnimacion() {
        if (stepTimer) clearInterval(stepTimer);
        if (progressTimer) clearInterval(progressTimer);

        renderStepList(-1, steps.length - 1);
        progressBar.style.width = '100%';
        progressMessage.textContent = 'Escaneo finalizado.';

        setTimeout(() => {
            progressCard.classList.add('hidden');
            progressBar.style.width = '0%';
            progressMessage.textContent = 'Inicializando motor de analisis...';
            if (scanStepList) scanStepList.innerHTML = '';
        }, 800);
    }

    function renderResults(data) {
        const resultados = Array.isArray(data.resultados) ? data.resultados : [];
        const rows = resultados.length ? resultados.map((r) => {
            const tipo = r.tipo || 'Sin tipo';
            const severidad = r.severidad || 'Baja';
            const descripcion = r.descripcion || 'Sin descripcion';

            let severidadHtml = `<span class="text-xs font-semibold text-sky-300">${severidad}</span>`;
            if (tipo === 'Ninguna detectada') {
                severidadHtml = `
                    <span class="status-badge-safe">
                        <span class="material-symbols-outlined text-[10px]">check</span>
                        SEGURO
                    </span>`;
            } else if (severidad === 'Alta') {
                severidadHtml = `<span class="text-xs font-semibold text-red-400">${severidad}</span>`;
            } else if (severidad === 'Media') {
                severidadHtml = `<span class="text-xs font-semibold text-yellow-300">${severidad}</span>`;
            }

            return `
                <tr class="border-b border-accent-dark/10">
                    <td class="px-6 py-4 text-sm text-slate-200">${tipo}</td>
                    <td class="px-6 py-4">${severidadHtml}</td>
                    <td class="px-6 py-4 text-sm text-slate-400">${descripcion}</td>
                </tr>`;
        }).join('') : `
            <tr class="border-b border-accent-dark/10">
                <td class="px-6 py-4 text-sm text-slate-200">Ninguna detectada</td>
                <td class="px-6 py-4"><span class="text-xs font-semibold text-slate-400">-</span></td>
                <td class="px-6 py-4 text-sm text-slate-400">Ejecuta un escaneo para ver resultados</td>
            </tr>`;

        resultsBody.innerHTML = rows;
        resultUrl.textContent = data.url || 'Sin escaneo aun';
        resultProtocol.textContent = data.protocolo || 'No especificado';
        totalVuln.textContent = String(data.total_vulnerabilidades || 0);

        if ((data.total_vulnerabilidades || 0) > 0) {
            summaryStatus.className = 'flex items-center gap-2 text-yellow-300';
            summaryStatus.innerHTML = '<span class="material-symbols-outlined text-sm">warning</span><span class="text-xs font-medium">Vulnerabilidades detectadas</span>';
        } else {
            summaryStatus.className = 'flex items-center gap-2 text-green-500';
            summaryStatus.innerHTML = '<span class="material-symbols-outlined text-sm">check_box</span><span class="text-xs font-medium">No se detectaron vulnerabilidades</span>';
        }

        if (statsTotalHallazgos) {
            statsTotalHallazgos.textContent = String(data.total_hallazgos_bd || 0);
        }
        if (statsCriticas) {
            statsCriticas.textContent = `${data.total_criticas_bd || 0} Criticas/Altas (en enlace)`;
        }
        if (statsTotalEscaneos) {
            statsTotalEscaneos.textContent = String(data.total_escaneos_bd || 0);
        }
        if (statsEscaneosHoy) {
            statsEscaneosHoy.textContent = `${data.escaneos_hoy_bd || 0} hoy`;
        }

        if (data.escaneo_id) {
            ultimoEscaneoId = Number(data.escaneo_id);
            if (sendReportButton) {
                sendReportButton.dataset.escaneoId = String(data.escaneo_id);
            }
        }
    }

    function actualizarPreview() {
        const base = (urlInput.value || '').trim();
        const limpio = base.replace(/^https?:\/\//i, '');
        urlPreview.textContent = limpio ? `${protocoloInput.value}${limpio}` : 'https://www.youtube.com/';
    }

    function validarEntradaUrl(protocolo, urlRaw) {
        if (!['http://', 'https://'].includes(protocolo)) {
            return { ok: false, titulo: 'URL no valida', mensaje: 'Protocolo invalido. Solo se permite HTTP o HTTPS.' };
        }

        const valor = (urlRaw || '').trim().replace(/[\x00-\x1F\x7F]/g, '');
        if (!valor) {
            return { ok: false, titulo: 'URL requerida', mensaje: 'Necesitas ingresar una URL.' };
        }

        if (/\s/.test(valor)) {
            return { ok: false, titulo: 'URL no valida', mensaje: 'Coloque una URL valida.' };
        }

        const urlSinProtocolo = valor.replace(/^https?:\/\//i, '');
        if (!urlSinProtocolo || urlSinProtocolo.startsWith('/')) {
            return { ok: false, titulo: 'URL no valida', mensaje: 'Coloque una URL valida.' };
        }

        let hostname = '';
        try {
            const parsed = new URL(`${protocolo}${urlSinProtocolo}`);
            hostname = (parsed.hostname || '').toLowerCase();
            if (!hostname) {
                return { ok: false, titulo: 'URL no valida', mensaje: 'Coloque una URL valida.' };
            }
        } catch (_) {
            return { ok: false, titulo: 'URL no valida', mensaje: 'Coloque una URL valida.' };
        }

        const esIpv4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(hostname);
        const patronDominio = /^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

        if (!esIpv4 && !patronDominio.test(hostname)) {
            return { ok: false, titulo: 'URL no valida', mensaje: 'Coloque una URL valida.' };
        }

        return { ok: true, urlLimpia: urlSinProtocolo };
    }

    protocoloInput.addEventListener('change', actualizarPreview);
    urlInput.addEventListener('input', () => {
        actualizarPreview();
        if ((urlInput.value || '').trim()) {
            limpiarErrorCampoUrl();
        }
    });

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        limpiarAlertas();
        limpiarErrorCampoUrl();

        const validacion = validarEntradaUrl(protocoloInput.value, urlInput.value);
        if (!validacion.ok) {
            mostrarErrorCampoUrl(validacion.mensaje);
            urlInput.focus();
            return;
        }

        const payload = {
            protocolo: protocoloInput.value,
            url: validacion.urlLimpia,
        };

        scanButton.disabled = true;
        scanButton.classList.add('opacity-60', 'cursor-not-allowed');
        iniciarAnimacion();

        try {
            const response = await fetch('/api/escanear', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });

            const data = await response.json().catch(() => ({}));

            if (!response.ok) {
                if (response.status === 429) {
                    mostrarAlerta('warn', 'Limite de escaneo alcanzado', data.error || 'Intenta nuevamente en unos segundos.');
                } else {
                    mostrarAlerta('error', 'URL no valida', data.error || 'Coloque una URL valida.');
                }
                return;
            }

            renderResults(data);
        } catch (error) {
            mostrarAlerta('error', 'Error de escaneo', 'Ocurrio un error de red al iniciar el escaneo. Intenta nuevamente.');
        } finally {
            finalizarAnimacion();
            scanButton.disabled = false;
            scanButton.classList.remove('opacity-60', 'cursor-not-allowed');
        }
    });

    if (sendReportButton) {
        sendReportButton.addEventListener('click', async () => {
            if (!ultimoEscaneoId) {
                mostrarEstadoEnvio('Primero ejecuta un escaneo para generar la vista previa del informe.', true);
                return;
            }

            sendReportButton.disabled = true;
            sendReportButton.classList.add('opacity-60', 'cursor-not-allowed');
            mostrarEstadoEnvio('Abriendo vista previa del informe...');

            try {
                const destino = `/reportes/vista-previa?escaneo_id=${encodeURIComponent(String(ultimoEscaneoId))}`;
                window.location.href = destino;
            } catch (_) {
                mostrarEstadoEnvio('No se pudo abrir la vista previa del informe.', true);
            } finally {
                sendReportButton.disabled = false;
                sendReportButton.classList.remove('opacity-60', 'cursor-not-allowed');
            }
        });
    }

    actualizarPreview();
})();
