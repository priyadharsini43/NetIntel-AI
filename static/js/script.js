document.addEventListener('DOMContentLoaded', () => {
    // --- Homepage Upload Logic ---
    const uploadForm = document.getElementById('uploadForm');
    if (uploadForm) {
        const fileInput = document.getElementById('fileInput');
        const loadingIndicator = document.getElementById('loadingIndicator');
        const errorMessage = document.getElementById('errorMessage');
        const errorText = document.getElementById('errorText');

        // Drag and drop styles
        uploadForm.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadForm.classList.add('dragover');
        });

        uploadForm.addEventListener('dragleave', (e) => {
            e.preventDefault();
            uploadForm.classList.remove('dragover');
        });

        uploadForm.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadForm.classList.remove('dragover');
            if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                fileInput.files = e.dataTransfer.files;
                handleUpload(fileInput.files[0]);
            }
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                handleUpload(fileInput.files[0]);
            }
        });

        function handleUpload(file) {
            // Reset state
            errorMessage.classList.add('d-none');
            
            // Feature 1: Multi-format packet upload validation
            if (!file.name.endsWith('.pcap') && !file.name.endsWith('.cap') && !file.name.endsWith('.pcapng')) {
                showError("Invalid file type. Please upload a .pcap, .cap, or .pcapng file.");
                fileInput.value = ''; // clear input
                return;
            }

            uploadForm.classList.add('d-none');
            loadingIndicator.classList.remove('d-none');

            const formData = new FormData();
            formData.append('file', file);

            fetch('/upload', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(err => { throw new Error(err.error || 'Upload failed'); });
                }
                return response.json();
            })
            .then(data => {
                // Success! Redirect to results page with filename
                window.location.href = `/results?filename=${encodeURIComponent(data.filename)}`;
            })
            .catch(error => {
                showError(error.message);
                uploadForm.classList.remove('d-none');
                loadingIndicator.classList.add('d-none');
                fileInput.value = ''; // clear input
            });
        }

        function showError(msg) {
            errorText.textContent = msg;
            errorMessage.classList.remove('d-none');
        }
    }

    // --- Results Dashboard Logic ---
    const dashboardContent = document.getElementById('dashboardContent');
    if (dashboardContent) {
        const urlParams = new URLSearchParams(window.location.search);
        const filename = urlParams.get('filename');
        
        const resultsLoading = document.getElementById('resultsLoading');
        const errorContainer = document.getElementById('errorContainer');
        const resultsErrorText = document.getElementById('resultsErrorText');
        const filenameDisplay = document.getElementById('filenameDisplay');
        
        // Data variables for download and display
        let reportData = null;
        let filteredData = [];
        let currentPage = 1;
        const rowsPerPage = 50;

        if (!filename) {
            showResultsError("No filename provided. Please upload a file first.");
            return;
        }

        filenameDisplay.textContent = `File: ${filename.split('_').slice(1).join('_') || filename}`;

        // Fetch Analysis Results
        fetch(`/analyze/${encodeURIComponent(filename)}`)
            .then(response => {
                if (!response.ok) {
                    return response.json().then(err => { throw new Error(err.error || 'Analysis failed'); });
                }
                return response.json();
            })
            .then(data => {
                reportData = data;
                renderDashboard(data);
                resultsLoading.classList.add('d-none');
                dashboardContent.classList.remove('d-none');
            })
            .catch(error => {
                showResultsError(error.message);
            });

        function showResultsError(msg) {
            resultsLoading.classList.add('d-none');
            resultsErrorText.textContent = msg;
            errorContainer.classList.remove('d-none');
        }

        function renderDashboard(data) {
            const { summary, details, recommendations } = data;
            
            // 1. Update Summary Cards
            document.getElementById('totalPackets').textContent = summary.total_packets.toLocaleString();
            document.getElementById('normalPackets').textContent = summary.normal_packets.toLocaleString();
            document.getElementById('anomalousPackets').textContent = summary.anomalous_packets.toLocaleString();
            
            // Progress bars
            const normalPct = summary.total_packets > 0 ? (summary.normal_packets / summary.total_packets) * 100 : 0;
            const anomalyPct = summary.total_packets > 0 ? (summary.anomalous_packets / summary.total_packets) * 100 : 0;
            
            document.getElementById('normalProgressBar').style.width = `${normalPct}%`;
            document.getElementById('anomalousProgressBar').style.width = `${anomalyPct}%`;

            // Feature 2: Display Threat Level Card
            renderThreatLevel(summary);

            // Feature 3: Display AI Recommendations
            if (recommendations && recommendations.length > 0) {
                renderRecommendations(recommendations);
            }

            // 2. Render Charts
            renderCharts(details);

            // 3. Setup filters and render Table
            applyFilters();
        }

        // Feature 2: Threat Level Card Rendering
        function renderThreatLevel(summary) {
            const threatLevel = summary.threat_level || 'UNKNOWN';
            const anomalyPct = summary.anomaly_percentage || 0;
            
            // Update threat card
            const threatCard = document.getElementById('threatLevelCard');
            const threatIcon = document.getElementById('threatIcon');
            const threatBadge = document.getElementById('threatLevelBadge');
            const threatMeter = document.getElementById('threatMeter');
            const threatPercentage = document.getElementById('threatPercentage');
            
            // Apply color-coding
            let iconClass = 'bg-success-subtle text-success';
            let badgeColor = 'bg-success';
            let meterColor = 'bg-success';
            
            if (threatLevel === 'LOW') {
                iconClass = 'bg-success-subtle text-success';
                badgeColor = 'bg-success';
                meterColor = 'bg-success';
                threatBadge.innerHTML = '<span class="badge rounded-pill ' + badgeColor + '"><i class="bi bi-shield-check me-1"></i>LOW</span>';
            } else if (threatLevel === 'MEDIUM') {
                iconClass = 'bg-warning-subtle text-warning';
                badgeColor = 'bg-warning';
                meterColor = 'bg-warning';
                threatBadge.innerHTML = '<span class="badge rounded-pill ' + badgeColor + '"><i class="bi bi-exclamation-triangle me-1"></i>MEDIUM</span>';
            } else if (threatLevel === 'HIGH') {
                iconClass = 'bg-danger-subtle text-danger';
                badgeColor = 'bg-danger';
                meterColor = 'bg-danger';
                threatBadge.innerHTML = '<span class="badge rounded-pill ' + badgeColor + '"><i class="bi bi-shield-x me-1"></i>HIGH</span>';
            }
            
            // Update icon box
            threatIcon.className = 'icon-box rounded-circle p-2 me-3 ' + iconClass;
            threatIcon.innerHTML = '<i class="bi bi-shield-fill fs-4"></i>';
            
            // Update meter
            threatMeter.style.width = `${Math.min(anomalyPct, 100)}%`;
            threatMeter.className = `progress-bar ${meterColor}`;
            
            // Update percentage display
            threatPercentage.textContent = `${anomalyPct.toFixed(1)}% Risk Score`;
        }

        // Feature 3: AI Recommendations Card Rendering
        function renderRecommendations(recommendations) {
            const container = document.getElementById('recommendationsContainer');
            if (!container) return;
            
            container.innerHTML = ''; // Clear previous
            
            recommendations.forEach((rec, idx) => {
                // Determine colors based on priority
                let priorityBadgeClass = 'bg-secondary';
                let priorityIcon = 'bi-info-circle';
                
                if (rec.priority === 'CRITICAL') {
                    priorityBadgeClass = 'bg-danger';
                    priorityIcon = 'bi-exclamation-octagon-fill';
                } else if (rec.priority === 'HIGH') {
                    priorityBadgeClass = 'bg-danger-subtle text-danger';
                    priorityIcon = 'bi-exclamation-triangle-fill';
                } else if (rec.priority === 'MEDIUM') {
                    priorityBadgeClass = 'bg-warning-subtle text-warning';
                    priorityIcon = 'bi-exclamation-diamond-fill';
                } else if (rec.priority === 'LOW') {
                    priorityBadgeClass = 'bg-success-subtle text-success';
                    priorityIcon = 'bi-check-circle-fill';
                }
                
                // Build recommendation card
                const recCard = document.createElement('div');
                recCard.className = 'col-md-6 col-lg-4';
                recCard.innerHTML = `
                    <div class="glass-card p-3 rounded-3 h-100 border-start border-3" style="border-color: var(--bs-${rec.priority.toLowerCase()}-color, #6b7280);">
                        <div class="d-flex align-items-start mb-2">
                            <i class="bi ${priorityIcon} ${priorityBadgeClass} rounded-circle p-2 me-2" style="flex-shrink: 0;"></i>
                            <div>
                                <h6 class="fw-bold mb-0 small">${rec.title}</h6>
                                <span class="badge rounded-pill text-white" style="font-size: 10px; background-color: var(--bs-${rec.priority.toLowerCase()}-color, #6b7280);">${rec.priority}</span>
                            </div>
                        </div>
                        <p class="small text-muted mb-2">${rec.description}</p>
                        <ul class="small mb-0 ps-3 text-muted">
                            ${rec.actions.map(action => `<li class="mb-1">${action}</li>`).join('')}
                        </ul>
                    </div>
                `;
                container.appendChild(recCard);
            });
        }

        // --- Filter & Pagination Logic ---
        const searchInput = document.getElementById('searchInput');
        const protocolFilter = document.getElementById('protocolFilter');
        const anomalousOnlyFilter = document.getElementById('anomalousOnlyFilter');
        const prevPageBtn = document.getElementById('prevPageBtn');
        const nextPageBtn = document.getElementById('nextPageBtn');

        if (searchInput) searchInput.addEventListener('input', () => { currentPage = 1; applyFilters(); });
        if (protocolFilter) protocolFilter.addEventListener('change', () => { currentPage = 1; applyFilters(); });
        if (anomalousOnlyFilter) anomalousOnlyFilter.addEventListener('change', () => { currentPage = 1; applyFilters(); });
        
        if (prevPageBtn) prevPageBtn.addEventListener('click', () => { if (currentPage > 1) { currentPage--; renderTable(); } });
        if (nextPageBtn) nextPageBtn.addEventListener('click', () => { if (currentPage < Math.ceil(filteredData.length / rowsPerPage)) { currentPage++; renderTable(); } });

        function applyFilters() {
            if (!reportData || !reportData.details) return;
            
            const searchTerms = searchInput ? searchInput.value.toLowerCase().trim() : '';
            const protoId = protocolFilter ? protocolFilter.value : 'ALL';
            const anomalousOnly = anomalousOnlyFilter ? anomalousOnlyFilter.checked : false;

            filteredData = reportData.details.filter(pkt => {
                // Anomaly Filter
                if (anomalousOnly && !pkt.is_anomalous) return false;
                
                // Protocol Filter
                if (protoId !== 'ALL' && pkt.protocol.toString() !== protoId) return false;
                
                // Search Filter (IPs and Ports)
                if (searchTerms !== '') {
                    const srcStr = `${pkt.src_ip}:${pkt.src_port || ''}`.toLowerCase();
                    const dstStr = `${pkt.dst_ip}:${pkt.dst_port || ''}`.toLowerCase();
                    if (!srcStr.includes(searchTerms) && !dstStr.includes(searchTerms)) {
                        return false;
                    }
                }
                
                return true;
            });
            
            renderTable();
        }

        function renderCharts(details) {
            // Data aggregations
            let normal = 0, anomalous = 0;
            let tcp = 0, udp = 0, icmp = 0;
            let confBins = { '<50%': 0, '50-75%': 0, '75-90%': 0, '>90%': 0 };

            details.forEach(pkt => {
                if (pkt.is_anomalous) anomalous++;
                else normal++;

                if (pkt.protocol === 6) tcp++;
                else if (pkt.protocol === 17) udp++;
                else if (pkt.protocol === 1) icmp++;

                if (pkt.confidence < 50) confBins['<50%']++;
                else if (pkt.confidence < 75) confBins['50-75%']++;
                else if (pkt.confidence < 90) confBins['75-90%']++;
                else confBins['>90%']++;
            });

            // 1. Traffic Breakdown Chart (Anomalous vs Normal)
            const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
            new Chart(ctxTraffic, {
                type: 'doughnut',
                data: {
                    labels: ['Normal', 'Anomalous'],
                    datasets: [{
                        data: [normal, anomalous],
                        backgroundColor: ['rgba(16, 185, 129, 0.8)', 'rgba(239, 68, 68, 0.8)'],
                        borderColor: ['rgba(16, 185, 129, 1)', 'rgba(239, 68, 68, 1)'],
                        borderWidth: 1,
                        hoverOffset: 4
                    }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { position: 'bottom', labels: { color: '#f8fafc', padding: 10, font: { family: "'Inter', sans-serif" } } } },
                    cutout: '70%'
                }
            });

            // 2. Protocol Distribution Chart
            const ctxProto = document.getElementById('protocolChart').getContext('2d');
            new Chart(ctxProto, {
                type: 'pie',
                data: {
                    labels: ['TCP', 'UDP', 'ICMP'],
                    datasets: [{
                        data: [tcp, udp, icmp],
                        backgroundColor: ['rgba(59, 130, 246, 0.8)', 'rgba(168, 85, 247, 0.8)', 'rgba(245, 158, 11, 0.8)'],
                        borderColor: ['rgba(59, 130, 246, 1)', 'rgba(168, 85, 247, 1)', 'rgba(245, 158, 11, 1)'],
                        borderWidth: 1,
                        hoverOffset: 4
                    }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { position: 'bottom', labels: { color: '#f8fafc', padding: 10, font: { family: "'Inter', sans-serif" } } } }
                }
            });

            // 3. Confidence Scores Chart
            const ctxConf = document.getElementById('confidenceChart').getContext('2d');
            new Chart(ctxConf, {
                type: 'bar',
                data: {
                    labels: Object.keys(confBins),
                    datasets: [{
                        label: 'Packets',
                        data: Object.values(confBins),
                        backgroundColor: 'rgba(99, 102, 241, 0.8)',
                        borderColor: 'rgba(99, 102, 241, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.1)' }, ticks: { color: '#94a3b8' } },
                        x: { grid: { display: false }, ticks: { color: '#94a3b8' } }
                    }
                }
            });
        }

        function getProtocolName(protoNum) {
            const protos = { 1: 'ICMP', 6: 'TCP', 17: 'UDP' };
            return protos[protoNum] || `Proto-${protoNum}`;
        }

        // Feature 5: Packet Details Modal Handler
        function showPacketDetails(pkt) {
            const modal = new bootstrap.Modal(document.getElementById('packetDetailsModal'));
            const content = document.getElementById('packetDetailsContent');
            
            // Build detailed packet view
            content.innerHTML = `
                <div class="row g-3">
                    <div class="col-12">
                        <h6 class="text-primary fw-bold">Core Information</h6>
                        <div class="row g-2">
                            <div class="col-6">
                                <small class="text-muted">Packet ID</small>
                                <p class="mb-0 font-monospace">${pkt.packet_id}</p>
                            </div>
                            <div class="col-6">
                                <small class="text-muted">Packet Size</small>
                                <p class="mb-0 font-monospace">${pkt.packet_size} bytes</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-12">
                        <h6 class="text-primary fw-bold">Network Layer</h6>
                        <div class="row g-2">
                            <div class="col-6">
                                <small class="text-muted">Source IP</small>
                                <p class="mb-0 font-monospace">${pkt.src_ip || 'N/A'}</p>
                            </div>
                            <div class="col-6">
                                <small class="text-muted">Destination IP</small>
                                <p class="mb-0 font-monospace">${pkt.dst_ip || 'N/A'}</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-12">
                        <h6 class="text-primary fw-bold">Transport Layer</h6>
                        <div class="row g-2">
                            <div class="col-4">
                                <small class="text-muted">Protocol</small>
                                <p class="mb-0 fw-bold">${getProtocolName(pkt.protocol)}</p>
                            </div>
                            <div class="col-4">
                                <small class="text-muted">Source Port</small>
                                <p class="mb-0 font-monospace">${pkt.src_port || 'N/A'}</p>
                            </div>
                            <div class="col-4">
                                <small class="text-muted">Destination Port</small>
                                <p class="mb-0 font-monospace">${pkt.dst_port || 'N/A'}</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-12">
                        <h6 class="text-primary fw-bold">Analysis Results</h6>
                        <div class="row g-2">
                            <div class="col-6">
                                <small class="text-muted">Status</small>
                                <p class="mb-0">
                                    ${pkt.is_anomalous 
                                        ? '<span class="badge bg-danger"><i class="bi bi-shield-x me-1"></i>Anomalous</span>' 
                                        : '<span class="badge bg-success"><i class="bi bi-shield-check me-1"></i>Normal</span>'}
                                </p>
                            </div>
                            <div class="col-6">
                                <small class="text-muted">Prediction</small>
                                <p class="mb-0">
                                    ${pkt.is_anomalous ? '<span class="text-danger fw-bold">Threat Detected</span>' : '<span class="text-success fw-bold">Clean</span>'}
                                </p>
                            </div>
                            <div class="col-12">
                                <small class="text-muted">Confidence Score</small>
                                <div class="progress mt-1" style="height: 8px;">
                                    <div class="progress-bar ${pkt.confidence > 80 ? (pkt.is_anomalous ? 'bg-danger' : 'bg-success') : 'bg-warning'}" 
                                         role="progressbar" style="width: ${pkt.confidence}%"></div>
                                </div>
                                <p class="mb-0 small mt-1 fw-bold">${pkt.confidence.toFixed(2)}%</p>
                            </div>
                        </div>
                    </div>
                    ${pkt.tcp_flags !== undefined ? `
                    <div class="col-12">
                        <h6 class="text-primary fw-bold">TCP Flags</h6>
                        <p class="mb-0 font-monospace text-muted">0x${pkt.tcp_flags.toString(16).toUpperCase().padStart(2, '0')}</p>
                    </div>
                    ` : ''}
                    <div class="col-12">
                        <h6 class="text-primary fw-bold">Extracted Features</h6>
                        <table class="table table-sm table-borderless text-muted">
                            <tbody>
                                ${Object.entries(pkt)
                                    .filter(([key, val]) => !['is_anomalous', 'confidence', 'packet_id'].includes(key))
                                    .map(([key, val]) => `
                                        <tr>
                                            <td class="fw-bold">${key}</td>
                                            <td class="text-end font-monospace">${val}</td>
                                        </tr>
                                    `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
            
            modal.show();
        }

        function renderTable() {
            const tbody = document.getElementById('packetTableBody');
            const paginationInfo = document.getElementById('paginationInfo');
            if (!tbody) return;
            
            tbody.innerHTML = '';
            
            const totalItems = filteredData.length;
            const totalPages = Math.ceil(totalItems / rowsPerPage) || 1;
            
            if (currentPage > totalPages) currentPage = totalPages;
            if (currentPage < 1) currentPage = 1;
            
            const startIndex = (currentPage - 1) * rowsPerPage;
            const endIndex = Math.min(startIndex + rowsPerPage, totalItems);
            
            const pageData = filteredData.slice(startIndex, endIndex);

            pageData.forEach(pkt => {
                const tr = document.createElement('tr');
                tr.style.cursor = 'pointer';
                tr.addEventListener('click', () => showPacketDetails(pkt));
                
                // Status Badge
                const statusBadge = pkt.is_anomalous 
                    ? `<span class="badge rounded-pill bg-danger badge-custom"><i class="bi bi-shield-x me-1"></i>Anomalous</span>`
                    : `<span class="badge rounded-pill bg-success badge-custom"><i class="bi bi-shield-check me-1"></i>Normal</span>`;
                
                // Confidence color
                const confColor = pkt.confidence > 90 ? (pkt.is_anomalous ? 'text-danger' : 'text-success') : 'text-warning';

                tr.innerHTML = `
                    <td class="text-muted">#${pkt.packet_id}</td>
                    <td><span class="badge bg-secondary">${getProtocolName(pkt.protocol)}</span></td>
                    <td class="font-monospace">${pkt.src_ip}:${pkt.src_port || '*'}</td>
                    <td class="font-monospace">${pkt.dst_ip}:${pkt.dst_port || '*'}</td>
                    <td>${statusBadge}</td>
                    <td class="fw-semibold ${confColor}">${pkt.confidence.toFixed(1)}%</td>
                `;
                tbody.appendChild(tr);
            });
            
            if (pageData.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-muted">No packets match the current filters.</td></tr>`;
            }
            
            // Update pagination UI
            if (paginationInfo) {
                paginationInfo.textContent = `Showing ${totalItems === 0 ? 0 : startIndex + 1}-${endIndex} of ${totalItems} packets`;
            }
            if (prevPageBtn) prevPageBtn.disabled = currentPage === 1;
            if (nextPageBtn) nextPageBtn.disabled = currentPage === totalPages;
        }

        // --- Download Report Logic ---
        document.getElementById('exportCsvBtn').addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = `/export/csv/${encodeURIComponent(filename)}`;
        });
        
        document.getElementById('exportJsonBtn').addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = `/export/json/${encodeURIComponent(filename)}`;
        });

        // Feature 4: PDF Export
        const exportPdfBtn = document.getElementById('exportPdfBtn');
        if (exportPdfBtn) {
            exportPdfBtn.addEventListener('click', (e) => {
                e.preventDefault();
                window.location.href = `/export/pdf/${encodeURIComponent(filename)}`;
            });
        }
    }
});
