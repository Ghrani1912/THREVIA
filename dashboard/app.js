// THREVIA Dashboard - Real-time data integration
const API_BASE = 'http://localhost:8000/api/v1';

// Fetch and update metrics
async function updateMetrics() {
    try {
        const response = await fetch(`${API_BASE}/metrics/summary`);
        const data = await response.json();
        
        // Update header badges
        const critBadge = document.getElementById('crit-badge');
        const elevBadge = document.getElementById('elev-badge');
        const nominalBadge = document.getElementById('nominal-badge');
        
        if (critBadge) critBadge.textContent = `${data.critical_alerts || 0} CRIT`;
        if (elevBadge) elevBadge.textContent = `${data.high_alerts || 0} ELEV`;
        if (nominalBadge) nominalBadge.textContent = `${data.total_threats || 0} TOTAL`;
        
        // Update subsystem status
        const subsystemText = document.querySelector('[class*="SUBSYSTEMS"]');
        if (subsystemText) {
            subsystemText.innerHTML = `
                <span class="text-on-surface-variant">SUBSYSTEMS:</span>
                <span class="text-secondary">CORE: OK</span>
                <span class="text-outline-variant">|</span>
                <span class="text-secondary-fixed-dim">BLOOM: ${data.bloom_hits || 0} HITS</span>
                <span class="text-outline-variant">|</span>
                <span class="text-primary-container">ML_ALERTS: ${data.ml_alerts || 0}</span>
                <span class="text-outline-variant">|</span>
                <span class="text-primary-fixed-dim">SPIKE_ALERTS: ${data.spike_alerts || 0}</span>
            `;
        }
        
        console.log('✓ Metrics updated:', data);
    } catch (error) {
        console.error('✗ Failed to fetch metrics:', error);
    }
}

// Fetch and display recent threats in telemetry stream
async function updateThreatStream() {
    try {
        const response = await fetch(`${API_BASE}/threats/recent?limit=20`);
        const data = await response.json();
        
        const streamContainer = document.getElementById('incident-stream');
        if (streamContainer && data.threats && data.threats.length > 0) {
            streamContainer.innerHTML = data.threats.slice(0, 15).map(threat => {
                const time = threat.created_at || threat.timestamp || 'Unknown';
                const timeStr = new Date(time).toLocaleTimeString();
                const srcIp = threat.src_ip || threat.source_ip || 'N/A';
                const severity = threat.severity || 'Medium';
                const severityClass = severity === 'Critical' ? 'text-error' : 'text-primary-container';
                
                let detail = '';
                if (threat.type === 'spike_alert') {
                    detail = `${threat.connection_count || 0} connections in window`;
                } else if (threat.type === 'ml_alert') {
                    // ML alerts have attack_type classification
                    const attackType = threat.attack_type || 'Unknown';
                    const confidence = threat.confidence ? `(${(threat.confidence * 100).toFixed(1)}%)` : '';
                    detail = `ML Alert → ${attackType} ${confidence}`;
                } else if (threat.predicted_label) {
                    detail = threat.predicted_label;
                } else {
                    detail = threat.attack_cat || 'Bloom Filter Hit';
                }
                
                return `
                    <div class="p-space-sm bg-surface-container-low border-l-2 border-error mb-space-xs hover:bg-surface-container transition-colors cursor-pointer">
                        <div class="flex items-center justify-between mb-space-xs">
                            <span class="font-label-md text-label-md ${severityClass} font-bold uppercase">${severity}</span>
                            <span class="font-label-sm text-label-sm text-on-surface-variant">${timeStr}</span>
                        </div>
                        <div class="font-body-md text-body-md text-on-surface font-semibold">
                            SRC: ${srcIp}
                        </div>
                        <div class="font-label-sm text-label-sm text-primary-container mt-space-xs">
                            ⚡ ${detail}
                        </div>
                        ${threat.rf_binary_prob ? `<div class="font-label-sm text-label-sm text-secondary mt-space-xs">ML CONFIDENCE: ${(threat.rf_binary_prob * 100).toFixed(1)}%</div>` : ''}
                    </div>
                `;
            }).join('');
        } else if (streamContainer) {
            streamContainer.innerHTML = `
                <div class="text-center py-space-lg text-on-surface-variant font-label-sm text-label-sm">
                    <div class="animate-pulse">⟳ Waiting for alerts...</div>
                    <div class="mt-space-sm text-secondary">${data.count || 0} total alerts in database</div>
                </div>
            `;
        }
        
        console.log(`✓ Threat stream updated: ${data.count || 0} threats`);
    } catch (error) {
        console.error('✗ Failed to fetch threats:', error);
        const streamContainer = document.getElementById('incident-stream');
        if (streamContainer) {
            streamContainer.innerHTML = `
                <div class="text-center py-space-lg text-error font-label-sm text-label-sm">
                    ✗ Connection error - check API server
                </div>
            `;
        }
    }
}

// Update UTC time
function updateTime() {
    const timeEl = document.getElementById('utc-time');
    if (timeEl) {
        const now = new Date();
        timeEl.textContent = now.toISOString().substr(0, 19).replace('T', ' ');
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    console.log('THREVIA Dashboard initializing...');
    
    // Initial updates
    updateMetrics();
    updateThreatStream();
    updateTime();
    
    // Set up auto-refresh
    setInterval(updateMetrics, 5000);      // Update metrics every 5 seconds
    setInterval(updateThreatStream, 3000); // Update threats every 3 seconds
    setInterval(updateTime, 1000);         // Update time every second
    
    console.log('✓ THREVIA Dashboard ready - live data active');
});

// Export for debugging
window.THREVIA = {
    updateMetrics,
    updateThreatStream,
    API_BASE,
    setRadarPaused,
    isRadarPaused: () => radarPaused
};


// Radar visualization with top 8 threat IPs
let radarIPs = [];
let radarAngle = 0;
// Shared with the topology view: [SPACE] freezes both the sweep and the graph.
let radarPaused = false;

function setRadarPaused(paused) {
    radarPaused = !!paused;
    return radarPaused;
}

async function updateRadarIPs() {
    try {
        // Fetch a wide window and stratify: nominal flows trickle in
        // continuously while alerts arrive in ~5s bursts, so a plain
        // newest-first slice is all-green between bursts and all-alert
        // right after one. Fix the blip mix explicitly instead.
        const response = await fetch(`${API_BASE}/threats/recent?limit=100`);
        const data = await response.json();
        
        if (data.threats) {
            const isNominal = t => t.observation === 'nominal';
            const attacks = data.threats.filter(t => !isNominal(t));
            const nominal = data.threats.filter(isNominal);
            const NOMINAL_SLOTS = 2; // green baseline presence per sweep
            const picked = [
                ...attacks.slice(0, 8 - NOMINAL_SLOTS),
                ...nominal.slice(0, NOMINAL_SLOTS),
            ];
            radarIPs = picked.map((threat, idx) => ({
                ip: threat.src_ip || '0.0.0.0',
                severity: threat.severity || 'Medium',
                observation: threat.observation || '',
                angle: (idx * 45) + (radarAngle % 360), // Spread around circle
                distance: 60 + Math.random() * 30 // Random distance from center
            }));
        }
    } catch (error) {
        console.error('Failed to update radar:', error);
    }
}

function drawRadar() {
    const canvas = document.getElementById('radarCanvas');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = Math.min(centerX, centerY) * 0.8;
    
    // Clear canvas
    ctx.fillStyle = '#0a0e0f';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    
    // Draw radar circles
    ctx.strokeStyle = '#00ff8844';
    ctx.lineWidth = 1;
    for (let i = 1; i <= 3; i++) {
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius * (i / 3), 0, Math.PI * 2);
        ctx.stroke();
    }
    
    // Draw crosshairs
    ctx.beginPath();
    ctx.moveTo(centerX - radius, centerY);
    ctx.lineTo(centerX + radius, centerY);
    ctx.moveTo(centerX, centerY - radius);
    ctx.lineTo(centerX, centerY + radius);
    ctx.stroke();
    
    // Draw sweep line
    if (!radarPaused) radarAngle = (radarAngle + 2) % 360;
    const sweepRad = (radarAngle * Math.PI) / 180;
    const gradient = ctx.createLinearGradient(
        centerX, centerY,
        centerX + radius * Math.cos(sweepRad),
        centerY + radius * Math.sin(sweepRad)
    );
    gradient.addColorStop(0, '#00ff8888');
    gradient.addColorStop(1, '#00ff8800');
    
    ctx.strokeStyle = gradient;
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(centerX, centerY);
    ctx.lineTo(
        centerX + radius * Math.cos(sweepRad),
        centerY + radius * Math.sin(sweepRad)
    );
    ctx.stroke();
    
    // Draw IP blips
    radarIPs.forEach(blip => {
        const angle = (blip.angle * Math.PI) / 180;
        const dist = (blip.distance / 100) * radius;
        const x = centerX + dist * Math.cos(angle);
        const y = centerY + dist * Math.sin(angle);
        
        // Color by severity. Nominal (benign) traffic arrives from the
        // nominal_flows mirror with severity "Nominal" / observation "nominal"
        // and renders green -- previously impossible, since only alert
        // collections were queried and alerts are High/Critical by definition.
        let color = '#ff5555'; // red default for attacks
        if (blip.severity === 'Critical') color = '#ff3344';
        else if (blip.severity === 'High') color = '#ffaa00';
        else if (blip.severity === 'Medium') color = '#ff8844';
        else if (blip.severity === 'Low' || blip.severity === 'Nominal' || blip.observation === 'nominal') color = '#88ff88';
        
        // Draw blip
        ctx.fillStyle = color;
        ctx.beginPath();
        ctx.arc(x, y, 4, 0, Math.PI * 2);
        ctx.fill();
        
        // Draw IP label
        ctx.fillStyle = color;
        ctx.font = '10px monospace';
        ctx.fillText(blip.ip, x + 8, y - 8);
    });
    
    requestAnimationFrame(drawRadar);
}

// Initialize radar on load
document.addEventListener('DOMContentLoaded', function() {
    updateRadarIPs();
    setInterval(updateRadarIPs, 5000); // Update IPs every 5 seconds
    drawRadar(); // Start animation loop
});


// ══════════════════════════════════════════════════════════════════════════════
// EXPORT LOG FUNCTIONALITY
// ══════════════════════════════════════════════════════════════════════════════

async function exportAlertsToCSV() {
    try {
        // Fetch all recent alerts
        const response = await fetch(`${API_BASE}/threats/recent?limit=1000`);
        const data = await response.json();
        
        if (!data.threats || data.threats.length === 0) {
            alert('No alerts to export');
            return;
        }
        
        // Convert to CSV
        const threats = data.threats;
        
        // CSV Headers
        const headers = [
            'Timestamp',
            'Type',
            'Source IP',
            'Destination IP',
            'Attack Type',
            'Confidence',
            'Severity',
            'Connection Count',
            'Ground Truth Label',
            'Ground Truth Category'
        ];
        
        // CSV Rows
        const rows = threats.map(threat => {
            const timestamp = threat.created_at || threat.event_time || threat.timestamp || 'N/A';
            const type = threat.type || 'unknown';
            const srcIp = threat.src_ip || threat.source_ip || 'N/A';
            const dstIp = threat.dst_ip || threat.destination_ip || 'N/A';
            const attackType = threat.attack_type || 'N/A';
            const confidence = threat.confidence ? (threat.confidence * 100).toFixed(2) + '%' : 'N/A';
            const severity = threat.severity || 'N/A';
            const connCount = threat.connection_count || 'N/A';
            const gtLabel = threat.ground_truth_label || 'N/A';
            const gtCat = threat.ground_truth_cat || 'N/A';
            
            return [
                timestamp,
                type,
                srcIp,
                dstIp,
                attackType,
                confidence,
                severity,
                connCount,
                gtLabel,
                gtCat
            ];
        });
        
        // Build CSV content
        const csvContent = [
            headers.join(','),
            ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
        ].join('\n');
        
        // Create download
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19);
        const filename = `threvia_alerts_${timestamp}.csv`;
        
        link.href = URL.createObjectURL(blob);
        link.download = filename;
        link.style.display = 'none';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        console.log(`✓ Exported ${threats.length} alerts to ${filename}`);
        
        // Visual feedback
        const btn = document.getElementById('btn-export-log');
        if (btn) {
            const originalText = btn.textContent;
            btn.textContent = 'EXPORTED ✓';
            btn.style.backgroundColor = '#00ff88';
            btn.style.color = '#000';
            setTimeout(() => {
                btn.textContent = originalText;
                btn.style.backgroundColor = '';
                btn.style.color = '';
            }, 2000);
        }
        
    } catch (error) {
        console.error('✗ Failed to export alerts:', error);
        alert('Failed to export alerts. Check console for details.');
    }
}

// Attach export handler on page load
document.addEventListener('DOMContentLoaded', function() {
    const exportBtn = document.getElementById('btn-export-log');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportAlertsToCSV);
        console.log('✓ Export log button initialized');
    }
});


// ══════════════════════════════════════════════════════════════════════════════
// FORENSIC TELEMETRY PANEL
// ══════════════════════════════════════════════════════════════════════════════

function updateForensicPanel(threat) {
    // Update header with source IP
    const drawerIp = document.getElementById('drawer-ip');
    if (drawerIp) {
        drawerIp.textContent = threat.src_ip || threat.source_ip || 'Unknown IP';
    }
    
    // Update danger index (based on confidence).  No hardcoded fallback: if a
    // threat has no confidence field, show an explicit placeholder rather
    // than an invented 75.0/50.0 that looks like a real score.
    const drawerDanger = document.getElementById('drawer-danger');
    if (drawerDanger) {
        const dangerScore = (threat.confidence !== undefined && threat.confidence !== null)
            ? (threat.confidence * 100).toFixed(1)
            : '--';
        drawerDanger.textContent = `${dangerScore} / 100`;
    }
    
    // Update PageRank.  Placeholder removed: a constant 0.084 presented as
    // per-entity telemetry is indistinguishable from a real measurement.
    const drawerPagerank = document.getElementById('drawer-pagerank');
    if (drawerPagerank) {
        drawerPagerank.textContent = (threat.pagerank !== undefined && threat.pagerank !== null)
            ? String(threat.pagerank)
            : '-- (not indexed)';
    }
    
    // Update graph degree
    const drawerDegree = document.getElementById('drawer-degree');
    if (drawerDegree) {
        const degree = threat.connection_count || '--';
        drawerDegree.textContent = degree;
    }
    
    // Update community
    const drawerCommunity = document.getElementById('drawer-comm');
    if (drawerCommunity) {
        drawerCommunity.textContent = 'Cluster-Î"'; // Placeholder
    }
    
    // Update bloom filter status
    const drawerBloomStatus = document.getElementById('drawer-bloom-status');
    if (drawerBloomStatus) {
        const status = threat.type === 'bloom_hit' 
            ? 'STATUS: EXACT MATCH' 
            : 'STATUS: NO MATCH';
        drawerBloomStatus.textContent = status;
    }
    
    // Update bloom filter hash (generate fake hash for demo)
    const drawerBloomHash = document.getElementById('drawer-bloom-hash');
    if (drawerBloomHash) {
        const ip = threat.src_ip || threat.source_ip || '0.0.0.0';
        const parts = ip.split('.');
        const hash = `[0x${parts[0] || 0}FF81, 0x${parts[1] || 0}2A10, 0x${parts[2] || 0}10C3, 0x${parts[3] || 0}98F2, 0xEE419] â€¢ε 0.001% COLLISION PROB`;
        drawerBloomHash.textContent = `HASH(K1..K5): ${hash}`;
    }
    
    // Update packet header (generate hex dump)
    const drawerPacketType = document.getElementById('drawer-packet-type');
    const drawerHexDump = document.getElementById('drawer-hex-dump');
    
    if (drawerPacketType && drawerHexDump) {
        const flagsMap = {
            'ml_alert': 'TCP SYN FLOOD [FLAGS: 0x002]',
            'spike_alert': 'TCP SYN FLOOD [FLAGS: 0x002]',
            'bloom_hit': 'TCP PSH ACK [FLAGS: 0x018]'
        };
        const flags = flagsMap[threat.type] || 'TCP [FLAGS: 0x000]';
        drawerPacketType.textContent = flags;
        
        // Generate fake hex dump
        const hexDump = `0000:  45 00 00 3c 1a 2b 40 00  40 06 b2 e4 c6 33 64 2c  E...<.+@.@...3d,
0010:  0a 00 01 0a 44 31 00 50  78 91 f0 18 00 00 00 00  ....D1.Px.......
0020:  a0 02 72 10 c3 40 00 00  02 04 05 b4 04 02 08 0a  ..r..@..........
0030:  3d 89 2a 11 00 00 00 00  01 03 03 07 00 00 00 00  =.*.............`;
        
        drawerHexDump.textContent = hexDump;
    }
    
    console.log('✓ Forensic panel updated for:', threat.src_ip || threat.source_ip);
}

// Make incident cards clickable
function makeIncidentsClickable() {
    const streamContainer = document.getElementById('incident-stream');
    if (!streamContainer) return;
    
    // Delegate click events to incident cards
    streamContainer.addEventListener('click', async (e) => {
        const card = e.target.closest('.p-space-sm.bg-surface-container-low');
        if (!card) return;
        
        // Extract IP from card
        const srcIpElement = card.querySelector('.font-body-md');
        if (!srcIpElement) return;
        
        const srcIpMatch = srcIpElement.textContent.match(/SRC:\s*([\d.]+)/);
        if (!srcIpMatch) return;
        
        const srcIp = srcIpMatch[1];
        
        // Find the threat data
        try {
            const response = await fetch(`${API_BASE}/threats/recent?limit=100`);
            const data = await response.json();
            const threat = data.threats.find(t => 
                (t.src_ip === srcIp || t.source_ip === srcIp)
            );
            
            if (threat) {
                updateForensicPanel(threat);
                
                // Highlight selected card
                document.querySelectorAll('#incident-stream .p-space-sm').forEach(c => {
                    c.style.borderLeft = '2px solid var(--md-sys-color-error)';
                });
                card.style.borderLeft = '4px solid var(--md-sys-color-primary)';
                
                console.log('✓ Selected incident:', srcIp);
            }
        } catch (error) {
            console.error('✗ Failed to fetch incident details:', error);
        }
    });
    
    console.log('✓ Incident click handlers attached');
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    makeIncidentsClickable();
});

// ══════════════════════════════════════════════════════════════════════════════
// SPECTRAL WATERFALL MODULE
// ══════════════════════════════════════════════════════════════════════════════

let waterfallData = [];
const waterfallConfig = {
    cellWidth: 12,
    cellHeight: 24,
    gap: 2,
    paddingLeft: 100,
    paddingBottom: 40
};

async function updateSpectralWaterfall() {
    const canvas = document.getElementById('waterfallCanvas');
    if (!canvas) return;
    
    // Only fetch if visible to save resources
    if (document.getElementById('spectral-section').style.display === 'none') {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/analytics/waterfall?minutes=60`);
        const data = await response.json();
        
        if (data.waterfall) {
            waterfallData = data.waterfall;
            drawWaterfall();
        }
    } catch (error) {
        console.error('Failed to update waterfall:', error);
    }
}

function drawWaterfall() {
    const container = document.getElementById('waterfall-grid');
    const canvas = document.getElementById('waterfallCanvas');
    const ctx = canvas.getContext('2d');
    
    const width = container.clientWidth;
    const height = container.clientHeight;
    
    if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
    }
    
    if (!waterfallData || waterfallData.length === 0) {
        ctx.fillStyle = '#0c0f0e';
        ctx.fillRect(0, 0, width, height);
        ctx.fillStyle = '#dac2ae';
        ctx.font = '12px JetBrains Mono';
        ctx.textAlign = 'center';
        ctx.fillText('NO THREAT DENSITY DATA AVAILABLE', width/2, height/2);
        return;
    }

    const attackTypes = [...new Set(waterfallData.map(d => d.attack_type))].sort();
    const allTimestamps = [...new Set(waterfallData.map(d => d.timestamp))].sort();
    const xBuckets = allTimestamps.length > 0 ? allTimestamps : [new Date().toISOString().substring(0, 16) + ':00'];
    
    const cw = waterfallConfig.cellWidth;
    const ch = waterfallConfig.cellHeight;
    const gap = waterfallConfig.gap;
    const pl = waterfallConfig.paddingLeft;
    const pb = waterfallConfig.paddingBottom;
    
    ctx.fillStyle = '#0c0f0e';
    ctx.fillRect(0, 0, width, height);
    
    ctx.fillStyle = '#dac2ae';
    ctx.font = '10px JetBrains Mono';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    
    attackTypes.forEach((type, yIndex) => {
        const y = yIndex * (ch + gap) + ch/2;
        ctx.fillText(type, pl - 10, y);
        ctx.strokeStyle = '#282b29';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(pl, y);
        ctx.lineTo(width, y);
        ctx.stroke();
    });
    
    const matrix = {};
    attackTypes.forEach(t => matrix[t] = {});
    let maxCount = 1;
    
    waterfallData.forEach(d => {
        matrix[d.attack_type][d.timestamp] = d;
        if (d.count > maxCount) maxCount = d.count;
    });
    
    const getColor = (count, max) => {
        if (!count || count === 0) return '#1d201f';
        const ratio = Math.min(count / Math.max(max, 5), 1.0);
        if (ratio < 0.3) return `rgba(68, 244, 152, ${0.2 + ratio})`;
        if (ratio < 0.7) return `rgba(255, 158, 27, ${0.4 + ratio})`;
        return `rgba(255, 180, 171, ${0.6 + ratio})`;
    };
    
    const maxCols = Math.floor((width - pl) / (cw + gap));
    const startIdx = Math.max(0, xBuckets.length - maxCols);
    const visibleBuckets = xBuckets.slice(startIdx);
    
    canvas.waterfallLayout = {
        attackTypes,
        visibleBuckets,
        matrix,
        cw, ch, gap, pl, pb,
        rects: []
    };

    attackTypes.forEach((type, yIndex) => {
        const y = yIndex * (ch + gap);
        visibleBuckets.forEach((ts, xIndex) => {
            const x = pl + xIndex * (cw + gap);
            const cellData = matrix[type][ts];
            const count = cellData ? cellData.count : 0;
            ctx.fillStyle = getColor(count, maxCount);
            ctx.fillRect(x, y, cw, ch);
            canvas.waterfallLayout.rects.push({
                x, y, w: cw, h: ch,
                data: cellData || { attack_type: type, timestamp: ts, count: 0, connections: 0 }
            });
        });
    });
    
    ctx.fillStyle = '#dac2ae';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    const labelStep = Math.max(1, Math.floor(visibleBuckets.length / 8));
    
    visibleBuckets.forEach((ts, xIndex) => {
        if (xIndex % labelStep === 0 || xIndex === visibleBuckets.length - 1) {
            const x = pl + xIndex * (cw + gap) + cw/2;
            const y = attackTypes.length * (ch + gap) + 5;
            const timeStr = ts.substring(11, 16);
            ctx.fillText(timeStr, x, y);
            ctx.strokeStyle = '#544434';
            ctx.beginPath();
            ctx.moveTo(x, y - 5);
            ctx.lineTo(x, y - 2);
            ctx.stroke();
        }
    });
}

document.addEventListener('DOMContentLoaded', function() {
    const canvas = document.getElementById('waterfallCanvas');
    const tooltip = document.getElementById('waterfall-tooltip');
    
    if (canvas && tooltip) {
        canvas.addEventListener('mousemove', (e) => {
            if (!canvas.waterfallLayout) return;
            const rect = canvas.getBoundingClientRect();
            const mouseX = e.clientX - rect.left;
            const mouseY = e.clientY - rect.top;
            
            let hit = null;
            for (const r of canvas.waterfallLayout.rects) {
                if (mouseX >= r.x && mouseX <= r.x + r.w &&
                    mouseY >= r.y && mouseY <= r.y + r.h) {
                    hit = r.data;
                    break;
                }
            }
            
            if (hit && hit.count > 0) {
                document.getElementById('wf-tt-type').textContent = hit.attack_type;
                document.getElementById('wf-tt-time').textContent = hit.timestamp.substring(11, 19) + ' UTC';
                document.getElementById('wf-tt-count').textContent = `${hit.count} ALERTS`;
                document.getElementById('wf-tt-conn').textContent = `${hit.connections} TOTAL CONNECTIONS`;
                
                tooltip.style.left = `${e.clientX + 15}px`;
                tooltip.style.top = `${e.clientY + 15}px`;
                tooltip.style.display = 'flex';
                canvas.style.cursor = 'crosshair';
            } else {
                tooltip.style.display = 'none';
                canvas.style.cursor = 'default';
            }
        });
        
        canvas.addEventListener('mouseleave', () => {
            tooltip.style.display = 'none';
        });
        
        window.addEventListener('resize', () => {
            if (document.getElementById('spectral-section').style.display !== 'none') {
                drawWaterfall();
            }
        });
    }
    
    // Hook into global refresh interval
    setInterval(updateSpectralWaterfall, 5000);
    updateSpectralWaterfall();
});
