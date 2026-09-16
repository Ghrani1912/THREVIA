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
    API_BASE
};


// Radar visualization with top 8 threat IPs
let radarIPs = [];
let radarAngle = 0;

async function updateRadarIPs() {
    try {
        const response = await fetch(`${API_BASE}/threats/recent?limit=8`);
        const data = await response.json();
        
        if (data.threats) {
            radarIPs = data.threats.slice(0, 8).map((threat, idx) => ({
                ip: threat.src_ip || '0.0.0.0',
                severity: threat.severity || 'Medium',
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
    radarAngle = (radarAngle + 2) % 360;
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
        
        // Color by severity
        let color = '#ff5555'; // red default for attacks
        if (blip.severity === 'Critical') color = '#ff3344';
        else if (blip.severity === 'High') color = '#ffaa00';
        else if (blip.severity === 'Medium') color = '#ff8844';
        else if (blip.severity === 'Low') color = '#88ff88';
        
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
