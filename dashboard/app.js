// THREVIA Dashboard - Real-time data integration
// The API serves this dashboard itself (main.py mounts /static and /dashboard),
// so the backend is on whatever origin served the page. Pinning it to :8000 meant
// the view could only be opened on the port the server happened to bind; the
// literal stays as the fallback for a file:// load.
const API_BASE = (typeof window !== 'undefined' && window.location && /^https?:$/.test(window.location.protocol))
    ? `${window.location.origin}/api/v1`
    : 'http://localhost:8000/api/v1';

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
                // Same palette as the scope, so a band means one colour everywhere
                // in the UI. This used to be `Critical ? text-error :
                // text-primary-container`, which painted High, Medium, Low and
                // Nominal identically: four bands collapsed into two, and the
                // list contradicted the legend sitting next to it. A contact with
                // no verdict at all (a Bloom hit) is Ungraded, not Medium.
                const severity = threat.severity || 'Ungraded';
                const severityColor = RADAR_SEVERITY_COLORS[severity]
                    || (severity === 'Low' ? RADAR_SEVERITY_COLORS.Nominal
                                           : RADAR_SEVERITY_COLORS.Ungraded);
                
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
                    <div class="p-space-sm bg-surface-container-low border-l-2 mb-space-xs hover:bg-surface-container transition-colors cursor-pointer" style="border-left-color:${severityColor}">
                        <div class="flex items-center justify-between mb-space-xs">
                            <span class="font-label-md text-label-md font-bold uppercase" style="color:${severityColor}" title="Severity band — the same colour the scope draws">${severity}</span>
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

// ── Radar severity encoding ───────────────────────────────────────────────────
// The scope encodes a *severity band*, not an attack family. This object is the
// single definition of that encoding: drawRadar paints blips from it and
// renderRadarLegend paints the legend swatches from it, so the key can never say
// one thing while the scope draws another.
//
// The legend this replaces claimed the orange contacts were "ELEVATED
// (PortScan/SYN Sweep)" and the red "CRITICAL INTRUSION (DDoS/Exfil)". drawRadar
// never looks at attack_type at all -- those oranges are DDoS/DoS/Bot verdicts
// that merely scored below the critical cut -- so the labels contradicted the
// colours they sat next to.
const RADAR_SEVERITY_COLORS = {
    Critical: '#ff3344',
    High:     '#ffaa00',
    Medium:   '#ff8844',
    Nominal:  '#88ff88',
    // A contact with no verdict to band: Bloom-filter hits carry src_ip and a
    // label but no P(attack). Drawn as red so an untriaged match is never the
    // quietest thing on the scope.
    Ungraded: '#ff5555',
};

// Legend rows, in the order the ladder escalates. `field` names the payload key
// each band's cut is read from, so a band whose cut cannot be read says so
// instead of rendering a plausible-looking number.
const RADAR_BANDS = [
    { id: 'critical', name: 'CRITICAL', color: RADAR_SEVERITY_COLORS.Critical },
    { id: 'high',     name: 'HIGH',     color: RADAR_SEVERITY_COLORS.High },
    { id: 'medium',   name: 'MEDIUM',   color: RADAR_SEVERITY_COLORS.Medium },
    { id: 'nominal',  name: 'NOMINAL MIRROR FLOW', color: RADAR_SEVERITY_COLORS.Nominal },
];

// Severity rank, for ordering the scope worst-first. The colour is not enough:
// High and Medium are both orange to the eye, so "first by colour" would not have
// put the worst contact in front of the viewer.
const SEVERITY_RANK = { Critical: 3, High: 2, Medium: 1, Low: 0 };

// The scope's slot budget, and the whole reason it has one.
//
// Ranking everything and taking the top six is not a summary of the traffic, it
// is a summary of the top of one distribution. With 656 Critical contacts in a
// five-minute window, "the 6 worst" were always Critical -- so the scope lost its
// yellow and orange entirely, which is the same defect as before (one band
// painted the whole screen) wearing the opposite colour. A quota keeps the worst
// contacts while guaranteeing every band is on the scope, because a display that
// shows one colour is not telling you the mix, it is hiding it.
const RADAR_SLOT_QUOTA = { Critical: 3, High: 2, Medium: 1 };
const RADAR_NOMINAL_SLOTS = 2; // green baseline presence per sweep
const RADAR_ATTACK_SLOTS = 6;

/** Network prefix, for telling one incident from one attacker counted twice. */
function subnetOf(ip) {
    const parts = String(ip || '').split('.');
    return parts.length === 4 ? parts.slice(0, 3).join('.') : String(ip || '');
}

/**
 * Choose the contacts the scope draws: quota per band, worst-first inside a band.
 *
 * De-duplication runs first and is relaxed only if it cannot fill a band, so the
 * blips are distinct incidents rather than one attacker drawn three times (the
 * live Critical band is ~100% DDoS spread over four /24s, so this is the common
 * case, not a corner case). A candidate is only a repeat when *both* its family
 * and its subnet are already on the scope: requiring either one to be new would
 * reject every Critical after the first, because that band is a single family.
 * Slots left over after the quota go to whatever is worst, which covers a band
 * with no contacts at all without leaving a hole.
 */
function pickRadarContacts(attacks, slots) {
    const ranked = attacks.slice().sort((a, b) =>
        (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0)
        || String(b.created_at || '').localeCompare(String(a.created_at || '')));

    const chosen = [];
    const families = new Set();
    const subnets = new Set();

    const take = (band, want, strict) => {
        let added = 0;
        for (const threat of ranked) {
            if (added >= want || chosen.length >= slots) return added;
            if (band && threat.severity !== band) continue;
            if (chosen.indexOf(threat) !== -1) continue;
            const family = threat.attack_type || 'unclassified';
            const subnet = subnetOf(threat.src_ip);
            if (strict && families.has(family) && subnets.has(subnet)) continue;
            chosen.push(threat);
            families.add(family);
            subnets.add(subnet);
            added += 1;
        }
        return added;
    };

    const quota = Object.entries(RADAR_SLOT_QUOTA);
    for (const [band, want] of quota) take(band, want, true);          // distinct incidents
    for (const [band, want] of quota) {                                 // top each band up
        const have = chosen.filter(t => t.severity === band).length;
        if (have < want) take(band, want - have, false);
    }
    if (chosen.length < slots) take(null, slots - chosen.length, false); // spare slots
    // Top-ups land at the end of `chosen`; re-sort so the array stays worst-first
    // too. Slots are drawn positionally, so without this the *layout* would still
    // be ordered while the list it came from was not.
    return chosen.sort((a, b) =>
        (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0)
        || String(b.created_at || '').localeCompare(String(a.created_at || '')));
}

/**
 * Resolve a blip's severity band to the colour the scope draws it in.
 *
 * The ladder's bottom rung ("Low") has no branch on purpose: Low means "scored
 * below the medium cut", and the medium cut *is* the deployed alert threshold,
 * so nothing that reaches this feed is Low. If one ever arrived it would fall
 * through to Ungraded -- flagged as untriaged rather than silently green.
 */
function radarColorFor(blip) {
    if (blip.observation === 'nominal' || blip.severity === 'Nominal') return RADAR_SEVERITY_COLORS.Nominal;
    if (blip.severity === 'Critical') return RADAR_SEVERITY_COLORS.Critical;
    if (blip.severity === 'High')     return RADAR_SEVERITY_COLORS.High;
    if (blip.severity === 'Medium')   return RADAR_SEVERITY_COLORS.Medium;
    return RADAR_SEVERITY_COLORS.Ungraded;
}

const _fmtCut = v => (typeof v === 'number' ? v.toFixed(4) : '--');

/**
 * State the scope's sampling rule, which is half of what a blip means.
 *
 * "Worst-first" is only meaningful next to the window it was drawn from, and
 * `null` means the API fell back to the newest stored contacts because the
 * window was empty -- a different claim, so it gets different words.
 */
function renderRadarScope(windowMinutes) {
    const el = document.getElementById('radar-legend-scope');
    if (!el) return;
    // The slot rule is built from RADAR_SLOT_QUOTA rather than typed out, so the
    // legend cannot describe a mix the scope is not drawing.
    const mix = Object.entries(RADAR_SLOT_QUOTA).map(([band, n]) => `${n} ${band}`).join(' / ');
    const bands = `bands ${mix}${RADAR_NOMINAL_SLOTS ? ` / ${RADAR_NOMINAL_SLOTS} Nominal` : ''}`;
    if (typeof windowMinutes === 'number' && windowMinutes > 0) {
        el.textContent = `${bands} \u00b7 worst first, last ${windowMinutes} min`;
        return;
    }
    // null is the API saying "the window was empty, I fell back"; anything else is
    // a response that carried no window at all. Different claims about the
    // sample, so different words.
    el.textContent = windowMinutes === null
        ? `${bands} \u00b7 window empty, newest stored contacts`
        : `${bands} \u00b7 sample window unread`;
}

/**
 * Paint the legend from the gate that shipped with the radar's own feed.
 *
 * The two ladders are separate and the legend says so, because they grade
 * different quantities: `severity_band` bands P(attack) from the ML feed, while
 * `spike_severity_band` bands a connection count from the streamed spike feed.
 */
function renderRadarLegend(gate) {
    // Swatches are painted unconditionally: the colour encoding is a property of
    // the code, and it stays true even when the cuts cannot be read.
    RADAR_BANDS.forEach(band => {
        const swatch = document.getElementById(`radar-swatch-${band.id}`);
        const name = document.getElementById(`radar-name-${band.id}`);
        if (swatch) swatch.style.background = band.color;
        if (name) name.style.color = band.color;
    });

    const bands = gate && gate.severity_band;
    const spike = gate && gate.spike_severity_band;
    const spikeGate = gate && gate.spike_threshold_conn_per_window;
    const rules = {
        critical: bands && bands.critical != null
            ? `P(attack) \u2265 ${_fmtCut(bands.critical)} \u00b7 spike \u2265 ${spike && spike.critical != null ? spike.critical : '--'} conn/win`
            : 'deployed cut unread',
        high: bands && bands.high != null
            ? `P(attack) \u2265 ${_fmtCut(bands.high)} \u00b7 spike \u2265 ${spike && spike.high != null ? spike.high : '--'} conn/win`
            : 'deployed cut unread',
        medium: bands && bands.medium != null
            ? `P(attack) \u2265 ${_fmtCut(bands.medium)} \u00b7 spike ${spikeGate != null ? spikeGate : '--'}\u2013${spike && spike.high != null ? spike.high - 1 : '--'} conn/win`
            : 'deployed cut unread',
        nominal: 'nominal_flows mirror \u00b7 benign baseline, never scored',
    };
    Object.keys(rules).forEach(id => {
        const el = document.getElementById(`radar-rule-${id}`);
        if (el) el.textContent = rules[id];
    });

    const src = document.getElementById('radar-legend-source');
    if (!src) return;
    if (!gate) {
        src.textContent = 'deployed bands unreadable \u2014 colours only';
        return;
    }
    // Say which artifact and when, and never let a defaults fallback pass as the
    // deployed calibration: load_thresholds() cannot raise, it can only silently
    // return the module defaults.
    const provenance = [gate.source];
    // The policy appends "+env(VAR)" to its provenance when an environment
    // variable overrides the artifact. That is the one case where the file above
    // is *not* what the detector is running, so it is worth a word.
    if (/\+env\(/.test(String(gate.resolved_from || ''))) provenance.push('env override in effect');
    if (gate.generated_at) provenance.push(`gen ${String(gate.generated_at).slice(0, 10)}`);
    src.textContent = `bands: ${provenance.join(' \u00b7 ')}`;
    if (gate.severity_band_warning || gate.severity_band_error || gate.thresholds_error) {
        src.textContent += ' \u26a0 NOT DEPLOYED VALUES';
    }
}

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
        
        if (data.gate) renderRadarLegend(data.gate);
        renderRadarScope(data.window_minutes);

        if (data.threats) {
            const isNominal = t => t.observation === 'nominal';
            const attacks = data.threats.filter(t => !isNominal(t));
            const nominal = data.threats.filter(isNominal);
            // Taking the feed's own order meant taking whichever rows the
            // database put first, and every row in a micro-batch shares a
            // timestamp -- so the colour mix was decided by tie order rather than
            // by what was happening. The quota pick replaces that with a stated
            // rule; see RADAR_SLOT_QUOTA.
            const picked = [
                ...pickRadarContacts(attacks, RADAR_ATTACK_SLOTS),
                ...nominal.slice(0, RADAR_NOMINAL_SLOTS),
            ];
            radarIPs = picked.map((threat, idx) => ({
                ip: threat.src_ip || '0.0.0.0',
                severity: threat.severity || 'Medium',
                observation: threat.observation || '',
                angle: (idx * 45) + (radarAngle % 360), // Spread around circle
                distance: 60 + Math.random() * 30 // Random distance from center
            }));
            renderContactCount(radarIPs);
        }
    } catch (error) {
        console.error('Failed to update radar:', error);
    }
}

/**
 * The readout tile must count what the scope is actually drawing.
 *
 * The tile was static HTML reading "0 VECTORS" while blips were on screen, which
 * is the same defect as a legend that names the wrong colour: a readout the user
 * can watch contradict the display next to it. The band mix goes in the tooltip
 * because the tile has room for a number, not for a breakdown.
 */
function renderContactCount(blips) {
    const el = document.getElementById('stat-contacts');
    if (!el) return;
    const n = blips ? blips.length : 0;
    el.textContent = `${n} VECTOR${n === 1 ? '' : 'S'}`;
    if (!n) {
        el.title = 'No contacts on the scope — the last 5-minute window held none.';
        return;
    }
    const counts = {};
    blips.forEach(b => {
        const band = b.severity || 'Ungraded';
        counts[band] = (counts[band] || 0) + 1;
    });
    const mix = Object.entries(counts).map(([band, k]) => `${k} ${band}`).join(' · ');
    el.title = `Contacts drawn on the scope — ${mix}`;
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
        
        // Colour from the shared encoding; see RADAR_SEVERITY_COLORS /
        // radarColorFor above for what each band means and why the legend is
        // painted from the same object.
        const color = radarColorFor(blip);
        
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
// SOC CONTROLS
// ══════════════════════════════════════════════════════════════════════════════
//
// Every button here used to be inert: no handler, no id, nothing to click. What
// each one is *entitled* to do is limited by what exists behind it, so they are
// grouped by that rather than fixed uniformly:
//
//   * ACTIONS WITH A BACKEND — none of these. killstream, isolate, dispatch,
//     pcap dump, blackhole and C2-bloom have no API endpoint, no collection and
//     no state to change. Their fix is an *acknowledgement*, matching the
//     convention graph.js already uses for the topology equivalents: the label
//     reports the click for a moment, then reverts. Nothing is sent anywhere and
//     nothing claims to have been -- if any of these ever gets an endpoint, the
//     handler belongs there, not here.
//   * LOCAL UI STATE — the forensic drawer really can be hidden and reopened,
//     the mute button really can toggle, and escalation really can be a mode.
//     Those are implemented for real below.

/** Label swap shared by the acknowledgement buttons, via a `data-ack` text. */
const ACK_MS = 1600;

function acknowledgeButton(btn) {
    // These buttons carry an icon span before the label, so replacing the
    // button's own textContent would delete the icon -- and restoring it would
    // not bring it back. (The topology equivalents get away with that only
    // because they happen to be text-only buttons.) Swap the label element when
    // there is one.
    const label = btn.querySelector('span:last-of-type') || btn;
    const idle = (btn.dataset.idle || label.textContent).trim();
    btn.dataset.idle = idle;
    label.textContent = btn.dataset.ack;
    clearTimeout(btn._ackTimer);
    btn._ackTimer = setTimeout(() => { label.textContent = idle; }, ACK_MS);
}

// The drawer is a real panel, so open/close is real state. updateForensicPanel
// reopens it, which is what makes the close button safe to press: selecting an
// incident brings the panel back.
function setDrawerOpen(open) {
    const drawer = document.getElementById('forensic-drawer');
    if (drawer) drawer.style.display = open ? '' : 'none';
    return !!drawer;
}

function initSocControls() {
    document.querySelectorAll('[data-ack]').forEach(btn => {
        btn.addEventListener('click', () => acknowledgeButton(btn));
    });

    const closeBtn = document.getElementById('btn-close-drawer');
    if (closeBtn) closeBtn.addEventListener('click', () => setDrawerOpen(false));

    // [ESC] CLOSE says what it does: honour the key it names, but only while the
    // drawer is actually open, and without stealing the key from the filter
    // inputs or from graph.js's own Escape handling.
    window.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape') return;
        const tag = (e.target && e.target.tagName) || '';
        if (tag === 'INPUT' || tag === 'TEXTAREA') return;
        const drawer = document.getElementById('forensic-drawer');
        if (drawer && drawer.style.display !== 'none') setDrawerOpen(false);
    });

    // No audio exists anywhere in this dashboard, so this button cannot mute
    // anything. It still toggles, because a control that reports its own state is
    // honest and a control that ignores clicks is not -- but it must not imply
    // there is sound to silence.
    const muteBtn = document.getElementById('btn-mute');
    const muteIcon = document.getElementById('btn-mute-icon');
    if (muteBtn && muteIcon) {
        muteBtn.addEventListener('click', () => {
            const muted = muteIcon.textContent.trim() !== 'volume_off';
            muteIcon.textContent = muted ? 'volume_off' : 'volume_up';
            muteBtn.setAttribute('aria-pressed', String(muted));
            muteBtn.title = muted ? 'No audio output to mute' : 'Audio Mute Toggle';
        });
    }

    // Escalation is a view mode here: it highlights the alert banner and says so
    // on the button. No incident is escalated on the wire, and the label does not
    // claim otherwise.
    const escalateBtn = document.getElementById('btn-escalate');
    const escalateLabel = document.getElementById('btn-escalate-label');
    const bannerBody = document.getElementById('alert-banner-body');
    if (escalateBtn && escalateLabel && bannerBody) {
        escalateBtn.addEventListener('click', () => {
            const on = !bannerBody.classList.contains('bg-error-container/20');
            bannerBody.classList.toggle('bg-error-container/20', on);
            bannerBody.classList.toggle('bg-surface-container-low', !on);
            escalateLabel.textContent = on ? 'ESCALATED' : 'ESCALATE';
            escalateBtn.setAttribute('aria-pressed', String(on));
        });
    }

    console.log('✓ SOC controls initialized');
}

document.addEventListener('DOMContentLoaded', initSocControls);


// ══════════════════════════════════════════════════════════════════════════════
// FORENSIC TELEMETRY PANEL
// ══════════════════════════════════════════════════════════════════════════════

function updateForensicPanel(threat) {
    // The analyst-verdict buttons label *this* contact, so the panel keeps a
    // reference to the selected threat instead of re-deriving it from the DOM
    // (and instead of labelling whichever contact happens to be newest).
    selectedThreat = threat;
    resetVerdictControls(threat);

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

    // Selecting a contact reopens the panel, so closing it is never a dead end.
    setDrawerOpen(true);

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
// SPECTRAL TELEMETRY — MULTI-VECTOR OVERLAY + TEMPORAL CORRELATION INSPECTION
// ══════════════════════════════════════════════════════════════════════════════
//
// Three layers, all derived from the one series the API returns:
//   1. a short-time Fourier transform of the displayed aggregate, drawn as a
//      relative-energy spectrogram behind the traces;
//   2. one trace per attack family on an auto-scaled magnitude axis (real ingress
//      bandwidth where stream_alerts carries total_bytes, flows per bucket
//      otherwise), on the uniform sample grid the API declares;
//   3. a correlation readout — peak, overshoot over the vector's own median,
//      Pearson correlation and cross-correlation lag against the dominant
//      vector — plus a breach marker at the peak escalation bucket.
//
// The grid is not rebuilt here: simulated runs at 10 s off ml_alerts.first_seen
// (361 samples per 60-minute window) and live stays at 1 min off stream_alerts,
// and every label and lag states which of the two is in force.
//
// Nothing in the readout is a hardcoded constant: every figure is computed from
// the series that is drawn, and the two ML recalls come from the deployed
// thresholds artifact rather than being restated here.

let waterfallData = [];
let waterfallMeta = {
    mode: 'live',
    bytes_available: false,
    gate: null,
    window_minutes: 60,
    // Sample spacing and the full sample grid, as declared by the API. The two
    // modes do not share a resolution, so nothing below may assume one.
    bucket_seconds: 60,
    timestamps: [],
    samples: 0
};

// ── Bucket granularity ───────────────────────────────────────────────────────
// The API declares its own sample spacing because the two modes differ: the
// simulated overlay is bucketed off ml_alerts.first_seen every 10 s (361 samples
// across a 60-minute window), while the live feed is a per-minute stream_alerts
// aggregate (61). Every label, lag and offset below is derived from what actually
// arrived, so neither mode is ever annotated with the other's resolution.

function bucketSeconds() { return waterfallMeta.bucket_seconds || 60; }

function granularityLabel(seconds) {
    const s = seconds || bucketSeconds();
    if (s < 60) return `${s}S`;
    if (s % 60 === 0) return `${s / 60}M`;
    return `${Math.floor(s / 60)}M${s % 60}S`;
}

// Clock face for an axis tick or a readout. A sub-minute grid keeps the seconds,
// or six adjacent 10 s samples would all print the same "HH:MM".
function bucketTimeLabel(ts) {
    if (!ts || ts.length < 16) return ts || '--';
    return (bucketSeconds() < 60 && ts.length >= 19) ? ts.substring(11, 19) : ts.substring(11, 16);
}

// A distance expressed in buckets, resolved to the granularity in force.
function bucketOffsetLabel(bucketCount) {
    return granularityLabel(Math.abs(bucketCount) * bucketSeconds());
}

// paddingRight leaves room for the live-edge value labels, paddingLeft for the
// magnitude ticks.
const waterfallConfig = {
    paddingLeft: 76,
    paddingRight: 96,
    paddingTop: 12,
    paddingBottom: 44
};

// STFT window in *buckets*, so its wall-clock span follows the mode's
// granularity: 160 s on the 10 s simulated grid, 16 min on the 1 min live grid.
// 16 keeps the naive DFT trivial; floorDb sets the bottom of the colour ramp
// (relative to the strongest bin of the displayed series).
//
// minRangeDb guarantees the ramp spans at least 18 dB on a flat series; maxRangeDb
// caps it when the window is almost entirely idle (one live bucket in a 361-sample
// grid), where the percentile floor lands on numerical noise and would otherwise
// wash the whole plot out to a single saturated column.
const SPECTRO = { window: 16, alpha: 0.38, minRangeDb: 18, maxRangeDb: 60, floorPercentile: 0.25 };

// Measured detector recall, keyed by the hold-out the deployed cut was calibrated
// on (thresholds.json -> measured_recall_pct). Families with no measured number
// are reported as NOT MEASURED rather than being given one.
const MEASURED_RECALL_KEY = { 'DDoS': 'friday_ddos_test', 'Bot': 'friday_bot_test' };

// Vectors the pipeline deliberately withholds from the auto-alert feed
// (detection_policy.suppress_infiltration).
const SUPPRESSED_VECTORS = { 'Infiltration': 'FP MITIGATION' };

// Per-attack-type visual identity (dash pattern keeps lines distinguishable in
// grayscale or when colors collide). Colors follow the dashboard's palette.
const TRACE_STYLES = {
    'DDoS':        { color: '#e03e3e', dash: [],             width: 2.2 },
    'Bot':         { color: '#ffc58a', dash: [4, 3],         width: 1.6 },
    'PortScan':    { color: '#ff9e1b', dash: [],             width: 1.6 },
    'DoS':         { color: '#ffd166', dash: [3, 3],         width: 1.5 },
    'Brute Force': { color: '#b45309', dash: [2, 2],         width: 1.4 },
    'XSS':         { color: '#ff9891', dash: [6, 3],         width: 1.4 },
    'Sql Injection': { color: '#ff9891', dash: [1, 2],       width: 1.4 },
    'Infiltration': { color: '#ff9891', dash: [8, 3],        width: 1.4 },
    'Attack (unclassified)': { color: '#9aa7bd', dash: [5, 4], width: 1.2 },
    'Unknown':     { color: '#9aa7bd', dash: [5, 4],         width: 1.2 },
    '_default':    { color: '#44f498', dash: [],             width: 1.4 }
};

function traceStyleFor(type) {
    if (TRACE_STYLES[type]) return TRACE_STYLES[type];
    // Fallback for unmapped labels: pick a stable pseudo-random entry so each
    // type keeps a consistent color across refreshes.
    const keys = Object.keys(TRACE_STYLES).filter(k => k !== '_default');
    let h = 0;
    for (let i = 0; i < type.length; i++) h = (h * 31 + type.charCodeAt(i)) >>> 0;
    return TRACE_STYLES[keys[h % keys.length]];
}

// Lines the analyst has toggled off (persisted across refreshes in-session).
const hiddenTraces = new Set();

// Overlay mode. 'live' = escalated (post-threshold) alerts from stream_alerts,
// which the deployed cut narrows to DDoS alone on this corpus. 'simulated' =
// every pre-gate ML verdict from ml_alerts, i.e. the full multi-vector overlay
// this view was built for. The API serves both from the same endpoint.
let spectralMode = 'live';

function applySpectralModeUI() {
    const simulated = spectralMode === 'simulated';
    const label = document.getElementById('btn-wf-mode-label');
    const btn = document.getElementById('btn-wf-mode');
    const badge = document.getElementById('wf-feed-badge');
    const caption = document.getElementById('wf-mode-caption');
    const note = document.getElementById('wf-mode-note');

    if (label) label.textContent = simulated ? 'LIVE VERSION' : 'SIMULATED VERSION';
    if (btn) {
        btn.classList.toggle('border-primary', simulated);
        btn.classList.toggle('text-primary', simulated);
        btn.classList.toggle('border-outline-variant', !simulated);
        btn.classList.toggle('text-on-surface-variant', !simulated);
    }
    if (badge) {
        badge.textContent = simulated ? 'SIMULATED FEED' : 'LIVE FEED';
        badge.className = simulated
            ? 'font-label-sm text-label-sm text-primary-container'
            : 'font-label-sm text-label-sm text-secondary animate-pulse';
    }
    if (caption) caption.textContent = spectralCaption(null);
    if (note) note.style.display = simulated ? 'flex' : 'none';
}

// The caption carries the data source, the magnitude basis *and* the bucket
// granularity, because the two modes are never compared on one silent scale or
// on one silent sample rate.
function spectralCaption(basis) {
    const mode = spectralMode === 'simulated'
        ? '// PRE-GATE ML VERDICTS (ALL VECTORS)'
        : '// ESCALATED ALERTS (POST-THRESHOLD)';
    const gran = `${granularityLabel()} BUCKETS`;
    if (!basis) return `${mode} · ${gran}`;
    return `${mode} · ${basis === 'bandwidth' ? 'INGRESS BANDWIDTH' : 'FLOW VOLUME'} · ${gran}`;
}

function setSpectralMode(mode) {
    const next = mode === 'simulated' ? 'simulated' : 'live';
    if (next === spectralMode) return;
    spectralMode = next;
    // Trace visibility is per-mode: a vector hidden in one view should not
    // silently hide the same-named line in the other.
    hiddenTraces.clear();
    applySpectralModeUI();
    updateSpectralWaterfall();
}

async function updateSpectralWaterfall() {
    const canvas = document.getElementById('waterfallCanvas');
    if (!canvas) return;
    
    // Only fetch if visible to save resources
    if (document.getElementById('spectral-section').style.display === 'none') {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/analytics/waterfall?minutes=60&mode=${spectralMode}`);
        const data = await response.json();
        
        if (data.waterfall) {
            waterfallData = data.waterfall;
            waterfallMeta = {
                mode: data.mode || 'live',
                bytes_available: !!data.bytes_available,
                gate: data.gate || null,
                window_minutes: data.window_minutes || 60,
                // Spacing is per-mode: 10 s for the pre-gate overlay, 60 s live.
                bucket_seconds: data.bucket_seconds || 60,
                timestamps: Array.isArray(data.timestamps) ? data.timestamps : [],
                samples: data.samples || 0
            };
            drawWaterfall();
        }
    } catch (error) {
        console.error('Failed to update waterfall:', error);
    }
}

function buildTraceToggles(metrics, scale) {
    const wrap = document.getElementById('wf-trace-toggles');
    if (!wrap) return;
    wrap.innerHTML = '';
    metrics.forEach(m => {
        const type = m.type;
        const st = traceStyleFor(type);
        const label = document.createElement('label');
        label.className = 'flex items-center gap-1 bg-surface-container px-space-xs py-0.5 border cursor-pointer hover:bg-surface-container-high transition-colors';
        label.style.borderColor = st.color + '66';
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.checked = !hiddenTraces.has(type);
        cb.style.accentColor = st.color;
        cb.addEventListener('change', () => {
            if (cb.checked) hiddenTraces.delete(type); else hiddenTraces.add(type);
            drawWaterfall();
        });
        const swatch = document.createElement('span');
        swatch.className = 'inline-block w-2';
        swatch.style.height = st.dash.length ? '0' : '2px';
        swatch.style.background = st.color;
        if (st.dash.length) {
            swatch.style.borderTop = `2px dashed ${st.color}`;
            swatch.style.background = 'transparent';
        }
        const name = document.createElement('span');
        name.className = 'font-bold font-mono text-[10px]';
        name.style.color = st.color;
        name.textContent = `${type} [peak ${fmtValue(m.peak, scale)} ${scale.unit}]`;
        label.title = `${m.alerts} alert(s) in window · shape: ${m.shape}`;
        label.appendChild(cb); label.appendChild(swatch); label.appendChild(name);
        wrap.appendChild(label);
    });
}

// ── Statistics helpers ───────────────────────────────────────────────────────

function spectralMean(a) { return a.length ? a.reduce((s, v) => s + v, 0) / a.length : 0; }

function spectralMedian(a) {
    if (!a.length) return 0;
    const s = a.slice().sort((x, y) => x - y);
    const mid = s.length >> 1;
    return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

function spectralStd(a) {
    if (!a.length) return 0;
    const m = spectralMean(a);
    return Math.sqrt(spectralMean(a.map(v => (v - m) * (v - m))));
}

// Pearson correlation over the overlapping prefix of two series.
function pearson(a, b) {
    const n = Math.min(a.length, b.length);
    if (n < 3) return 0;
    const xa = a.slice(0, n), xb = b.slice(0, n);
    const ma = spectralMean(xa), mb = spectralMean(xb);
    let num = 0, da = 0, db = 0;
    for (let i = 0; i < n; i++) {
        const x = xa[i] - ma, y = xb[i] - mb;
        num += x * y; da += x * x; db += y * y;
    }
    if (da <= 0 || db <= 0) return 0;
    return num / Math.sqrt(da * db);
}

// Lag of `b` relative to `a`, in buckets, by maximising Pearson correlation over
// the overlap. A positive lag means b's shape appears *after* a's.
function bestLag(a, b, maxLag) {
    let best = { lag: 0, r: -2 };
    for (let lag = -maxLag; lag <= maxLag; lag++) {
        const as = lag >= 0 ? a.slice(0, a.length - lag) : a.slice(-lag);
        const bs = lag >= 0 ? b.slice(lag) : b.slice(0, b.length + lag);
        const r = pearson(as, bs);
        if (r > best.r) best = { lag, r: isFinite(r) ? r : 0 };
    }
    return best;
}

// Heuristic shape label derived only from the plotted series: how much of the
// window is active, how concentrated the mass is in its top buckets, how flat the
// flat runs are, and the spread relative to its own mean.
function classifyShape(vals) {
    const total = vals.reduce((s, v) => s + v, 0);
    const m = spectralMean(vals);
    if (total <= 0 || m <= 0) return 'NO SIGNAL';
    const cv = spectralStd(vals) / m;
    const deltas = vals.slice(1).map((v, i) => Math.abs(v - vals[i]));
    const maxDelta = Math.max.apply(null, deltas.concat([1e-9]));
    const flat = deltas.filter(d => d <= maxDelta * 0.02).length / deltas.length;
    const active = vals.filter(v => v > 0.15 * m).length / vals.length;
    const top3 = vals.slice().sort((a, b) => b - a).slice(0, 3)
        .reduce((s, v) => s + v, 0) / total;
    if (active < 0.45 || top3 > 0.5) return 'MICRO-BURST';
    if (flat > 0.3) return 'STEPPED SWEEP';
    if (cv < 0.22) return 'SUSTAINED FLOOR';
    if (cv > 0.85) return 'BURSTY';
    return 'OSCILLATING';
}

// ── Magnitude basis ──────────────────────────────────────────────────────────
// stream_alerts rows carry total_bytes, so a genuine ingress-bandwidth axis is
// available and rows are per-bucket totals (bits/s = bytes * 8 / bucket_seconds).
// ml_alerts carries no byte or packet fields, so the simulated overlay is plotted
// in flows.  The unit is always labelled -- with the bucket width in it -- so the
// two modes are never silently read off one scale or one sample rate.

function magnitudeBasis() {
    return waterfallMeta.bytes_available ? 'bandwidth' : 'flows';
}

function bandScaleFor(peakBytes) {
    const perSecond = 8 / bucketSeconds();
    const bps = peakBytes * perSecond;
    if (bps >= 1e9) return { unit: 'Gbps', factor: perSecond / 1e9, digits: 2 };
    if (bps >= 1e6) return { unit: 'Mbps', factor: perSecond / 1e6, digits: 1 };
    if (bps >= 1e3) return { unit: 'kbps', factor: perSecond / 1e3, digits: 1 };
    return { unit: 'bps', factor: perSecond, digits: 0 };
}

function metricScale(basis, peakBytes) {
    return basis === 'bandwidth'
        ? bandScaleFor(peakBytes)
        : { unit: `FLOWS/${granularityLabel()}`, factor: 1, digits: 0, integer: true };
}

function valueForRow(row) {
    if (!row) return 0;
    return magnitudeBasis() === 'bandwidth' ? (row.bytes || 0) : (row.connections || 0);
}

function fmtValue(v, scale) {
    const x = v * scale.factor;
    if (scale.integer) return Math.round(x).toLocaleString();
    if (Math.abs(x) >= 100) return x.toFixed(0);
    if (Math.abs(x) >= 10) return x.toFixed(Math.max(1, scale.digits - 1));
    return x.toFixed(scale.digits);
}

function niceStep(raw) {
    if (!(raw > 0)) return 1;
    const mag = Math.pow(10, Math.floor(Math.log10(raw)));
    const norm = raw / mag;
    return (norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 5 ? 5 : 10) * mag;
}

// ── Spectrogram (STFT of the displayed aggregate) ────────────────────────────

function hannWindow(n) {
    const w = new Array(n);
    for (let i = 0; i < n; i++) w[i] = 0.5 - 0.5 * Math.cos((2 * Math.PI * i) / (n - 1));
    return w;
}

// Naive DFT. A 16-bucket window over a 60-bucket span is <=45 frames, so O(n^2)
// costs ~11k multiply-adds per redraw — cheaper than carrying an FFT.
function dftMagnitudes(frame) {
    const n = frame.length, half = n >> 1;
    const out = new Array(half + 1);
    for (let k = 0; k <= half; k++) {
        let re = 0, im = 0;
        for (let t = 0; t < n; t++) {
            const a = (-2 * Math.PI * k * t) / n;
            re += frame[t] * Math.cos(a);
            im += frame[t] * Math.sin(a);
        }
        out[k] = Math.sqrt(re * re + im * im);
    }
    return out;
}

// Relative-energy spectrogram of the aggregate series being plotted. This is a
// real STFT of real telemetry — a surge lights up as broadband energy — but it is
// a spectrum of the alert series over time, not of packets on the wire, so the
// magnitudes are normalised to the strongest bin and reported in relative dB.
function computeSpectrogram(values) {
    const win = SPECTRO.window;
    if (values.length < win) return null;
    const w = hannWindow(win);
    const frames = [];
    for (let start = 0; start + win <= values.length; start++) {
        // Each frame is mean-removed before windowing. Without this the DC bin
        // dominates every frame and the display degenerates into a bright band
        // at the level of the series, hiding the time-frequency structure.
        const seg = values.slice(start, start + win);
        const segMean = spectralMean(seg);
        const frame = new Array(win);
        for (let i = 0; i < win; i++) frame[i] = (seg[i] - segMean) * w[i];
        frames.push(dftMagnitudes(frame));
    }
    let peak = 0;
    frames.forEach(f => f.forEach(m => { if (m > peak) peak = m; }));
    if (!(peak > 0)) return null;
    const db = frames.map(f => f.map(m => 20 * Math.log10(Math.max(m, 1e-9) / peak)));

    // The colour floor is measured, not fixed: most cells of a spiky series sit
    // well below its strongest bin, and a fixed floor either washes the whole
    // plot out or hides the structure. Floor at the 25th percentile, keeping a
    // minimum range so a flat series still shows contrast.
    const flat = db.reduce((acc, row) => acc.concat(row), []).sort((a, b) => a - b);
    const pick = p => flat[Math.min(flat.length - 1, Math.max(0, Math.round(p * (flat.length - 1))))];
    const floorDb = Math.max(
        Math.min(pick(SPECTRO.floorPercentile), -SPECTRO.minRangeDb),
        -SPECTRO.maxRangeDb
    );

    return {
        window: win,
        frames: frames.length,
        bins: frames[0].length,
        floorDb,
        db
    };
}

function spectroRGB(db, floorDb) {
    const t = Math.max(0, Math.min(1, (db - floorDb) / -(floorDb || -1)));
    // Deliberately weighted dark: the traces have to stay legible on top, so only
    // the strongest bins reach amber.
    const stops = [
        [0.00, [4, 7, 6]],
        [0.45, [26, 8, 10]],
        [0.70, [96, 22, 20]],
        [0.88, [186, 62, 32]],
        [1.00, [255, 158, 27]]
    ];
    for (let i = 1; i < stops.length; i++) {
        if (t <= stops[i][0]) {
            const t0 = stops[i - 1][0], c0 = stops[i - 1][1];
            const t1 = stops[i][0], c1 = stops[i][1];
            const f = (t - t0) / (t1 - t0 || 1);
            return [
                Math.round(c0[0] + (c1[0] - c0[0]) * f),
                Math.round(c0[1] + (c1[1] - c0[1]) * f),
                Math.round(c0[2] + (c1[2] - c0[2]) * f)
            ];
        }
    }
    return [255, 220, 168];
}

let spectroCanvas = null;

function drawSpectrogram(ctx, pl, pt, plotW, plotH, values) {
    const spec = computeSpectrogram(values);
    if (!spec) return null;
    if (!spectroCanvas) spectroCanvas = document.createElement('canvas');
    if (spectroCanvas.width !== spec.frames || spectroCanvas.height !== spec.bins) {
        spectroCanvas.width = spec.frames;
        spectroCanvas.height = spec.bins;
    }
    const sctx = spectroCanvas.getContext('2d');
    const img = sctx.createImageData(spec.frames, spec.bins);
    for (let f = 0; f < spec.frames; f++) {
        for (let b = 0; b < spec.bins; b++) {
            // Bin 0 is drawn at the bottom, Nyquist at the top.
            const y = spec.bins - 1 - b;
            const rgb = spectroRGB(spec.db[f][b], spec.floorDb);
            const o = (y * spec.frames + f) * 4;
            img.data[o] = rgb[0];
            img.data[o + 1] = rgb[1];
            img.data[o + 2] = rgb[2];
            img.data[o + 3] = 255;
        }
    }
    sctx.putImageData(img, 0, 0);
    ctx.save();
    ctx.globalAlpha = SPECTRO.alpha;
    ctx.drawImage(spectroCanvas, pl, pt, plotW, plotH);
    ctx.restore();
    return spec;
}

function renderSpectroLegend(spec, basis) {
    const host = document.getElementById('wf-spectro-legend');
    const ramp = document.getElementById('wf-spectro-ramp');
    if (!host) return;
    if (!spec) { host.style.display = 'none'; return; }
    host.style.display = 'flex';
    const rampStops = [];
    for (let i = 0; i <= 8; i++) {
        const rgb = spectroRGB(spec.floorDb * (1 - i / 8), spec.floorDb);
        rampStops.push(`rgb(${rgb[0]},${rgb[1]},${rgb[2]}) ${(i / 8) * 100}%`);
    }
    if (ramp) ramp.style.background = `linear-gradient(to right, ${rampStops.join(', ')})`;
    const minEl = document.getElementById('wf-spectro-min');
    const maxEl = document.getElementById('wf-spectro-max');
    if (minEl) minEl.textContent = `${spec.floorDb.toFixed(0)} dB`;
    if (maxEl) maxEl.textContent = '0 dB';
    const basisEl = document.getElementById('wf-spectro-basis');
    if (basisEl) {
        // The STFT window is fixed in buckets, so state its wall-clock span too:
        // 16 buckets is 160 s of the 10 s grid but 16 min of the 1 min grid.
        const span = spec.window * bucketSeconds();
        const spanLabel = span < 60
            ? `${span}s`
            : (span % 60 === 0 ? `${span / 60}m` : `${Math.floor(span / 60)}m${span % 60}s`);
        basisEl.textContent = `STFT ${spec.window}-SAMPLE HANN (${spanLabel}) · ${spec.frames} FRAMES OF ${granularityLabel()} BUCKETS${basis === 'flows' ? ' · FLOWS BASIS' : ''}`;
    }
}

// ── Per-vector metrics ───────────────────────────────────────────────────────

function computeSpectralMetrics(bucketKeys, seriesMap, types) {
    const series = {};
    types.forEach(t => { series[t] = bucketKeys.map(k => valueForRow(seriesMap[t][k])); });
    const peakOf = t => (series[t].length ? Math.max.apply(null, series[t]) : 0);
    const ordered = types.slice().sort((a, b) => peakOf(b) - peakOf(a));
    const dominant = ordered[0];
    const maxLag = Math.min(15, Math.max(1, bucketKeys.length - 2));
    const recalls = (waterfallMeta.gate && waterfallMeta.gate.measured_recall_pct) || {};

    return ordered.map(type => {
        const vals = series[type];
        const peak = peakOf(type);
        const base = spectralMedian(vals);
        const lag = type === dominant ? { lag: 0, r: 1 } : bestLag(series[dominant], vals, maxLag);
        let alerts = 0;
        bucketKeys.forEach(k => { alerts += (seriesMap[type][k] && seriesMap[type][k].count) || 0; });
        const recallKey = MEASURED_RECALL_KEY[type];
        return {
            type,
            series: vals,
            peak,
            peakIdx: vals.indexOf(peak),
            base,
            surgePct: base > 0 ? (peak / base - 1) * 100 : 0,
            alerts,
            corr: lag.r,
            lagBuckets: lag.lag,
            // A lag is counted in buckets, so its wall-clock width is the mode's
            // bucket width, not a fixed minute.
            lagSeconds: lag.lag * bucketSeconds(),
            shape: classifyShape(vals),
            recall: recallKey && recalls[recallKey] != null ? recalls[recallKey] : null,
            recallKey: recallKey || null,
            suppressed: SUPPRESSED_VECTORS[type] || null,
            isDominant: type === dominant
        };
    });
}

function renderCorrelationPanel(metrics, scale, bucketKeys, basis, breach) {
    const rows = document.getElementById('wf-corr-rows');
    if (rows) {
        if (!metrics.length) {
            rows.innerHTML = '<span class="text-on-surface-variant">NO VISIBLE VECTORS</span>';
        } else {
            rows.innerHTML = metrics.map(m => {
                const st = traceStyleFor(m.type);
                const lagText = m.isDominant
                    ? 'REFERENCE'
                    : `LAG ${m.lagBuckets > 0 ? '+' : (m.lagBuckets < 0 ? '-' : '')}${Math.abs(m.lagBuckets)}B (${bucketOffsetLabel(m.lagBuckets)})`;
                const recallText = m.recall != null
                    ? `ML ${m.recall.toFixed(2)}% RECALL`
                    : (m.suppressed ? `ML SUPPRESSED (${m.suppressed})` : 'ML NOT MEASURED');
                const recallClass = m.recall != null
                    ? (m.recall >= 90 ? 'text-secondary' : 'text-primary-container')
                    : (m.suppressed ? 'text-primary-container' : 'text-on-surface-variant');
                const title = `${m.alerts} alert(s) in window · median baseline ${fmtValue(m.base, scale)} ${scale.unit}`;
                return `
                    <div class="flex items-center gap-space-xs min-w-0 bg-surface-container/60 px-space-xs py-0.5 border border-outline-variant/20" title="${title}">
                        <span class="w-2 h-2 shrink-0 inline-block" style="background:${st.color}"></span>
                        <span class="font-bold shrink-0" style="color:${st.color}">${m.type}</span>
                        <span class="text-on-surface font-bold shrink-0">${fmtValue(m.peak, scale)} ${scale.unit}</span>
                        <span class="text-on-surface-variant shrink-0">(+${m.surgePct.toFixed(0)}%)</span>
                        <span class="text-on-surface-variant shrink-0" title="Pearson correlation and cross-correlation lag against the dominant vector">[r ${m.corr.toFixed(2)} · ${lagText}]</span>
                        <span class="px-space-xs border shrink-0 ${m.isDominant ? 'border-error/50 text-error' : 'border-outline-variant/40 text-on-surface-variant'}" title="Heuristic shape label computed from the coefficient of variation and step count of the plotted series">${m.shape}</span>
                        <span class="shrink-0 ${recallClass}" ${m.recallKey ? `title="thresholds.json measured_recall_pct.${m.recallKey} at the deployed cut"` : ''}>${recallText}</span>
                    </div>`;
            }).join('');
        }
    }

    const basisEl = document.getElementById('wf-corr-basis');
    if (basisEl) {
        basisEl.textContent = `BASIS: ${basis === 'bandwidth' ? 'INGRESS BANDWIDTH (total_bytes)' : 'FLOW VOLUME (flow_count)'}`;
    }

    const winEl = document.getElementById('wf-corr-window');
    if (winEl) {
        const first = bucketKeys[0] || '';
        const last = bucketKeys[bucketKeys.length - 1] || '';
        winEl.textContent = `[${bucketKeys.length} BUCKETS | ${granularityLabel()}] ${bucketTimeLabel(first)}→${bucketTimeLabel(last)}`;
        winEl.title = `Sampled every ${granularityLabel()} from ${waterfallMeta.mode === 'simulated' ? 'ml_alerts.first_seen' : 'stream_alerts.created_at'}`;
    }

    const gate = waterfallMeta.gate || {};
    const gateEl = document.getElementById('wf-corr-gate');
    if (gateEl) {
        const cut = gate.attack_threshold != null ? `P(ATTACK)≥${gate.attack_threshold.toFixed(4)}` : 'P(ATTACK) UNREAD';
        const spike = gate.spike_threshold_conn_per_window != null ? `SPIKE≥${gate.spike_threshold_conn_per_window}/MIN` : 'SPIKE UNREAD';
        gateEl.textContent = `GATE: ${cut} · ${spike}`;
        gateEl.title = gate.error
            ? `Thresholds artifact unreadable: ${gate.error}`
            : `Read from ${gate.source}${gate.generated_at ? ` (generated ${gate.generated_at})` : ''}`;
    }

    const breachEl = document.getElementById('wf-corr-breach');
    if (breachEl) {
        if (breach) {
            // The marker tracks the aggregate of the visible vectors, so say so
            // rather than implying it is any single family's peak.
            breachEl.textContent = `BREACH LOCK: T-${bucketOffsetLabel(breach.idxFromEnd)} AGG ${fmtValue(breach.value, scale)} ${scale.unit}`;
            breachEl.className = 'px-space-xs py-0.5 border border-error bg-error-container/20 text-error font-bold';
        } else {
            breachEl.textContent = 'BREACH LOCK: NONE';
            breachEl.className = 'px-space-xs py-0.5 border border-outline-variant/50 bg-surface-container text-on-surface-variant font-bold';
        }
    }

    const suppressEl = document.getElementById('wf-corr-suppress');
    if (suppressEl) {
        const suppressed = metrics.filter(m => m.suppressed);
        if (suppressed.length) {
            suppressEl.textContent = `SUPPRESS: ${suppressed.map(m => m.type).join(', ')}`;
            suppressEl.className = 'px-space-xs py-0.5 border border-primary-container bg-primary-container/20 text-primary-container font-bold';
            suppressEl.title = 'These families are routed to manual review instead of the auto-alert feed. Only the auto-alert feed is drawn here.';
        } else {
            suppressEl.textContent = 'SUPPRESS: NONE';
            suppressEl.className = 'px-space-xs py-0.5 border border-outline-variant/50 bg-surface-container text-on-surface-variant font-bold';
        }
    }

    const conclusionEl = document.getElementById('wf-corr-conclusion');
    if (conclusionEl) conclusionEl.textContent = buildConclusion(metrics, scale, breach);
}

// Reads the correlation matrix in plain language. Every clause is backed by a
// number in the rows above it; this is a heuristic over the plotted series, not a
// classifier verdict. The bar for claiming staged traffic is deliberately high --
// on per-minute alert volumes a |r| under 0.5 is noise, and saying so is more
// useful than narrating it.
const MIN_NARRATIVE_CORR = 0.5;

function buildConclusion(metrics, scale, breach) {
    if (!metrics.length) return 'ANALYST CONCLUSION (HEURISTIC): NO VISIBLE VECTORS';
    const dom = metrics[0];
    const lead = metrics.slice(1)
        .filter(m => Math.abs(m.corr) >= MIN_NARRATIVE_CORR)
        .sort((a, b) => Math.abs(b.corr) - Math.abs(a.corr))[0];
    const domStr = `${dom.type} AT ${fmtValue(dom.peak, scale)} ${scale.unit} (+${dom.surgePct.toFixed(0)}% OVER ITS OWN MEDIAN)`;
    const tail = breach ? ` BREACH LOCK AT T-${bucketOffsetLabel(breach.idxFromEnd)}.` : '';

    if (lead && lead.lagBuckets > 0) {
        return `ANALYST CONCLUSION (HEURISTIC): ${lead.type} TRAILS THE ${dom.type} SURGE BY ${lead.lagBuckets} BUCKET(S) (${lead.lagSeconds}s) AT r=${lead.corr.toFixed(2)} — CONSISTENT WITH STAGED SECONDARY TRAFFIC INSIDE THE ${dom.type} ENVELOPE. DOMINANT VECTOR: ${domStr}.${tail}`;
    }
    if (lead && lead.lagBuckets < 0) {
        return `ANALYST CONCLUSION (HEURISTIC): ${lead.type} LEADS THE ${dom.type} SURGE BY ${Math.abs(lead.lagBuckets)} BUCKET(S) (${Math.abs(lead.lagSeconds)}s) AT r=${lead.corr.toFixed(2)} — POSSIBLE RECONNAISSANCE PRECURSOR. DOMINANT VECTOR: ${domStr}.${tail}`;
    }
    if (lead) {
        return `ANALYST CONCLUSION (HEURISTIC): ${dom.type} AND ${lead.type} CO-MOVE AT r=${lead.corr.toFixed(2)} WITH ZERO LAG — SINGLE CAMPAIGN RATHER THAN INDEPENDENT EVENTS. DOMINANT VECTOR: ${domStr}.${tail}`;
    }
    const best = metrics.slice(1).sort((a, b) => Math.abs(b.corr) - Math.abs(a.corr))[0];
    const bestStr = best ? ` STRONGEST OTHER PAIRING: ${best.type} AT r=${best.corr.toFixed(2)}.` : '';
    return `ANALYST CONCLUSION (HEURISTIC): NO CROSS-VECTOR CORRELATION AT OR ABOVE r=${MIN_NARRATIVE_CORR.toFixed(2)} — VECTORS INDEPENDENT. DOMINANT VECTOR: ${domStr}.${bestStr}${tail}`;
}

// ── Render ───────────────────────────────────────────────────────────────────

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
    
    ctx.fillStyle = '#030604';
    ctx.fillRect(0, 0, width, height);
    ctx.font = '10px JetBrains Mono';

    if (!waterfallData || waterfallData.length === 0) {
        ctx.fillStyle = '#dac2ae';
        ctx.textAlign = 'center';
        ctx.fillText('NO THREAT DENSITY DATA AVAILABLE', width/2, height/2);
        renderSpectroLegend(null, null);
        return;
    }

    const { paddingLeft: pl, paddingRight: pr, paddingTop: pt, paddingBottom: pb } = waterfallConfig;
    const plotW = width - pl - pr;
    const plotH = height - pt - pb;

    // Time axis: the API's declared grid, so every type shares one X grid *and*
    // the grid stays uniform in time where nothing fired.  Rebuilding it from the
    // returned rows would silently compress the gaps and hand the STFT a
    // 60-sample series where the simulated overlay has 361 real samples.
    const bucketKeys = (waterfallMeta.timestamps && waterfallMeta.timestamps.length)
        ? waterfallMeta.timestamps
        : [...new Set(waterfallData.map(d => d.timestamp))].sort();
    if (bucketKeys.length === 0) return;
    const bucketCount = bucketKeys.length;
    const xFor = i => pl + (bucketCount === 1 ? plotW / 2 : (i / (bucketCount - 1)) * plotW);

    // Series: one per attack family, sharing the bucket grid. Whole rows are kept
    // because which field is the magnitude depends on the mode's basis.
    const seriesMap = {};
    waterfallData.forEach(d => {
        if (!seriesMap[d.attack_type]) seriesMap[d.attack_type] = {};
        seriesMap[d.attack_type][d.timestamp] = d;
    });
    const allTypes = Object.keys(seriesMap).sort();
    const visibleTypes = allTypes.filter(t => !hiddenTraces.has(t));

    // Magnitude scale is derived from the whole window (every family, not just the
    // visible ones) so hiding a trace never rescales the axis under the analyst.
    const basis = magnitudeBasis();
    let peakBytes = 0;
    allTypes.forEach(t => bucketKeys.forEach(k => {
        const row = seriesMap[t][k];
        if (row && (row.bytes || 0) > peakBytes) peakBytes = row.bytes;
    }));
    const scale = metricScale(basis, peakBytes);

    // Toggles are built from every family so they stay available when the last
    // visible trace is switched off.
    buildTraceToggles(computeSpectralMetrics(bucketKeys, seriesMap, allTypes), scale);

    const metrics = computeSpectralMetrics(bucketKeys, seriesMap, visibleTypes);
    if (!metrics.length) {
        ctx.fillStyle = '#dac2ae';
        ctx.textAlign = 'center';
        ctx.fillText('ALL TRACES HIDDEN - ENABLE A VECTOR TRACE ABOVE', width/2, height/2);
        renderSpectroLegend(null, basis);
        renderCorrelationPanel([], scale, bucketKeys, basis, null);
        return;
    }

    // Aggregate over the visible vectors drives the spectrogram and the breach
    // marker, so both answer "what the analyst is actually looking at".
    const aggregate = bucketKeys.map(k => visibleTypes.reduce((s, t) => s + valueForRow(seriesMap[t][k]), 0));

    // Nice Y maximum in display units.
    let yMax = 0;
    metrics.forEach(m => m.series.forEach(v => { const d = v * scale.factor; if (d > yMax) yMax = d; }));
    const step = niceStep(Math.max(yMax / 5, 1e-9));
    const yTop = Math.max(step, Math.ceil(yMax / step) * step);
    const yFor = v => pt + plotH - (v / yTop) * plotH;
    const yForDisplay = v => yFor(v * scale.factor);

    // Caption carries the source and the magnitude basis together.
    const captionEl = document.getElementById('wf-mode-caption');
    if (captionEl) captionEl.textContent = spectralCaption(basis);

    // Layer 1 — spectrogram of the aggregate, behind everything.
    const spec = drawSpectrogram(ctx, pl, pt, plotW, plotH, aggregate);
    renderSpectroLegend(spec, basis);

    // Grid + magnitude ticks
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    ctx.font = '10px JetBrains Mono';
    for (let v = 0; v <= yTop + 1e-9; v += step) {
        const y = yFor(v);
        ctx.strokeStyle = 'rgba(84, 68, 52, 0.18)';
        ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(pl, y); ctx.lineTo(pl + plotW, y); ctx.stroke();
        ctx.fillStyle = '#dac2ae';
        ctx.fillText(fmtValue(v / scale.factor, scale), pl - 6, y);
    }
    // Axis unit, so the basis is never ambiguous between the two modes.
    ctx.save();
    ctx.translate(11, pt + plotH / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = '#ffc58a';
    ctx.font = '9px JetBrains Mono';
    ctx.fillText(scale.unit, 0, 0);
    ctx.restore();

    // X tick labels (time buckets, thinned to fit)
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    const labelStep = Math.max(1, Math.ceil(bucketCount / Math.max(4, Math.floor(plotW / 70))));
    bucketKeys.forEach((ts, i) => {
        if (i % labelStep !== 0 && i !== bucketCount - 1) return;
        const x = xFor(i);
        ctx.strokeStyle = 'rgba(84, 68, 52, 0.18)';
        ctx.beginPath(); ctx.moveTo(x, pt); ctx.lineTo(x, pt + plotH); ctx.stroke();
        ctx.fillStyle = '#dac2ae';
        ctx.fillText(bucketTimeLabel(ts), x, pt + plotH + 6);
    });

    // Layer 2 — baseline + breach markers on the aggregate
    const aggregateDisplay = aggregate.map(v => v * scale.factor);
    const aggBase = spectralMedian(aggregateDisplay);
    const hasSignal = aggregateDisplay.some(v => v > 0);
    const breachIdx = hasSignal ? aggregateDisplay.indexOf(Math.max.apply(null, aggregateDisplay)) : -1;
    const breach = breachIdx >= 0
        ? { idx: breachIdx, idxFromEnd: bucketCount - 1 - breachIdx, value: aggregate[breachIdx] }
        : null;

    // The marker *lines* sit under the traces so they never chop them up; their
    // labels are drawn last (see "annotation labels" below) so the traces never
    // chop the labels up either.
    ctx.save();
    ctx.beginPath(); ctx.rect(pl, pt, plotW, plotH); ctx.clip();
    if (aggBase > 0) {
        const by = yFor(aggBase);
        ctx.strokeStyle = 'rgba(218, 194, 174, 0.45)';
        ctx.setLineDash([2, 4]);
        ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(pl, by); ctx.lineTo(pl + plotW, by); ctx.stroke();
        ctx.setLineDash([]);
    }
    if (breach) {
        const bx = xFor(breach.idx);
        ctx.strokeStyle = 'rgba(224, 62, 62, 0.75)';
        ctx.setLineDash([5, 3]);
        ctx.lineWidth = 1.2;
        ctx.beginPath(); ctx.moveTo(bx, pt); ctx.lineTo(bx, pt + plotH); ctx.stroke();
        ctx.setLineDash([]);
    }
    ctx.restore();

    // Layer 3 — one trace per visible family, all on the shared axes.
    ctx.save();
    ctx.beginPath();
    ctx.rect(pl, pt - 2, plotW, plotH + 4);
    ctx.clip();
    metrics.forEach(m => {
        const st = traceStyleFor(m.type);
        ctx.strokeStyle = st.color;
        ctx.lineWidth = st.width;
        ctx.setLineDash(st.dash);
        ctx.lineJoin = 'round';
        ctx.lineCap = 'round';
        ctx.globalAlpha = 0.95;
        ctx.beginPath();
        m.series.forEach((v, i) => {
            const x = xFor(i), y = yForDisplay(v);
            if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
        });
        ctx.stroke();
        ctx.setLineDash([]);
    });
    ctx.restore();

    // Annotation labels, on top of everything and on a backing plate: the
    // spectrogram is brightest exactly where these land, and the traces cross them.
    ctx.save();
    ctx.beginPath(); ctx.rect(pl, pt, plotW, plotH); ctx.clip();
    ctx.font = '9px JetBrains Mono';
    if (aggBase > 0) {
        const baseLabel = `AGG BASELINE ${fmtValue(aggBase / scale.factor, scale)} ${scale.unit}`;
        const by = yFor(aggBase);
        const bw = ctx.measureText(baseLabel).width;
        ctx.fillStyle = 'rgba(3, 6, 4, 0.85)';
        ctx.fillRect(pl + 3, by - 13, bw + 6, 12);
        ctx.fillStyle = 'rgba(218, 194, 174, 0.95)';
        ctx.textAlign = 'left';
        ctx.textBaseline = 'bottom';
        ctx.fillText(baseLabel, pl + 6, by - 2);
    }
    if (breach) {
        const bx = xFor(breach.idx);
        const flip = breach.idx > bucketCount * 0.75;
        const breachLabel = `BREACH LOCK T-${bucketOffsetLabel(breach.idxFromEnd)}`;
        ctx.font = 'bold 9px JetBrains Mono';
        ctx.textAlign = flip ? 'right' : 'left';
        ctx.textBaseline = 'top';
        const bw = ctx.measureText(breachLabel).width;
        const bx0 = flip ? bx - 4 - bw - 4 : bx + 1;
        ctx.fillStyle = 'rgba(3, 6, 4, 0.85)';
        ctx.fillRect(bx0, pt + 2, bw + 6, 12);
        ctx.fillStyle = '#ff6b6b';
        ctx.fillText(breachLabel, bx0 + 3, pt + 4);
    }
    ctx.restore();

    // Current-value dots + labels at the live edge (right, beside the last bucket).
    const liveX = xFor(bucketCount - 1);
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';
    ctx.font = '9px JetBrains Mono';

    // De-overlap the edge labels, then shift the whole stack so the lowest one
    // does not collide with the time axis. Low-volume vectors all pile up near
    // zero, so without the clamp their labels land on the tick row.
    const labelItems = metrics.map(m => {
        const last = m.series[m.series.length - 1] || 0;
        const y = yForDisplay(last);
        return { style: traceStyleFor(m.type), label: `${m.type}: ${fmtValue(last, scale)}`, y, ly: y };
    });
    const placed = [];
    labelItems.forEach(it => {
        while (placed.some(s => Math.abs(s - it.ly) < 11)) it.ly += 11;
        placed.push(it.ly);
    });
    const hi = Math.max.apply(null, placed);
    const lo = Math.min.apply(null, placed);
    let shift = 0;
    if (hi > pt + plotH - 4) shift = pt + plotH - 4 - hi;
    else if (lo < pt + 6) shift = pt + 6 - lo;
    labelItems.forEach(it => {
        ctx.fillStyle = it.style.color;
        ctx.beginPath();
        ctx.arc(liveX, it.y, 3, 0, Math.PI * 2);
        ctx.fill();
        ctx.strokeStyle = '#0c0f0e';
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.fillText(it.label, liveX + 6, it.ly + shift);
    });
    ctx.font = '10px JetBrains Mono';
    ctx.fillStyle = '#44f498';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.fillText('T-0 [LIVE]', liveX, pt + plotH + 6);

    renderCorrelationPanel(metrics, scale, bucketKeys, basis, breach);

    // Hit-test layout for the crosshair tooltip.
    canvas.waterfallLayout = {
        pl, pt, plotW, plotH,
        bucketKeys, xFor, yFor, yForDisplay, yTop,
        seriesMap,
        visibleTypes,
        metrics,
        scale,
        basis,
        valueAt: (type, ts) => valueForRow(seriesMap[type] && seriesMap[type][ts]),
        countAt: (type, ts) => ((seriesMap[type] && seriesMap[type][ts] && seriesMap[type][ts].count) || 0)
    };
}

document.addEventListener('DOMContentLoaded', function() {
    const canvas = document.getElementById('waterfallCanvas');
    const tooltip = document.getElementById('waterfall-tooltip');
    
    if (canvas && tooltip) {
        canvas.addEventListener('mousemove', (e) => {
            const L = canvas.waterfallLayout;
            if (!L) return;
            const rect = canvas.getBoundingClientRect();
            const mx = e.clientX - rect.left;
            const my = e.clientY - rect.top;
            
            // Snap to nearest time bucket; show a vertical hairline + per-line values.
            if (mx < L.pl || mx > L.pl + L.plotW || my < L.pt || my > L.pt + L.plotH) {
                tooltip.style.display = 'none';
                drawWaterfall();
                return;
            }
            const frac = (mx - L.pl) / L.plotW;
            let idx = Math.round(frac * (L.bucketKeys.length - 1));
            idx = Math.max(0, Math.min(L.bucketKeys.length - 1, idx));
            const ts = L.bucketKeys[idx];
            
            if (canvas._hairlineIdx !== idx) {
                drawWaterfall();
                canvas._hairlineIdx = idx;
                const ctx = canvas.getContext('2d');
                const hx = L.xFor(idx);
                ctx.strokeStyle = '#44f498';
                ctx.setLineDash([4, 3]);
                ctx.lineWidth = 1;
                ctx.beginPath(); ctx.moveTo(hx, L.pt); ctx.lineTo(hx, L.pt + L.plotH); ctx.stroke();
                ctx.setLineDash([]);
                L.visibleTypes.forEach(type => {
                    const st = traceStyleFor(type);
                    const y = L.yForDisplay(L.valueAt(type, ts));
                    ctx.fillStyle = st.color;
                    ctx.beginPath(); ctx.arc(hx, y, 3, 0, Math.PI * 2); ctx.fill();
                    ctx.strokeStyle = '#0c0f0e'; ctx.lineWidth = 1; ctx.stroke();
                });
            }
            
            // Tooltip: top 4 attack types at this bucket by the plotted magnitude.
            const rows = L.visibleTypes
                .map(type => ({ type, value: L.valueAt(type, ts), count: L.countAt(type, ts) }))
                .filter(r => r.value > 0)
                .sort((a, b) => b.value - a.value)
                .slice(0, 4);
            const alertsHere = L.visibleTypes.reduce((s, type) => s + L.countAt(type, ts), 0);
            if (rows.length > 0) {
                document.getElementById('wf-tt-type').textContent = ts.length >= 16 ? ts.substring(11, 19) + ' UTC' : ts;
                document.getElementById('wf-tt-time').textContent = `${rows.length} ACTIVE TYPES / ${alertsHere} ALERT(S)`;
                document.getElementById('wf-tt-count').textContent = rows.map(r => `${r.type}: ${fmtValue(r.value, L.scale)} ${L.scale.unit}`).join(' | ');
                document.getElementById('wf-tt-conn').textContent = `T-${bucketOffsetLabel(L.bucketKeys.length - 1 - idx)} · ${L.basis === 'bandwidth' ? 'INGRESS BANDWIDTH' : 'FLOW VOLUME'}`;
                
                const tipX = mx + 15 + 170 > rect.width ? mx - 180 : mx + 15;
                tooltip.style.left = `${tipX}px`;
                tooltip.style.top = `${my + 15}px`;
                tooltip.style.display = 'flex';
                canvas.style.cursor = 'crosshair';
            } else {
                tooltip.style.display = 'none';
            }
        });
        
        canvas.addEventListener('mouseleave', () => {
            tooltip.style.display = 'none';
            canvas._hairlineIdx = null;
            drawWaterfall();
        });
        
        window.addEventListener('resize', () => {
            if (document.getElementById('spectral-section').style.display !== 'none') {
                drawWaterfall();
            }
        });
    }

    // Live ⇄ simulated overlay toggle (see the mode note in index.html).
    const modeBtn = document.getElementById('btn-wf-mode');
    if (modeBtn) {
        modeBtn.addEventListener('click', () => {
            setSpectralMode(spectralMode === 'simulated' ? 'live' : 'simulated');
        });
    }
    applySpectralModeUI();
    
    // Hook into global refresh interval
    setInterval(updateSpectralWaterfall, 5000);
    updateSpectralWaterfall();
});


// ══════════════════════════════════════════════════════════════════════════════
// ONLINE LEARNING PANEL + ANALYST VERDICTS
// ══════════════════════════════════════════════════════════════════════════════
//
// The detector's adaptive layer reports what it is doing into MongoDB; this panel
// renders that report and nothing else.  Two things follow, and both matter
// because the panel is easy to mistake for a control surface:
//
//   * It never invents a number.  Missing state renders as an explicit gap
//     ("no detector reporting"), not as zeroes that look like measurements.
//   * The verdict buttons are the only writer here.  They post a label; the
//     detector consumes it on its next poll and the effect shows up in this panel
//     on a later sweep -- which is the honest latency of the loop.

let selectedThreat = null;
let verdictInFlight = false;

// Same palette the radar uses for its severity swatches, so the panel cannot end
// up with its own private idea of what "alerting" looks like.
const LEARNING_COLORS = {
    rate: RADAR_SEVERITY_COLORS.High,
    budget: RADAR_SEVERITY_COLORS.Nominal,
    grid: 'rgba(218, 194, 174, 0.25)',
};

function _learnSet(id, text, className) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
    if (className !== undefined) el.className = className;
}

const fmtPct = (v, digits = 2) =>
    (typeof v === 'number' && isFinite(v)) ? `${(v * 100).toFixed(digits)}%` : '--';

const fmtSigned = (v, digits = 3) => {
    if (typeof v !== 'number' || !isFinite(v)) return '--';
    return `${v >= 0 ? '+' : ''}${v.toFixed(digits)}`;
};

function renderLearningPanel(state) {
    const statusEl = document.getElementById('learning-status');
    const op = state.operating_point || {};
    const drift = state.drift || {};
    const cal = state.calibrator || {};
    const fb = state.feedback || {};

    if (state.source !== 'measured') {
        if (statusEl) {
            statusEl.textContent = 'NO DETECTOR';
            statusEl.className = 'px-space-xs py-space-xs bg-surface-container text-outline-variant font-label-sm text-label-sm font-bold';
        }
        ['learn-cut', 'learn-budget', 'learn-drift', 'learn-residual', 'learn-feedback']
            .forEach(id => _learnSet(id, '--'));
        _learnSet('learn-note',
            state.note || state.error ||
            'The detector has not reported any learning state, so there is nothing to show. ' +
            'This is an absence of telemetry, not a detector operating at zero.',
            'text-[10px] text-on-surface-variant leading-snug border-t border-surface-container-highest pt-space-xs');
        drawLearningSparkline([]);
        return;
    }

    const stale = !!state.stale;
    if (statusEl) {
        statusEl.textContent = stale
            ? `STALE ${Math.round(state.age_seconds || 0)}s`
            : 'LIVE';
        statusEl.className = stale
            ? 'px-space-xs py-space-xs bg-primary-container/20 text-primary-container border border-primary-container/40 font-label-sm text-label-sm font-bold'
            : 'px-space-xs py-space-xs bg-secondary/10 text-secondary border border-secondary/40 font-label-sm text-label-sm font-bold';
    }

    const cut = op.threshold, anchor = op.calibrated_threshold, delta = op.threshold_delta;
    _learnSet('learn-cut',
        `${(anchor ?? 0).toFixed(4)} → ${(cut ?? 0).toFixed(4)} (${fmtSigned(delta, 4)})` +
        (op.budget_saturated ? ' · CEILING' : ''),
        'text-on-surface font-bold');

    const bounds = Array.isArray(op.bounds) ? op.bounds : [];
    _learnSet('learn-budget',
        `${fmtPct(op.alert_rate_ema)} / ${fmtPct(op.budget)}` +
        (bounds.length === 2 ? ` · band ${bounds[0].toFixed(4)}–${bounds[1].toFixed(4)}` : ''),
        op.budget_saturated ? 'text-primary-container' : 'text-on-surface');

    const psi = typeof drift.psi === 'number' ? drift.psi : null;
    const ks = typeof drift.ks === 'number' ? drift.ks : null;
    _learnSet('learn-drift',
        `PSI ${psi === null ? '--' : psi.toFixed(3)} · KS ${ks === null ? '--' : ks.toFixed(3)} · ` +
        `${String(drift.verdict || '--').toUpperCase()} · ${drift.reanchors || 0} RE-ANCHORS`,
        drift.verdict === 'stable'
            ? 'text-secondary'
            : (drift.verdict === 'severe' ? 'text-error' : 'text-primary-container'));

    const identity = cal.identity === true;
    _learnSet('learn-residual',
        identity
            ? 'identity (no labels consumed)'
            : `${fmtSigned(cal.mean_shift)} logits mean · cap ±${(cal.max_logit_shift ?? 0).toFixed(1)} · ${cal.updates || 0} updates`,
        identity ? 'text-on-surface-variant' : 'text-on-surface');

    const recorded = state.feedback_total;
    _learnSet('learn-feedback',
        `${fb.learned || 0} consumed` +
        (typeof recorded === 'number' ? ` / ${recorded} recorded` : '') +
        ` · ${fb.nominal_negatives || 0} nominal negatives`,
        'text-on-surface');

    // One plain-English paragraph.  Everything here is a statement about what the
    // layer did, so it is built from the state rather than from the UI's hopes.
    const notes = [];
    notes.push(
        identity
            ? 'Score residual is the identity function: with no analyst verdicts consumed, this detector decides exactly what the frozen model decides.'
            : `Score residual re-ranks flows from ${cal.updates || 0} labels (mean ${fmtSigned(cal.mean_shift)} logits), capped at ±${(cal.max_logit_shift ?? 0).toFixed(1)}.`
    );
    if (op.budget_saturated) {
        notes.push(
            `The ${fmtPct(op.budget)} alert-rate budget is unreachable on this traffic, so the cut is pinned at the top of its band — the ladder above it is preserved on purpose.`
        );
    }
    if ((drift.reanchors || 0) > 0) {
        notes.push(
            `⚠ The score baseline was re-anchored ${drift.reanchors}×, which means the traffic stayed different from the reference long enough to become the new reference: the model is running on a distribution it was not trained on.`
        );
    }
    if (op.anchor_source) notes.push(`Cut anchored to ${op.anchor_source}.`);
    _learnSet('learn-note', notes.join(' '),
        'text-[10px] text-on-surface-variant leading-snug border-t border-surface-container-highest pt-space-xs');

    drawLearningSparkline(Array.isArray(state.history) ? state.history : []);
}

/** Alert rate over time, against the budget it is supposed to hold. */
function drawLearningSparkline(series) {
    const canvas = document.getElementById('learning-canvas');
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    const cssWidth = Math.max(160, canvas.getBoundingClientRect().width || 240);
    const cssHeight = 34;
    canvas.width = Math.round(cssWidth * dpr);
    canvas.height = Math.round(cssHeight * dpr);
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssWidth, cssHeight);

    const points = series
        .map(r => (typeof r.alert_rate === 'number' ? r.alert_rate : null))
        .filter(v => v !== null);
    const budget = series.length && typeof series[series.length - 1].budget === 'number'
        ? series[series.length - 1].budget
        : null;

    ctx.strokeStyle = LEARNING_COLORS.grid;
    ctx.lineWidth = 1;
    ctx.strokeRect(0.5, 0.5, cssWidth - 1, cssHeight - 1);

    if (!points.length) {
        ctx.fillStyle = LEARNING_COLORS.grid;
        ctx.font = '9px "JetBrains Mono", monospace';
        ctx.fillText('no batches observed yet', 6, cssHeight / 2 + 3);
        return;
    }

    const peak = Math.max(budget || 0, ...points, 1e-6) * 1.15;
    const x = i => (points.length === 1 ? cssWidth - 2 : (i / (points.length - 1)) * (cssWidth - 4) + 2);
    const y = v => cssHeight - 3 - (v / peak) * (cssHeight - 8);

    if (budget !== null) {
        ctx.strokeStyle = LEARNING_COLORS.budget;
        ctx.setLineDash([3, 3]);
        ctx.beginPath();
        ctx.moveTo(0, y(budget));
        ctx.lineTo(cssWidth, y(budget));
        ctx.stroke();
        ctx.setLineDash([]);
    }

    ctx.strokeStyle = LEARNING_COLORS.rate;
    ctx.lineWidth = 1.4;
    ctx.beginPath();
    points.forEach((v, i) => { i ? ctx.lineTo(x(i), y(v)) : ctx.moveTo(x(i), y(v)); });
    ctx.stroke();

    canvas.title = `Alert rate per batch (${points.length} batches), dashed = ${fmtPct(budget)} budget`;
}

// A hung API must not stack requests: this panel polls faster than the other
// views, and an unreachable MongoDB can leave a request pending for seconds. One
// in-flight poll at a time keeps the failure mode "stale panel" rather than
// "dozens of pending fetches".
let learningPollInFlight = false;

async function updateLearningPanel() {
    if (learningPollInFlight) return;
    learningPollInFlight = true;
    try {
        const response = await fetch(`${API_BASE}/learning/status?history=120`);
        renderLearningPanel(await response.json());
    } catch (error) {
        renderLearningPanel({ source: 'unavailable', error: `API unreachable: ${error}` });
    } finally {
        learningPollInFlight = false;
    }
}

/**
 * The score a verdict refers to.
 *
 * The online calibrator learns in the model's *raw* score space, so label the raw
 * score when the alert carries one.  `confidence` is the adapted score once the
 * layer has learned something, and feeding that back would be training the layer
 * on its own output.
 */
function scoreForVerdict(threat) {
    if (!threat) return null;
    const raw = (threat.p_attack_raw !== undefined && threat.p_attack_raw !== null)
        ? threat.p_attack_raw
        : threat.confidence;
    return (typeof raw === 'number' && isFinite(raw)) ? raw : null;
}

function resetVerdictControls(threat) {
    verdictInFlight = false;
    const status = document.getElementById('verdict-status');
    if (status) {
        status.textContent = 'NO VERDICT';
        status.className = 'text-primary font-bold';
    }
    const score = scoreForVerdict(threat);
    _learnSet('verdict-hint',
        score === null
            ? 'This contact carries no P(attack) (a Bloom hit is a lookup, not a score), so a verdict on it cannot train the calibrator.'
            : `Labels the raw score P(attack)=${score.toFixed(4)} from ${threat.src_ip || threat.source_ip || 'this source'}. The detector applies it on its next feedback poll.`,
        'text-[10px] text-on-surface-variant leading-snug');
}

async function submitVerdict(verdict) {
    if (verdictInFlight) return;
    if (!selectedThreat) {
        _learnSet('verdict-hint', 'Select an incident first — a verdict needs a source and a score.',
            'text-[10px] text-on-surface-variant leading-snug');
        return;
    }
    const score = scoreForVerdict(selectedThreat);
    if (score === null) {
        resetVerdictControls(selectedThreat);
        return;
    }

    verdictInFlight = true;
    try {
        const response = await fetch(`${API_BASE}/feedback`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                src_ip: selectedThreat.src_ip || selectedThreat.source_ip,
                p_attack: score,
                p_bot: (typeof selectedThreat.p_bot === 'number') ? selectedThreat.p_bot : undefined,
                attack_type: selectedThreat.attack_type,
                verdict,
                source: 'analyst',
            }),
        });
        const data = await response.json();
        const status = document.getElementById('verdict-status');
        if (data.ok) {
            if (status) {
                status.textContent = verdict === 'confirmed' ? 'CONFIRMED · QUEUED' : 'FALSE POSITIVE · QUEUED';
                status.className = verdict === 'confirmed'
                    ? 'text-secondary font-bold'
                    : 'text-error font-bold';
            }
            _learnSet('verdict-hint',
                'Stored. The detector consumes it within one feedback poll; the panel above updates on its next sweep.',
                'text-[10px] text-on-surface-variant leading-snug');
            setTimeout(updateLearningPanel, 1200);
        } else if (status) {
            status.textContent = 'REJECTED';
            status.className = 'text-error font-bold';
            _learnSet('verdict-hint', data.error || 'The API rejected this verdict.',
                'text-[10px] text-error leading-snug');
        }
    } catch (error) {
        _learnSet('verdict-hint', `Could not reach the API: ${error}`,
            'text-[10px] text-error leading-snug');
    } finally {
        verdictInFlight = false;
    }
}

document.addEventListener('DOMContentLoaded', function () {
    const confirmBtn = document.getElementById('btn-verdict-confirm');
    const fpBtn = document.getElementById('btn-verdict-fp');
    if (confirmBtn) confirmBtn.addEventListener('click', () => submitVerdict('confirmed'));
    if (fpBtn) fpBtn.addEventListener('click', () => submitVerdict('false_positive'));

    updateLearningPanel();
    setInterval(updateLearningPanel, 5000);
});
