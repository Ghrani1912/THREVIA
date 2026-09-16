/* ============================================================================
 * THREVIA — Phase 5 Network Topology
 * Attacker-centred subgraph view for the SOC dashboard
 * ============================================================================
 *
 * Why subgraphs and not "top 100 nodes by danger score"
 * -----------------------------------------------------
 * A node's danger score is meaningless in isolation. An attacker connected to
 * 40 peers in a tight cluster is a coordinated campaign; the same attacker
 * alone is a red dot. Cutting the graph by score severs exactly the edges that
 * made the pattern visible, so selection here is STRUCTURAL:
 *
 *   Level 0 (default)  malicious communities (top-K by severity), fully intact
 *                      ∪ every is_attacker node
 *                      ∪ every node directly connected to an attacker
 *                      → normal traffic with no attacker path is not drawn
 *
 *   Level 1 (on click) unfold a node's neighbourhood, even outside the
 *                      default set — "who else is this attacker talking to?"
 *
 *   Level 2 (explicit) the whole graph as a sampled, dimmed, structure-only
 *                      macro view (never meant to be read node-by-node)
 *
 * Scale inside a view is handled by collapsing peripheral peers of a large
 * cluster into a single "+N peers" aggregate that expands on click, by
 * defaulting the edge lens to has_attack edges only, and by tying the label
 * budget to how much is actually rendered.
 *
 * Data: GET /api/v1/graph/view?scope=threat|full&k=N   (normalised subgraph)
 *       GET /api/v1/graph/ego/{ip}                     (1-hop expansion)
 * ========================================================================== */
(function () {
  'use strict';

  var API = (typeof API_BASE !== 'undefined' && API_BASE) ? API_BASE : 'http://localhost:8000/api/v1';

  /* ── Palette (mirrors the Tailwind tokens in index.html) ─────────────────── */
  var COL = {
    attacker: '#ffb4ab',
    attackerFill: 'rgba(255,180,171,0.42)',
    peer: '#ff9e1b',
    peerFill: 'rgba(255,158,27,0.30)',
    benign: '#38bdf8',
    benignFill: 'rgba(56,189,248,0.28)',
    agg: '#dac2ae',
    aggFill: 'rgba(218,194,174,0.32)',
    edgeAttack: '#ff7373',
    edgeNormal: '#3a4a42',
    sel: '#ffc58a',
    label: '#e1e3e1'
  };

  var GREEK = ['Γ', 'Δ', 'Θ', 'Λ', 'Ξ', 'Π', 'Σ', 'Φ', 'Ψ', 'Ω', 'α', 'β', 'γ', 'δ', 'ε', 'ζ'];

  /* ── Tunables ────────────────────────────────────────────────────────────── */
  var CFG = {
    collapseOver: 40,      // a cluster bigger than this collapses its periphery
    collapseMin: 3,        // ...but never collapse fewer than this
    crowdedOver: 70,       // only collapse at all once the view is this busy
    labelAllUpTo: 42,      // small views label everything
    labelHardMax: 16,
    labelMinDanger: 45,    // in a crowded view, only label above this percentile
    minZoom: 0.22,
    maxZoom: 3.4,
    springLen: 104,
    springK: 0.055,
    repulse: 7200,
    anchorK: 0.014,
    damping: 0.86,
    alphaDecay: 0.972,
    alphaMin: 0.015
  };

  /* ── State ───────────────────────────────────────────────────────────────── */
  var S = {
    ready: false,
    loaded: false,
    scope: 'threat',
    k: 3,
    macro: false,
    detail: 'auto',            // 'auto' | 'full'
    edgeMode: 'attack',        // 'attack' | 'all'
    sevFilter: 'all',
    layout: 'force',           // 'force' | 'radial'

    nodes: new Map(),          // id -> node
    edges: [],                 // normalised edges
    adj: new Map(),            // id -> [{ id, edge }]
    comms: new Map(),          // community_id -> community
    meta: {},

    baseNodes: [], baseEdges: [], baseComms: [],
    extraNodes: new Map(), extraEdges: new Map(), extraComms: [],

    revealed: new Set(),       // nodes explicitly unfolded by the analyst
    selected: null,
    hovered: null,

    clusters: [],              // [{ cid, name, comm, nodes, anchor }]
    anchors: new Map(),        // community_id -> { nx, ny } (normalised)
    drawn: [],                 // visible nodes this frame (incl. aggregates)
    drawnEdges: [],
    agg: new Map(),            // community_id -> [{id,count}]

    alpha: 1,
    ticks: 0,
    t: 0,
    zoom: 1, panX: 0, panY: 0,
    fitPending: true, camTouched: false, settled: false,
    panOn: true, frozen: false,
    dragging: false, dragNode: null, dragMoved: false, dragStart: null,
    lastMouse: { x: 0, y: 0 },
    dpr: 1,
    w: 0, h: 0,
    level: 0
  };

  /* ── Small helpers ───────────────────────────────────────────────────────── */
  function $(id) { return document.getElementById(id); }
  function clamp(v, a, b) { return v < a ? a : (v > b ? b : v); }
  function fmt(n) {
    if (n === null || n === undefined || isNaN(n)) return '—';
    return Number(n).toLocaleString('en-US');
  }
  function fmtFlow(n) {
    n = Number(n) || 0;
    if (n >= 1e9) return (n / 1e9).toFixed(2) + 'B';
    if (n >= 1e6) return (n / 1e6).toFixed(2) + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k';
    return String(n);
  }
  function fmtBytes(n) {
    n = Number(n) || 0;
    if (n >= 1e9) return (n / 1e9).toFixed(2) + ' GB';
    if (n >= 1e6) return (n / 1e6).toFixed(1) + ' MB';
    if (n >= 1e3) return (n / 1e3).toFixed(1) + ' KB';
    return n + ' B';
  }
  function short(ip) {
    if (!ip) return '—';
    if (ip.length <= 20) return ip;
    return ip.slice(0, 18) + '…';
  }
  function greek(i) { return GREEK[((i % GREEK.length) + GREEK.length) % GREEK.length]; }

  /* ══════════════════════════════════════════════════════════════════════════
   * 1. DATA
   * ══════════════════════════════════════════════════════════════════════════ */

  function normNode(raw) {
    var id = String(raw.id || raw.ip || '').replace(/\uFEFF/g, '').trim();
    if (!id) return null;
    var cats = raw.attack_cats || [];
    return {
      id: id,
      is_attacker: !!(raw.is_attacker),
      community_id: (raw.community_id === null || raw.community_id === undefined) ? -1 : raw.community_id,
      community_malicious: !!(raw.community_malicious),
      malicious_neighbor: !!(raw.malicious_neighbor),
      pagerank: Number(raw.pagerank) || 0,
      danger_score: Number(raw.danger_score) || 0,
      danger_index: Number(raw.danger_index) || 0,
      danger_rank: raw.danger_rank || null,
      in_degree: Number(raw.in_degree) || 0,
      out_degree: Number(raw.out_degree) || 0,
      degree: Number(raw.degree) || (Number(raw.in_degree || 0) + Number(raw.out_degree || 0)),
      total_flows: Number(raw.total_flows) || 0,
      attack_cats: Array.isArray(cats) ? cats : [],
      label_class: raw.label_class || (raw.is_attacker ? 'ATTACKER' : 'NORMAL'),
      x: null, y: null, vx: 0, vy: 0, pinned: false
    };
  }

  function normEdge(raw) {
    var s = String(raw.source || raw.src_ip || '').replace(/\uFEFF/g, '').trim();
    var t = String(raw.target || raw.dst_ip || '').replace(/\uFEFF/g, '').trim();
    if (!s || !t || s === t) return null;
    return {
      source: s,
      target: t,
      has_attack: !!(raw.has_attack),
      weight: Number(raw.weight) || 1,
      total_bytes: Number(raw.total_bytes) || 0,
      attack_cats: raw.attack_cats || [],
      proto_counts: raw.proto_counts || {}
    };
  }

  function normComm(raw) {
    var cid = (raw.community_id === null || raw.community_id === undefined) ? -1 : raw.community_id;
    return {
      community_id: cid,
      size: Number(raw.size) || 0,
      attacker_count: Number(raw.attacker_count) || 0,
      attacker_ips: raw.attacker_ips || [],
      internal_edges: Number(raw.internal_edges) || 0,
      attack_cats: raw.attack_cats || [],
      is_malicious: !!raw.is_malicious,
      attack_edges: Number(raw.attack_edges) || 0,
      attack_bytes: Number(raw.attack_bytes) || 0,
      selected: !!raw.selected,
      drawn_nodes: Number(raw.drawn_nodes) || 0,
      synthetic: !!raw.synthetic
    };
  }

  function getJSON(url) {
    return fetch(url).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status + ' ' + r.statusText);
      return r.json();
    });
  }

  function setStatus(kind, msg, detail) {
    var overlay = $('topo-status-overlay');
    if (!overlay) return;
    if (kind === 'hide') { overlay.style.display = 'none'; return; }
    overlay.style.display = 'flex';
    var first = overlay.querySelector('span');
    if (first) {
      first.textContent = msg;
      first.className = kind === 'error'
        ? 'font-label-md text-label-md text-error font-bold px-space-md text-center'
        : 'font-label-md text-label-md text-primary animate-pulse';
    }
    var d = $('topo-status-detail');
    if (d) d.textContent = detail || '';
  }

  function loadView(scope, k) {
    setStatus('loading', '⟳ LOADING ATTACKER-CENTRED SUBGRAPH …',
      'GET /api/v1/graph/view?scope=' + scope + '&k=' + k);
    return getJSON(API + '/graph/view?scope=' + scope + '&k=' + k)
      .then(function (payload) {
        if (payload.error) throw new Error(payload.error);
        S.scope = payload.scope || scope;
        S.macro = S.scope === 'full';
        S.baseNodes = payload.nodes || [];
        S.baseEdges = payload.edges || [];
        S.baseComms = payload.communities || [];
        S.meta = payload.metadata || {};
        S.extraNodes = new Map();
        S.extraEdges = new Map();
        S.extraComms = [];
        S.revealed = new Set();
        S.selected = null;
        S.level = S.macro ? 2 : 0;
        S.comms = new Map();
        S.anchors = new Map();
        S.fitPending = true;
        S.settled = false;
        S.camTouched = false;
        rebuild(0);
        S.loaded = true;
        setLevel();
        setStatus('hide');
        if (!S.drawn.length) {
          setStatus('error', '✗ NO MALICIOUS CLUSTERS IN THE CURRENT GRAPH',
            'graph_communities has no is_malicious=true rows — build the graph first: python backend/graph/run_phase5.py all');
        }
      })
      .catch(function (err) {
        S.loaded = S.loaded || false;
        setStatus('error', '✗ TOPOLOGY FEED UNAVAILABLE — ' + err.message,
          'Expected ' + API + '/graph/view. Start the API (start_dashboard.ps1) and build the graph: python backend/graph/run_phase5.py all');
      });
  }

  function fetchEgo(ip) {
    return getJSON(API + '/graph/ego/' + encodeURIComponent(ip))
      .then(function (payload) {
        if (payload.error) return { found: false, error: payload.error };
        if (!payload.found) return { found: false };
        var added = 0;
        (payload.nodes || []).forEach(function (raw) {
          var n = normNode(raw);
          if (!n) return;
          if (!S.nodes.has(n.id)) added++;
          S.extraNodes.set(n.id, n);
        });
        (payload.edges || []).forEach(function (raw) {
          var e = normEdge(raw);
          if (!e) return;
          S.extraEdges.set(e.source + '|' + e.target, e);
        });
        (payload.communities || []).forEach(function (raw) {
          S.extraComms.push(normComm(raw));
        });
        return { found: true, added: added };
      })
      .catch(function (err) { return { found: false, error: err.message }; });
  }

  /* ══════════════════════════════════════════════════════════════════════════
   * 2. MODEL — default set, aggregation, danger ranking
   * ══════════════════════════════════════════════════════════════════════════ */

  /**
   * Carry a node's laid-out position across rebuilds. Without this every
   * rebuild (unfold, filter change, lens toggle) would teleport the whole
   * graph, which destroys the analyst's spatial memory of the cluster.
   */
  function carryPosition(n, old) {
    if (!old) return n;
    n.x = old.x;
    n.y = old.y;
    n.vx = old.vx;
    n.vy = old.vy;
    n.pinned = old.pinned;
    return n;
  }

  function rebuild(resetLayout) {
    // ── Nodes: server subgraph + anything pulled in by expansion ─────────────
    var prev = S.nodes;
    S.nodes = new Map();
    S.baseNodes.forEach(function (raw) {
      var n = normNode(raw);
      if (n) S.nodes.set(n.id, carryPosition(n, prev.get(n.id)));
    });
    S.extraNodes.forEach(function (n, id) {
      var existing = S.nodes.get(id);
      if (existing) { // merge: keep the richest attacker/community flags
        existing.is_attacker = existing.is_attacker || n.is_attacker;
        existing.malicious_neighbor = existing.malicious_neighbor || n.malicious_neighbor;
        existing.community_malicious = existing.community_malicious || n.community_malicious;
        return;
      }
      S.nodes.set(id, carryPosition(n, prev.get(id)));
    });

    // ── Edges (deduped, endpoints must exist) ────────────────────────────────
    var seen = new Set();
    S.edges = [];
    function pushEdge(e) {
      if (!e || !S.nodes.has(e.source) || !S.nodes.has(e.target)) return;
      var key = e.source + '|' + e.target;
      if (seen.has(key)) return;
      seen.add(key);
      S.edges.push(e);
    }
    S.baseEdges.forEach(function (raw) { pushEdge(normEdge(raw)); });
    S.extraEdges.forEach(function (e) { pushEdge(e); });

    // ── Adjacency (undirected for exploration) ───────────────────────────────
    S.adj = new Map();
    S.nodes.forEach(function (n) { S.adj.set(n.id, []); });
    S.edges.forEach(function (e) {
      S.adj.get(e.source).push({ id: e.target, edge: e, out: true });
      S.adj.get(e.target).push({ id: e.source, edge: e, out: false });
    });

    // ── Communities ──────────────────────────────────────────────────────────
    S.comms = new Map();
    S.baseComms.map(normComm).forEach(function (c) { S.comms.set(c.community_id, c); });
    (S.extraComms || []).forEach(function (c) {
      if (!S.comms.has(c.community_id)) S.comms.set(c.community_id, c);
    });

    // Membership from the nodes actually loaded (a community doc may cover more)
    S.members = new Map();
    S.nodes.forEach(function (n) {
      if (!S.members.has(n.community_id)) S.members.set(n.community_id, []);
      S.members.get(n.community_id).push(n.id);
      if (!S.comms.has(n.community_id)) {
        S.comms.set(n.community_id, {
          community_id: n.community_id, size: 0, attacker_count: 0, attacker_ips: [],
          internal_edges: 0, attack_cats: [], is_malicious: !!n.community_malicious,
          attack_edges: 0, attack_bytes: 0, selected: false, drawn_nodes: 0, synthetic: true
        });
      }
    });

    // ── Danger percentile within the loaded subgraph ─────────────────────────
    var ranked = Array.from(S.nodes.values()).sort(function (a, b) { return a.danger_score - b.danger_score; });
    ranked.forEach(function (n, i) {
      n.danger_percentile = ranked.length > 1 ? (i / (ranked.length - 1)) * 100 : 100;
      n.danger_index = Math.round(n.danger_percentile);
    });

    assignClusterNames();
    computeDrawable();
    if (resetLayout !== 'keep') {
      var fresh = seedPositions();
      if (fresh) S.fitPending = true;
    } else {
      warmSolver();
    }
    updateSummary();
    updateLegend();
  }

  function assignClusterNames() {
    var severe = [];
    S.comms.forEach(function (c) { if (c.is_malicious) severe.push(c); });
    severe.sort(function (a, b) {
      return (b.attacker_count - a.attacker_count) || (b.attack_edges - a.attack_edges) || (b.size - a.size);
    });
    severe.forEach(function (c, i) { c.name = 'Cluster-' + greek(i); });
    var benign = [];
    S.comms.forEach(function (c) { if (!c.is_malicious) benign.push(c); });
    benign.sort(function (a, b) { return b.size - a.size; });
    benign.forEach(function (c, i) { c.name = 'NET-' + String(c.community_id).padStart(2, '0') + greek(i).toLowerCase(); });
  }

  /** Severity class derived from structure, never from a bare score. */
  function sevOf(n) {
    if (n.type === 'aggregate') return 'warn';
    if (n.is_attacker) return 'crit';
    if (n.community_malicious) return 'warn';
    return 'clean';
  }

  /**
   * The default render set:
   *   malicious clusters (selected) ∪ attackers ∪ 1-hop neighbours of attackers
   * plus anything the analyst has explicitly unfolded.
   */
  function computeDrawable() {
    var visible = new Set();

    if (S.macro) {
      // Level 2 — everything loaded, drawn as structure only.
      S.nodes.forEach(function (n, id) { visible.add(id); });
    } else {
      S.nodes.forEach(function (n, id) {
        if (n.is_attacker) visible.add(id);
        if (n.malicious_neighbor) visible.add(id);
        var c = S.comms.get(n.community_id);
        if (c && c.is_malicious && c.selected) visible.add(id);
        if (S.revealed.has(id)) visible.add(id);
      });
    }

    // Severity lens
    if (S.sevFilter !== 'all') {
      var kept = new Set();
      visible.forEach(function (id) { if (sevOf(S.nodes.get(id)) === S.sevFilter) kept.add(id); });
      visible = kept;
    }

    // ── Collapse peripheral peers of big clusters into "+N peers" ────────────
    // Structural (always drawn individually): confirmed attackers, anything the
    // analyst unfolded, and peers pulled in from *benign* nets — those are the
    // "who else is this attacker talking to?" discoveries. The unflagged bulk of
    // a large cluster is what gets collapsed, once the cluster is big enough to
    // become a hairball.
    S.agg = new Map();
    var structural = new Set();
    visible.forEach(function (id) {
      var n = S.nodes.get(id);
      if (n.is_attacker || S.revealed.has(id) || id === S.selected) { structural.add(id); return; }
      var comm = S.comms.get(n.community_id);
      if (!comm || !comm.is_malicious) structural.add(id);
    });

    var collapsible = (S.detail !== 'full') && (visible.size > CFG.crowdedOver) && !S.macro;
    var collapsed = new Map();     // id -> aggregate id
    if (collapsible) {
      var byComm = new Map();
      visible.forEach(function (id) {
        var n = S.nodes.get(id);
        if (structural.has(id)) return;
        if (!byComm.has(n.community_id)) byComm.set(n.community_id, []);
        byComm.get(n.community_id).push(id);
      });
      byComm.forEach(function (ids, cid) {
        var membersInView = (S.members.get(cid) || []).filter(function (m) { return visible.has(m); }).length;
        if (membersInView <= CFG.collapseOver || ids.length < CFG.collapseMin) return;
        var aggId = 'agg:' + cid;
        S.agg.set(cid, { id: aggId, cid: cid, count: ids.length, members: ids.slice() });
        ids.forEach(function (id) { collapsed.set(id, aggId); });
      });
    }

    // ── Materialise drawn nodes ─────────────────────────────────────────────
    // Aggregate nodes are rebuilt from scratch each time, so salvage the
    // previous one's position when the bucket is unchanged.
    var prevAgg = new Map();
    S.drawn.forEach(function (n) { if (n.type === 'aggregate') prevAgg.set(n.community_id, n); });

    S.drawn = [];
    var aggNodes = new Map();
    S.agg.forEach(function (bucket, cid) {
      var comm = S.comms.get(cid) || {};
      var node = {
        id: bucket.id, type: 'aggregate', community_id: cid, count: bucket.count,
        members: bucket.members, is_attacker: false,
        malicious_neighbor: false, community_malicious: !!comm.is_malicious,
        danger_score: 0, danger_index: 30, pagerank: 0, degree: bucket.count,
        in_degree: 0, out_degree: 0, total_flows: 0, attack_cats: comm.attack_cats || [],
        label_class: 'PERIPHERAL PEERS',
        x: null, y: null, vx: 0, vy: 0, pinned: false
      };
      var old = prevAgg.get(cid);
      if (old && old.count === bucket.count) {
        node.x = old.x; node.y = old.y; node.vx = old.vx; node.vy = old.vy; node.pinned = old.pinned;
      }
      aggNodes.set(bucket.id, node);
      S.drawn.push(node);
      seedPosition(node);
    });
    visible.forEach(function (id) {
      if (collapsed.has(id)) return;
      var n = S.nodes.get(id);
      if (n) S.drawn.push(n);
    });

    // ── Materialise drawn edges (folding collapsed nodes onto aggregates) ───
    var edgeMap = new Map();
    S.edges.forEach(function (e) {
      var a = collapsed.get(e.source) || e.source;
      var b = collapsed.get(e.target) || e.target;
      if (a === b) return;
      if (!aggNodes.has(a) && !visible.has(a)) return;
      if (!aggNodes.has(b) && !visible.has(b)) return;
      if (S.edgeMode === 'attack' && !e.has_attack) return;
      var key = a + '|' + b;
      var acc = edgeMap.get(key);
      if (!acc) {
        acc = { source: a, target: b, has_attack: false, weight: 0, total_bytes: 0, attack_cats: [] };
        edgeMap.set(key, acc);
      }
      acc.weight += e.weight;
      acc.total_bytes += e.total_bytes;
      acc.has_attack = acc.has_attack || e.has_attack;
      if (e.attack_cats && acc.attack_cats.length < 6) {
        e.attack_cats.forEach(function (c) { if (acc.attack_cats.indexOf(c) < 0) acc.attack_cats.push(c); });
      }
    });
    S.drawnEdges = Array.from(edgeMap.values());

    buildClusters();
  }

  function buildClusters() {
    var byComm = new Map();
    S.drawn.forEach(function (n) {
      if (!byComm.has(n.community_id)) byComm.set(n.community_id, []);
      byComm.get(n.community_id).push(n);
    });
    var list = [];
    byComm.forEach(function (nodes, cid) {
      var comm = S.comms.get(cid) || { community_id: cid, is_malicious: false, size: nodes.length, name: 'NET-' + cid };
      list.push({ cid: cid, comm: comm, nodes: nodes, name: comm.name || ('NET-' + cid) });
    });
    list.sort(function (a, b) {
      return (Number(b.comm.is_malicious) - Number(a.comm.is_malicious)) || (b.nodes.length - a.nodes.length);
    });
    S.clusters = list;
    placeAnchors();
  }

  /**
   * The layout extent tracks the canvas size and the node count, so a small
   * view never ends up zoomed out to an unreadable speck field and a large one
   * is not crammed into the viewport.
   */
  function computeExtent() {
    var n = Math.max(S.drawn.length, 10);
    var grow = Math.sqrt(n / 16);
    S.extent = {
      w: Math.max(S.w || 720, 520) * 1.12 * grow,
      h: Math.max(S.h || 560, 420) * 1.12 * grow
    };
    return S.extent;
  }

  /**
   * Phyllotaxis spread — even 2D separation for any cluster count, and never a
   * collapsed line. Anchors are stored normalised and keyed by community id so
   * a cluster keeps the same home for the whole session (stable mental map),
   * while still scaling when the layout extent changes.
   */
  function placeAnchors() {
    var ext = S.extent || computeExtent();
    var golden = 2.39996323;
    S.clusters.forEach(function (cl) {
      var a = S.anchors.get(cl.cid);
      if (!a) {
        var k = S.anchors.size;
        if (S.clusters.length <= 1) {
          a = { nx: 0.5, ny: 0.5 };
        } else {
          var t = Math.min(1, (k + 0.5) / 8);
          var ang = k * golden - Math.PI / 2;
          a = {
            nx: 0.5 + Math.cos(ang) * 0.36 * Math.sqrt(t),
            ny: 0.5 + Math.sin(ang) * 0.36 * Math.sqrt(t)
          };
        }
        S.anchors.set(cl.cid, a);
      }
      cl.anchor = { x: a.nx * ext.w, y: a.ny * ext.h };
    });
  }

  function clusterOf(cid) {
    for (var i = 0; i < S.clusters.length; i++) {
      if (S.clusters[i].cid === cid) return S.clusters[i];
    }
    return null;
  }

  function seedPosition(node) {
    if (node.x !== null && node.y !== null) return;
    var ext = S.extent || computeExtent();
    var cl = clusterOf(node.community_id);
    var a = cl && cl.anchor ? cl.anchor : { x: ext.w / 2, y: ext.h / 2 };
    var spread = node.type === 'aggregate' ? 60 : 130;
    node.x = a.x + (Math.random() - 0.5) * spread;
    node.y = a.y + (Math.random() - 0.5) * spread;
    node.vx = 0; node.vy = 0;
  }

  function seedPositions() {
    // Anchors are stable for the life of a load — clearing them here would
    // strand already-laid-out nodes away from a newly seeded aggregate.
    placeAnchors();
    computeExtent();
    var fresh = S.drawn.filter(function (n) { return n.x === null || n.y === null; }).length;
    S.drawn.forEach(seedPosition);
    S.alpha = 1;
    S.ticks = 0;
    if (S.layout === 'radial') applyRadial();
    return fresh;
  }

  /** Newly unfolded nodes need the solver to run again, even on a 'keep' rebuild. */
  function warmSolver() {
    computeExtent();
    var fresh = 0;
    S.drawn.forEach(function (n) {
      if (n.x === null || n.y === null) { seedPosition(n); fresh++; }
    });
    if (fresh) S.alpha = Math.max(S.alpha, 0.5);
    if (S.layout === 'radial') applyRadial();
  }

  /* ══════════════════════════════════════════════════════════════════════════
   * 3. LAYOUT
   * ══════════════════════════════════════════════════════════════════════════ */

  function applyRadial() {
    var ext = S.extent || computeExtent();
    var cx = ext.w / 2, cy = ext.h / 2;
    var baseR = Math.min(ext.w, ext.h) * 0.40;
    S.clusters.forEach(function (cl, ci) {
      var ang = (ci / Math.max(S.clusters.length, 1)) * Math.PI * 2 - Math.PI / 2;
      var ox = cx + Math.cos(ang) * baseR * (cl.comm.is_malicious ? 0.85 : 1.05);
      var oy = cy + Math.sin(ang) * baseR * (cl.comm.is_malicious ? 0.85 : 1.05);
      var ordered = cl.nodes.slice().sort(function (a, b) { return (b.danger_index || 0) - (a.danger_index || 0); });
      ordered.forEach(function (n, i) {
        var t = (i + 1) / (ordered.length + 1);
        var a2 = ang + t * Math.PI * 1.15 - Math.PI * 0.575;
        var r = 26 + 150 * t;
        n.x = ox + Math.cos(a2) * r;
        n.y = oy + Math.sin(a2) * r;
        n.vx = n.vy = 0;
      });
    });
  }

  function stepLayout() {
    if (S.frozen || S.alpha < CFG.alphaMin || S.layout !== 'force') return;
    var alpha = S.alpha;
    var nodes = S.drawn;
    if (nodes.length < 2) { S.alpha = 0; return; }

    // ── grid-bucketed repulsion (keeps 1000+ nodes affordable) ───────────────
    var cell = 78;
    var grid = new Map();
    nodes.forEach(function (n) {
      var key = Math.floor(n.x / cell) + ',' + Math.floor(n.y / cell);
      if (!grid.has(key)) grid.set(key, []);
      grid.get(key).push(n);
    });
    var f = new Map();
    nodes.forEach(function (n) { f.set(n.id, { x: 0, y: 0 }); });

    nodes.forEach(function (n) {
      var gx = Math.floor(n.x / cell), gy = Math.floor(n.y / cell);
      for (var i = -1; i <= 1; i++) {
        for (var j = -1; j <= 1; j++) {
          var bucket = grid.get((gx + i) + ',' + (gy + j));
          if (!bucket) continue;
          for (var k = 0; k < bucket.length; k++) {
            var m = bucket[k];
            if (m === n) continue;
            var dx = n.x - m.x, dy = n.y - m.y;
            var d2 = dx * dx + dy * dy;
            if (d2 < 1) { d2 = 1; dx = (Math.random() - 0.5); dy = (Math.random() - 0.5); }
            if (d2 > 26000) continue;          // ~160px cutoff
            var force = CFG.repulse / d2;
            var d = Math.sqrt(d2);
            f.get(n.id).x += (dx / d) * force;
            f.get(n.id).y += (dy / d) * force;
          }
        }
      }
    });

    // ── springs along drawn edges ───────────────────────────────────────────
    // Averaged per node instead of summed: an attacker wired to 40 peers must
    // not be crushed into the centroid by 40x the spring force of a leaf node.
    var byId = new Map();
    nodes.forEach(function (n) { byId.set(n.id, n); });
    var springs = new Map();
    function spring(id) {
      var s = springs.get(id);
      if (!s) { s = { x: 0, y: 0, n: 0 }; springs.set(id, s); }
      return s;
    }
    S.drawnEdges.forEach(function (e) {
      var a = byId.get(e.source), b = byId.get(e.target);
      if (!a || !b) return;
      var dx = b.x - a.x, dy = b.y - a.y;
      var d = Math.sqrt(dx * dx + dy * dy) || 1;
      var target = CFG.springLen + (e.has_attack ? -18 : 12);
      var k = CFG.springK * (1 + Math.min(Math.log1p(e.weight) * 0.12, 0.9));
      var move = (d - target) * k;
      var ux = dx / d, uy = dy / d;
      var sa = spring(a.id), sb = spring(b.id);
      sa.x += ux * move; sa.y += uy * move; sa.n++;
      sb.x -= ux * move; sb.y -= uy * move; sb.n++;
    });
    springs.forEach(function (s, id) {
      var fc = f.get(id);
      if (!fc) return;
      fc.x += s.x / Math.max(s.n, 1);
      fc.y += s.y / Math.max(s.n, 1);
    });

    // ── cluster gravity: keeps each campaign visually distinct ──────────────
    nodes.forEach(function (n) {
      var cl = clusterOf(n.community_id);
      if (!cl || !cl.anchor) return;
      var fc = f.get(n.id);
      fc.x += (cl.anchor.x - n.x) * CFG.anchorK * (n.type === 'aggregate' ? 1.6 : 1);
      fc.y += (cl.anchor.y - n.y) * CFG.anchorK * (n.type === 'aggregate' ? 1.6 : 1);
    });

    // ── integrate ───────────────────────────────────────────────────────────
    var ext = S.extent || computeExtent();
    nodes.forEach(function (n) {
      if (n.pinned) { n.vx = n.vy = 0; return; }
      var fc = f.get(n.id);
      n.vx = (n.vx + fc.x * alpha) * CFG.damping;
      n.vy = (n.vy + fc.y * alpha) * CFG.damping;
      var speed = Math.sqrt(n.vx * n.vx + n.vy * n.vy);
      var cap = 26;
      if (speed > cap) { n.vx = (n.vx / speed) * cap; n.vy = (n.vy / speed) * cap; }
      n.x = clamp(n.x + n.vx, 40, ext.w - 40);
      n.y = clamp(n.y + n.vy, 40, ext.h - 40);
    });

    S.alpha *= CFG.alphaDecay;
    S.ticks++;
  }

  function fitView() {
    var nodes = S.drawn;
    if (!nodes.length || !S.w || !S.h) return;
    var minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    nodes.forEach(function (n) {
      if (n.x < minX) minX = n.x;
      if (n.y < minY) minY = n.y;
      if (n.x > maxX) maxX = n.x;
      if (n.y > maxY) maxY = n.y;
    });
    var bw = Math.max(maxX - minX, 120), bh = Math.max(maxY - minY, 120);

    // Frame inside the area that the HUD overlays do not cover.
    var padX = 26, padTop = 124, padBottom = 84;
    var availW = Math.max(S.w - 2 * padX, 160);
    var availH = Math.max(S.h - padTop - padBottom, 140);
    var target = Math.min(availW / (bw + 130), availH / (bh + 130));

    // Never frame so far out that nodes become unreadable specks.
    target = clamp(target, 0.42, 1.5);
    S.zoom = target;
    S.panX = S.w / 2 - ((minX + maxX) / 2) * target;
    S.panY = padTop + availH / 2 - ((minY + maxY) / 2) * target;
  }

  function centerOn(node, zoom) {
    if (!node || !S.w) return;
    if (zoom) S.zoom = clamp(zoom, CFG.minZoom, CFG.maxZoom);
    S.panX = S.w / 2 - node.x * S.zoom;
    S.panY = S.h / 2 - node.y * S.zoom;
  }

  /* ══════════════════════════════════════════════════════════════════════════
   * 4. RENDER
   * ══════════════════════════════════════════════════════════════════════════ */

  var canvas = null, ctx = null;
  var labelRects = [];

  function resizeCanvas() {
    if (!canvas) return;
    var rect = canvas.parentElement.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    S.dpr = window.devicePixelRatio || 1;
    S.w = rect.width;
    S.h = rect.height;
    canvas.width = Math.round(rect.width * S.dpr);
    canvas.height = Math.round(rect.height * S.dpr);
    if (S.drawn.length) { computeExtent(); S.alpha = Math.max(S.alpha, 0.35); S.fitPending = true; }
  }

  function radiusOf(n) {
    if (n.type === 'aggregate') return 13 + clamp(Math.log1p(n.count) * 3.2, 0, 9);
    if (n.is_attacker) return 9 + clamp(n.danger_index / 100 * 6, 0, 6);
    return 4.5 + clamp(n.danger_index / 100 * 5, 0, 5);
  }

  /** Never let a node shrink below ~3.6 screen px, so a zoomed-out view stays
   *  readable and every node stays clickable. */
  function effRadius(n) {
    var r = radiusOf(n);
    return Math.max(r, 3.6 / Math.max(S.zoom, 0.02));
  }

  function labelSet() {
    var set = new Set();
    var total = S.drawn.length;
    if (total <= CFG.labelAllUpTo) {
      S.drawn.forEach(function (n) { set.add(n.id); });
      return set;
    }
    S.drawn.forEach(function (n) {
      if (n.is_attacker || n.id === S.selected || n.id === S.hovered || n.type === 'aggregate') set.add(n.id);
    });
    var rest = S.drawn.filter(function (n) { return !set.has(n.id); })
      .sort(function (a, b) { return b.danger_index - a.danger_index; });
    for (var i = 0; i < rest.length; i++) {
      if (set.size >= CFG.labelHardMax) break;
      if (rest[i].danger_index >= CFG.labelMinDanger) set.add(rest[i].id);
    }
    return set;
  }

  function strokeFor(comm) {
    if (!comm || comm.is_malicious) return [];       // solid
    return [5, 4];                                    // dashed for benign nets
  }

  function draw() {
    if (!ctx) return;
    ctx.setTransform(S.dpr, 0, 0, S.dpr, 0, 0);
    ctx.clearRect(0, 0, S.w, S.h);
    if (!S.w || !S.h) return;

    var macro = S.macro;
    ctx.save();
    ctx.translate(S.panX, S.panY);
    ctx.scale(S.zoom, S.zoom);

    var byId = new Map();
    S.drawn.forEach(function (n) { byId.set(n.id, n); });

    // ── cluster islands ─────────────────────────────────────────────────────
    S.clusters.forEach(function (cl) {
      if (!cl.nodes.length) return;
      var cx = 0, cy = 0;
      cl.nodes.forEach(function (n) { cx += n.x; cy += n.y; });
      cx /= cl.nodes.length; cy /= cl.nodes.length;
      var maxR = 0;
      cl.nodes.forEach(function (n) {
        var d = Math.hypot(n.x - cx, n.y - cy);
        if (d > maxR) maxR = d;
      });
      var r = maxR + 34;
      var stroke = cl.comm.is_malicious ? COL.attacker : (macro ? COL.edgeNormal : COL.benign);
      ctx.save();
      ctx.globalAlpha = macro ? 0.16 : 0.30;
      ctx.setLineDash(strokeFor(cl.comm));
      ctx.lineWidth = 1;
      ctx.strokeStyle = stroke;
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.stroke();
      ctx.setLineDash([]);
      if (!macro && cl.comm.is_malicious) {
        ctx.globalAlpha = 0.05;
        ctx.fillStyle = stroke;
        ctx.fill();
      }
      ctx.restore();

      if (!macro) {
        var collapsedCount = 0;
        cl.nodes.forEach(function (n) { if (n.type === 'aggregate') collapsedCount += n.count; });
        var clusterLabel = cl.name + (cl.comm.is_malicious
          ? ' · ' + (cl.comm.attacker_count || 0) + ' ATK / ' + cl.nodes.length + ' SHOWN'
          : ' · ' + cl.nodes.length + ' NODES');
        if (collapsedCount) clusterLabel += ' (+' + collapsedCount + ' COLLAPSED)';
        ctx.save();
        ctx.globalAlpha = cl.comm.is_malicious ? 0.95 : 0.55;
        ctx.fillStyle = cl.comm.is_malicious ? COL.attacker : COL.benign;
        ctx.font = 'bold 11px "JetBrains Mono", monospace';
        ctx.fillText(clusterLabel, cx - ctx.measureText(clusterLabel).width / 2, cy - r - 8);
        ctx.restore();
      }
    });

    // ── edges ───────────────────────────────────────────────────────────────
    S.drawnEdges.forEach(function (e) {
      var a = byId.get(e.source), b = byId.get(e.target);
      if (!a || !b) return;
      var w = e.has_attack ? clamp(0.9 + Math.log1p(e.weight) * 0.32, 0.9, 3.4) : 0.7;
      ctx.beginPath();
      ctx.lineWidth = macro ? w * 0.7 : w;
      ctx.strokeStyle = e.has_attack ? COL.edgeAttack : COL.edgeNormal;
      ctx.globalAlpha = macro ? (e.has_attack ? 0.35 : 0.10) : (e.has_attack ? 0.75 : 0.30);
      if (e.has_attack && !S.frozen && !macro) {
        ctx.setLineDash([7, 5]);
        ctx.lineDashOffset = -(S.t * 0.55) % 12;
      } else {
        ctx.setLineDash([]);
      }
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.globalAlpha = 1;

      // flow marker on high-volume attack edges
      if (e.has_attack && !macro && e.weight > 40) {
        var t = ((S.t * 0.006) + (e.source.length % 7) / 7) % 1;
        var px = a.x + (b.x - a.x) * t, py = a.y + (b.y - a.y) * t;
        ctx.fillStyle = COL.attacker;
        ctx.fillRect(px - 1.5, py - 1.5, 3, 3);
      }
    });

    // ── nodes ───────────────────────────────────────────────────────────────
    var labels = labelSet();
    labelRects = [];
    S.drawn.forEach(function (n) {
      var r = effRadius(n);
      var isSel = S.selected === n.id;
      var isHov = S.hovered && S.hovered.id === n.id;
      var color, fill;
      if (n.type === 'aggregate') { color = COL.agg; fill = COL.aggFill; }
      else if (n.is_attacker) { color = COL.attacker; fill = COL.attackerFill; }
      else if (n.community_malicious) { color = COL.peer; fill = COL.peerFill; }
      else { color = COL.benign; fill = COL.benignFill; }

      ctx.save();
      ctx.globalAlpha = macro && !n.is_attacker ? 0.55 : 1;

      if (n.is_attacker && !macro) {
        var pulse = 1 + 0.22 * Math.sin(S.t * 0.06 + (n.id.charCodeAt(n.id.length - 1) || 0));
        ctx.beginPath();
        ctx.strokeStyle = 'rgba(255,180,171,0.45)';
        ctx.lineWidth = 1;
        ctx.arc(n.x, n.y, r * pulse + 6, 0, Math.PI * 2);
        ctx.stroke();
      }

      ctx.lineWidth = isSel ? 2.4 : (isHov ? 1.8 : (n.type === 'aggregate' ? 1.8 : 1.5));
      ctx.strokeStyle = isSel ? COL.sel : (isHov ? '#ffffff' : color);
      ctx.fillStyle = fill;

      if (n.type === 'aggregate') {
        // A collapsed bucket must read as "there is more here", not as a node.
        drawHexagon(ctx, n.x, n.y, r);
        ctx.fill(); ctx.stroke();
        ctx.save();
        ctx.strokeStyle = COL.agg;
        ctx.globalAlpha = 0.55;
        ctx.lineWidth = 1;
        ctx.setLineDash([3, 3]);
        ctx.beginPath();
        ctx.arc(n.x, n.y, r + 6, 0, Math.PI * 2);
        ctx.stroke();
        ctx.restore();
      } else if (n.is_attacker) {
        ctx.fillRect(n.x - r, n.y - r, r * 2, r * 2);
        ctx.strokeRect(n.x - r, n.y - r, r * 2, r * 2);
        ctx.beginPath();
        ctx.strokeStyle = '#0c0f0e';
        ctx.lineWidth = 1.2;
        ctx.moveTo(n.x - 3.5, n.y); ctx.lineTo(n.x + 3.5, n.y);
        ctx.moveTo(n.x, n.y - 3.5); ctx.lineTo(n.x, n.y + 3.5);
        ctx.stroke();
      } else if (n.community_malicious) {
        ctx.beginPath();
        ctx.moveTo(n.x, n.y - r * 1.25);
        ctx.lineTo(n.x + r * 1.25, n.y);
        ctx.lineTo(n.x, n.y + r * 1.25);
        ctx.lineTo(n.x - r * 1.25, n.y);
        ctx.closePath();
        ctx.fill(); ctx.stroke();
      } else {
        ctx.beginPath();
        ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.fill(); ctx.stroke();
      }

      if (isSel) {
        ctx.beginPath();
        ctx.strokeStyle = COL.sel;
        ctx.lineWidth = 1;
        ctx.setLineDash([3, 3]);
        ctx.arc(n.x, n.y, r + 9, 0, Math.PI * 2);
        ctx.stroke();
        ctx.setLineDash([]);
      }
      ctx.restore();

    });

    // ── labels ──────────────────────────────────────────────────────────────
    // Drawn in screen space at a constant size so they stay legible at any
    // zoom. The budget is tied to how much is actually rendered, and the
    // overlap test silently drops whatever no longer fits — a 15-node cluster
    // therefore shows every label while a 300-node one shows only the top few.
    ctx.save();
    ctx.scale(1 / S.zoom, 1 / S.zoom);
    var order = S.drawn.slice().sort(function (a, b) {
      return (labelPriority(b) - labelPriority(a)) || (b.danger_index - a.danger_index);
    });
    order.forEach(function (n) {
      var isSel = S.selected === n.id;
      var isHov = !!(S.hovered && S.hovered.id === n.id);
      var forced = isSel || isHov || n.is_attacker || n.type === 'aggregate';
      if (!forced && !labels.has(n.id)) return;

      var fs = forced ? 11 : 10;
      var text = n.type === 'aggregate' ? '+' + n.count + ' PEERS' : short(n.id);
      ctx.font = (forced ? 'bold ' : '') + fs + 'px "JetBrains Mono", monospace';
      var tw = ctx.measureText(text).width;
      var sx = (n.x + radiusOf(n) + 5) * S.zoom;
      var sy = (n.y + 3) * S.zoom;

      function collides(y) {
        for (var i = 0; i < labelRects.length; i++) {
          var o = labelRects[i];
          if (!(sx > o.x + o.w || sx + tw < o.x || y - fs > o.y + o.h || y + 2 < o.y)) return true;
        }
        return false;
      }

      var yi = sy;
      if (collides(yi)) {
        // Silent labels simply drop out; important ones step aside vertically
        // so an attacker's name never gets buried under a peer's.
        var keep = isSel || isHov || n.is_attacker || n.type === 'aggregate';
        if (!keep) return;
        var step = 0;
        for (var a = 1; a <= 4; a++) {
          var cand = [sy - a * 13, sy + a * 13];
          if (!collides(cand[0])) { yi = cand[0]; step = 1; break; }
          if (!collides(cand[1])) { yi = cand[1]; step = 1; break; }
        }
        if (!step) return;
      }

      var rect = { x: sx, y: yi - fs, w: tw, h: fs + 2 };
      labelRects.push(rect);
      ctx.fillStyle = isSel ? COL.sel
        : (n.type === 'aggregate' ? COL.agg : (macro && !forced ? 'rgba(225,227,225,0.5)' : COL.label));
      ctx.fillText(text, sx, yi);
    });
    ctx.restore();

    ctx.restore();
  }

  /** Labels are allocated by structural importance first, then influence. */
  function labelPriority(n) {
    if (S.selected === n.id) return 4;
    if (S.hovered && S.hovered.id === n.id) return 3;
    if (n.is_attacker) return 2;
    if (n.type === 'aggregate') return 1;
    return 0;
  }

  function drawHexagon(c, x, y, r) {
    c.beginPath();
    for (var i = 0; i < 6; i++) {
      var a = (Math.PI / 3) * i - Math.PI / 6;
      var px = x + Math.cos(a) * r, py = y + Math.sin(a) * r;
      if (i === 0) c.moveTo(px, py); else c.lineTo(px, py);
    }
    c.closePath();
  }

  function frame() {
    var topo = $('topology-section');
    var hidden = topo && topo.style.display === 'none';
    if (!hidden) {
      S.t++;
      stepLayout();
      if (S.w && S.h) draw();
      // Frame the view once nodes exist, then again when the layout cools —
      // but never fight a camera the analyst has already moved.
      if (S.fitPending && S.drawn.length) { fitView(); S.fitPending = false; }
      if (!S.camTouched && !S.settled && S.alpha < CFG.alphaMin && S.drawn.length) {
        fitView();
        S.settled = true;
      }
    }
    requestAnimationFrame(frame);
  }

  /* ══════════════════════════════════════════════════════════════════════════
   * 5. SIDEBAR / SUMMARY / LEGEND
   * ══════════════════════════════════════════════════════════════════════════ */

  function updateSummary() {
    var m = S.meta || {};
    var macro = !!S.macro;
    var nodes = S.drawn.length;
    var edges = S.drawnEdges.length;
    set('topo-sum-nodes', fmt(m.total_nodes) + ' ENTITIES (' + fmt(nodes) + ' IN VIEW)');
    set('topo-sum-edges', fmt(m.total_edges) + ' FLOWS (' + fmt(edges) + ' DRAWN)');
    set('topo-sum-comms', fmt(m.communities) + ' DETECTED' + (m.modularity ? ' (Q=' + Number(m.modularity).toFixed(3) + ')' : ''));
    set('topo-sum-malicious', fmt(m.malicious_communities) + ' FLAGGED (' + fmt(m.selected_communities ? m.selected_communities.length : 0) + ' EXPANDED)');

    var topAtk = null;
    S.nodes.forEach(function (n) {
      if (!n.is_attacker) return;
      if (!topAtk || n.pagerank > topAtk.pagerank) topAtk = n;
    });
    set('topo-sum-topattacker', topAtk ? topAtk.id + ' (' + topAtk.pagerank.toFixed(4) + ')' : '—');

    var densest = null;
    S.comms.forEach(function (c) {
      if (!c.is_malicious) return;
      if (!densest || (c.internal_edges || 0) > (densest.internal_edges || 0)) densest = c;
    });
    set('topo-sum-densest', densest ? densest.name + ' (' + fmt(densest.internal_edges) + ' EDGES)' : '—');

    // Coverage readout — always say what is NOT drawn.
    var notDrawn = Math.max(0, (Number(m.total_nodes) || 0) - nodes);

    // Edges that belong to the view but are suppressed by the current lens
    // (as opposed to edges folded into an aggregate or left out entirely).
    var represented = new Set();
    S.drawn.forEach(function (n) { represented.add(n.id); });
    S.agg.forEach(function (b) { b.members.forEach(function (mm) { represented.add(mm); }); });
    var hiddenByLens = 0;
    if (S.edgeMode === 'attack') {
      S.edges.forEach(function (e) {
        if (!e.has_attack && represented.has(e.source) && represented.has(e.target)) hiddenByLens++;
      });
    }
    set('topo-coverage-nodes', fmt(nodes) + ' / ' + fmt(m.total_nodes) + ' NODES IN VIEW');
    set('topo-coverage-edges', fmt(edges) + ' EDGES DRAWN · ' + fmt(S.drawnEdges.filter(function (e) { return e.has_attack; }).length) + ' ATTACK');
    set('topo-coverage-omitted', fmt(notDrawn) + (macro ? ' SAMPLED OUT' : ' OMITTED (NO ATTACKER PATH)') +
      (hiddenByLens ? ' · ' + fmt(hiddenByLens) + ' HIDDEN BY EDGE LENS' : ''));
  }

  function set(id, text) {
    var el = $(id);
    if (el) el.textContent = text;
  }

  function updateLegend() {
    var box = $('topo-community-legend');
    if (!box) return;
    var rows = ['<div class="text-on-surface-variant font-bold uppercase text-[9px] border-b border-outline-variant/20 pb-0.5 mb-0.5">COMMUNITY STROKE ENCODING</div>'];
    var severe = [];
    S.comms.forEach(function (c) { if (c.is_malicious) severe.push(c); });
    severe.sort(function (a, b) { return (b.attacker_count - a.attacker_count) || (b.size - a.size); });
    if (!severe.length) {
      rows.push('<span class="text-on-surface-variant">NO MALICIOUS CLUSTER IN THIS GRAPH</span>');
    }
    severe.slice(0, 4).forEach(function (c) {
      var pct = c.size ? Math.round((c.attacker_count / c.size) * 100) : 0;
      rows.push('<span class="text-error font-mono">─── [SOLID] ' + c.name + ' (ATK ' + pct + '%)' +
        (c.selected ? '' : ' · NOT EXPANDED') + '</span>');
    });
    var benign = 0;
    S.comms.forEach(function (c) { if (!c.is_malicious) benign++; });
    if (benign) {
      rows.push('<span class="text-secondary font-mono">- - - [DASH] ' + benign + ' BENIGN NET' + (benign === 1 ? '' : 'S') + ' (LEVEL 1/2 ONLY)</span>');
    }
    box.innerHTML = rows.join('');
  }

  function roleLabel(n) {
    if (n.type === 'aggregate') return 'COLLAPSED PERIPHERAL PEERS';
    if (n.is_attacker) return 'SOURCE HOST (CONFIRMED ATTACKER)';
    if (n.community_malicious) return 'COMPROMISED PEER (FLAGGED CLUSTER)';
    if (n.malicious_neighbor) return 'PERIPHERAL · DIRECT LINK TO ATTACKER';
    return 'PERIPHERAL (BENIGN)';
  }

  function updateSidebar(node) {
    var badge = $('node-badge-status');
    if (!node) {
      set('topo-node-ip', 'SELECT A NODE');
      set('topo-node-type', 'CLICK ANY NODE IN THE CANVAS');
      set('topo-node-pr', '—');
      set('topo-node-degree', '—');
      set('topo-node-danger', '—');
      set('topo-node-danger-raw', 'danger_score = —');
      set('topo-node-comm', '—');
      set('topo-node-comm-detail', 'NO CLUSTER DATA');
      set('topo-node-rank', 'RANK: —');
      var cats = $('topo-node-cats'); if (cats) cats.innerHTML = '';
      var list = $('topo-connected-list'); if (list) list.innerHTML = '<div class="bg-surface-container p-1 text-[10px] text-on-surface-variant">NO NODE SELECTED</div>';
      if (badge) {
        badge.className = 'px-space-xs py-0.5 bg-surface-container-highest text-on-surface-variant font-label-sm text-[10px] font-bold';
        badge.textContent = 'NO SELECTION';
      }
      return;
    }

    var sev = sevOf(node);
    set('topo-node-ip', node.type === 'aggregate' ? '+' + node.count + ' PEERS (AGGREGATE)' : node.id);
    set('topo-node-type', 'TYPE: ' + roleLabel(node) + (node.type === 'aggregate'
      ? ' // CLUSTER: ' + ((S.comms.get(node.community_id) || {}).name || '—')
      : ' // CLASS: ' + node.label_class));
    set('topo-node-pr', node.pagerank.toFixed(6));
    set('topo-node-degree', node.degree + ' EDGES (IN:' + node.in_degree + ' / OUT:' + node.out_degree + ')');
    set('topo-node-danger', node.danger_index + ' / 100 [' + sev.toUpperCase() + ']');
    set('topo-node-danger-raw', 'danger_score = ' + node.danger_score.toFixed(6) + ' · raw influence');
    set('topo-node-rank', node.danger_rank ? 'RANK: #' + node.danger_rank : 'RANK: —');

    var comm = S.comms.get(node.community_id);
    if (comm) {
      var pct = comm.size ? ((comm.attacker_count / comm.size) * 100).toFixed(1) : '0.0';
      set('topo-node-comm', comm.name + (comm.is_malicious ? ' [FLAGGED]' : ' [BENIGN]'));
      set('topo-node-comm-detail', 'Size: ' + fmt(comm.size) + ' nodes // ' + fmt(comm.attacker_count) +
        ' attackers (' + pct + '% compromised cluster) // ' + fmt(comm.internal_edges) + ' internal edges');
    } else {
      set('topo-node-comm', '—');
      set('topo-node-comm-detail', 'NO CLUSTER DATA');
    }

    var cats = $('topo-node-cats');
    if (cats) {
      var catList = (node.attack_cats && node.attack_cats.length) ? node.attack_cats.slice(0, 6) : [];
      cats.innerHTML = catList.map(function (c) {
        return '<span class="px-space-xs py-0.5 bg-error-container/40 text-error font-bold text-[9px] uppercase">[' + c + ']</span>';
      }).join('') || '<span class="text-[9px] text-on-surface-variant">NO ATTACK SIGNATURE ON THIS ENTITY</span>';
    }

    // Danger meter
    var bars = $('tactical-meter-bars');
    if (bars) {
      var filled = Math.round(clamp(node.danger_index, 0, 100) / 10);
      var tone = sev === 'crit' ? 'bg-error' : (sev === 'warn' ? 'bg-primary-container' : 'bg-secondary');
      var html = '';
      for (var i = 0; i < 10; i++) {
        html += '<div class="' + (i < filled ? tone : 'bg-outline-variant/30') + ' h-full"></div>';
      }
      bars.innerHTML = html;
    }

    if (badge) {
      if (sev === 'crit') {
        badge.className = 'px-space-xs py-0.5 bg-error text-on-error font-label-sm text-[10px] font-bold';
        badge.textContent = 'CRITICAL MALICIOUS';
      } else if (sev === 'warn') {
        badge.className = 'px-space-xs py-0.5 bg-primary-container text-on-primary-container font-label-sm text-[10px] font-bold';
        badge.textContent = 'ELEVATED SUSPICIOUS';
      } else {
        badge.className = 'px-space-xs py-0.5 bg-secondary text-on-secondary font-label-sm text-[10px] font-bold';
        badge.textContent = 'BENIGN / PERIPHERAL';
      }
    }

    renderConnected(node);
  }

  function renderConnected(node) {
    var box = $('topo-connected-list');
    if (!box) return;
    var links = S.adj.get(node.id) || [];

    if (node.type === 'aggregate') {
      box.innerHTML = node.members.slice(0, 40).map(function (m) {
        var n = S.nodes.get(m);
        return '<div class="bg-surface-container p-1 text-[10px] flex items-center justify-between">' +
          '<span class="font-mono text-on-surface">' + short(m) + '</span>' +
          '<span class="text-on-surface-variant text-[9px] uppercase">' + (n && n.malicious_neighbor ? 'ATTACKER LINK' : 'PEER') + '</span></div>';
      }).join('') + (node.members.length > 40
        ? '<div class="bg-surface-container p-1 text-[10px] text-on-surface-variant">+' + (node.members.length - 40) + ' MORE — CLICK THE AGGREGATE TO EXPAND</div>'
        : '');
      return;
    }

    if (!links.length) {
      box.innerHTML = '<div class="bg-surface-container p-1 text-[10px] text-on-surface-variant">NO EDGES IN THE LOADED SUBGRAPH — CLICK TO PULL ITS EGO-NETWORK</div>';
      return;
    }
    links.sort(function (a, b) { return b.edge.weight - a.edge.weight; });
    box.innerHTML = links.slice(0, 8).map(function (l) {
      var other = S.nodes.get(l.id) || { id: l.id };
      var tone = l.edge.has_attack ? 'border-error text-error' : (other.community_malicious ? 'border-primary-container text-primary-container' : 'border-secondary text-secondary');
      var role = other.is_attacker ? 'ATTACKER' : (other.community_malicious ? 'PEER/BOT' : 'HOST');
      var tag = l.edge.has_attack ? '[ATTACK]' : '[BENIGN]';
      return '<div class="bg-surface-container p-1 text-[10px] flex items-center justify-between gap-space-xs border-l-2 ' + tone + ' hover:bg-surface-container-high transition-colors cursor-pointer topo-neighbor" data-ip="' + l.id + '">' +
        '<span class="font-mono text-on-surface truncate">' + short(l.id) + ' <span class="text-on-surface-variant">[' + role + ']</span></span>' +
        '<span class="font-semibold whitespace-nowrap">' + fmtFlow(l.edge.weight) + ' pkts [' + fmtBytes(l.edge.total_bytes) + ']</span>' +
        '<span class="text-[9px] uppercase whitespace-nowrap">' + tag + '</span></div>';
    }).join('');

    box.querySelectorAll('.topo-neighbor').forEach(function (el) {
      el.addEventListener('click', function () {
        var ip = el.getAttribute('data-ip');
        select(ip, true);
      });
    });
  }

  /* ══════════════════════════════════════════════════════════════════════════
   * 6. INTERACTION
   * ══════════════════════════════════════════════════════════════════════════ */

  function nodeAt(clientX, clientY) {
    if (!canvas) return null;
    var rect = canvas.getBoundingClientRect();
    var x = (clientX - rect.left - S.panX) / S.zoom;
    var y = (clientY - rect.top - S.panY) / S.zoom;      for (var i = S.drawn.length - 1; i >= 0; i--) {
      var n = S.drawn[i];
      var r = effRadius(n) + 4;
      if (Math.abs(n.x - x) <= r && Math.abs(n.y - y) <= r) return n;
    }
    return null;
  }

  function setLevel(lvl) {
    if (lvl !== undefined) S.level = Math.max(S.level, lvl);
    var badge = $('topo-scope-badge');
    if (!badge) return;
    if (S.macro) {
      badge.textContent = '[LEVEL 2 · FULL MACRO VIEW]';
      badge.className = 'px-space-xs py-space-xs border border-error-container bg-error-container/20 text-error font-bold';
    } else if (S.level >= 1) {
      badge.textContent = '[LEVEL 1 · +' + S.revealed.size + ' UNFOLDED NODES]';
      badge.className = 'px-space-xs py-space-xs border border-outline-variant/40 bg-surface-container text-primary-container font-bold';
    } else {
      badge.textContent = '[LEVEL 0 · THREAT CLUSTERS]';
      badge.className = 'px-space-xs py-space-xs border border-outline-variant/40 bg-surface-container text-primary font-bold';
    }
  }

  function select(id, center) {
    var node = S.drawn.filter(function (n) { return n.id === id; })[0] || S.nodes.get(id);
    if (!node) return;
    S.selected = node.id;
    updateSidebar(node);
    if (center) centerOn(node, Math.max(S.zoom, 0.9));
  }

  /** Level 1 — unfold a node's neighbourhood, fetching its ego-net if unknown. */
  function expand(node) {
    if (!node) return;

    if (node.type === 'aggregate') {
      node.members.forEach(function (m) { S.revealed.add(m); });
      rebuild('keep');
      setLevel(1);
      return;
    }

    var local = S.adj.get(node.id) || [];
    // The loaded subgraph only knows attacker-adjacent nodes; anything thinner
    // than that needs its real 1-hop neighbourhood pulled from the API.
    var needsFetch = !S.macro && local.length < 2;
    var work = needsFetch ? fetchEgo(node.id) : Promise.resolve({ found: true });

    work.then(function (res) {
      if (needsFetch && (!res || !res.found)) {
        var msg = (res && res.error) ? res.error : 'node absent from graph_nodes';
        setStatus('error', '✗ NO EGO-NETWORK FOR ' + node.id, msg);
        setTimeout(function () { if (S.loaded) setStatus('hide'); }, 4200);
        return;
      }
      if (needsFetch) rebuild('keep');   // pick up the freshly merged edges
      S.revealed.add(node.id);
      (S.adj.get(node.id) || []).forEach(function (l) { S.revealed.add(l.id); });
      rebuild('keep');
      setLevel(1);
      select(node.id, false);
    });
  }

  function onMouseDown(ev) {
    if (ev.button !== 0) return;
    var hit = nodeAt(ev.clientX, ev.clientY);
    if (hit) {
      S.selected = hit.id;
      S.dragNode = hit;
      S.dragMoved = false;
      S.dragStart = { x: ev.clientX, y: ev.clientY };
      hit.pinned = true;
      updateSidebar(hit);
      return;
    }
    if (S.panOn) {
      S.dragging = true;
      S.camTouched = true;
      S.lastMouse = { x: ev.clientX, y: ev.clientY };
    }
  }

  function onMouseMove(ev) {
    if (S.dragNode) {
      // Only treat it as a drag past a few pixels, otherwise it is a click
      // (and a click means "unfold this node").
      if (!S.dragMoved && S.dragStart) {
        var travel = Math.hypot(ev.clientX - S.dragStart.x, ev.clientY - S.dragStart.y);
        if (travel < 4) return;
        S.dragMoved = true;
      }
      var rect = canvas.getBoundingClientRect();
      S.dragNode.x = (ev.clientX - rect.left - S.panX) / S.zoom;
      S.dragNode.y = (ev.clientY - rect.top - S.panY) / S.zoom;
      S.alpha = Math.max(S.alpha, 0.28);
      return;
    }
    if (S.dragging) {
      S.panX += ev.clientX - S.lastMouse.x;
      S.panY += ev.clientY - S.lastMouse.y;
      S.lastMouse = { x: ev.clientX, y: ev.clientY };
      return;
    }

    var hit = nodeAt(ev.clientX, ev.clientY);
    S.hovered = hit;
    var tip = $('topo-tooltip');
    if (hit && tip) {
      var rect2 = canvas.getBoundingClientRect();
      tip.style.display = 'flex';
      var tx = ev.clientX - rect2.left + 16;
      var ty = ev.clientY - rect2.top + 12;
      if (tx > S.w - 220) tx = ev.clientX - rect2.left - 210;
      if (ty > S.h - 90) ty = ev.clientY - rect2.top - 84;
      tip.style.left = tx + 'px';
      tip.style.top = ty + 'px';
      set('tt-ip', hit.type === 'aggregate' ? '+' + hit.count + ' PEERS' : hit.id);
      set('tt-role', roleLabel(hit) + ' · ' + ((S.comms.get(hit.community_id) || {}).name || '—'));
      set('tt-stats', hit.type === 'aggregate'
        ? 'CLICK TO EXPAND THE COLLAPSED PEERS'
        : 'PR: ' + hit.pagerank.toFixed(6) + ' · DEGREE: ' + hit.degree + ' · FLOWS: ' + fmt(hit.total_flows));
      set('tt-hint', 'CLICK TO UNFOLD NEIGHBOURHOOD · DRAG TO MOVE');
    } else if (tip) {
      tip.style.display = 'none';
    }
  }

  function onMouseUp() {
    if (S.dragNode) {
      var node = S.dragNode;
      node.pinned = false;
      S.dragNode = null;
      if (!S.dragMoved) {
        expand(node);
      } else {
        S.alpha = Math.max(S.alpha, 0.16);
      }
    }
    S.dragging = false;
  }

  function onWheel(ev) {
    if (!canvas) return;
    ev.preventDefault();
    var rect = canvas.getBoundingClientRect();
    var mx = ev.clientX - rect.left, my = ev.clientY - rect.top;
    var factor = ev.deltaY < 0 ? 1.12 : 1 / 1.12;
    var next = clamp(S.zoom * factor, CFG.minZoom, CFG.maxZoom);
    var k = next / S.zoom;
    S.panX = mx - (mx - S.panX) * k;
    S.panY = my - (my - S.panY) * k;
    S.zoom = next;
    S.camTouched = true;
  }

  /* ── Buttons ─────────────────────────────────────────────────────────────── */
  function cycleClusterCount() {
    var order = [1, 3, 5, 0];
    var i = order.indexOf(S.k);
    S.k = order[(i < 0 ? 1 : (i + 1)) % order.length];
    set('btn-topo-clusters', '[CLUSTERS: ' + (S.k === 0 ? 'ALL' : 'TOP ' + S.k) + ']');
    loadView('threat', S.k);
  }

  function toggleScope() {
    if (S.scope === 'threat') {
      S.scope = 'full';
      set('btn-topo-scope', '[RETURN TO THREAT CLUSTERS]');
      loadView('full', S.k);
    } else {
      S.scope = 'threat';
      set('btn-topo-scope', '[SHOW FULL GRAPH]');
      loadView('threat', S.k);
    }
  }

  function toggleEdges() {
    S.edgeMode = S.edgeMode === 'attack' ? 'all' : 'attack';
    var b = $('btn-topo-edges');
    if (b) {
      b.textContent = '[EDGES: ' + (S.edgeMode === 'attack' ? 'ATTACK ONLY' : 'ALL TRAFFIC') + ']';
      b.className = S.edgeMode === 'attack'
        ? 'px-space-xs py-space-xs bg-surface-container border border-outline-variant/30 text-on-surface-variant hover:text-on-surface text-[10px]'
        : 'px-space-xs py-space-xs bg-primary-container text-on-primary-container font-bold text-[10px]';
    }
    rebuild('keep');
  }

  function toggleDetail() {
    S.detail = S.detail === 'auto' ? 'full' : 'auto';
    var b = $('btn-topo-detail');
    if (b) {
      b.textContent = '[DETAIL: ' + (S.detail === 'auto' ? 'AUTO-COLLAPSE' : 'FULL') + ']';
    }
    rebuild('keep');
  }

  function toggleFreeze() {
    S.frozen = !S.frozen;
    var b = $('btn-topo-freeze');
    if (b) {
      b.textContent = '[FREEZE: ' + (S.frozen ? 'ON' : 'OFF') + ']';
      b.className = S.frozen
        ? 'px-space-xs py-space-xs bg-error-container/20 border border-error-container text-error text-[10px] font-bold'
        : 'px-space-xs py-space-xs bg-surface-container border border-outline-variant/30 text-on-surface-variant text-[10px]';
    }
    var pauseBtn = $('btn-pause-radar');
    if (pauseBtn) pauseBtn.textContent = S.frozen ? '[SPACE] RESUME' : '[SPACE] FREEZE';
    if (window.THREVIA && typeof window.THREVIA.setRadarPaused === 'function') {
      window.THREVIA.setRadarPaused(S.frozen);
    }
    if (!S.frozen) S.alpha = Math.max(S.alpha, 0.3);
  }

  function toggleLayout() {
    S.layout = S.layout === 'force' ? 'radial' : 'force';
    var b = $('btn-layout-mode');
    if (b) b.textContent = '[LAYOUT: ' + (S.layout === 'force' ? 'FORCE-DIRECTED' : 'RADIAL FAN') + ']';
    if (S.layout === 'radial') { applyRadial(); fitView(); }
    else { S.drawn.forEach(function (n) { n.vx = 0; n.vy = 0; }); S.alpha = 0.9; }
  }

  function initSeverityFilters() {
    var btns = document.querySelectorAll('.topo-filter-btn');
    btns.forEach(function (b) {
      b.addEventListener('click', function () {
        btns.forEach(function (el) {
          el.classList.remove('bg-primary-container', 'text-on-primary-container', 'font-bold');
          el.classList.add('bg-surface-container', 'text-on-surface-variant');
        });
        b.classList.remove('bg-surface-container', 'text-on-surface-variant');
        b.classList.add('bg-primary-container', 'text-on-primary-container', 'font-bold');
        S.sevFilter = b.getAttribute('data-filter') || 'all';
        rebuild('keep');
      });
    });
  }

  var searchTimer = null;
  function onSearch(ev) {
    var q = (ev.target.value || '').trim().replace(/\uFEFF/g, '');
    if (!q) return;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(function () {
      var exact = S.nodes.get(q);
      if (exact) { select(q, true); expand(exact); return; }
      var partial = null;
      S.nodes.forEach(function (n) {
        if (!partial && (n.id.indexOf(q) === 0 || n.id.indexOf(q) >= 0)) partial = n;
      });
      if (partial) { select(partial.id, true); return; }
      // Not loaded — pull its ego-network in regardless of attacker status.
      setStatus('loading', '⟳ PULLING EGO-NETWORK FOR ' + q + ' …', 'GET /api/v1/graph/ego/' + q);
      fetchEgo(q).then(function (res) {
        if (res && res.found) {
          S.revealed.add(q);
          rebuild('keep');
          setStatus('hide');
          select(q, true);
          setLevel(1);
        } else {
          setStatus('error', '✗ ' + q + ' NOT IN graph_nodes',
            'Search only covers entities present in the UNSW-NB15 topology.');
          setTimeout(function () { if (S.loaded) setStatus('hide'); }, 4200);
        }
      });
    }, 220);
  }

  /* ── View switching (tabs) ───────────────────────────────────────────────── */
  var TAB_ACTIVE = 'px-space-md py-space-xs font-label-sm text-label-sm uppercase tracking-wider bg-primary-container text-on-primary-container font-bold flex items-center gap-space-xs';
  var TAB_IDLE = 'px-space-md py-space-xs font-label-sm text-label-sm uppercase tracking-wider bg-surface-container text-on-surface-variant hover:text-on-surface transition-colors flex items-center gap-space-xs';

  function showView(name) {
    var radar = $('radar-section'), topo = $('topology-section'), spec = $('spectral-section');
    var ind = $('telemetry-sweep-indicator');
    if (radar) radar.style.display = name === 'radar' ? 'flex' : 'none';
    if (topo) topo.style.display = name === 'topology' ? 'flex' : 'none';
    if (spec) spec.style.display = name === 'spectral' ? 'flex' : 'none';

    var tabs = { radar: $('tab-radar'), topology: $('tab-topology'), spectral: $('tab-spectral') };
    Object.keys(tabs).forEach(function (key) {
      if (tabs[key]) tabs[key].className = (key === name) ? TAB_ACTIVE : TAB_IDLE;
    });
    if (ind) {
      ind.textContent = name === 'topology' ? 'TOPOLOGY LINK ACTIVE'
        : (name === 'spectral' ? 'SPECTRAL MODULE OFFLINE' : 'SWEEP ACTIVE: 24 RPM');
      ind.className = name === 'topology' ? 'text-primary font-bold' : 'text-secondary font-bold';
    }
    if (name === 'topology') {
      resizeCanvas();
      S.fitPending = true;
      if (!S.loaded) loadView(S.scope === 'full' ? 'full' : 'threat', S.k);
      else if (!S.drawn.length) rebuild(0);
      setTimeout(resizeCanvas, 40);
    }
  }

  /* ══════════════════════════════════════════════════════════════════════════
   * 7. BOOT
   * ══════════════════════════════════════════════════════════════════════════ */

  function bindActions() {
    var map = {
      'btn-topo-zoomin': function () { S.zoom = clamp(S.zoom * 1.2, CFG.minZoom, CFG.maxZoom); S.camTouched = true; },
      'btn-topo-zoomout': function () { S.zoom = clamp(S.zoom / 1.2, CFG.minZoom, CFG.maxZoom); S.camTouched = true; },
      'btn-topo-reset': function () { S.camTouched = false; fitView(); },
      'btn-topo-freeze': toggleFreeze,
      'btn-topo-edges': toggleEdges,
      'btn-topo-clusters': cycleClusterCount,
      'btn-topo-detail': toggleDetail,
      'btn-layout-mode': toggleLayout,
      'btn-topo-scope': toggleScope
    };
    Object.keys(map).forEach(function (id) {
      var el = $(id);
      if (el) el.addEventListener('click', map[id]);
    });

    var panBtn = $('btn-topo-pan');
    if (panBtn) {
      panBtn.addEventListener('click', function () {
        S.panOn = !S.panOn;
        panBtn.textContent = '[PAN: ' + (S.panOn ? 'ON' : 'LOCKED') + ']';
        panBtn.className = S.panOn
          ? 'px-space-xs py-space-xs bg-secondary/10 border border-secondary/40 text-secondary text-[10px]'
          : 'px-space-xs py-space-xs bg-surface-container border border-outline-variant/30 text-on-surface-variant text-[10px]';
        if (canvas) canvas.style.cursor = S.panOn ? 'grab' : 'crosshair';
      });
    }

    // Cosmetic SOC actions mirror the rest of the dashboard's confirmations.
    var act = {
      'btn-topo-isolate': ['[ISOLATION QUEUED]', '[ISOLATE NODE]'],
      'btn-topo-trace': ['[TRACE: SUBGRAPH HOPS]', '[TRACE ATTACK PATH]'],
      'btn-topo-c2bloom': ['[ADDED TO C2 BLOOM]', '[ADD TO C2 BLOOM]'],
      'btn-topo-blackhole': ['[BGP BLACKHOLE PENDING]', '[BGP BLACKHOLE]']
    };
    Object.keys(act).forEach(function (id) {
      var el = $(id);
      if (!el) return;
      el.addEventListener('click', function () {
        var label = el.textContent;
        el.textContent = act[id][0];
        setTimeout(function () { el.textContent = act[id][1] || label; }, 1500);
      });
    });

    var search = $('topo-search-input');
    if (search) search.addEventListener('input', onSearch);

    var radarTab = $('tab-radar');
    if (radarTab) radarTab.addEventListener('click', function () { showView('radar'); });
    var topoTab = $('tab-topology');
    if (topoTab) topoTab.addEventListener('click', function () { showView('topology'); });
    var specTab = $('tab-spectral');
    if (specTab) specTab.addEventListener('click', function () { showView('spectral'); });

    var pause = $('btn-pause-radar');
    if (pause) pause.addEventListener('click', toggleFreeze);

    window.addEventListener('keydown', function (e) {
      var tag = (e.target && e.target.tagName) || '';
      if (tag === 'INPUT' || tag === 'TEXTAREA') {
        if (e.key === 'Escape' && e.target) { e.target.value = ''; e.target.blur(); }
        return;
      }
      if (e.key === '1') { showView('radar'); }
      else if (e.key === '2') { showView('topology'); }
      else if (e.key === '3') { showView('spectral'); }
      else if (e.key === ' ') { e.preventDefault(); toggleFreeze(); }
      else if (e.key === '/') { e.preventDefault(); if ($('topo-search-input') && S.loaded) $('topo-search-input').focus(); }
      else if (e.key === 'f' || e.key === 'F') { if (S.loaded) fitView(); }
      else if (e.key === 'Escape') {
        S.selected = null;
        updateSidebar(null);
        var tip = $('topo-tooltip');
        if (tip) tip.style.display = 'none';
      }
    });
  }

  function init() {
    canvas = $('topologyCanvas');
    if (!canvas) return;
    ctx = canvas.getContext('2d');

    bindActions();
    initSeverityFilters();
    updateSidebar(null);
    setLevel(0);

    canvas.addEventListener('mousedown', onMouseDown);
    canvas.addEventListener('mousemove', onMouseMove);
    canvas.addEventListener('wheel', onWheel, { passive: false });
    canvas.addEventListener('mouseleave', function () {
      S.hovered = null;
      var tip = $('topo-tooltip');
      if (tip) tip.style.display = 'none';
    });
    window.addEventListener('mouseup', onMouseUp);

    if (window.ResizeObserver) {
      new ResizeObserver(function () { resizeCanvas(); }).observe(canvas.parentElement);
    } else {
      window.addEventListener('resize', resizeCanvas);
    }
    window.addEventListener('resize', resizeCanvas);

    resizeCanvas();
    requestAnimationFrame(frame);

    // Deep-link: open straight into the topology view when asked.
    var params = new URLSearchParams(window.location.search);
    if ((params.get('view') || '').toLowerCase() === 'topology') showView('topology');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  window.THREVIA_TOPOLOGY = {
    showView: showView,
    loadView: loadView,
    select: select,
    expand: expand,
    rebuild: rebuild,
    state: S,
    config: CFG,
    fit: fitView
  };
})();
