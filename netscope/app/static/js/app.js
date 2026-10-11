'use strict';

/* ------------------------------------------------------------------ helpers */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
// Everything that originates in a capture (hostnames, user agents, ...) is attacker
// controlled, so it is always escaped before being placed into markup.
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ESC[c]);
const fmtNum = n => Number(n).toLocaleString();
const fmtBytes = n => {
  n = Number(n) || 0;
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${i ? n.toFixed(1) : n} ${units[i]}`;
};
const fmtBits = n => {
  n = Number(n) || 0;
  const units = ['bit/s', 'Kbit/s', 'Mbit/s', 'Gbit/s'];
  let i = 0;
  while (n >= 1000 && i < units.length - 1) { n /= 1000; i++; }
  return `${i ? n.toFixed(1) : Math.round(n)} ${units[i]}`;
};
const fmtDur = s => {
  s = Number(s) || 0;
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${Math.round(s % 60)}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
};
const fmtTime = iso => (iso ? new Date(iso).toLocaleString() : '');
const cssVar = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const palette = () => [1, 2, 3, 4, 5, 6, 7, 8].map(i => cssVar(`--c${i}`));
const badge = (text, cls = '') => `<span class="badge ${esc(cls)}">${esc(text)}</span>`;
const mono = t => `<span class="mono">${esc(t)}</span>`;

const state = {
  file: null, files: [], data: null, charts: {}, rendered: new Set(),
  tab: 'overview', selectedHost: null, mapNode: null, mapModel: null,
};

async function api(path, opts) {
  const res = await fetch(path, opts);
  let body = null;
  try { body = await res.json(); } catch (_) { /* non-JSON error body */ }
  if (!res.ok) throw new Error((body && body.error) || `Request failed (${res.status})`);
  return body;
}

function banner(msg, kind = 'info') {
  const el = $('#banner');
  el.hidden = !msg;
  el.className = `banner ${kind}`;
  el.textContent = msg || '';
}

/* ------------------------------------------------------------------- tables */
function dataTable(host, columns, rows, opts = {}) {
  const pageSize = opts.pageSize || 12;
  let sortCol = opts.sortCol ?? null, sortDir = opts.sortDir ?? -1, page = 0, q = '';
  host.replaceChildren();
  if (!rows.length) { host.innerHTML = `<div class="empty">${esc(opts.empty || 'Nothing to show.')}</div>`; return; }

  let search = null;
  if (opts.search !== false && rows.length > 6) {
    search = document.createElement('input');
    search.type = 'search';
    search.placeholder = 'Filter…';
    search.setAttribute('aria-label', 'Filter table');
    host.append(search);
  }
  const scroll = document.createElement('div');
  scroll.className = 'table-scroll';
  const pager = document.createElement('div');
  pager.className = 'pager';
  host.append(scroll, pager);

  const val = (c, r) => (c.value ? c.value(r) : r[c.key]);
  const cell = (c, r) => (c.html ? c.html(r) : esc(c.fmt ? c.fmt(val(c, r), r) : val(c, r)));
  let view = [];

  function draw() {
    let list = rows;
    if (q) list = list.filter(r => columns.some(c => String(val(c, r) ?? '').toLowerCase().includes(q)));
    if (sortCol !== null) {
      const c = columns[sortCol];
      list = [...list].sort((a, b) => {
        const x = val(c, a), y = val(c, b);
        const d = typeof x === 'number' && typeof y === 'number'
          ? x - y : String(x ?? '').localeCompare(String(y ?? ''), undefined, { numeric: true });
        return d * sortDir;
      });
    }
    const pages = Math.max(1, Math.ceil(list.length / pageSize));
    page = Math.min(page, pages - 1);
    view = list.slice(page * pageSize, (page + 1) * pageSize);
    scroll.innerHTML = `<table><thead><tr>${columns.map((c, i) =>
      `<th data-i="${i}" class="${c.align || ''}">${esc(c.label)}${sortCol === i ? (sortDir > 0 ? ' ▲' : ' ▼') : ''}</th>`).join('')}</tr></thead>
      <tbody>${view.map((r, ri) => `<tr data-ri="${ri}" class="${opts.onRow ? 'clickable' : ''}">${columns.map(c =>
        `<td class="${c.align || ''}">${cell(c, r)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
    pager.innerHTML = list.length > pageSize
      ? `<span>${fmtNum(list.length)} rows</span><button ${page === 0 ? 'disabled' : ''} data-p="-1">Prev</button>
         <span>${page + 1} / ${pages}</span><button ${page >= pages - 1 ? 'disabled' : ''} data-p="1">Next</button>`
      : `<span>${fmtNum(list.length)} row${list.length === 1 ? '' : 's'}</span>`;
    if (!list.length) scroll.innerHTML = '<div class="empty">No rows match the filter.</div>';
  }

  scroll.addEventListener('click', e => {
    const th = e.target.closest('th');
    if (th) {
      const i = Number(th.dataset.i);
      sortDir = sortCol === i ? -sortDir : -1;
      sortCol = i;
      return draw();
    }
    const tr = e.target.closest('tr[data-ri]');
    if (tr && opts.onRow) opts.onRow(view[Number(tr.dataset.ri)]);
  });
  pager.addEventListener('click', e => {
    const b = e.target.closest('button[data-p]');
    if (b) { page += Number(b.dataset.p); draw(); }
  });
  if (search) search.addEventListener('input', () => { q = search.value.trim().toLowerCase(); page = 0; draw(); });
  draw();
}

const hostChip = ip => `<button type="button" class="chip" data-host="${esc(ip)}">${esc(ip)}</button>`;

/* ------------------------------------------------------------------- charts */
function chart(id, config) {
  if (state.charts[id]) state.charts[id].destroy();
  const canvas = document.getElementById(id);
  if (!canvas || typeof Chart === 'undefined') return;
  Chart.defaults.color = cssVar('--muted');
  Chart.defaults.borderColor = cssVar('--border');
  config.options = Object.assign({ responsive: true, maintainAspectRatio: false }, config.options || {});
  state.charts[id] = new Chart(canvas, config);
}

const doughnut = (id, labels, data) => chart(id, {
  type: 'doughnut',
  data: { labels, datasets: [{ data, backgroundColor: palette(), borderColor: cssVar('--panel'), borderWidth: 2 }] },
  options: { cutout: '58%', plugins: { legend: { position: 'right', labels: { boxWidth: 10 } } } },
});

const hbar = (id, labels, datasets, tickFmt) => chart(id, {
  type: 'bar',
  data: { labels, datasets },
  options: {
    indexAxis: 'y',
    plugins: { legend: { display: datasets.length > 1 } },
    scales: { x: { beginAtZero: true, ticks: tickFmt ? { callback: tickFmt } : {} },
              y: { grid: { display: false } } },
  },
});

/* ----------------------------------------------------------------- overview */
function kpiHtml(items) {
  return items.map(([label, value, sub]) => `<div class="kpi"><div class="label">${esc(label)}</div>
    <div class="value">${esc(value)}</div><div class="sub">${esc(sub || '')}</div></div>`).join('');
}

function renderOverview() {
  const d = state.data, s = d.summary, pal = palette();
  $('#kpis').innerHTML = kpiHtml([
    ['Packets', fmtNum(s.packets), `avg ${fmtNum(s.avg_packet_size)} B`],
    ['Data', fmtBytes(s.bytes), fmtBits(s.avg_bits_per_second) + ' avg'],
    ['Duration', fmtDur(s.duration_seconds), `${s.avg_packets_per_second} pkt/s avg`],
    ['Peak rate', `${fmtNum(s.peak_packets_per_second)} pkt/s`, fmtBytes(s.peak_bytes_per_second) + '/s'],
    ['Hosts', fmtNum(s.unique_hosts), `${fmtNum(s.unique_conversations)} conversations`],
    ['DNS names', fmtNum(s.unique_domains), `${d.dns.queries} queries`],
    ['Broadcast / multicast', `${fmtNum(s.broadcast_packets)} / ${fmtNum(s.multicast_packets)}`, 'packets'],
    ['Risk', `${s.risk_score}/100`, `${s.risk_level} · ${s.findings} findings`],
  ]);

  doughnut('protoChart', d.protocols.map(p => p.name), d.protocols.map(p => p.packets));
  const apps = d.applications.slice(0, 10);
  hbar('appChart', apps.map(a => a.name), [{ label: 'Packets', data: apps.map(a => a.packets), backgroundColor: pal[0] }]);
  doughnut('flagsChart', d.tcp.flags.slice(0, 8).map(f => f.name), d.tcp.flags.slice(0, 8).map(f => f.packets));
  renderTimeline();

  const top = d.hosts.slice(0, 8);
  hbar('hostsChart', top.map(h => h.ip), [
    { label: 'Sent', data: top.map(h => h.bytes_sent), backgroundColor: pal[0] },
    { label: 'Received', data: top.map(h => h.bytes_recv), backgroundColor: pal[1] },
  ], v => fmtBytes(v));
  const ports = d.ports.slice(0, 10);
  hbar('portsChart', ports.map(p => (p.service === String(p.port) ? `${p.port}/${p.protocol}` : `${p.service} ${p.port}/${p.protocol}`)),
    [{ label: 'Packets', data: ports.map(p => p.packets), backgroundColor: pal[2] }]);
  chart('sizeChart', {
    type: 'bar',
    data: { labels: d.packet_sizes.map(p => p.range), datasets: [{ label: 'Packets', data: d.packet_sizes.map(p => p.count), backgroundColor: pal[3] }] },
    options: { plugins: { legend: { display: false } }, scales: { x: { title: { display: true, text: 'Bytes' }, grid: { display: false } }, y: { beginAtZero: true } } },
  });

  dataTable($('#commsTable'), [
    { label: 'Source', html: r => hostChip(r.src) },
    { label: 'Destination', html: r => hostChip(r.dst) },
    { label: 'Packets', key: 'packets', align: 'num', fmt: fmtNum },
    { label: 'Bytes', key: 'bytes', align: 'num', fmt: fmtBytes },
  ], d.communications, { pageSize: 8, sortCol: 2 });
}

function renderTimeline() {
  const t = state.data.timeline, metric = $('#timelineMetric').value, pal = palette();
  const withSeconds = t.bucket_seconds < 60;
  const labels = t.points.map(p => new Date(p.t * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: withSeconds ? '2-digit' : undefined }));
  $('#timelineHint').textContent = `One point = ${t.bucket_seconds}s of traffic.`;
  if (metric === 'packets') {
    const ds = [['TCP', 'tcp', pal[0]], ['UDP', 'udp', pal[1]], ['Other', 'other', pal[3]]].map(([label, key, color]) => ({
      label, data: t.points.map(p => p[key]), borderColor: color, backgroundColor: color + '66', fill: true, tension: .25, pointRadius: 0,
    }));
    chart('timelineChart', { type: 'line', data: { labels, datasets: ds },
      options: { interaction: { mode: 'index', intersect: false }, scales: { y: { stacked: true, beginAtZero: true }, x: { ticks: { maxTicksLimit: 10 } } } } });
  } else {
    chart('timelineChart', { type: 'line',
      data: { labels, datasets: [{ label: 'Throughput', data: t.points.map(p => Math.round(p.bytes * 8 / t.bucket_seconds)), borderColor: pal[2], backgroundColor: pal[2] + '55', fill: true, tension: .25, pointRadius: 0 }] },
      options: { interaction: { mode: 'index', intersect: false }, plugins: { legend: { display: false }, tooltip: { callbacks: { label: c => fmtBits(c.parsed.y) } } },
                 scales: { y: { beginAtZero: true, ticks: { callback: v => fmtBits(v) } }, x: { ticks: { maxTicksLimit: 10 } } } } });
  }
}

/* ------------------------------------------------------------ hosts & flows */
const scopeBadge = s => badge(s, s === 'public' ? 'public' : s === 'private' ? 'private' : '');

function renderHosts() {
  const d = state.data;
  dataTable($('#hostsTable'), [
    { label: 'Host', html: r => mono(r.ip), value: r => r.ip },
    { label: 'Scope', html: r => scopeBadge(r.scope), value: r => r.scope },
    { label: 'OS guess', key: 'os_guess' },
    { label: 'MAC', value: r => r.macs.join(', '), html: r => esc(r.macs.join(', ')) || '<span class="muted">n/a</span>' },
    { label: 'Services', value: r => r.services.join(', ') },
    { label: 'Peers', key: 'peers', align: 'num' },
    { label: 'Pkts out', key: 'packets_sent', align: 'num', fmt: fmtNum },
    { label: 'Pkts in', key: 'packets_recv', align: 'num', fmt: fmtNum },
    { label: 'Sent', key: 'bytes_sent', align: 'num', fmt: fmtBytes },
    { label: 'Received', key: 'bytes_recv', align: 'num', fmt: fmtBytes },
    { label: 'Total', key: 'total_bytes', align: 'num', fmt: fmtBytes },
  ], d.hosts, { pageSize: 15, sortCol: 10, onRow: r => showHost(r.ip) });
  if (state.selectedHost) showHost(state.selectedHost, false);
}

function showHost(ip, navigate = true) {
  const d = state.data, h = d.hosts.find(x => x.ip === ip);
  if (!h) return;
  state.selectedHost = ip;
  if (navigate && state.tab !== 'hosts') switchTab('hosts');
  const box = $('#hostDetail');
  box.hidden = false;
  const related = d.security.findings.filter(f => f.hosts.includes(ip));
  box.innerHTML = `<div class="card-head"><h3>${esc(ip)} ${scopeBadge(h.scope)}</h3>
      <button class="btn ghost" type="button" id="closeHost">Close</button></div>
    <div class="detail-grid">
      <div><span>OS guess (TTL ${esc(h.ttl ?? '?')})</span>${esc(h.os_guess)}</div>
      <div><span>MAC addresses</span>${esc(h.macs.join(', ') || 'n/a')}</div>
      <div><span>Services offered</span>${esc(h.services.join(', ') || 'none seen')}</div>
      <div><span>Peers</span>${fmtNum(h.peers)}</div>
      <div><span>Sent</span>${fmtBytes(h.bytes_sent)} · ${fmtNum(h.packets_sent)} pkts</div>
      <div><span>Received</span>${fmtBytes(h.bytes_recv)} · ${fmtNum(h.packets_recv)} pkts</div>
      <div><span>First seen</span>${esc(fmtTime(h.first_seen))}</div>
      <div><span>Last seen</span>${esc(fmtTime(h.last_seen))}</div>
    </div>
    ${related.length ? `<h3>Security findings</h3><p>${related.map(f => badge(f.severity, f.severity) + esc(f.title)).join('<br>')}</p>` : ''}
    <h3>Conversations</h3><div id="hostConvs"></div>`;
  $('#closeHost').onclick = () => { state.selectedHost = null; box.hidden = true; };
  dataTable($('#hostConvs'), convColumns(ip), d.conversations.filter(c => c.a === ip || c.b === ip),
    { pageSize: 8, sortCol: 4, search: false, empty: 'No conversations recorded for this host.' });
  box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function convColumns(self) {
  return [
    { label: 'Endpoint A', html: r => hostChip(r.a), value: r => r.a },
    { label: 'Endpoint B', html: r => hostChip(r.b), value: r => r.b },
    { label: 'Protocols', html: r => r.protocols.map(p => badge(p)).join(''), value: r => r.protocols.join(',') },
    { label: 'Packets', key: 'packets', align: 'num', fmt: fmtNum },
    { label: 'Bytes', key: 'bytes', align: 'num', fmt: fmtBytes },
    { label: 'A → B', key: 'bytes_a_to_b', align: 'num', fmt: fmtBytes },
    { label: 'B → A', key: 'bytes_b_to_a', align: 'num', fmt: fmtBytes },
    { label: 'Duration', key: 'duration_seconds', align: 'num', fmt: fmtDur },
  ];
}

const renderConversations = () => dataTable($('#convTable'), convColumns(), state.data.conversations, { pageSize: 15, sortCol: 4 });

/* ---------------------------------------------------------------------- DNS */
function renderDns() {
  const dns = state.data.dns, pal = palette();
  $('#dnsKpis').innerHTML = kpiHtml([
    ['Queries', fmtNum(dns.queries), `${fmtNum(dns.responses)} responses`],
    ['Unique names', fmtNum(dns.unique_domains)],
    ['NXDOMAIN', fmtNum(dns.nxdomain), 'name not found'],
    ['Resolvers', fmtNum(dns.servers.length), dns.servers[0] ? `busiest: ${dns.servers[0].ip}` : ''],
    ['Suspicious domains', fmtNum(dns.suspicious.length), 'tunnelling / DGA hints'],
  ]);
  const top = dns.top_domains.slice(0, 10);
  const short = n => (n.length > 34 ? n.slice(0, 32) + '…' : n);
  hbar('dnsTopChart', top.map(t => short(t.name)), [{ label: 'Queries', data: top.map(t => t.count), backgroundColor: pal[0] }]);
  doughnut('dnsTypeChart', dns.query_types.map(t => t.name), dns.query_types.map(t => t.count));
  doughnut('dnsRcodeChart', dns.response_codes.map(t => t.name), dns.response_codes.map(t => t.count));
  $('#dnsSuspiciousCard').hidden = !dns.suspicious.length;
  dataTable($('#dnsSuspicious'), [
    { label: 'Base domain', html: r => mono(r.domain), value: r => r.domain },
    { label: 'Distinct names', key: 'distinct_names', align: 'num' },
    { label: 'Queries', key: 'queries', align: 'num' },
    { label: 'Example', html: r => mono(r.sample), value: r => r.sample },
  ], dns.suspicious, { search: false });
  dataTable($('#dnsResolved'), [
    { label: 'Name', html: r => mono(r.name), value: r => r.name },
    { label: 'Addresses', value: r => r.addresses.join(', ') },
  ], dns.resolutions, { pageSize: 10, empty: 'No A/AAAA answers were captured.' });
}

/* ------------------------------------------------------------------ web/TLS */
function renderWeb() {
  const { http, tls } = state.data, pal = palette();
  $('#webKpis').innerHTML = kpiHtml([
    ['HTTP requests', fmtNum(http.total_requests), 'unencrypted'],
    ['HTTP hosts', fmtNum(http.hosts.length)],
    ['TLS records', fmtNum(tls.records)],
    ['TLS server names', fmtNum(tls.server_names.length), 'from ClientHello SNI'],
  ]);
  dataTable($('#httpTable'), [
    { label: 'Method', html: r => badge(r.method) , value: r => r.method },
    { label: 'Host', key: 'host' },
    { label: 'Path', html: r => mono(r.path), value: r => r.path },
    { label: 'Count', key: 'count', align: 'num' },
    { label: 'Clients', html: r => r.clients.map(hostChip).join(' '), value: r => r.clients.join(',') },
  ], http.requests, { pageSize: 8, empty: 'No plain HTTP requests found.' });
  dataTable($('#tlsTable'), [
    { label: 'Server name', html: r => mono(r.name), value: r => r.name },
    { label: 'Hellos', key: 'hellos', align: 'num' },
    { label: 'Clients', html: r => r.clients.map(hostChip).join(' '), value: r => r.clients.join(',') },
  ], tls.server_names, { pageSize: 10, empty: 'No TLS handshakes with SNI found.' });
  dataTable($('#uaTable'), [
    { label: 'User agent', key: 'agent' },
    { label: 'Count', key: 'count', align: 'num' },
  ], http.user_agents, { search: false, empty: 'No user agents seen.' });
  const codes = http.status_codes;
  chart('statusChart', {
    type: 'bar',
    data: { labels: codes.map(c => c.code), datasets: [{ label: 'Responses', data: codes.map(c => c.count), backgroundColor: pal[4] }] },
    options: { plugins: { legend: { display: false }, title: { display: true, text: 'HTTP status codes' } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } },
  });
}

/* ----------------------------------------------------------------- security */
function evidenceText(v) {
  if (Array.isArray(v)) return v.join(', ');
  if (v && typeof v === 'object') return Object.entries(v).map(([k, x]) => `${k}: ${x}`).join(', ');
  return String(v);
}

function renderSecurity() {
  const d = state.data, sec = d.security;
  const color = { Low: '--ok', Moderate: '--warn', High: '--bad', Critical: '--crit' }[sec.risk_level];
  const circ = 2 * Math.PI * 52;
  $('#riskCard').innerHTML = `<div class="risk-ring"><svg width="120" height="120" viewBox="0 0 120 120">
      <circle cx="60" cy="60" r="52" fill="none" stroke="${cssVar('--border')}" stroke-width="10"/>
      <circle cx="60" cy="60" r="52" fill="none" stroke="${cssVar(color)}" stroke-width="10" stroke-linecap="round"
        stroke-dasharray="${(circ * sec.risk_score / 100).toFixed(1)} ${circ.toFixed(1)}"/></svg>
      <div class="num"><div>${sec.risk_score}<small>${esc(sec.risk_level)} risk</small></div></div></div>
    <div><h3 style="margin-bottom:6px">Heuristic risk score</h3>
      <p class="hint" style="max-width:520px">Derived from the detections below. It flags traffic worth a closer look; it is not proof of compromise.</p>
      <div class="sev-counts">${['critical', 'high', 'medium', 'low'].map(k => `<div>${badge(k, k)}<b>${sec.counts[k]}</b></div>`).join('')}</div></div>`;
  $('#findings').innerHTML = sec.findings.length ? sec.findings.map(f => `
    <article class="finding ${esc(f.severity)}">
      <h4>${badge(f.severity, f.severity)}${esc(f.title)}<span class="cat">${esc(f.category)}</span></h4>
      <p>${esc(f.description)}</p>
      <div>${f.hosts.map(hostChip).join('')}</div>
      <dl class="evidence">${Object.entries(f.evidence).map(([k, v]) => `<dt>${esc(k.replace(/_/g, ' '))}</dt><dd>${esc(evidenceText(v))}</dd>`).join('')}</dl>
    </article>`).join('') : '<div class="card"><p class="muted">No suspicious behaviour detected in this capture.</p></div>';

  dataTable($('#arpTable'), [
    { label: 'IP', html: r => mono(r.ip), value: r => r.ip },
    { label: 'MAC address(es)', value: r => r.macs.join(', ') },
    { label: 'Packets', key: 'packets', align: 'num' },
    { label: 'Status', html: r => (r.conflict ? badge('conflict', 'bad') : badge('ok')), value: r => (r.conflict ? 'conflict' : 'ok') },
  ], d.arp.table, { search: false, pageSize: 10, empty: 'No ARP traffic.' });
  dataTable($('#insecureTable'), [
    { label: 'Service', html: r => badge(r.service, 'medium'), value: r => r.service },
    { label: 'Packets', key: 'packets', align: 'num' },
    { label: 'Example connection', html: r => mono(r.connections[0] ? r.connections[0].pair : ''), value: r => (r.connections[0] || {}).pair },
  ], d.insecure_services, { search: false, empty: 'No cleartext services seen.' });
  dataTable($('#icmpTable'), [{ label: 'Type', key: 'name' }, { label: 'Count', key: 'count', align: 'num' }],
    d.icmp.types, { search: false, empty: 'No ICMP traffic.' });
}

/* ------------------------------------------------------------- network map */
/**
 * Fruchterman–Reingold layout, run to completion so the result is a static picture.
 * Input/output use the same shape as common graph components:
 *   nodes: [{ label, center: { x, y } }]   edges: [{ source, target }]  (indexes)
 */
function layoutGraph(count, edges, width, height) {
  const k = Math.sqrt((width * height) / Math.max(count, 1)) * 0.7;
  const pos = Array.from({ length: count }, (_, i) => {
    const r = Math.sqrt(i + 1) * k * 0.45, a = i * 2.399963;
    return { x: width / 2 + Math.cos(a) * r, y: height / 2 + Math.sin(a) * r };
  });
  let temp = width / 8;
  for (let it = 0; it < 320; it++) {
    const disp = pos.map(() => ({ x: 0, y: 0 }));
    for (let i = 0; i < count; i++) {
      for (let j = i + 1; j < count; j++) {
        const dx = pos[i].x - pos[j].x, dy = pos[i].y - pos[j].y;
        const dist = Math.max(Math.hypot(dx, dy), 0.01), f = (k * k) / dist;
        disp[i].x += dx / dist * f; disp[i].y += dy / dist * f;
        disp[j].x -= dx / dist * f; disp[j].y -= dy / dist * f;
      }
    }
    for (const e of edges) {
      const dx = pos[e.source].x - pos[e.target].x, dy = pos[e.source].y - pos[e.target].y;
      const dist = Math.max(Math.hypot(dx, dy), 0.01), f = (dist * dist) / k;
      disp[e.source].x -= dx / dist * f; disp[e.source].y -= dy / dist * f;
      disp[e.target].x += dx / dist * f; disp[e.target].y += dy / dist * f;
    }
    for (let i = 0; i < count; i++) {
      disp[i].x += (width / 2 - pos[i].x) * 0.04;
      disp[i].y += (height / 2 - pos[i].y) * 0.04;
      const len = Math.max(Math.hypot(disp[i].x, disp[i].y), 0.01), lim = Math.min(len, temp);
      pos[i].x += disp[i].x / len * lim;
      pos[i].y += disp[i].y / len * lim;
    }
    temp *= 0.985;
  }
  const pad = 60;
  const xs = pos.map(p => p.x), ys = pos.map(p => p.y);
  const minX = Math.min(...xs), maxX = Math.max(...xs), minY = Math.min(...ys), maxY = Math.max(...ys);
  const scale = Math.min((width - 2 * pad) / (maxX - minX || 1), (height - 2 * pad) / (maxY - minY || 1));
  const ox = (width - (maxX - minX) * scale) / 2, oy = (height - (maxY - minY) * scale) / 2;
  return pos.map(p => ({ x: +(ox + (p.x - minX) * scale).toFixed(1), y: +(oy + (p.y - minY) * scale).toFixed(1) }));
}

const PROTO_COLOR = { TCP: '--c1', UDP: '--c2', ICMP: '--c3', ARP: '--c4' };
const protoColor = protos => cssVar(PROTO_COLOR[['TCP', 'UDP', 'ICMP', 'ARP'].find(p => protos.includes(p))] || '--c8');
const SVGNS = 'http://www.w3.org/2000/svg';
function svgEl(name, attrs = {}, parent) {
  const el = document.createElementNS(SVGNS, name);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  if (parent) parent.append(el);
  return el;
}

function buildMapModel() {
  const limit = Number($('#mapLimit').value), g = state.data.graph, W = 800, H = 520;
  const nodesIn = g.nodes.slice(0, limit), index = new Map(nodesIn.map((n, i) => [n.id, i]));
  const edges = g.links.filter(l => index.has(l.source) && index.has(l.target)).map(l => ({
    source: index.get(l.source), target: index.get(l.target),
    packets: l.packets, bytes: l.bytes, protocols: l.protocols,
  }));
  const centers = layoutGraph(nodesIn.length, edges, W, H);
  const flows = new Map(state.data.conversations.map(c => [`${c.a}|${c.b}`, c]));
  edges.forEach(e => {
    const a = nodesIn[e.source].id, b = nodesIn[e.target].id;
    const c = flows.get(`${a}|${b}`) || flows.get(`${b}|${a}`);
    // Directional volume as seen from the edge's source -> target orientation.
    e.forward = c ? (c.a === a ? c.bytes_a_to_b : c.bytes_b_to_a) : e.bytes;
    e.backward = c ? e.bytes - e.forward : 0;
  });
  return {
    W, H,
    nodes: nodesIn.map((n, i) => ({ label: i, center: centers[i], ...n })),
    edges,
  };
}

function renderMap() {
  const svg = $('#graphSvg');
  const model = state.mapModel = buildMapModel();
  state.mapNode = null;
  svg.replaceChildren();
  if (!model.nodes.length) { $('#mapNodes').innerHTML = '<div class="empty">No hosts to draw.</div>'; return; }

  const maxBytes = Math.max(...model.nodes.map(n => n.bytes), 1);
  const maxPackets = Math.max(...model.edges.map(e => e.packets), 1);
  const edgeLayer = svgEl('g', {}, svg), packetLayer = svgEl('g', {}, svg), nodeLayer = svgEl('g', {}, svg);
  const radius = n => 13 + 13 * Math.sqrt(n.bytes / maxBytes);

  model.edges.forEach((e, i) => {
    const a = model.nodes[e.source].center, b = model.nodes[e.target].center;
    const d = `M ${a.x} ${a.y} L ${b.x} ${b.y}`;
    const title = `${model.nodes[e.source].id} ⇄ ${model.nodes[e.target].id}\n${fmtNum(e.packets)} packets · ${fmtBytes(e.bytes)}\n${e.protocols.join(', ')}`;
    const line = svgEl('line', { class: 'edge', x1: a.x, y1: a.y, x2: b.x, y2: b.y,
      'stroke-width': (1 + 4 * Math.sqrt(e.packets / maxPackets)).toFixed(2) }, edgeLayer);
    e.lineEl = line;
    const hit = svgEl('line', { class: 'edge-hit', x1: a.x, y1: a.y, x2: b.x, y2: b.y }, edgeLayer);
    svgEl('title', {}, hit).textContent = title;

    const color = protoColor(e.protocols);
    e.dots = [];
    [[d, e.forward], [`M ${b.x} ${b.y} L ${a.x} ${a.y}`, e.backward]].forEach(([path, vol], dir) => {
      if (vol <= 0) return;
      const count = 1 + Math.min(2, Math.floor(2 * Math.sqrt(e.packets / maxPackets)));
      const dur = 2.4 + ((i * 7 + dir * 3) % 10) * 0.28;
      for (let k = 0; k < count; k++) {
        const dot = svgEl('circle', { class: 'packet', r: 3.2, fill: color }, packetLayer);
        svgEl('animateMotion', { dur: `${dur}s`, begin: `${(k * dur / count + i * 0.13).toFixed(2)}s`, repeatCount: 'indefinite', path }, dot);
        e.dots.push(dot);
      }
    });
  });

  model.nodes.forEach(n => {
    const g = svgEl('g', { class: `node ${n.scope === 'public' ? 'public' : ''} ${n.flagged ? 'flagged' : ''}`,
      tabindex: 0, role: 'button', 'aria-label': `Device ${n.label}: ${n.id}` }, nodeLayer);
    svgEl('circle', { class: 'body', cx: n.center.x, cy: n.center.y, r: radius(n).toFixed(1) }, g);
    svgEl('text', { class: 'idx', x: n.center.x, y: n.center.y }, g).textContent = n.label;
    svgEl('text', { class: 'ip', x: n.center.x, y: n.center.y + radius(n) + 12 }, g).textContent = n.id;
    svgEl('title', {}, g).textContent = `${n.id} · ${n.scope} · ${fmtBytes(n.bytes)}${n.flagged ? ' · flagged by security checks' : ''}`;
    g.addEventListener('click', ev => { ev.stopPropagation(); selectMapNode(n.label); });
    g.addEventListener('keydown', ev => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); selectMapNode(n.label); } });
    n.el = g;
  });
  svg.onclick = () => selectMapNode(null);

  $('#mapLegend').innerHTML = [['TCP', '--c1'], ['UDP', '--c2'], ['ICMP', '--c3'], ['ARP', '--c4']]
    .map(([p, c]) => `<span><i style="background:${cssVar(c)}"></i>${p}</span>`).join('')
    + `<span><i style="border:2px solid ${cssVar('--bad')};background:none"></i>flagged</span>`;
  dataTable($('#mapNodes'), [
    { label: '#', key: 'label', align: 'num' },
    { label: 'Device', html: r => mono(r.id), value: r => r.id },
    { label: 'Traffic', key: 'bytes', align: 'num', fmt: fmtBytes },
  ], model.nodes, { pageSize: 10, sortCol: 0, sortDir: 1, search: false, onRow: r => selectMapNode(r.label) });
  applyPause();
  selectMapNode(null);
}

function selectMapNode(label) {
  const m = state.mapModel;
  if (!m) return;
  state.mapNode = label === state.mapNode ? null : label;
  const sel = state.mapNode;
  const linked = new Set(sel === null ? [] : [sel]);
  m.edges.forEach(e => {
    const on = sel !== null && (e.source === sel || e.target === sel);
    if (on) { linked.add(e.source); linked.add(e.target); }
    e.lineEl.classList.toggle('active', on);
    e.lineEl.classList.toggle('dim', sel !== null && !on);
    e.dots.forEach(d => d.classList.toggle('dim', sel !== null && !on));
  });
  m.nodes.forEach(n => {
    n.el.classList.toggle('selected', n.label === sel);
    n.el.classList.toggle('dim', sel !== null && !linked.has(n.label));
  });
  const box = $('#mapDetail');
  if (sel === null) { box.innerHTML = '<p class="muted">Select a node to see its neighbours.</p>'; return; }
  const n = m.nodes[sel];
  const neighbours = m.edges.filter(e => e.source === sel || e.target === sel).map(e => {
    const other = m.nodes[e.source === sel ? e.target : e.source];
    return { other, e, out: e.source === sel ? e.forward : e.backward, inn: e.source === sel ? e.backward : e.forward };
  }).sort((a, b) => b.e.bytes - a.e.bytes);
  box.innerHTML = `<h4>#${n.label} · ${esc(n.id)} ${scopeBadge(n.scope)}</h4>
    <div class="muted">${esc(n.os)} · ${fmtBytes(n.bytes)} total${n.flagged ? ' · ' + badge('flagged', 'bad') : ''}</div>
    <ul>${neighbours.map(x => `<li>#${x.other.label} ${mono(x.other.id)}: ${fmtNum(x.e.packets)} pkts<br><span class="muted">sent ${fmtBytes(x.out)} · received ${fmtBytes(x.inn)}</span></li>`).join('') || '<li class="muted">No routes within the displayed devices.</li>'}</ul>
    <p style="margin:10px 0 0"><button class="btn ghost" type="button" data-host="${esc(n.id)}">Open host details</button></p>`;
}

let packetsPaused = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
function applyPause() {
  const svg = $('#graphSvg');
  if (typeof svg.pauseAnimations === 'function') packetsPaused ? svg.pauseAnimations() : svg.unpauseAnimations();
  $('#mapPause').textContent = packetsPaused ? 'Resume packets' : 'Pause packets';
}

function copyGraphJson() {
  const m = state.mapModel;
  if (!m) return;
  const payload = {
    nodes: m.nodes.map(n => ({ label: n.label, center: n.center })),
    edges: m.edges.map(e => ({ source: e.source, target: e.target })),
  };
  const text = JSON.stringify(payload, null, 2);
  (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject())
    .then(() => banner('Graph JSON copied (nodes with label/center, edges with source/target).', 'info'))
    .catch(() => banner('Clipboard unavailable in this browser context.', 'error'));
  setTimeout(() => { if (!$('#banner').classList.contains('error')) banner(''); }, 3500);
}

/* ------------------------------------------------------------ orchestration */
const RENDERERS = {
  overview: renderOverview, map: renderMap, hosts: renderHosts,
  conversations: renderConversations, dns: renderDns, web: renderWeb, security: renderSecurity,
};

function renderTab(name) {
  if (!state.data || state.rendered.has(name)) return;
  state.rendered.add(name);
  RENDERERS[name]();
}

function switchTab(name) {
  state.tab = name;
  $$('.tab-btn').forEach(b => { const on = b.dataset.tab === name; b.classList.toggle('active', on); b.setAttribute('aria-selected', on); });
  $$('.tab').forEach(t => t.classList.toggle('active', t.id === `tab-${name}`));
  renderTab(name);
}

function renderAll() {
  const d = state.data;
  state.rendered.clear();
  const pill = $('#findingsPill');
  pill.hidden = !d.security.findings.length;
  pill.textContent = d.security.findings.length;
  renderTab(state.tab);
  $('#footer').textContent = `${d.meta.file} · ${fmtBytes(d.meta.size_bytes)} · analyzed in ${d.meta.analysis_seconds}s`
    + (d.meta.truncated ? ' · truncated at the packet limit' : '')
    + (d.meta.malformed_packets ? ` · ${d.meta.malformed_packets} unreadable packets skipped` : '');
  if (d.meta.truncated) banner('This capture exceeded the packet limit, so only the first packets were analyzed.', 'info');
  buildExportMenu();
}

function buildExportMenu() {
  const f = encodeURIComponent(state.file);
  const items = [['Full analysis (JSON)', `/api/export/json?file=${f}`],
    ...['hosts', 'conversations', 'findings', 'dns', 'ports'].map(s => [`${s[0].toUpperCase()}${s.slice(1)} (CSV)`, `/api/export/csv?section=${s}&file=${f}`])];
  $('#exportMenu').innerHTML = items.map(([label, href]) => `<a href="${href}" download>${esc(label)}</a>`).join('');
}

async function loadFiles(preferred) {
  const { files, default: def } = await api('/api/files');
  state.files = files;
  const names = files.map(f => f.name);
  state.file = [preferred, state.file, def, names[0]].find(n => n && names.includes(n)) || null;
  $('#fileSelect').innerHTML = files.map(f => `<option value="${esc(f.name)}" ${f.name === state.file ? 'selected' : ''}>${esc(f.name)} (${fmtBytes(f.size_bytes)})</option>`).join('');
  const current = files.find(f => f.name === state.file);
  $('#deleteBtn').hidden = !current || current.is_default;
}

async function load() {
  if (!state.file) { banner('No capture files yet. Upload a .pcap or .pcapng file to begin.', 'info'); return; }
  $('#loading').hidden = false;
  try {
    state.data = await api(`/api/analysis?file=${encodeURIComponent(state.file)}`);
    state.selectedHost = null;
    $('#hostDetail').hidden = true;
    banner('');
    renderAll();
  } catch (err) {
    banner(err.message, 'error');
  } finally {
    $('#loading').hidden = true;
  }
}

async function uploadCapture(file) {
  if (!file) return;
  banner(`Uploading ${file.name}…`, 'info');
  const body = new FormData();
  body.append('file', file);
  try {
    const res = await api('/api/upload', { method: 'POST', body });
    await loadFiles(res.file);
    await load();
  } catch (err) {
    banner(err.message, 'error');
  }
}

function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  try { localStorage.setItem('netscope-theme', theme); } catch (_) { /* storage blocked */ }
  if (state.data) { state.rendered.clear(); Object.values(state.charts).forEach(c => c.destroy()); state.charts = {}; renderTab(state.tab); }
}

function initEvents() {
  $$('.tab-btn').forEach(b => b.addEventListener('click', () => switchTab(b.dataset.tab)));
  $('#fileSelect').addEventListener('change', async e => { state.file = e.target.value; await loadFiles(state.file); load(); });
  $('#uploadBtn').addEventListener('click', () => $('#fileInput').click());
  $('#fileInput').addEventListener('change', e => { uploadCapture(e.target.files[0]); e.target.value = ''; });
  $('#refreshBtn').addEventListener('click', load);
  $('#deleteBtn').addEventListener('click', async () => {
    if (!confirm(`Delete ${state.file}?`)) return;
    try { await api(`/api/files/${encodeURIComponent(state.file)}`, { method: 'DELETE' }); state.file = null; await loadFiles(); await load(); }
    catch (err) { banner(err.message, 'error'); }
  });
  $('#themeBtn').addEventListener('click', () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
  $('#timelineMetric').addEventListener('change', renderTimeline);
  $('#mapLimit').addEventListener('change', renderMap);
  $('#mapPause').addEventListener('click', () => { packetsPaused = !packetsPaused; applyPause(); });
  $('#mapCopy').addEventListener('click', copyGraphJson);

  const menu = $('#exportMenu'), btn = $('#exportBtn');
  btn.addEventListener('click', e => { e.stopPropagation(); menu.hidden = !menu.hidden; btn.setAttribute('aria-expanded', !menu.hidden); });
  document.addEventListener('click', () => { menu.hidden = true; btn.setAttribute('aria-expanded', false); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') menu.hidden = true; });

  // Any element carrying data-host jumps to that host's detail view.
  document.addEventListener('click', e => {
    const el = e.target.closest('[data-host]');
    if (el) { e.stopPropagation(); showHost(el.dataset.host); }
  });

  let depth = 0;
  const zone = $('#dropzone');
  window.addEventListener('dragenter', e => { if (e.dataTransfer && [...e.dataTransfer.types].includes('Files')) { depth++; zone.hidden = false; } });
  window.addEventListener('dragleave', () => { depth = Math.max(0, depth - 1); if (!depth) zone.hidden = true; });
  window.addEventListener('dragover', e => e.preventDefault());
  window.addEventListener('drop', e => { e.preventDefault(); depth = 0; zone.hidden = true; uploadCapture(e.dataTransfer.files[0]); });
}

(async function init() {
  let theme = null;
  try { theme = localStorage.getItem('netscope-theme'); } catch (_) { /* storage blocked */ }
  document.documentElement.dataset.theme = theme || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  initEvents();
  try {
    await loadFiles();
    await load();
  } catch (err) {
    banner(err.message, 'error');
  }
})();
