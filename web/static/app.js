const log = document.getElementById('log');
const details = document.getElementById('details');
const filterControls = Array.from(document.querySelectorAll('#filters input[type=checkbox]'));

function getEnabledFilters() {
  return filterControls.filter(c => c.checked).map(c => c.dataset.proto);
}

function matchesFilter(obj) {
  const enabled = getEnabledFilters();
  if (!obj.protocol_queue || obj.protocol_queue.length === 0) return true;
  return obj.protocol_queue.some(p => enabled.includes(p));
}

function appendLine(obj) {
  const div = document.createElement('div');
  div.className = 'line';
  div.textContent = `Frame #${obj.packet_num ?? '?'}: ${ (obj.protocol_queue || []).join(', ') }`;
  div.dataset.payload = JSON.stringify(obj);
  div.onclick = () => {
    details.textContent = JSON.stringify(obj, null, 2);
  };
  log.appendChild(div);
  // keep scrolled to bottom
  log.scrollTop = log.scrollHeight;
}

const protocol = (location.protocol === 'https:') ? 'wss' : 'ws';
const ws = new WebSocket(`${protocol}://${location.hostname}:8765/`);

ws.onopen = () => {
  const msg = { note: '[connected to sniffer]' };
  appendLine({ packet_num: '---', protocol_queue: ['info'], _note: msg.note });
};
ws.onclose = () => appendLine({ packet_num: '---', protocol_queue: ['info'], _note: '[disconnected]' });
ws.onerror = (e) => appendLine({ packet_num: '---', protocol_queue: ['info'], _note: '[websocket error]' });

ws.onmessage = (ev) => {
  try {
    const obj = JSON.parse(ev.data);
    if (!matchesFilter(obj)) return;
    appendLine(obj);
  } catch (e) {
    appendLine({ packet_num: '---', protocol_queue: ['raw'], _note: ev.data });
  }
};

// Re-render log when filters change (simple strategy: clear and wait for new frames)
filterControls.forEach(c => c.addEventListener('change', () => {
  // Recompute visible frames when filters change
  refreshVisible();
}));

// Search and export
const searchInput = document.getElementById('search');
const exportBtn = document.getElementById('export');
let visibleFrames = []; // store parsed objects currently displayed
let allFrames = []; // store all received frames (for re-filtering)
const hostListEl = document.getElementById('host-list');
const seenHosts = new Set();
let activeHost = null; // currently selected host to filter by

function appendLine(obj) {
  const div = document.createElement('div');
  div.className = 'line';
  div.dataset.payload = JSON.stringify(obj);

  // Left: title
  const title = document.createElement('span');
  title.textContent = `Frame #${obj.packet_num ?? '?'}: ${ (obj.protocol_queue || []).join(', ') }`;
  title.style.marginRight = '8px';
  div.appendChild(title);

  // Middle: host link (if available)
  if (obj.host) {
    const hostLink = document.createElement('a');
    hostLink.className = 'host-link';
    hostLink.textContent = obj.host;
    // Determine scheme
    let scheme = 'http';
    try {
      if ((obj.tcp && obj.tcp.dport === 443) || (obj.protocol_queue && obj.protocol_queue.includes('TLS'))) {
        scheme = 'https';
      }
    } catch (e) { scheme = 'http'; }
    let href = obj.host;
    if (!/^https?:\/\//i.test(href)) href = `${scheme}://${obj.host}`;
    hostLink.href = href;
    hostLink.target = '_blank';
    hostLink.rel = 'noopener noreferrer';
    hostLink.style.marginRight = '8px';
    // Prevent clicking the link from selecting the frame (stop propagation)
    hostLink.addEventListener('click', (ev) => ev.stopPropagation());
    div.appendChild(hostLink);
  }

  // Click to show details
  div.addEventListener('click', () => {
    details.textContent = JSON.stringify(obj, null, 2);
  });

  log.appendChild(div);
  visibleFrames.push(obj);
  // keep scrolled to bottom
  log.scrollTop = log.scrollHeight;
}

function hostMatches(obj) {
  if (!activeHost) return true;
  return !!obj.host && obj.host === activeHost;
}

function renderHosts() {
  hostListEl.innerHTML = '';
  // add a clear entry
  const clearLi = document.createElement('li');
  clearLi.textContent = activeHost ? 'Clear filter' : 'All hosts';
  clearLi.style.fontStyle = 'italic';
  clearLi.addEventListener('click', () => {
    activeHost = null;
    renderHosts();
    refreshVisible();
  });
  hostListEl.appendChild(clearLi);

  Array.from(seenHosts).sort().forEach(h => {
    const li = document.createElement('li');
    li.textContent = h;
    li.addEventListener('click', () => {
      activeHost = (activeHost === h) ? null : h;
      renderHosts();
      refreshVisible();
    });
    if (activeHost === h) li.classList.add('selected');
    hostListEl.appendChild(li);
  });
}

function refreshVisible() {
  visibleFrames = [];
  log.innerHTML = '';
  details.textContent = '';
  for (const obj of allFrames) {
    if (!matchesFilter(obj)) continue;
    if (!matchesSearch(obj)) continue;
    if (!hostMatches(obj)) continue;
    appendLine(obj);
  }
}

function matchesSearch(obj) {
  const q = searchInput.value.trim().toLowerCase();
  if (!q) return true;
  const text = JSON.stringify(obj).toLowerCase();
  return text.includes(q);
}

ws.onmessage = (ev) => {
  try {
    const obj = JSON.parse(ev.data);
    // store master list
    allFrames.push(obj);
    // update hosts
    if (obj.host) {
      if (!seenHosts.has(obj.host)) {
        seenHosts.add(obj.host);
        renderHosts();
      }
    }
    // display if it matches current UI filters/search/host selection
    if (!matchesFilter(obj)) return;
    if (!matchesSearch(obj)) return;
    if (!hostMatches(obj)) return;
    appendLine(obj);
  } catch (e) {
    appendLine({ packet_num: '---', protocol_queue: ['raw'], _note: ev.data });
  }
};

searchInput.addEventListener('input', () => {
  // re-filter the full list using current search + filters
  refreshVisible();
});

exportBtn.addEventListener('click', () => {
  const data = visibleFrames.map(x => JSON.stringify(x)).join('\n');
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'sniffer_export.jsonl';
  a.click();
  URL.revokeObjectURL(url);
});

// Simulation: inject sample frames (HTTP and TLS SNI) for UI testing
const simulateBtn = document.getElementById('simulate');
function makeHttpFrame(num, host) {
  return {
    packet_num: num,
    protocol_queue: ['Ethernet', 'IPv4', 'TCP', 'HTTP'],
    frame_length: 200,
    epoch_time: Date.now() / 1000,
    ipv4: { src: '192.0.2.1', dst: '93.184.216.34' },
    tcp: { sport: 52344, dport: 80 },
    host: host,
    data: `GET / HTTP/1.1\r\nHost: ${host}\r\n\r\n`,
  };
}

function makeTlsFrame(num, sni) {
  return {
    packet_num: num,
    protocol_queue: ['Ethernet', 'IPv4', 'TCP', 'TLS'],
    frame_length: 300,
    epoch_time: Date.now() / 1000,
    ipv4: { src: '192.0.2.1', dst: '151.101.1.69' },
    tcp: { sport: 52345, dport: 443 },
    host: sni,
    data: null,
  };
}

simulateBtn.addEventListener('click', () => {
  const samples = [
    makeHttpFrame('sim-1', 'example.com'),
    makeTlsFrame('sim-2', 'www.github.com'),
    makeHttpFrame('sim-3', 'news.example.org'),
    makeTlsFrame('sim-4', 'api.example.net'),
  ];
  samples.forEach(s => {
    // behave like a received frame: add to master list and hosts, then maybe display
    allFrames.push(s);
    if (s.host && !seenHosts.has(s.host)) {
      seenHosts.add(s.host);
      renderHosts();
    }
    if (matchesFilter(s) && matchesSearch(s) && hostMatches(s)) {
      appendLine(s);
    }
  });
});
