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
  // For now just clear the details/log so user sees new matches quickly.
  log.innerHTML = '';
  details.textContent = '';
}));

// Search and export
const searchInput = document.getElementById('search');
const exportBtn = document.getElementById('export');
let visibleFrames = []; // store parsed objects currently displayed

function appendLine(obj) {
  const div = document.createElement('div');
  div.className = 'line';
  div.textContent = `Frame #${obj.packet_num ?? '?'}: ${ (obj.protocol_queue || []).join(', ') }`;
  div.dataset.payload = JSON.stringify(obj);
  div.onclick = () => {
    details.textContent = JSON.stringify(obj, null, 2);
  };
  log.appendChild(div);
  visibleFrames.push(obj);
  // keep scrolled to bottom
  log.scrollTop = log.scrollHeight;
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
    if (!matchesFilter(obj)) return;
    if (!matchesSearch(obj)) return;
    appendLine(obj);
  } catch (e) {
    appendLine({ packet_num: '---', protocol_queue: ['raw'], _note: ev.data });
  }
};

searchInput.addEventListener('input', () => {
  // simple re-filter: clear and reset visibleFrames
  visibleFrames = [];
  log.innerHTML = '';
  details.textContent = '';
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
