/* ============================================================================
 *  ui.js - interface layer
 *  Reads input, calls the Subnet engine, and renders the results.
 *  Only numbers produced by the engine are inserted as HTML, never raw user
 *  text (errors use textContent), so there is no injection surface.
 * ========================================================================== */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const EXAMPLES = ['192.168.1.10/24', '10.0.0.0/8', '172.16.5.4/12', '203.0.113.77/27', '100.64.1.1/10', '8.8.8.8/32'];
  let current = null;                                      

  
  function setStatus(msg, isError) {
    const el = $('status');
    el.textContent = (isError ? '[ERR] ' : '[ OK] ') + msg;
    el.className = 'status ' + (isError ? 'err' : 'ok');
  }

  let toastTimer;
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 1400);
  }

  /* ---- Rendering --------------------------------------------------------- */
  /** Summary cards; clicking a card copies its value. */
  function renderSummary(r) {
    const fields = [
      ['Network', r.networkStr], ['Broadcast', r.broadcastStr],
      ['Subnet mask', r.maskStr], ['Wildcard', r.wildcardStr],
      ['CIDR', `${r.networkStr}/${r.prefix}`], ['Class', r.cls],
      ['First host', r.firstStr], ['Last host', r.lastStr],
      ['Usable hosts', r.usable.toLocaleString()], ['Total addresses', r.total.toLocaleString()],
    ];
    $('summary').innerHTML = fields
      .map(([k, v]) => `<button class="card" data-copy="${v}" title="Click to copy"><span>${k}</span><b>${v}</b></button>`)
      .join('');
  }

  /** Binary view: network bits are cyan, host bits are green. */
  function renderBinary(r) {
    const bits = (n) => Subnet.toBinary(n).replace(/\./g, '').split('')
      .map((b, i) => `<i class="${i < r.prefix ? 'net' : 'host'}">${b}</i>${(i + 1) % 8 === 0 && i < 31 ? '<u>.</u>' : ''}`)
      .join('');
    $('binary').innerHTML =
      `<div><span>IP</span><code>${bits(r.ip)}</code></div>` +
      `<div><span>MASK</span><code>${bits(r.mask)}</code></div>` +
      `<div><span>NET</span><code>${bits(r.network)}</code></div>`;
  }

  /** Security notes: classification, nmap commands and sweep-time estimate. */
  function renderIntel(r) {
    const c = Subnet.classify(r.network);
    const target = `${r.networkStr}/${r.prefix}`;
    $('intel').innerHTML =
      `<p><span class="tag ${c.risk}">${c.label}</span></p><p class="note">${c.note}</p>` +
      `<p class="kv">Host discovery <code>nmap -sn ${target}</code></p>` +
      `<p class="kv">Top-port scan <code>nmap -sS --top-ports 100 ${target}</code></p>` +
      `<p class="kv">Est. sweep time <b>${Subnet.scanTime(r.total)}</b> <em>(1 probe per address at 1,000 pps)</em></p>`;
  }

  /** Subnet splitter table (capped at 256 rows by the engine). */
  function renderSplit() {
    const np = parseInt($('newPrefix').value, 10);
    if (!current || isNaN(np) || np < current.prefix || np > 32) {
      $('splitInfo').textContent = `Enter a prefix between /${current ? current.prefix : 0} and /32.`;
      $('splitBody').innerHTML = '';
      return;
    }
    const { count, rows } = Subnet.split(current, np);
    $('splitInfo').textContent = `${count.toLocaleString()} subnet(s) of /${np}` + (count > rows.length ? ` (showing first ${rows.length})` : '');
    $('splitBody').innerHTML = rows
      .map((s, i) => `<tr><td>${i + 1}</td><td>${s.networkStr}/${s.prefix}</td><td>${s.firstStr} - ${s.lastStr}</td><td>${s.broadcastStr}</td><td>${s.usable.toLocaleString()}</td></tr>`)
      .join('');
  }

  /* ---- Main action ------------------------------------------------------- */
  function analyze() {
    const parsed = Subnet.parse($('target').value);
    if (parsed.error) { setStatus(parsed.error, true); $('results').hidden = true; return; }
    current = Subnet.calc(parsed.ip, parsed.prefix);
    setStatus(`parsed ${current.ipStr}/${current.prefix} in network ${current.networkStr}`);
    renderSummary(current); renderBinary(current); renderIntel(current);
    $('newPrefix').value = Math.min(current.prefix + 1, 32);  // sensible splitter default
    renderSplit();
    $('results').hidden = false;
  }

  /* ---- Event wiring ------------------------------------------------------ */
  $('chips').innerHTML = EXAMPLES.map((e) => `<button class="chip" data-ex="${e}">${e}</button>`).join('');
  $('analyze').addEventListener('click', analyze);
  $('target').addEventListener('keydown', (e) => { if (e.key === 'Enter') analyze(); });
  $('newPrefix').addEventListener('input', renderSplit);

  document.addEventListener('click', (e) => {
    const ex = e.target.closest('[data-ex]');
    if (ex) { $('target').value = ex.dataset.ex; analyze(); return; }
    const cp = e.target.closest('[data-copy]');
    if (cp && navigator.clipboard) navigator.clipboard.writeText(cp.dataset.copy).then(() => toast(`Copied ${cp.dataset.copy}`));
  });

  analyze();                                               // show a result on first load
})();
/* ============================================================================
 *  ui.js - interface layer
 *  Reads input, calls the Subnet engine, and renders the results.
 *  Only numbers produced by the engine are inserted as HTML, never raw user
 *  text (errors use textContent), so there is no injection surface.
 * ========================================================================== */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const EXAMPLES = ['192.168.1.10/24', '10.0.0.0/8', '172.16.5.4/12', '203.0.113.77/27', '100.64.1.1/10', '8.8.8.8/32'];
  let current = null;                                      

  
  function setStatus(msg, isError) {
    const el = $('status');
    el.textContent = (isError ? '[ERR] ' : '[ OK] ') + msg;
    el.className = 'status ' + (isError ? 'err' : 'ok');
  }

  let toastTimer;
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 1400);
  }

  /* ---- Rendering --------------------------------------------------------- */
  /** Summary cards; clicking a card copies its value. */
  function renderSummary(r) {
    const fields = [
      ['Network', r.networkStr], ['Broadcast', r.broadcastStr],
      ['Subnet mask', r.maskStr], ['Wildcard', r.wildcardStr],
      ['CIDR', `${r.networkStr}/${r.prefix}`], ['Class', r.cls],
      ['First host', r.firstStr], ['Last host', r.lastStr],
      ['Usable hosts', r.usable.toLocaleString()], ['Total addresses', r.total.toLocaleString()],
    ];
    $('summary').innerHTML = fields
      .map(([k, v]) => `<button class="card" data-copy="${v}" title="Click to copy"><span>${k}</span><b>${v}</b></button>`)
      .join('');
  }

  /** Binary view: network bits are cyan, host bits are green. */
  function renderBinary(r) {
    const bits = (n) => Subnet.toBinary(n).replace(/\./g, '').split('')
      .map((b, i) => `<i class="${i < r.prefix ? 'net' : 'host'}">${b}</i>${(i + 1) % 8 === 0 && i < 31 ? '<u>.</u>' : ''}`)
      .join('');
    $('binary').innerHTML =
      `<div><span>IP</span><code>${bits(r.ip)}</code></div>` +
      `<div><span>MASK</span><code>${bits(r.mask)}</code></div>` +
      `<div><span>NET</span><code>${bits(r.network)}</code></div>`;
  }

  /** Security notes: classification, nmap commands and sweep-time estimate. */
  function renderIntel(r) {
    const c = Subnet.classify(r.network);
    const target = `${r.networkStr}/${r.prefix}`;
    $('intel').innerHTML =
      `<p><span class="tag ${c.risk}">${c.label}</span></p><p class="note">${c.note}</p>` +
      `<p class="kv">Host discovery <code>nmap -sn ${target}</code></p>` +
      `<p class="kv">Top-port scan <code>nmap -sS --top-ports 100 ${target}</code></p>` +
      `<p class="kv">Est. sweep time <b>${Subnet.scanTime(r.total)}</b> <em>(1 probe per address at 1,000 pps)</em></p>`;
  }

  /** Subnet splitter table (capped at 256 rows by the engine). */
  function renderSplit() {
    const np = parseInt($('newPrefix').value, 10);
    if (!current || isNaN(np) || np < current.prefix || np > 32) {
      $('splitInfo').textContent = `Enter a prefix between /${current ? current.prefix : 0} and /32.`;
      $('splitBody').innerHTML = '';
      return;
    }
    const { count, rows } = Subnet.split(current, np);
    $('splitInfo').textContent = `${count.toLocaleString()} subnet(s) of /${np}` + (count > rows.length ? ` (showing first ${rows.length})` : '');
    $('splitBody').innerHTML = rows
      .map((s, i) => `<tr><td>${i + 1}</td><td>${s.networkStr}/${s.prefix}</td><td>${s.firstStr} - ${s.lastStr}</td><td>${s.broadcastStr}</td><td>${s.usable.toLocaleString()}</td></tr>`)
      .join('');
  }

  /* ---- Main action ------------------------------------------------------- */
  function analyze() {
    const parsed = Subnet.parse($('target').value);
    if (parsed.error) { setStatus(parsed.error, true); $('results').hidden = true; return; }
    current = Subnet.calc(parsed.ip, parsed.prefix);
    setStatus(`parsed ${current.ipStr}/${current.prefix} in network ${current.networkStr}`);
    renderSummary(current); renderBinary(current); renderIntel(current);
    $('newPrefix').value = Math.min(current.prefix + 1, 32);  // sensible splitter default
    renderSplit();
    $('results').hidden = false;
  }

  /* ---- Event wiring ------------------------------------------------------ */
  $('chips').innerHTML = EXAMPLES.map((e) => `<button class="chip" data-ex="${e}">${e}</button>`).join('');
  $('analyze').addEventListener('click', analyze);
  $('target').addEventListener('keydown', (e) => { if (e.key === 'Enter') analyze(); });
  $('newPrefix').addEventListener('input', renderSplit);

  document.addEventListener('click', (e) => {
    const ex = e.target.closest('[data-ex]');
    if (ex) { $('target').value = ex.dataset.ex; analyze(); return; }
    const cp = e.target.closest('[data-copy]');
    if (cp && navigator.clipboard) navigator.clipboard.writeText(cp.dataset.copy).then(() => toast(`Copied ${cp.dataset.copy}`));
  });

  analyze();                                               // show a result on first load
})();
/* ============================================================================
 *  ui.js - interface layer
 *  Reads input, calls the Subnet engine, and renders the results.
 *  Only numbers produced by the engine are inserted as HTML, never raw user
 *  text (errors use textContent), so there is no injection surface.
 * ========================================================================== */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const EXAMPLES = ['192.168.1.10/24', '10.0.0.0/8', '172.16.5.4/12', '203.0.113.77/27', '100.64.1.1/10', '8.8.8.8/32'];
  let current = null;                                      

  
  function setStatus(msg, isError) {
    const el = $('status');
    el.textContent = (isError ? '[ERR] ' : '[ OK] ') + msg;
    el.className = 'status ' + (isError ? 'err' : 'ok');
  }

  let toastTimer;
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 1400);
  }

  /* ---- Rendering --------------------------------------------------------- */
  /** Summary cards; clicking a card copies its value. */
  function renderSummary(r) {
    const fields = [
      ['Network', r.networkStr], ['Broadcast', r.broadcastStr],
      ['Subnet mask', r.maskStr], ['Wildcard', r.wildcardStr],
      ['CIDR', `${r.networkStr}/${r.prefix}`], ['Class', r.cls],
      ['First host', r.firstStr], ['Last host', r.lastStr],
      ['Usable hosts', r.usable.toLocaleString()], ['Total addresses', r.total.toLocaleString()],
    ];
    $('summary').innerHTML = fields
      .map(([k, v]) => `<button class="card" data-copy="${v}" title="Click to copy"><span>${k}</span><b>${v}</b></button>`)
      .join('');
  }

  /** Binary view: network bits are cyan, host bits are green. */
  function renderBinary(r) {
    const bits = (n) => Subnet.toBinary(n).replace(/\./g, '').split('')
      .map((b, i) => `<i class="${i < r.prefix ? 'net' : 'host'}">${b}</i>${(i + 1) % 8 === 0 && i < 31 ? '<u>.</u>' : ''}`)
      .join('');
    $('binary').innerHTML =
      `<div><span>IP</span><code>${bits(r.ip)}</code></div>` +
      `<div><span>MASK</span><code>${bits(r.mask)}</code></div>` +
      `<div><span>NET</span><code>${bits(r.network)}</code></div>`;
  }

  /** Security notes: classification, nmap commands and sweep-time estimate. */
  function renderIntel(r) {
    const c = Subnet.classify(r.network);
    const target = `${r.networkStr}/${r.prefix}`;
    $('intel').innerHTML =
      `<p><span class="tag ${c.risk}">${c.label}</span></p><p class="note">${c.note}</p>` +
      `<p class="kv">Host discovery <code>nmap -sn ${target}</code></p>` +
      `<p class="kv">Top-port scan <code>nmap -sS --top-ports 100 ${target}</code></p>` +
      `<p class="kv">Est. sweep time <b>${Subnet.scanTime(r.total)}</b> <em>(1 probe per address at 1,000 pps)</em></p>`;
  }

  /** Subnet splitter table (capped at 256 rows by the engine). */
  function renderSplit() {
    const np = parseInt($('newPrefix').value, 10);
    if (!current || isNaN(np) || np < current.prefix || np > 32) {
      $('splitInfo').textContent = `Enter a prefix between /${current ? current.prefix : 0} and /32.`;
      $('splitBody').innerHTML = '';
      return;
    }
    const { count, rows } = Subnet.split(current, np);
    $('splitInfo').textContent = `${count.toLocaleString()} subnet(s) of /${np}` + (count > rows.length ? ` (showing first ${rows.length})` : '');
    $('splitBody').innerHTML = rows
      .map((s, i) => `<tr><td>${i + 1}</td><td>${s.networkStr}/${s.prefix}</td><td>${s.firstStr} - ${s.lastStr}</td><td>${s.broadcastStr}</td><td>${s.usable.toLocaleString()}</td></tr>`)
      .join('');
  }

  /* ---- Main action ------------------------------------------------------- */
  function analyze() {
    const parsed = Subnet.parse($('target').value);
    if (parsed.error) { setStatus(parsed.error, true); $('results').hidden = true; return; }
    current = Subnet.calc(parsed.ip, parsed.prefix);
    setStatus(`parsed ${current.ipStr}/${current.prefix} in network ${current.networkStr}`);
    renderSummary(current); renderBinary(current); renderIntel(current);
    $('newPrefix').value = Math.min(current.prefix + 1, 32);  // sensible splitter default
    renderSplit();
    $('results').hidden = false;
  }

  /* ---- Event wiring ------------------------------------------------------ */
  $('chips').innerHTML = EXAMPLES.map((e) => `<button class="chip" data-ex="${e}">${e}</button>`).join('');
  $('analyze').addEventListener('click', analyze);
  $('target').addEventListener('keydown', (e) => { if (e.key === 'Enter') analyze(); });
  $('newPrefix').addEventListener('input', renderSplit);

  document.addEventListener('click', (e) => {
    const ex = e.target.closest('[data-ex]');
    if (ex) { $('target').value = ex.dataset.ex; analyze(); return; }
    const cp = e.target.closest('[data-copy]');
    if (cp && navigator.clipboard) navigator.clipboard.writeText(cp.dataset.copy).then(() => toast(`Copied ${cp.dataset.copy}`));
  });

  analyze();                                               // show a result on first load
})();
/* ============================================================================
 *  ui.js - interface layer
 *  Reads input, calls the Subnet engine, and renders the results.
 *  Only numbers produced by the engine are inserted as HTML, never raw user
 *  text (errors use textContent), so there is no injection surface.
 * ========================================================================== */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const EXAMPLES = ['192.168.1.10/24', '10.0.0.0/8', '172.16.5.4/12', '203.0.113.77/27', '100.64.1.1/10', '8.8.8.8/32'];
  let current = null;                                      

  
  function setStatus(msg, isError) {
    const el = $('status');
    el.textContent = (isError ? '[ERR] ' : '[ OK] ') + msg;
    el.className = 'status ' + (isError ? 'err' : 'ok');
  }

  let toastTimer;
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 1400);
  }

  /* ---- Rendering --------------------------------------------------------- */
  /** Summary cards; clicking a card copies its value. */
  function renderSummary(r) {
    const fields = [
      ['Network', r.networkStr], ['Broadcast', r.broadcastStr],
      ['Subnet mask', r.maskStr], ['Wildcard', r.wildcardStr],
      ['CIDR', `${r.networkStr}/${r.prefix}`], ['Class', r.cls],
      ['First host', r.firstStr], ['Last host', r.lastStr],
      ['Usable hosts', r.usable.toLocaleString()], ['Total addresses', r.total.toLocaleString()],
    ];
    $('summary').innerHTML = fields
      .map(([k, v]) => `<button class="card" data-copy="${v}" title="Click to copy"><span>${k}</span><b>${v}</b></button>`)
      .join('');
  }

  /** Binary view: network bits are cyan, host bits are green. */
  function renderBinary(r) {
    const bits = (n) => Subnet.toBinary(n).replace(/\./g, '').split('')
      .map((b, i) => `<i class="${i < r.prefix ? 'net' : 'host'}">${b}</i>${(i + 1) % 8 === 0 && i < 31 ? '<u>.</u>' : ''}`)
      .join('');
    $('binary').innerHTML =
      `<div><span>IP</span><code>${bits(r.ip)}</code></div>` +
      `<div><span>MASK</span><code>${bits(r.mask)}</code></div>` +
      `<div><span>NET</span><code>${bits(r.network)}</code></div>`;
  }

  /** Security notes: classification, nmap commands and sweep-time estimate. */
  function renderIntel(r) {
    const c = Subnet.classify(r.network);
    const target = `${r.networkStr}/${r.prefix}`;
    $('intel').innerHTML =
      `<p><span class="tag ${c.risk}">${c.label}</span></p><p class="note">${c.note}</p>` +
      `<p class="kv">Host discovery <code>nmap -sn ${target}</code></p>` +
      `<p class="kv">Top-port scan <code>nmap -sS --top-ports 100 ${target}</code></p>` +
      `<p class="kv">Est. sweep time <b>${Subnet.scanTime(r.total)}</b> <em>(1 probe per address at 1,000 pps)</em></p>`;
  }

  /** Subnet splitter table (capped at 256 rows by the engine). */
  function renderSplit() {
    const np = parseInt($('newPrefix').value, 10);
    if (!current || isNaN(np) || np < current.prefix || np > 32) {
      $('splitInfo').textContent = `Enter a prefix between /${current ? current.prefix : 0} and /32.`;
      $('splitBody').innerHTML = '';
      return;
    }
    const { count, rows } = Subnet.split(current, np);
    $('splitInfo').textContent = `${count.toLocaleString()} subnet(s) of /${np}` + (count > rows.length ? ` (showing first ${rows.length})` : '');
    $('splitBody').innerHTML = rows
      .map((s, i) => `<tr><td>${i + 1}</td><td>${s.networkStr}/${s.prefix}</td><td>${s.firstStr} - ${s.lastStr}</td><td>${s.broadcastStr}</td><td>${s.usable.toLocaleString()}</td></tr>`)
      .join('');
  }

  /* ---- Main action ------------------------------------------------------- */
  function analyze() {
    const parsed = Subnet.parse($('target').value);
    if (parsed.error) { setStatus(parsed.error, true); $('results').hidden = true; return; }
    current = Subnet.calc(parsed.ip, parsed.prefix);
    setStatus(`parsed ${current.ipStr}/${current.prefix} in network ${current.networkStr}`);
    renderSummary(current); renderBinary(current); renderIntel(current);
    $('newPrefix').value = Math.min(current.prefix + 1, 32);  // sensible splitter default
    renderSplit();
    $('results').hidden = false;
  }

  /* ---- Event wiring ------------------------------------------------------ */
  $('chips').innerHTML = EXAMPLES.map((e) => `<button class="chip" data-ex="${e}">${e}</button>`).join('');
  $('analyze').addEventListener('click', analyze);
  $('target').addEventListener('keydown', (e) => { if (e.key === 'Enter') analyze(); });
  $('newPrefix').addEventListener('input', renderSplit);

  document.addEventListener('click', (e) => {
    const ex = e.target.closest('[data-ex]');
    if (ex) { $('target').value = ex.dataset.ex; analyze(); return; }
    const cp = e.target.closest('[data-copy]');
    if (cp && navigator.clipboard) navigator.clipboard.writeText(cp.dataset.copy).then(() => toast(`Copied ${cp.dataset.copy}`));
  });

  analyze();                                               // show a result on first load
})();
/* ============================================================================
 *  ui.js - interface layer
 *  Reads input, calls the Subnet engine, and renders the results.
 *  Only numbers produced by the engine are inserted as HTML, never raw user
 *  text (errors use textContent), so there is no injection surface.
 * ========================================================================== */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const EXAMPLES = ['192.168.1.10/24', '10.0.0.0/8', '172.16.5.4/12', '203.0.113.77/27', '100.64.1.1/10', '8.8.8.8/32'];
  let current = null;                                      

  
  function setStatus(msg, isError) {
    const el = $('status');
    el.textContent = (isError ? '[ERR] ' : '[ OK] ') + msg;
    el.className = 'status ' + (isError ? 'err' : 'ok');
  }

  let toastTimer;
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 1400);
  }

  /* ---- Rendering --------------------------------------------------------- */
  /** Summary cards; clicking a card copies its value. */
  function renderSummary(r) {
    const fields = [
      ['Network', r.networkStr], ['Broadcast', r.broadcastStr],
      ['Subnet mask', r.maskStr], ['Wildcard', r.wildcardStr],
      ['CIDR', `${r.networkStr}/${r.prefix}`], ['Class', r.cls],
      ['First host', r.firstStr], ['Last host', r.lastStr],
      ['Usable hosts', r.usable.toLocaleString()], ['Total addresses', r.total.toLocaleString()],
    ];
    $('summary').innerHTML = fields
      .map(([k, v]) => `<button class="card" data-copy="${v}" title="Click to copy"><span>${k}</span><b>${v}</b></button>`)
      .join('');
  }

  /** Binary view: network bits are cyan, host bits are green. */
  function renderBinary(r) {
    const bits = (n) => Subnet.toBinary(n).replace(/\./g, '').split('')
      .map((b, i) => `<i class="${i < r.prefix ? 'net' : 'host'}">${b}</i>${(i + 1) % 8 === 0 && i < 31 ? '<u>.</u>' : ''}`)
      .join('');
    $('binary').innerHTML =
      `<div><span>IP</span><code>${bits(r.ip)}</code></div>` +
      `<div><span>MASK</span><code>${bits(r.mask)}</code></div>` +
      `<div><span>NET</span><code>${bits(r.network)}</code></div>`;
  }

  /** Security notes: classification, nmap commands and sweep-time estimate. */
  function renderIntel(r) {
    const c = Subnet.classify(r.network);
    const target = `${r.networkStr}/${r.prefix}`;
    $('intel').innerHTML =
      `<p><span class="tag ${c.risk}">${c.label}</span></p><p class="note">${c.note}</p>` +
      `<p class="kv">Host discovery <code>nmap -sn ${target}</code></p>` +
      `<p class="kv">Top-port scan <code>nmap -sS --top-ports 100 ${target}</code></p>` +
      `<p class="kv">Est. sweep time <b>${Subnet.scanTime(r.total)}</b> <em>(1 probe per address at 1,000 pps)</em></p>`;
  }

  /** Subnet splitter table (capped at 256 rows by the engine). */
  function renderSplit() {
    const np = parseInt($('newPrefix').value, 10);
    if (!current || isNaN(np) || np < current.prefix || np > 32) {
      $('splitInfo').textContent = `Enter a prefix between /${current ? current.prefix : 0} and /32.`;
      $('splitBody').innerHTML = '';
      return;
    }
    const { count, rows } = Subnet.split(current, np);
    $('splitInfo').textContent = `${count.toLocaleString()} subnet(s) of /${np}` + (count > rows.length ? ` (showing first ${rows.length})` : '');
    $('splitBody').innerHTML = rows
      .map((s, i) => `<tr><td>${i + 1}</td><td>${s.networkStr}/${s.prefix}</td><td>${s.firstStr} - ${s.lastStr}</td><td>${s.broadcastStr}</td><td>${s.usable.toLocaleString()}</td></tr>`)
      .join('');
  }

  /* ---- Main action ------------------------------------------------------- */
  function analyze() {
    const parsed = Subnet.parse($('target').value);
    if (parsed.error) { setStatus(parsed.error, true); $('results').hidden = true; return; }
    current = Subnet.calc(parsed.ip, parsed.prefix);
    setStatus(`parsed ${current.ipStr}/${current.prefix} in network ${current.networkStr}`);
    renderSummary(current); renderBinary(current); renderIntel(current);
    $('newPrefix').value = Math.min(current.prefix + 1, 32);  // sensible splitter default
    renderSplit();
    $('results').hidden = false;
  }

  /* ---- Event wiring ------------------------------------------------------ */
  $('chips').innerHTML = EXAMPLES.map((e) => `<button class="chip" data-ex="${e}">${e}</button>`).join('');
  $('analyze').addEventListener('click', analyze);
  $('target').addEventListener('keydown', (e) => { if (e.key === 'Enter') analyze(); });
  $('newPrefix').addEventListener('input', renderSplit);

  document.addEventListener('click', (e) => {
    const ex = e.target.closest('[data-ex]');
    if (ex) { $('target').value = ex.dataset.ex; analyze(); return; }
    const cp = e.target.closest('[data-copy]');
    if (cp && navigator.clipboard) navigator.clipboard.writeText(cp.dataset.copy).then(() => toast(`Copied ${cp.dataset.copy}`));
  });

  analyze();                                               // show a result on first load
})();
/* ============================================================================
 *  ui.js - interface layer
 *  Reads input, calls the Subnet engine, and renders the results.
 *  Only numbers produced by the engine are inserted as HTML, never raw user
 *  text (errors use textContent), so there is no injection surface.
 * ========================================================================== */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const EXAMPLES = ['192.168.1.10/24', '10.0.0.0/8', '172.16.5.4/12', '203.0.113.77/27', '100.64.1.1/10', '8.8.8.8/32'];
  let current = null;                                      

  
  function setStatus(msg, isError) {
    const el = $('status');
    el.textContent = (isError ? '[ERR] ' : '[ OK] ') + msg;
    el.className = 'status ' + (isError ? 'err' : 'ok');
  }

  let toastTimer;
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 1400);
  }

  /* ---- Rendering --------------------------------------------------------- */
  /** Summary cards; clicking a card copies its value. */
  function renderSummary(r) {
    const fields = [
      ['Network', r.networkStr], ['Broadcast', r.broadcastStr],
      ['Subnet mask', r.maskStr], ['Wildcard', r.wildcardStr],
      ['CIDR', `${r.networkStr}/${r.prefix}`], ['Class', r.cls],
      ['First host', r.firstStr], ['Last host', r.lastStr],
      ['Usable hosts', r.usable.toLocaleString()], ['Total addresses', r.total.toLocaleString()],
    ];
    $('summary').innerHTML = fields
      .map(([k, v]) => `<button class="card" data-copy="${v}" title="Click to copy"><span>${k}</span><b>${v}</b></button>`)
      .join('');
  }

  /** Binary view: network bits are cyan, host bits are green. */
  function renderBinary(r) {
    const bits = (n) => Subnet.toBinary(n).replace(/\./g, '').split('')
      .map((b, i) => `<i class="${i < r.prefix ? 'net' : 'host'}">${b}</i>${(i + 1) % 8 === 0 && i < 31 ? '<u>.</u>' : ''}`)
      .join('');
    $('binary').innerHTML =
      `<div><span>IP</span><code>${bits(r.ip)}</code></div>` +
      `<div><span>MASK</span><code>${bits(r.mask)}</code></div>` +
      `<div><span>NET</span><code>${bits(r.network)}</code></div>`;
  }

  /** Security notes: classification, nmap commands and sweep-time estimate. */
  function renderIntel(r) {
    const c = Subnet.classify(r.network);
    const target = `${r.networkStr}/${r.prefix}`;
    $('intel').innerHTML =
      `<p><span class="tag ${c.risk}">${c.label}</span></p><p class="note">${c.note}</p>` +
      `<p class="kv">Host discovery <code>nmap -sn ${target}</code></p>` +
      `<p class="kv">Top-port scan <code>nmap -sS --top-ports 100 ${target}</code></p>` +
      `<p class="kv">Est. sweep time <b>${Subnet.scanTime(r.total)}</b> <em>(1 probe per address at 1,000 pps)</em></p>`;
  }

  /** Subnet splitter table (capped at 256 rows by the engine). */
  function renderSplit() {
    const np = parseInt($('newPrefix').value, 10);
    if (!current || isNaN(np) || np < current.prefix || np > 32) {
      $('splitInfo').textContent = `Enter a prefix between /${current ? current.prefix : 0} and /32.`;
      $('splitBody').innerHTML = '';
      return;
    }
    const { count, rows } = Subnet.split(current, np);
    $('splitInfo').textContent = `${count.toLocaleString()} subnet(s) of /${np}` + (count > rows.length ? ` (showing first ${rows.length})` : '');
    $('splitBody').innerHTML = rows
      .map((s, i) => `<tr><td>${i + 1}</td><td>${s.networkStr}/${s.prefix}</td><td>${s.firstStr} - ${s.lastStr}</td><td>${s.broadcastStr}</td><td>${s.usable.toLocaleString()}</td></tr>`)
      .join('');
  }

  /* ---- Main action ------------------------------------------------------- */
  function analyze() {
    const parsed = Subnet.parse($('target').value);
    if (parsed.error) { setStatus(parsed.error, true); $('results').hidden = true; return; }
    current = Subnet.calc(parsed.ip, parsed.prefix);
    setStatus(`parsed ${current.ipStr}/${current.prefix} in network ${current.networkStr}`);
    renderSummary(current); renderBinary(current); renderIntel(current);
    $('newPrefix').value = Math.min(current.prefix + 1, 32);  // sensible splitter default
    renderSplit();
    $('results').hidden = false;
  }

  /* ---- Event wiring ------------------------------------------------------ */
  $('chips').innerHTML = EXAMPLES.map((e) => `<button class="chip" data-ex="${e}">${e}</button>`).join('');
  $('analyze').addEventListener('click', analyze);
  $('target').addEventListener('keydown', (e) => { if (e.key === 'Enter') analyze(); });
  $('newPrefix').addEventListener('input', renderSplit);

  document.addEventListener('click', (e) => {
    const ex = e.target.closest('[data-ex]');
    if (ex) { $('target').value = ex.dataset.ex; analyze(); return; }
    const cp = e.target.closest('[data-copy]');
    if (cp && navigator.clipboard) navigator.clipboard.writeText(cp.dataset.copy).then(() => toast(`Copied ${cp.dataset.copy}`));
  });

  analyze();                                               // show a result on first load
})();
/* ============================================================================
 *  ui.js - interface layer
 *  Reads input, calls the Subnet engine, and renders the results.
 *  Only numbers produced by the engine are inserted as HTML, never raw user
 *  text (errors use textContent), so there is no injection surface.
 * ========================================================================== */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const EXAMPLES = ['192.168.1.10/24', '10.0.0.0/8', '172.16.5.4/12', '203.0.113.77/27', '100.64.1.1/10', '8.8.8.8/32'];
  let current = null;                                      

  
  function setStatus(msg, isError) {
    const el = $('status');
    el.textContent = (isError ? '[ERR] ' : '[ OK] ') + msg;
    el.className = 'status ' + (isError ? 'err' : 'ok');
  }

  let toastTimer;
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 1400);
  }

  /* ---- Rendering --------------------------------------------------------- */
  /** Summary cards; clicking a card copies its value. */
  function renderSummary(r) {
    const fields = [
      ['Network', r.networkStr], ['Broadcast', r.broadcastStr],
      ['Subnet mask', r.maskStr], ['Wildcard', r.wildcardStr],
      ['CIDR', `${r.networkStr}/${r.prefix}`], ['Class', r.cls],
      ['First host', r.firstStr], ['Last host', r.lastStr],
      ['Usable hosts', r.usable.toLocaleString()], ['Total addresses', r.total.toLocaleString()],
    ];
    $('summary').innerHTML = fields
      .map(([k, v]) => `<button class="card" data-copy="${v}" title="Click to copy"><span>${k}</span><b>${v}</b></button>`)
      .join('');
  }

  /** Binary view: network bits are cyan, host bits are green. */
  function renderBinary(r) {
    const bits = (n) => Subnet.toBinary(n).replace(/\./g, '').split('')
      .map((b, i) => `<i class="${i < r.prefix ? 'net' : 'host'}">${b}</i>${(i + 1) % 8 === 0 && i < 31 ? '<u>.</u>' : ''}`)
      .join('');
    $('binary').innerHTML =
      `<div><span>IP</span><code>${bits(r.ip)}</code></div>` +
      `<div><span>MASK</span><code>${bits(r.mask)}</code></div>` +
      `<div><span>NET</span><code>${bits(r.network)}</code></div>`;
  }

  /** Security notes: classification, nmap commands and sweep-time estimate. */
  function renderIntel(r) {
    const c = Subnet.classify(r.network);
    const target = `${r.networkStr}/${r.prefix}`;
    $('intel').innerHTML =
      `<p><span class="tag ${c.risk}">${c.label}</span></p><p class="note">${c.note}</p>` +
      `<p class="kv">Host discovery <code>nmap -sn ${target}</code></p>` +
      `<p class="kv">Top-port scan <code>nmap -sS --top-ports 100 ${target}</code></p>` +
      `<p class="kv">Est. sweep time <b>${Subnet.scanTime(r.total)}</b> <em>(1 probe per address at 1,000 pps)</em></p>`;
  }

  /** Subnet splitter table (capped at 256 rows by the engine). */
  function renderSplit() {
    const np = parseInt($('newPrefix').value, 10);
    if (!current || isNaN(np) || np < current.prefix || np > 32) {
      $('splitInfo').textContent = `Enter a prefix between /${current ? current.prefix : 0} and /32.`;
      $('splitBody').innerHTML = '';
      return;
    }
    const { count, rows } = Subnet.split(current, np);
    $('splitInfo').textContent = `${count.toLocaleString()} subnet(s) of /${np}` + (count > rows.length ? ` (showing first ${rows.length})` : '');
    $('splitBody').innerHTML = rows
      .map((s, i) => `<tr><td>${i + 1}</td><td>${s.networkStr}/${s.prefix}</td><td>${s.firstStr} - ${s.lastStr}</td><td>${s.broadcastStr}</td><td>${s.usable.toLocaleString()}</td></tr>`)
      .join('');
  }

  /* ---- Main action ------------------------------------------------------- */
  function analyze() {
    const parsed = Subnet.parse($('target').value);
    if (parsed.error) { setStatus(parsed.error, true); $('results').hidden = true; return; }
    current = Subnet.calc(parsed.ip, parsed.prefix);
    setStatus(`parsed ${current.ipStr}/${current.prefix} in network ${current.networkStr}`);
    renderSummary(current); renderBinary(current); renderIntel(current);
    $('newPrefix').value = Math.min(current.prefix + 1, 32);  // sensible splitter default
    renderSplit();
    $('results').hidden = false;
  }

  /* ---- Event wiring ------------------------------------------------------ */
  $('chips').innerHTML = EXAMPLES.map((e) => `<button class="chip" data-ex="${e}">${e}</button>`).join('');
  $('analyze').addEventListener('click', analyze);
  $('target').addEventListener('keydown', (e) => { if (e.key === 'Enter') analyze(); });
  $('newPrefix').addEventListener('input', renderSplit);

  document.addEventListener('click', (e) => {
    const ex = e.target.closest('[data-ex]');
    if (ex) { $('target').value = ex.dataset.ex; analyze(); return; }
    const cp = e.target.closest('[data-copy]');
    if (cp && navigator.clipboard) navigator.clipboard.writeText(cp.dataset.copy).then(() => toast(`Copied ${cp.dataset.copy}`));
  });

  analyze();                                               // show a result on first load
})();

