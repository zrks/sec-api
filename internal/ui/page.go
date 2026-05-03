package ui

const Page = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DomainRiskDigest</title>
  <style>
    body { font-family: Inter, system-ui, sans-serif; margin: 0; background: #0b1020; color: #e5e7eb; }
    main { max-width: 1100px; margin: 0 auto; padding: 24px; }
    h1, h2 { margin: 0 0 12px; }
    .grid { display: grid; grid-template-columns: 320px 1fr; gap: 20px; }
    .card { background: #121933; border: 1px solid #26304f; border-radius: 12px; padding: 16px; }
    input, button, textarea { width: 100%; box-sizing: border-box; border-radius: 8px; border: 1px solid #31406a; background: #0f1730; color: #e5e7eb; padding: 10px 12px; }
    button { cursor: pointer; background: #2563eb; border-color: #2563eb; font-weight: 600; }
    button.secondary { background: #17213f; border-color: #31406a; }
    .stack { display: grid; gap: 10px; }
    .domain { padding: 12px; border: 1px solid #26304f; border-radius: 10px; background: #0e1530; }
    .row { display: flex; gap: 8px; flex-wrap: wrap; }
    .row button { width: auto; }
    pre { white-space: pre-wrap; word-break: break-word; background: #08101f; border-radius: 10px; padding: 14px; overflow: auto; }
    .ok { color: #4ade80; }
    .warn { color: #f59e0b; }
    .mono { font-family: ui-monospace, SFMono-Regular, monospace; }
    @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
<main>
  <div class="grid">
    <section class="card stack">
      <div>
        <h1>DomainRiskDigest</h1>
        <div class="warn">Local MVP test console</div>
      </div>
      <label class="stack">
        <span>Domain</span>
        <input id="domainInput" placeholder="example.com">
      </label>
      <button id="createBtn">Create Domain</button>
      <button id="refreshBtn" class="secondary">Refresh Domain List</button>
      <div id="status" class="mono"></div>
    </section>
    <section class="card stack">
      <h2>Domains</h2>
      <div id="domains" class="stack"></div>
      <h2>Selected Output</h2>
      <pre id="output">Select an action to inspect API responses.</pre>
    </section>
  </div>
</main>
<script>
const statusEl = document.getElementById('status');
const outputEl = document.getElementById('output');
const domainsEl = document.getElementById('domains');

function setStatus(text) { statusEl.textContent = text; }
function show(data) { outputEl.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2); }

async function request(path, options = {}) {
  const res = await fetch(path, options);
  const text = await res.text();
  let data = text;
  try { data = JSON.parse(text); } catch (_) {}
  if (!res.ok) {
    throw new Error(typeof data === 'string' ? data : JSON.stringify(data));
  }
  return data;
}

function ownershipNote(domain) {
  return '<div class="mono">Ownership verification is optional for future sensitive features.</div>';
}

function renderDomain(domain) {
  const wrapper = document.createElement('div');
  wrapper.className = 'domain stack';
  const status = domain.status ? domain.status : 'active';
  wrapper.innerHTML =
    '<div><strong>' + domain.domain + '</strong> <span class="ok">' + status + '</span></div>' +
    '<div class="mono">id: ' + domain.id + '</div>' +
    ownershipNote(domain) +
    '<div class="row">' +
      '<button data-action="detail">Details</button>' +
      '<button data-action="scan">Scan now</button>' +
      '<button data-action="report">Latest report</button>' +
    '</div>';
  wrapper.querySelectorAll('button').forEach((button) => {
    button.addEventListener('click', async () => {
      const action = button.dataset.action;
      try {
        setStatus(action + ' ' + domain.domain + '...');
        if (action === 'detail') show(await request('/api/v1/domains/' + domain.id));
        if (action === 'scan') show(await request('/api/v1/domains/' + domain.id + '/scan-now', { method: 'POST' }));
        if (action === 'report') show(await request('/api/v1/domains/' + domain.id + '/latest-report'));
        await loadDomains();
        setStatus('done');
      } catch (err) {
        setStatus('error');
        show(String(err));
      }
    });
  });
  return wrapper;
}

async function loadDomains() {
  const domains = await request('/api/v1/domains');
  domainsEl.innerHTML = '';
  if (!domains.length) {
    domainsEl.innerHTML = '<div class="warn">No domains yet.</div>';
    return;
  }
  domains.forEach((domain) => domainsEl.appendChild(renderDomain(domain)));
}

document.getElementById('createBtn').addEventListener('click', async () => {
  const domain = document.getElementById('domainInput').value.trim();
  if (!domain) return;
  try {
    setStatus('creating...');
    const result = await request('/api/v1/domains', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });
    show(result);
    document.getElementById('domainInput').value = '';
    await loadDomains();
    setStatus('created');
  } catch (err) {
    setStatus('error');
    show(String(err));
  }
});

document.getElementById('refreshBtn').addEventListener('click', async () => {
  try {
    setStatus('refreshing...');
    await loadDomains();
    setStatus('ready');
  } catch (err) {
    setStatus('error');
    show(String(err));
  }
});

loadDomains().then(() => setStatus('ready')).catch((err) => {
  setStatus('error');
  show(String(err));
});
</script>
</body>
</html>`
