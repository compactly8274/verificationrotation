async function loadServices() {
  const container = document.getElementById('services-container');
  container.innerHTML = '<article aria-busy="true"></article>';
  try {
    const res = await fetch('/api/services');
    const services = await res.json();
    renderServices(services);
  } catch (e) {
    container.innerHTML = '<p style="color:red">Failed to load services.</p>';
  }
}

function renderServices(services) {
  const container = document.getElementById('services-container');
  if (!services.length) {
    container.innerHTML = '<p>No services configured.</p>';
    return;
  }
  let html = '<div class="grid">';
  for (const svc of services) {
    const statusClass = svc.status;
    const ageText = svc.age_days !== null ? `${svc.age_days}d ago` : 'never';
    const staleWarning = svc.status === 'stale' ? ' <span class="badge stale">stale</span>' : '';
    html += `
      <article class="service-card">
        <header>
          <div>
            <h4><span class="status-dot ${statusClass}"></span>${svc.display_name}${staleWarning}</h4>
            <small class="hit-count">Refs: ${svc.hit_count} | Last rotated: ${ageText}</small>
          </div>
          <div>
            <button class="secondary outline" onclick="openModal('${svc.id}', '${svc.display_name}')">Rotate</button>
          </div>
        </header>
        ${svc.settings_url ? `<p><a href="${svc.settings_url}" target="_blank">Open settings</a></p>` : ''}
      </article>
    `;
  }
  html += '</div>';
  container.innerHTML = html;
}

async function loadScanStatus() {
  try {
    const res = await fetch('/api/scan-status');
    const data = await res.json();
    const badge = document.getElementById('scan-status-badge');
    const lastScan = document.getElementById('last-scan');
    if (data.in_progress) {
      badge.textContent = 'Scanning...';
      badge.className = 'badge';
    } else if (data.last_scan) {
      const d = new Date(data.last_scan);
      const mins = Math.floor((Date.now() - d) / 60000);
      badge.textContent = mins < 60 ? `${mins}m ago` : `${Math.floor(mins/60)}h ago`;
      badge.className = 'badge ok';
      lastScan.textContent = `Last scan: ${d.toLocaleString()}`;
    } else {
      badge.textContent = 'No scan yet';
      badge.className = 'badge';
    }
  } catch (e) {
    console.error('scan status error', e);
  }
}

function openModal(serviceId, displayName) {
  document.getElementById('modal-service-id').value = serviceId;
  document.getElementById('modal-title').textContent = `Rotate ${displayName}`;
  document.getElementById('modal-new-value').value = '';
  document.getElementById('modal-result').textContent = '';
  document.getElementById('rotate-modal').showModal();
}

function closeModal() {
  document.getElementById('rotate-modal').close();
}

async function submitRotate(event) {
  event.preventDefault();
  const serviceId = document.getElementById('modal-service-id').value;
  const newValue = document.getElementById('modal-new-value').value;
  const dryRun = document.getElementById('modal-dry-run').checked;
  const genPw = document.getElementById('modal-gen-pw').checked;
  const syncBw = document.getElementById('modal-sync-bw').checked;
  const resultPre = document.getElementById('modal-result');
  resultPre.textContent = 'Working...';

  const form = new FormData();
  if (newValue) form.append('new_value', newValue);
  form.append('dry_run', dryRun ? 'true' : 'false');
  form.append('generate_password', genPw ? 'true' : 'false');
  form.append('sync_bitwarden_flag', syncBw ? 'true' : 'false');

  try {
    const res = await fetch(`/api/rotate/${serviceId}`, { method: 'POST', body: form });
    const data = await res.json();
    resultPre.textContent = JSON.stringify(data, null, 2);
    if (data.success && !dryRun) {
      setTimeout(loadServices, 500);
    }
  } catch (e) {
    resultPre.textContent = 'Error: ' + e.message;
  }
}

async function rotateAll() {
  if (!confirm('Rotate all stale services?')) return;
  const btn = document.getElementById('btn-rotate-all');
  btn.disabled = true;
  btn.textContent = 'Rotating...';
  try {
    const res = await fetch('/api/rotate-all', {
      method: 'POST',
      body: new URLSearchParams({ dry_run: 'false', generate_password: 'true', sync_bitwarden_flag: 'true' })
    });
    const data = await res.json();
    alert('Done. Check the page for results.');
    loadServices();
  } catch (e) {
    alert('Error: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Rotate All Stale';
  }
}

// Hosts page functions
async function loadHosts() {
  const container = document.getElementById('hosts-container');
  if (!container) return;
  container.innerHTML = '<article aria-busy="true"></article>';
  try {
    const res = await fetch('/api/hosts');
    const hosts = await res.json();
    renderHosts(hosts);
  } catch (e) {
    container.innerHTML = '<p style="color:red">Failed to load hosts.</p>';
  }
}

function renderHosts(hosts) {
  const container = document.getElementById('hosts-container');
  if (!hosts.length) {
    container.innerHTML = '<p>No remote hosts configured. Add one to scan it for secret references.</p>';
    return;
  }
  let html = '<table><thead><tr><th>Label</th><th>Host</th><th>User</th><th>Search Dirs</th><th>Actions</th></tr></thead><tbody>';
  for (const h of hosts) {
    const sd = JSON.stringify(h.search_dirs).replace(/"/g, '&quot;');
    const dr = JSON.stringify(h.db_refs).replace(/"/g, '&quot;');
    html += `
      <tr data-id="${h.id}" data-label="${h.label}" data-host="${h.host}" data-user="${h.user}" data-searchdirs="${sd}" data-dbrefs="${dr}">
        <td>${h.label}</td>
        <td>${h.host}</td>
        <td>${h.user}</td>
        <td><code>${h.search_dirs.join(', ')}</code></td>
        <td>
          <button class="secondary outline" onclick="editHostFromRow(this.closest('tr'))">Edit</button>
          <button class="secondary outline" onclick="deleteHost(${h.id})">Delete</button>
        </td>
      </tr>
    `;
  }
  html += '</tbody></table>';
  container.innerHTML = html;
}

function openHostModal() {
  document.getElementById('host-modal-id').value = '';
  document.getElementById('host-label').value = '';
  document.getElementById('host-host').value = '';
  document.getElementById('host-user').value = '';
  document.getElementById('host-search-dirs').value = '["/mnt/Data/appdata"]';
  document.getElementById('host-db-refs').value = '[]';
  document.getElementById('host-modal-title').textContent = 'Add Host';
  document.getElementById('host-modal-result').textContent = '';
  document.getElementById('host-modal').showModal();
}

function closeHostModal() {
  document.getElementById('host-modal').close();
}

function editHostFromRow(row) {
  document.getElementById('host-modal-id').value = row.dataset.id;
  document.getElementById('host-label').value = row.dataset.label;
  document.getElementById('host-host').value = row.dataset.host;
  document.getElementById('host-user').value = row.dataset.user;
  document.getElementById('host-search-dirs').value = row.dataset.searchdirs.replace(/&quot;/g, '"');
  document.getElementById('host-db-refs').value = row.dataset.dbrefs.replace(/&quot;/g, '"');
  document.getElementById('host-modal-title').textContent = 'Edit Host';
  document.getElementById('host-modal-result').textContent = '';
  document.getElementById('host-modal').showModal();
}

async function submitHost(event) {
  event.preventDefault();
  const id = document.getElementById('host-modal-id').value;
  const label = document.getElementById('host-label').value;
  const host = document.getElementById('host-host').value;
  const user = document.getElementById('host-user').value;
  const searchDirs = document.getElementById('host-search-dirs').value;
  const dbRefs = document.getElementById('host-db-refs').value;
  const resultPre = document.getElementById('host-modal-result');
  resultPre.textContent = 'Saving...';

  const form = new FormData();
  form.append('label', label);
  form.append('host', host);
  form.append('user', user);
  form.append('search_dirs', searchDirs);
  form.append('db_refs', dbRefs);

  try {
    const url = id ? `/api/hosts/${id}` : '/api/hosts';
    const method = id ? 'PUT' : 'POST';
    const res = await fetch(url, { method, body: form });
    const data = await res.json();
    resultPre.textContent = JSON.stringify(data, null, 2);
    if (data.success) {
      setTimeout(() => { closeHostModal(); loadHosts(); }, 500);
    }
  } catch (e) {
    resultPre.textContent = 'Error: ' + e.message;
  }
}

async function deleteHost(id) {
  if (!confirm('Delete this host?')) return;
  try {
    const res = await fetch(`/api/hosts/${id}`, { method: 'DELETE' });
    const data = await res.json();
    if (data.success) loadHosts();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

// SSH Keys page functions
async function loadSshKeys() {
  const container = document.getElementById('ssh-keys-container');
  if (!container) return;
  container.innerHTML = '<article aria-busy="true"></article>';
  try {
    const res = await fetch('/api/ssh-keys');
    const keys = await res.json();
    renderSshKeys(keys);
  } catch (e) {
    container.innerHTML = '<p style="color:red">Failed to load SSH keys.</p>';
  }
}

function renderSshKeys(keys) {
  const container = document.getElementById('ssh-keys-container');
  if (!keys.length) {
    container.innerHTML = '<p>No SSH keys generated yet. Generate one to get started.</p>';
    return;
  }
  let html = '<table><thead><tr><th>Name</th><th>Public Key</th><th>Created</th><th>Actions</th></tr></thead><tbody>';
  for (const k of keys) {
    html += `
      <tr data-id="${k.id}" data-name="${k.name}" data-public="${k.public_key.replace(/"/g, '&quot;')}">
        <td>${k.name}</td>
        <td><code>${k.public_key.slice(0, 40)}...</code></td>
        <td>${new Date(k.created_at).toLocaleString()}</td>
        <td>
          <button class="secondary outline" onclick="showSshKeyFromRow(this.closest('tr'))">Show</button>
          <button class="secondary outline" onclick="deleteSshKey(${k.id})">Delete</button>
        </td>
      </tr>
    `;
  }
  html += '</tbody></table>';
  container.innerHTML = html;
}

function openSshKeyModal() {
  document.getElementById('ssh-key-name').value = '';
  document.getElementById('ssh-key-modal-result').textContent = '';
  document.getElementById('ssh-key-display').style.display = 'none';
  document.getElementById('ssh-key-modal-title').textContent = 'Generate SSH Key';
  document.getElementById('ssh-key-modal').showModal();
}

function closeSshKeyModal() {
  document.getElementById('ssh-key-modal').close();
}

function showSshKeyFromRow(row) {
  openSshKeyModal();
  document.getElementById('ssh-key-modal-title').textContent = row.dataset.name;
  document.getElementById('ssh-key-display').style.display = 'block';
  document.getElementById('ssh-key-public').value = row.dataset.public;
}

function copyPublicKey() {
  const ta = document.getElementById('ssh-key-public');
  ta.select();
  navigator.clipboard.writeText(ta.value);
}

async function submitSshKey(event) {
  event.preventDefault();
  const name = document.getElementById('ssh-key-name').value;
  const resultPre = document.getElementById('ssh-key-modal-result');
  const displayDiv = document.getElementById('ssh-key-display');
  resultPre.textContent = 'Generating...';
  displayDiv.style.display = 'none';

  const form = new FormData();
  form.append('name', name);

  try {
    const res = await fetch('/api/ssh-keys', { method: 'POST', body: form });
    const data = await res.json();
    if (data.success) {
      resultPre.textContent = 'Key generated successfully.';
      document.getElementById('ssh-key-public').value = data.public_key;
      displayDiv.style.display = 'block';
      loadSshKeys();
    } else {
      resultPre.textContent = 'Error: ' + (data.detail || 'unknown');
    }
  } catch (e) {
    resultPre.textContent = 'Error: ' + e.message;
  }
}

async function deleteSshKey(id) {
  if (!confirm('Delete this key?')) return;
  try {
    const res = await fetch(`/api/ssh-keys/${id}`, { method: 'DELETE' });
    const data = await res.json();
    if (data.success) loadSshKeys();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

// Initial load (page-aware)
if (document.getElementById('services-container')) {
  loadServices();
  loadScanStatus();
  setInterval(loadScanStatus, 30000);
}
if (document.getElementById('hosts-container')) {
  loadHosts();
}
if (document.getElementById('ssh-keys-container')) {
  loadSshKeys();
}
