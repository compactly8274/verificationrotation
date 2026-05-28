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

// Initial load
loadServices();
loadScanStatus();
setInterval(loadScanStatus, 30000);
