(() => {
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

  const toast = $('#toast');
  const toastText = $('#toastText');
  let toastTimer;
  let scanRunning = false;
  let validationRunning = false;
  let selectedValidation = $('.validation-card.active');
  const targetEnvironments = ['Staging', 'Preview', 'Read-only'];
  let environmentIndex = 0;

  function showToast(message, type = 'success') {
    toastText.textContent = message;
    toast.classList.toggle('warning-toast', type === 'warning');
    toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('show'), 3200);
  }

  function setButtonBusy(button, busy, busyText, idleText) {
    button.disabled = busy;
    button.classList.toggle('is-busy', busy);
    const label = button.querySelector('[data-label]') || button.querySelector('#scanButtonText');
    if (label) label.textContent = busy ? busyText : idleText;
  }

  // Navigation is intentionally local to this preview. It gives the shell a usable feeling without loading an external route.
  $$('.nav-item').forEach((item) => {
    item.addEventListener('click', () => {
      $$('.nav-item').forEach((nav) => nav.classList.remove('active'));
      item.classList.add('active');
      showToast(`${item.textContent.trim()} view is available in the full workspace.`);
    });
  });

  // Scope actions keep the user inside authorized, controlled mode.
  $('#scopeButton')?.addEventListener('click', () => {
    showToast('Scope locked to staging fixtures. Production traffic is blocked by policy.');
  });
  $('#editScope')?.addEventListener('click', () => {
    showToast('Scope editor opened — 1 target and 2 approved subdomains.');
  });
  $('#changeFixture')?.addEventListener('click', () => {
    showToast('Fixture selector opened — checkout-v2 is the active safe dataset.');
  });
  $('#targetDropdown')?.addEventListener('click', (event) => {
    environmentIndex = (environmentIndex + 1) % targetEnvironments.length;
    event.currentTarget.innerHTML = `${targetEnvironments[environmentIndex]} <span>⌄</span>`;
    const isReadOnly = targetEnvironments[environmentIndex] === 'Read-only';
    showToast(`${targetEnvironments[environmentIndex]} scope selected${isReadOnly ? ' — validation will remain read-only.' : '.'}`);
  });

  // Scanning module selection is a local profile toggle, not a live scanner.
  const moduleRows = $$('.module-row');
  const moduleCount = $('#moduleCount');
  function updateModuleCount() {
    const selected = moduleRows.filter((row) => row.classList.contains('selected')).length;
    if (moduleCount) moduleCount.textContent = selected;
    const toggleAll = $('#toggleAll');
    if (toggleAll) toggleAll.textContent = selected === moduleRows.length ? 'Deselect all' : 'Select all';
  }
  moduleRows.forEach((row) => {
    row.addEventListener('click', () => {
      row.classList.toggle('selected');
      updateModuleCount();
      showToast(`${row.dataset.module} ${row.classList.contains('selected') ? 'enabled' : 'disabled'} for the next scan.`);
    });
  });
  $('#toggleAll')?.addEventListener('click', (event) => {
    const select = moduleRows.some((row) => !row.classList.contains('selected'));
    moduleRows.forEach((row) => row.classList.toggle('selected', select));
    updateModuleCount();
    event.currentTarget.textContent = select ? 'Deselect all' : 'Select all';
    showToast(select ? 'All 21 scanning modules enabled.' : 'All scanning modules disabled.');
  });

  // The scan timeline is a safe, local preview of a read-only scan job.
  const scanButton = $('#scanButton');
  const scanProgress = $('#scanProgress');
  const scanFill = $('#progressFill');
  const progressLabel = $('#progressLabel');
  const progressDetail = $('#progressDetail');
  const progressPercent = $('#progressPercent');
  const scanStateText = $('#scanStateText');
  const scanStages = [
    ['Checking scope policy', 'Confirming target ownership and safe-mode rules…'],
    ['Mapping surface', 'Enumerating approved routes, DNS records, and services…'],
    ['Evaluating controls', 'Comparing headers, cookies, auth, and API signals…'],
    ['Prioritizing signals', 'Correlating findings with the validation playbooks…'],
    ['Scan complete', 'Evidence bundle is ready for controlled review.']
  ];

  function runScan() {
    if (scanRunning) return;
    scanRunning = true;
    scanProgress.classList.remove('hidden');
    scanButton.disabled = true;
    scanButton.classList.add('is-busy');
    $('#scanButtonText').textContent = 'Scanning…';
    $('#scanEstimate').textContent = 'in progress';
    scanStateText.textContent = 'Running';
    scanStateText.parentElement.classList.add('running');
    let progress = 0;
    const timer = setInterval(() => {
      progress += progress < 30 ? 8 : progress < 70 ? 11 : 7;
      if (progress >= 100) progress = 100;
      const stageIndex = progress === 100 ? 4 : Math.min(Math.floor(progress / 25), 3);
      const [label, detail] = scanStages[stageIndex];
      progressLabel.textContent = label;
      progressDetail.textContent = detail;
      progressPercent.textContent = `${progress}%`;
      scanFill.style.width = `${progress}%`;
      if (progress === 100) {
        clearInterval(timer);
        setTimeout(() => {
          scanRunning = false;
          scanButton.disabled = false;
          scanButton.classList.remove('is-busy');
          $('#scanButtonText').textContent = 'Run security scan';
          $('#scanEstimate').textContent = '~ 4 min';
          scanStateText.textContent = 'Completed';
          scanStateText.parentElement.classList.remove('running');
          scanProgress.classList.add('hidden');
          $('#highMetric').textContent = '03';
          showToast('Safe scan complete — 48 assets mapped, 3 high-priority signals.');
        }, 450);
      }
    }, 260);
  }
  scanButton?.addEventListener('click', runScan);

  // Selecting a validation playbook only updates the evidence preview in the local lab.
  function syncSelectedValidation(card) {
    selectedValidation = card;
    $$('.validation-card').forEach((item) => item.classList.toggle('active', item === card));
    const icon = $('#selectedIcon');
    const name = $('#selectedName');
    const hint = $('#selectedHint');
    const risk = $('#selectedRisk');
    const result = $('#selectedResult');
    const evidence = $('#selectedEvidence');
    icon.textContent = card.dataset.icon;
    name.textContent = card.dataset.validation;
    hint.textContent = card.querySelector('small').textContent;
    risk.textContent = card.dataset.risk;
    risk.className = `selected-risk ${card.dataset.risk.toLowerCase()}`;
    result.textContent = card.dataset.result;
    evidence.textContent = card.dataset.evidence;
    const sourceIcon = card.querySelector('.validation-icon');
    icon.style.color = getComputedStyle(sourceIcon).color;
    icon.style.background = getComputedStyle(sourceIcon).backgroundColor;
    $('#validationProgress').classList.add('hidden');
    $('#validationRunButton').disabled = false;
    $('#validationRunButton').innerHTML = '<span>▷</span> Run safe validation';
  }
  $$('.validation-card').forEach((card) => card.addEventListener('click', () => syncSelectedValidation(card)));

  const validationButton = $('#validationRunButton');
  function runValidation() {
    if (validationRunning || !selectedValidation) return;
    validationRunning = true;
    const progress = $('#validationProgress');
    const fill = $('#validationProgressFill');
    const label = $('#validationProgressLabel');
    const percent = $('#validationProgressPercent');
    progress.classList.remove('hidden');
    validationButton.disabled = true;
    validationButton.innerHTML = '<span>…</span> Running safe fixture';
    const stages = ['Building fixture matrix', 'Applying read-only canaries', 'Comparing expected responses', 'Evidence captured'];
    let value = 0;
    const timer = setInterval(() => {
      value += 25;
      fill.style.width = `${value}%`;
      percent.textContent = `${value}%`;
      label.textContent = stages[Math.min(value / 25 - 1, stages.length - 1)];
      if (value === 100) {
        clearInterval(timer);
        setTimeout(() => {
          validationRunning = false;
          validationButton.disabled = false;
          validationButton.innerHTML = '<span>↻</span> Re-run safe validation';
          progress.classList.add('hidden');
          showToast(`${selectedValidation.dataset.validation} complete — evidence captured locally.`);
        }, 400);
      }
    }, 360);
  }
  validationButton?.addEventListener('click', runValidation);

  $('#exportButton')?.addEventListener('click', () => {
    const exportData = {
      target: $('#targetUrl').value,
      mode: 'controlled-validation-preview',
      selectedPlaybook: selectedValidation?.dataset.validation,
      generatedAt: new Date().toISOString(),
      note: 'Local preview evidence only. No live requests or exploitation performed.'
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'greyhat-validation-evidence.json';
    link.click();
    URL.revokeObjectURL(url);
    showToast('Evidence JSON exported from the local preview.');
  });

  $('#targetUrl')?.addEventListener('change', (event) => {
    const value = event.currentTarget.value.trim();
    if (!value) {
      event.currentTarget.value = 'https://demo.northstar.app';
      showToast('A target is required before scanning.', 'warning');
      return;
    }
    showToast('Target updated. Run a scan to refresh the local results.');
  });

  updateModuleCount();
})();
