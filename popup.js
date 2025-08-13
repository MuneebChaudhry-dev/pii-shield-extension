// Popup interface logic
let currentTab = null;
let extensionEnabled = true;
let scanStats = {
  scansToday: 0,
  piiDetected: 0,
  filesProtected: 0,
};

// Initialize popup
document.addEventListener('DOMContentLoaded', async () => {
  // Get current tab
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTab = tabs[0];

  // Load settings
  loadSettings();

  // Load stats
  loadStats();

  // Setup event listeners
  setupEventListeners();

  // Check for existing scan results
  checkScanResults();
});

// Load extension settings
async function loadSettings() {
  chrome.storage.sync.get(['enabled', 'patterns'], (settings) => {
    extensionEnabled = settings.enabled !== false;
    updateToggleState(document.getElementById('mainToggle'), extensionEnabled);
    updateStatus(extensionEnabled);

    // Update pattern toggles
    if (settings.patterns) {
      Object.keys(settings.patterns).forEach((pattern) => {
        const toggle = document.querySelector(`[data-pattern="${pattern}"]`);
        if (toggle) {
          updateToggleState(toggle, settings.patterns[pattern]);
        }
      });
    }
  });
}

// Load statistics
async function loadStats() {
  chrome.storage.local.get(['stats'], (data) => {
    if (data.stats) {
      const today = new Date().toDateString();
      if (data.stats.date === today) {
        scanStats = data.stats;
        updateStatsDisplay();
      } else {
        // Reset stats for new day
        scanStats = {
          scansToday: 0,
          piiDetected: 0,
          filesProtected: 0,
        };
        saveStats();
      }
    }
  });
}

// Save statistics
function saveStats() {
  chrome.storage.local.set({
    stats: {
      ...scanStats,
      date: new Date().toDateString(),
    },
  });
}

// Update stats display
function updateStatsDisplay() {
  document.getElementById('scansToday').textContent = scanStats.scansToday;
  document.getElementById('piiDetected').textContent = scanStats.piiDetected;
  document.getElementById('filesProtected').textContent =
    scanStats.filesProtected;
}

// Setup event listeners
function setupEventListeners() {
  // Main toggle
  document
    .getElementById('mainToggle')
    .addEventListener('click', toggleExtension);

  // Pattern toggles
  document.querySelectorAll('.pattern-toggle').forEach((toggle) => {
    toggle.addEventListener('click', (e) => togglePattern(e.currentTarget));
  });

  // Action buttons
  document
    .getElementById('scanPageBtn')
    .addEventListener('click', scanCurrentPage);
  document
    .getElementById('viewDetailsBtn')
    .addEventListener('click', viewDetailedReport);
}

// Toggle extension on/off
function toggleExtension() {
  extensionEnabled = !extensionEnabled;
  updateToggleState(document.getElementById('mainToggle'), extensionEnabled);
  updateStatus(extensionEnabled);

  // Save setting
  chrome.storage.sync.set({ enabled: extensionEnabled });

  // Notify background script
  chrome.runtime.sendMessage({
    action: 'toggleExtension',
    enabled: extensionEnabled,
  });
}

// Toggle pattern detection
function togglePattern(toggle) {
  const pattern = toggle.dataset.pattern;
  const isActive = toggle.classList.contains('active');

  updateToggleState(toggle, !isActive);

  // Save pattern settings
  chrome.storage.sync.get(['patterns'], (data) => {
    const patterns = data.patterns || {};
    patterns[pattern] = !isActive;
    chrome.storage.sync.set({ patterns });
  });
}

// Update toggle visual state
function updateToggleState(toggle, active) {
  if (active) {
    toggle.classList.add('active');
  } else {
    toggle.classList.remove('active');
  }
}

// Update status display
function updateStatus(enabled) {
  const statusIcon = document.getElementById('statusIcon');
  const statusTitle = document.getElementById('statusTitle');
  const statusDescription = document.getElementById('statusDescription');

  if (enabled) {
    statusIcon.className = 'status-icon safe';
    statusIcon.textContent = '✓';
    statusTitle.textContent = 'Protection Active';
    statusDescription.textContent =
      'Monitoring file uploads for sensitive data';
  } else {
    statusIcon.className = 'status-icon';
    statusIcon.style.background = 'rgba(156, 163, 175, 0.1)';
    statusIcon.style.color = '#6b7280';
    statusIcon.textContent = '⏸';
    statusTitle.textContent = 'Protection Paused';
    statusDescription.textContent = 'Click toggle to resume monitoring';
  }
}

// Check for existing scan results
async function checkScanResults() {
  chrome.runtime.sendMessage(
    {
      action: 'getScanResults',
      tabId: currentTab.id,
    },
    (response) => {
      if (response && response.results && response.results.findings) {
        const findings = response.results.findings;
        updateScanStatus(findings);
      }
    }
  );
}

// Update scan status based on findings
function updateScanStatus(findings) {
  const statusIcon = document.getElementById('statusIcon');
  const statusTitle = document.getElementById('statusTitle');
  const statusDescription = document.getElementById('statusDescription');

  if (findings.length === 0) {
    statusIcon.className = 'status-icon safe';
    statusIcon.textContent = '✓';
    statusTitle.textContent = 'No PII Detected';
    statusDescription.textContent = 'This page appears to be safe';
  } else {
    const highSeverity = findings.filter((f) => f.severity === 'high').length;
    const mediumSeverity = findings.filter(
      (f) => f.severity === 'medium'
    ).length;

    if (highSeverity > 0) {
      statusIcon.className = 'status-icon danger';
      statusIcon.textContent = '⚡';
      statusTitle.textContent = 'Critical PII Found';
      statusDescription.textContent = `${findings.length} sensitive items detected`;
    } else if (mediumSeverity > 0) {
      statusIcon.className = 'status-icon warning';
      statusIcon.textContent = '⚠';
      statusTitle.textContent = 'Sensitive Data Found';
      statusDescription.textContent = `${findings.length} potential PII items detected`;
    } else {
      statusIcon.className = 'status-icon warning';
      statusIcon.textContent = 'ℹ';
      statusTitle.textContent = 'Low Risk Data Found';
      statusDescription.textContent = `${findings.length} items detected`;
    }
  }
}

// Scan current page
async function scanCurrentPage() {
  const scanBtn = document.getElementById('scanPageBtn');
  const originalContent = scanBtn.innerHTML;

  // Show scanning state
  scanBtn.innerHTML = '<span class="scanning">⟳</span><span>Scanning...</span>';
  scanBtn.disabled = true;

  // Send scan request
  chrome.tabs.sendMessage(
    currentTab.id,
    {
      action: 'scanPage',
    },
    (response) => {
      // Restore button
      setTimeout(() => {
        scanBtn.innerHTML = originalContent;
        scanBtn.disabled = false;
      }, 1000);

      if (response && response.findings) {
        // Update stats
        scanStats.scansToday++;
        scanStats.piiDetected += response.findings.length;
        saveStats();
        updateStatsDisplay();

        // Update status
        updateScanStatus(response.findings);

        // Store results
        chrome.runtime.sendMessage({
          action: 'storeScanResults',
          tabId: currentTab.id,
          findings: response.findings,
        });
      }
    }
  );
}

// View detailed report
function viewDetailedReport() {
  // Send message to content script to show sidebar
  chrome.tabs.sendMessage(currentTab.id, {
    action: 'showDetailedReport',
  });

  // Close popup
  window.close();
}

// Format time ago
function formatTimeAgo(timestamp) {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);

  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

// Listen for updates from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'updateStats') {
    scanStats = request.stats;
    updateStatsDisplay();
  }
});
