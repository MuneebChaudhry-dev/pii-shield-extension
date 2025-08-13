// Background service worker for PII Shield Extension

// Extension state
let extensionEnabled = true;
let scanResults = new Map();

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log('PII Shield Extension installed');

  // Set default settings
  chrome.storage.sync.set({
    enabled: true,
    autoScan: true,
    protectionLevel: 'medium',
    patterns: {
      ssn: true,
      creditCard: true,
      email: true,
      phone: true,
      bankAccount: true,
      cnic: true,
      passport: true,
      medicalId: true,
      ipAddress: false,
      dob: true,
    },
  });

  // Create context menu
  chrome.contextMenus.create({
    id: 'scan-selection',
    title: 'Scan for PII',
    contexts: ['selection'],
  });

  chrome.contextMenus.create({
    id: 'scan-page',
    title: 'Scan entire page',
    contexts: ['page'],
  });
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'scan-selection' && info.selectionText) {
    scanText(info.selectionText, tab.id);
  } else if (info.menuItemId === 'scan-page') {
    scanPage(tab.id);
  }
});

// Scan selected text
async function scanText(text, tabId) {
  try {
    const response = await chrome.tabs.sendMessage(tabId, {
      action: 'scanText',
      text: text,
    });

    if (response?.findings) {
      storeScanResults(tabId, response.findings);
      updateBadge(tabId, response.findings.length);
    }
  } catch (error) {
    console.error('Error scanning text:', error);
  }
}

// Scan entire page
async function scanPage(tabId) {
  try {
    const response = await chrome.tabs.sendMessage(tabId, {
      action: 'scanPage',
    });

    if (response?.findings) {
      storeScanResults(tabId, response.findings);
      updateBadge(tabId, response.findings.length);
    }
  } catch (error) {
    console.error('Error scanning page:', error);
  }
}

// Store scan results
function storeScanResults(tabId, findings) {
  scanResults.set(tabId, {
    timestamp: Date.now(),
    findings: findings,
    protected: false,
  });
}

// Update extension badge
function updateBadge(tabId, count) {
  if (count > 0) {
    chrome.action.setBadgeText({
      text: count.toString(),
      tabId: tabId,
    });

    // Set badge color based on severity
    const hasHigh = scanResults
      .get(tabId)
      ?.findings.some((f) => f.severity === 'high');
    const hasMedium = scanResults
      .get(tabId)
      ?.findings.some((f) => f.severity === 'medium');

    let color = '#10b981'; // Green (safe)
    if (hasHigh) {
      color = '#ef4444'; // Red (danger)
    } else if (hasMedium) {
      color = '#f59e0b'; // Yellow (warning)
    }

    chrome.action.setBadgeBackgroundColor({
      color: color,
      tabId: tabId,
    });
  } else {
    chrome.action.setBadgeText({
      text: '',
      tabId: tabId,
    });
  }
}

// Handle messages from content script and popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  switch (request.action) {
    case 'getScanResults':
      const tabId = request.tabId || sender.tab?.id;
      sendResponse({
        results: scanResults.get(tabId) || null,
      });
      break;

    case 'clearResults':
      scanResults.delete(request.tabId);
      updateBadge(request.tabId, 0);
      sendResponse({ success: true });
      break;

    case 'toggleExtension':
      extensionEnabled = request.enabled;
      chrome.storage.sync.set({ enabled: extensionEnabled });
      sendResponse({ success: true });
      break;

    case 'getSettings':
      chrome.storage.sync.get(null, (settings) => {
        sendResponse(settings);
      });
      return true; // Keep channel open for async response

    case 'updateSettings':
      chrome.storage.sync.set(request.settings, () => {
        sendResponse({ success: true });
      });
      return true;

    case 'scanFile':
      // Handle file scanning request
      handleFileScan(request.fileData, sender.tab.id);
      sendResponse({ success: true });
      break;
  }

  return true;
});

// Handle file scanning
async function handleFileScan(fileData, tabId) {
  try {
    const response = await chrome.tabs.sendMessage(tabId, {
      action: 'processFile',
      data: fileData,
    });

    if (response?.findings) {
      storeScanResults(tabId, response.findings);
      updateBadge(tabId, response.findings.length);
    }
  } catch (error) {
    console.error('Error scanning file:', error);
  }
}

// Clean up old scan results (older than 1 hour)
setInterval(() => {
  const oneHourAgo = Date.now() - 60 * 60 * 1000;
  for (const [tabId, result] of scanResults.entries()) {
    if (result.timestamp < oneHourAgo) {
      scanResults.delete(tabId);
    }
  }
}, 60 * 60 * 1000); // Run every hour

// Handle tab close - clean up results
chrome.tabs.onRemoved.addListener((tabId) => {
  scanResults.delete(tabId);
});

// Handle navigation - clear results for tab
// Check if webNavigation API is available before using it
if (chrome.webNavigation) {
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0) {
      // Main frame only
      scanResults.delete(details.tabId);
      updateBadge(details.tabId, 0);
    }
  });
} else {
  console.warn('webNavigation API not available');
}
