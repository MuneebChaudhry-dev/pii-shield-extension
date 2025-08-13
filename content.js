// PII Detection Patterns
const PII_PATTERNS = {
  ssn: {
    pattern: /\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b/g,
    type: 'SSN',
    severity: 'high',
    label: 'Social Security Number',
  },
  creditCard: {
    pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
    type: 'CREDIT_CARD',
    severity: 'high',
    label: 'Credit Card Number',
  },
  email: {
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    type: 'EMAIL',
    severity: 'medium',
    label: 'Email Address',
  },
  phone: {
    pattern: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    type: 'PHONE',
    severity: 'medium',
    label: 'Phone Number',
  },
  bankAccount: {
    pattern: /\b\d{8,17}\b/g,
    type: 'BANK_ACCOUNT',
    severity: 'high',
    label: 'Bank Account Number',
  },
  cnic: {
    pattern: /\b\d{5}-\d{7}-\d{1}\b/g,
    type: 'CNIC',
    severity: 'high',
    label: 'CNIC Number',
  },
  passport: {
    pattern: /\b[A-Z]{1,2}\d{6,9}\b/g,
    type: 'PASSPORT',
    severity: 'high',
    label: 'Passport Number',
  },
  medicalId: {
    pattern: /\b(?:MRN|MED|PAT)[-\s]?\d{6,10}\b/gi,
    type: 'MEDICAL_ID',
    severity: 'high',
    label: 'Medical Record Number',
  },
  ipAddress: {
    pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    type: 'IP_ADDRESS',
    severity: 'low',
    label: 'IP Address',
  },
  dob: {
    pattern:
      /\b(?:0[1-9]|1[0-2])[-\/](?:0[1-9]|[12]\d|3[01])[-\/](?:19|20)\d{2}\b/g,
    type: 'DATE_OF_BIRTH',
    severity: 'medium',
    label: 'Date of Birth',
  },
};

// State management
let isScanning = false;
let sidebar = null;
let overlay = null;
let detectedPII = [];

// Inject styles
function injectStyles() {
  const style = document.createElement('style');
  style.textContent = `
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    
    .pii-shield-overlay {
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      z-index: 999999;
      width: 400px;
      background: rgba(255, 255, 255, 0.98);
      backdrop-filter: blur(20px);
      border-radius: 24px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.15);
      padding: 32px;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      animation: slideIn 0.3s ease-out;
    }

    @keyframes slideIn {
      from {
        opacity: 0;
        transform: translate(-50%, -45%);
      }
      to {
        opacity: 1;
        transform: translate(-50%, -50%);
      }
    }

    .pii-shield-overlay.glass {
      background: linear-gradient(135deg, rgba(255, 255, 255, 0.9), rgba(255, 255, 255, 0.7));
      border: 1px solid rgba(255, 255, 255, 0.5);
    }

    .pii-shield-header {
      display: flex;
      align-items: center;
      gap: 16px;
      margin-bottom: 24px;
    }

    .pii-shield-icon {
      width: 56px;
      height: 56px;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 16px;
      font-size: 28px;
    }

    .pii-shield-icon.safe {
      background: linear-gradient(135deg, #10b981, #059669);
      box-shadow: 0 8px 20px rgba(16, 185, 129, 0.3);
    }

    .pii-shield-icon.warning {
      background: linear-gradient(135deg, #f59e0b, #d97706);
      box-shadow: 0 8px 20px rgba(245, 158, 11, 0.3);
    }

    .pii-shield-icon.danger {
      background: linear-gradient(135deg, #ef4444, #dc2626);
      box-shadow: 0 8px 20px rgba(239, 68, 68, 0.3);
    }

    .pii-shield-title {
      font-size: 20px;
      font-weight: 600;
      color: #1f2937;
      margin: 0;
    }

    .pii-shield-subtitle {
      font-size: 14px;
      color: #6b7280;
      margin: 4px 0 0 0;
    }

    .pii-shield-content {
      margin-bottom: 24px;
    }

    .pii-shield-stats {
      display: flex;
      gap: 12px;
      margin-bottom: 20px;
    }

    .pii-shield-stat {
      flex: 1;
      padding: 12px;
      background: rgba(249, 250, 251, 0.8);
      border-radius: 12px;
      text-align: center;
    }

    .pii-shield-stat-value {
      font-size: 24px;
      font-weight: 700;
      margin-bottom: 4px;
    }

    .pii-shield-stat-label {
      font-size: 12px;
      color: #6b7280;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .pii-shield-actions {
      display: flex;
      gap: 12px;
    }

    .pii-shield-btn {
      flex: 1;
      padding: 12px 20px;
      border-radius: 12px;
      font-size: 14px;
      font-weight: 500;
      border: none;
      cursor: pointer;
      transition: all 0.2s ease;
      font-family: inherit;
    }

    .pii-shield-btn:hover {
      transform: translateY(-1px);
    }

    .pii-shield-btn.primary {
      background: linear-gradient(135deg, #3b82f6, #2563eb);
      color: white;
      box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
    }

    .pii-shield-btn.secondary {
      background: rgba(243, 244, 246, 0.8);
      color: #4b5563;
      border: 1px solid rgba(229, 231, 235, 0.8);
    }

    .pii-shield-btn.danger {
      background: rgba(254, 226, 226, 0.5);
      color: #dc2626;
      border: 1px solid rgba(254, 202, 202, 0.5);
    }

    .pii-shield-sidebar {
      position: fixed;
      right: 0;
      top: 0;
      width: 420px;
      height: 100vh;
      background: rgba(255, 255, 255, 0.98);
      backdrop-filter: blur(20px);
      box-shadow: -10px 0 40px rgba(0, 0, 0, 0.1);
      z-index: 999998;
      transform: translateX(100%);
      transition: transform 0.3s ease-out;
      overflow-y: auto;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    .pii-shield-sidebar.open {
      transform: translateX(0);
    }

    .pii-shield-sidebar-header {
      padding: 24px;
      background: linear-gradient(135deg, #f9fafb, #f3f4f6);
      border-bottom: 1px solid rgba(229, 231, 235, 0.5);
      position: sticky;
      top: 0;
      z-index: 10;
    }

    .pii-shield-sidebar-close {
      position: absolute;
      right: 24px;
      top: 24px;
      width: 32px;
      height: 32px;
      border-radius: 8px;
      background: white;
      border: 1px solid #e5e7eb;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: all 0.2s;
    }

    .pii-shield-sidebar-close:hover {
      background: #f3f4f6;
      transform: rotate(90deg);
    }

    .pii-shield-sidebar-content {
      padding: 24px;
    }

    .pii-detection-item {
      background: white;
      border: 1px solid #e5e7eb;
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 12px;
      transition: all 0.2s;
    }

    .pii-detection-item:hover {
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
      transform: translateY(-1px);
    }

    .pii-detection-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
    }

    .pii-detection-type {
      display: flex;
      align-items: center;
      gap: 8px;
      font-weight: 500;
      color: #1f2937;
    }

    .pii-detection-severity {
      padding: 4px 8px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .severity-high {
      background: #fee2e2;
      color: #dc2626;
    }

    .severity-medium {
      background: #fef3c7;
      color: #d97706;
    }

    .severity-low {
      background: #dbeafe;
      color: #2563eb;
    }

    .pii-detection-value {
      font-family: 'Courier New', monospace;
      background: #f9fafb;
      padding: 8px 12px;
      border-radius: 8px;
      font-size: 13px;
      color: #4b5563;
      word-break: break-all;
    }

    .pii-detection-masked {
      color: #10b981;
      font-weight: 600;
    }

    .scanning-animation {
      display: inline-block;
      animation: pulse 1.5s ease-in-out infinite;
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }
  `;
  document.head.appendChild(style);
}

// Scan text for PII
function scanForPII(text) {
  const findings = [];

  for (const [key, config] of Object.entries(PII_PATTERNS)) {
    const matches = text.match(config.pattern);
    if (matches) {
      matches.forEach((match) => {
        findings.push({
          type: config.type,
          label: config.label,
          value: match,
          severity: config.severity,
          masked: maskPII(match, config.type),
        });
      });
    }
  }

  return findings;
}

// Mask PII based on type
function maskPII(value, type) {
  switch (type) {
    case 'SSN':
      return value.replace(/\d(?=\d{4})/g, '*');
    case 'CREDIT_CARD':
      return value.replace(/\d(?=\d{4})/g, '*');
    case 'EMAIL':
      const [localPart, domain] = value.split('@');
      return localPart.substring(0, 2) + '****@' + domain;
    case 'PHONE':
      return value.replace(/\d(?=\d{4})/g, '*');
    case 'BANK_ACCOUNT':
      return '****' + value.slice(-4);
    case 'CNIC':
      return value.replace(/\d(?=\d{4})/g, '*');
    default:
      return value.substring(0, 3) + '****';
  }
}

// Read file content
async function readFileContent(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();

    reader.onload = (e) => {
      resolve(e.target.result);
    };

    reader.onerror = reject;

    // Handle different file types
    if (file.type.includes('text') || file.name.endsWith('.txt')) {
      reader.readAsText(file);
    } else if (file.type.includes('pdf')) {
      // For PDF, we'd need a library like pdf.js
      // For now, return placeholder
      resolve('[PDF content would be extracted here]');
    } else if (file.type.includes('image')) {
      // For images, we'd need OCR
      // For now, return placeholder
      resolve('[Image OCR content would be extracted here]');
    } else {
      reader.readAsText(file);
    }
  });
}

// Create overlay UI
function createOverlay(findings) {
  removeOverlay();

  const severityCount = {
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
  };

  const totalFindings = findings.length;
  const overallSeverity =
    severityCount.high > 0
      ? 'danger'
      : severityCount.medium > 0
      ? 'warning'
      : 'safe';

  overlay = document.createElement('div');
  overlay.className = 'pii-shield-overlay glass';

  overlay.innerHTML = `
    <div class="pii-shield-header">
      <div class="pii-shield-icon ${overallSeverity}">
        ${
          overallSeverity === 'safe'
            ? '✓'
            : overallSeverity === 'warning'
            ? '⚠'
            : '⚡'
        }
      </div>
      <div>
        <h2 class="pii-shield-title">
          ${
            overallSeverity === 'safe'
              ? 'Document Scan Complete'
              : overallSeverity === 'warning'
              ? 'Sensitive Data Detected'
              : 'Critical Information Found'
          }
        </h2>
        <p class="pii-shield-subtitle">
          ${
            totalFindings === 0
              ? 'No sensitive information detected'
              : `Found ${totalFindings} potential PII item${
                  totalFindings > 1 ? 's' : ''
                }`
          }
        </p>
      </div>
    </div>
    
    ${
      totalFindings > 0
        ? `
      <div class="pii-shield-stats">
        ${
          severityCount.high > 0
            ? `
          <div class="pii-shield-stat">
            <div class="pii-shield-stat-value" style="color: #dc2626;">${severityCount.high}</div>
            <div class="pii-shield-stat-label">High Risk</div>
          </div>
        `
            : ''
        }
        ${
          severityCount.medium > 0
            ? `
          <div class="pii-shield-stat">
            <div class="pii-shield-stat-value" style="color: #d97706;">${severityCount.medium}</div>
            <div class="pii-shield-stat-label">Medium Risk</div>
          </div>
        `
            : ''
        }
        ${
          severityCount.low > 0
            ? `
          <div class="pii-shield-stat">
            <div class="pii-shield-stat-value" style="color: #2563eb;">${severityCount.low}</div>
            <div class="pii-shield-stat-label">Low Risk</div>
          </div>
        `
            : ''
        }
      </div>
    `
        : ''
    }
    
    <div class="pii-shield-actions">
      ${
        totalFindings > 0
          ? `
        <button class="pii-shield-btn danger" id="skip-upload">
          Skip & Upload
        </button>
        <button class="pii-shield-btn primary" id="view-details">
          View Details
        </button>
      `
          : `
        <button class="pii-shield-btn primary" id="proceed-upload">
          ✓ Ready to Upload
        </button>
      `
      }
    </div>
  `;

  document.body.appendChild(overlay);

  // Add event listeners
  if (totalFindings > 0) {
    document.getElementById('skip-upload')?.addEventListener('click', () => {
      removeOverlay();
      proceedWithUpload();
    });

    document.getElementById('view-details')?.addEventListener('click', () => {
      removeOverlay();
      showSidebar(findings);
    });
  } else {
    document.getElementById('proceed-upload')?.addEventListener('click', () => {
      removeOverlay();
      proceedWithUpload();
    });
  }
}

// Show sidebar with details
function showSidebar(findings) {
  removeSidebar();

  sidebar = document.createElement('div');
  sidebar.className = 'pii-shield-sidebar';

  sidebar.innerHTML = `
    <div class="pii-shield-sidebar-header">
      <div class="pii-shield-sidebar-close" id="close-sidebar">✕</div>
      <h3 style="margin: 0 0 8px 0; color: #1f2937;">PII Detection Results</h3>
      <p style="margin: 0; color: #6b7280; font-size: 14px;">
        Review and protect sensitive information before uploading
      </p>
    </div>
    
    <div class="pii-shield-sidebar-content">
      ${findings
        .map(
          (finding, index) => `
        <div class="pii-detection-item">
          <div class="pii-detection-header">
            <div class="pii-detection-type">
              <span>${finding.label}</span>
            </div>
            <span class="pii-detection-severity severity-${finding.severity}">
              ${finding.severity}
            </span>
          </div>
          <div class="pii-detection-value" data-index="${index}">
            <span class="original">${finding.value}</span>
            <span class="pii-detection-masked" style="display: none;">${finding.masked}</span>
          </div>
        </div>
      `
        )
        .join('')}
      
      <div style="margin-top: 24px; display: flex; gap: 12px;">
        <button class="pii-shield-btn secondary" id="protect-all">
          🛡️ Protect All
        </button>
        <button class="pii-shield-btn primary" id="ready-upload">
          ✓ Ready to Upload
        </button>
      </div>
    </div>
  `;

  document.body.appendChild(sidebar);

  // Animate sidebar in
  setTimeout(() => {
    sidebar.classList.add('open');
  }, 10);

  // Event listeners
  document
    .getElementById('close-sidebar')
    ?.addEventListener('click', removeSidebar);

  document.getElementById('protect-all')?.addEventListener('click', () => {
    document.querySelectorAll('.pii-detection-value').forEach((el) => {
      el.querySelector('.original').style.display = 'none';
      el.querySelector('.pii-detection-masked').style.display = 'inline';
    });

    // Change button to show protection is applied
    const btn = document.getElementById('protect-all');
    btn.textContent = '✓ Protected';
    btn.disabled = true;
    btn.style.opacity = '0.5';
  });

  document.getElementById('ready-upload')?.addEventListener('click', () => {
    removeSidebar();
    proceedWithUpload();
  });
}

// Remove overlay
function removeOverlay() {
  if (overlay) {
    overlay.remove();
    overlay = null;
  }
}

// Remove sidebar
function removeSidebar() {
  if (sidebar) {
    sidebar.classList.remove('open');
    setTimeout(() => {
      sidebar.remove();
      sidebar = null;
    }, 300);
  }
}

// Proceed with upload
function proceedWithUpload() {
  console.log('Proceeding with upload...');
  // Original upload logic would continue here
}

// Monitor file inputs
function monitorFileInputs() {
  // Monitor existing file inputs
  document.querySelectorAll('input[type="file"]').forEach((input) => {
    if (!input.hasAttribute('data-pii-monitored')) {
      input.setAttribute('data-pii-monitored', 'true');

      input.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (file) {
          e.preventDefault();
          e.stopPropagation();

          // Show scanning overlay
          createOverlay([]);

          // Read and scan file
          const content = await readFileContent(file);
          const findings = scanForPII(content);

          // Update overlay with results
          setTimeout(() => {
            createOverlay(findings);
            detectedPII = findings;
          }, 1000); // Simulate scanning time
        }
      });
    }
  });

  // Monitor drag and drop
  if (!document.body.hasAttribute('data-pii-drop-monitored')) {
    document.body.setAttribute('data-pii-drop-monitored', 'true');

    document.body.addEventListener('drop', async (e) => {
      const files = e.dataTransfer?.files;
      if (files && files.length > 0) {
        const file = files[0];

        // Check if this is a file upload area
        const target = e.target;
        const isUploadArea =
          target.matches(
            'input[type="file"], .upload-area, .dropzone, [data-upload]'
          ) || target.closest('.upload-area, .dropzone, [data-upload]');

        if (isUploadArea) {
          e.preventDefault();
          e.stopPropagation();

          // Show scanning overlay
          createOverlay([]);

          // Read and scan file
          const content = await readFileContent(file);
          const findings = scanForPII(content);

          // Update overlay with results
          setTimeout(() => {
            createOverlay(findings);
            detectedPII = findings;
          }, 1000);
        }
      }
    });
  }
}

// Initialize
function initialize() {
  injectStyles();
  monitorFileInputs();

  // Monitor for dynamically added file inputs
  const observer = new MutationObserver(() => {
    monitorFileInputs();
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });
}

// Start when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initialize);
} else {
  initialize();
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scanPage') {
    const pageText = document.body.innerText;
    const findings = scanForPII(pageText);
    sendResponse({ findings });
  }
  return true;
});
