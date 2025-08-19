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
let db = null; // Add IndexedDB reference

// Initialize IndexedDB
async function initDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('PIIShieldDB', 1);
    
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      db = request.result;
      resolve(db);
    };
    
    request.onupgradeneeded = (event) => {
      const database = event.target.result;
      
      // Create store for file exemptions
      const exemptionsStore = database.createObjectStore('exemptions', { keyPath: 'id' });
      exemptionsStore.createIndex('tabId', 'tabId', { unique: false });
      exemptionsStore.createIndex('timestamp', 'timestamp', { unique: false });
      
      // Create store for tab exemptions
      const tabsStore = database.createObjectStore('exemptedTabs', { keyPath: 'tabId' });
      tabsStore.createIndex('timestamp', 'timestamp', { unique: false });
    };
  });
}

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

    
.pii-shield-actions {
  display: flex;
  gap: 8px; /* Reduced gap for three buttons */
}

.pii-shield-btn {
  flex: 1;
  padding: 10px 16px; /* Slightly smaller padding */
  border-radius: 12px;
  font-size: 13px; /* Slightly smaller font */
  font-weight: 500;
  border: none;
  cursor: pointer;
  transition: all 0.2s ease;
  font-family: inherit;
  text-align: center;
}
  `;
  document.head.appendChild(style);
}

// Scan text for PII
// Scan text for PII
function scanForPII(text) {
  const findings = [];

  // Clean and normalize the text for better matching
  const cleanText = text.replace(/\s+/g, ' ').trim();

  for (const [key, config] of Object.entries(PII_PATTERNS)) {
    try {
      const matches = cleanText.match(config.pattern);
      if (matches) {
        // Remove duplicates
        const uniqueMatches = [...new Set(matches)];

        uniqueMatches.forEach((match) => {
          // Additional validation for certain patterns
          if (isValidPII(match, config.type)) {
            findings.push({
              type: config.type,
              label: config.label,
              value: match.trim(),
              severity: config.severity,
              masked: maskPII(match.trim(), config.type),
            });
          }
        });
      }
    } catch (error) {
      console.error(`Error scanning for ${key}:`, error);
    }
  }

  // Remove duplicate findings
  const uniqueFindings = findings.filter(
    (finding, index, self) =>
      index ===
      self.findIndex(
        (f) => f.value === finding.value && f.type === finding.type
      )
  );

  console.log('Unique findings:', uniqueFindings);
  return uniqueFindings;
}

// Additional validation for PII patterns
function isValidPII(value, type) {
  switch (type) {
    case 'CREDIT_CARD':
      // Basic Luhn algorithm check
      const digits = value.replace(/\D/g, '');
      return digits.length >= 13 && digits.length <= 19;

    case 'SSN':
      const ssnDigits = value.replace(/\D/g, '');
      return (
        ssnDigits.length === 9 &&
        ssnDigits !== '000000000' &&
        ssnDigits !== '123456789'
      );

    case 'BANK_ACCOUNT':
      const bankDigits = value.replace(/\D/g, '');
      return bankDigits.length >= 8 && bankDigits.length <= 17;

    case 'EMAIL':
      // More strict email validation
      return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());

    default:
      return true;
  }
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
// Replace the readFileContent function with this improved version:
async function readFileContent(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();

    reader.onload = (e) => {
      try {
        let content = e.target.result;

        // Handle different file types
        if (file.type.includes('json')) {
          // Pretty print JSON for better scanning
          try {
            const jsonData = JSON.parse(content);
            content = JSON.stringify(jsonData, null, 2);
          } catch (e) {
            // If JSON parsing fails, use as text
          }
        }

        console.log('File content sample:', content.substring(0, 500));
        resolve(content);
      } catch (error) {
        reject(error);
      }
    };

    reader.onerror = () => {
      reject(new Error('Failed to read file'));
    };

    // Handle different file types
    if (
      file.type.includes('text') ||
      file.name.endsWith('.txt') ||
      file.name.endsWith('.csv') ||
      file.name.endsWith('.json') ||
      file.type.includes('json')
    ) {
      reader.readAsText(file);
    } else if (file.type.includes('pdf')) {
      // For PDF, we'll read as text - this won't work perfectly but will catch some cases
      reader.readAsText(file);
    } else if (file.type.includes('word') || file.name.endsWith('.docx')) {
      // For Word docs, read as text - limited functionality
      reader.readAsText(file);
    } else {
      // Default to text reading for any other file type
      reader.readAsText(file);
    }
  });
}

// Create overlay UI
// Create overlay UI with three buttons for PII findings
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
            <div class="pii-shield-stat-label">High</div>
          </div>
        `
            : ''
        }
        ${
          severityCount.medium > 0
            ? `
          <div class="pii-shield-stat">
            <div class="pii-shield-stat-value" style="color: #d97706;">${severityCount.medium}</div>
            <div class="pii-shield-stat-label">Medium</div>
          </div>
        `
            : ''
        }
        ${
          severityCount.low > 0
            ? `
          <div class="pii-shield-stat">
            <div class="pii-shield-stat-value" style="color: #2563eb;">${severityCount.low}</div>
            <div class="pii-shield-stat-label">Low</div>
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
        <button class="pii-shield-btn secondary" id="skip-document">
          Skip This Document
        </button>
        <button class="pii-shield-btn danger" id="skip-tab">
          Skip This Tab
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
    document.getElementById('skip-document')?.addEventListener('click', () => {
      skipCurrentDocument();
    });

    document.getElementById('skip-tab')?.addEventListener('click', () => {
      skipCurrentTab();
    });

    document.getElementById('view-details')?.addEventListener('click', () => {
      removeOverlay();
      showSidebar(findings);
    });
  } else {
    document.getElementById('proceed-upload')?.addEventListener('click', () => {
      removeOverlay();
    });
  }
}

async function skipCurrentDocument() {
  console.log('skipCurrentDocument called');

  const file = window.piiShieldContext?.file;
  if (!file) {
    console.error('No file to skip');
    return;
  }

  try {
    await addFileExemption(file);
    console.log('File exemption added successfully');

    removeOverlay();

    // Proceed with upload
    proceedWithOriginalUpload();

    // Also handle form submission if needed
    if (window.piiShieldFormContext) {
      proceedWithFormSubmission();
    }

    showSuccessMessage(
      'Document Uploaded',
      'Document has been uploaded successfully without scanning.'
    );
  } catch (error) {
    console.error('Error adding file exemption:', error);
  }
}

async function skipCurrentTab() {
  console.log('skipCurrentTab called');

  try {
    await addTabExemption();
    console.log('Tab exemption added successfully');

    removeOverlay();

    // Proceed with upload
    proceedWithOriginalUpload();

    // Also handle form submission if needed
    if (window.piiShieldFormContext) {
      proceedWithFormSubmission();
    }

    showSuccessMessage(
      'Tab Scanning Disabled',
      'Document scanning disabled for this tab. Document uploaded successfully.'
    );
  } catch (error) {
    console.error('Error adding tab exemption:', error);
  }
}

function debugFileInput(input) {
  console.log('Input element:', input);
  console.log('Input value:', input.value);
  console.log('Input files:', input.files);
  console.log('Input onchange:', input.onchange);
  console.log('Input event listeners:', getEventListeners(input));
}
// Show success message (SweetAlert-like)
function showSuccessMessage(title, message) {
  const successOverlay = document.createElement('div');
  successOverlay.className = 'pii-shield-overlay glass';
  
  successOverlay.innerHTML = `
    <div class="pii-shield-header">
      <div class="pii-shield-icon safe">
        ✓
      </div>
      <div>
        <h2 class="pii-shield-title">${title}</h2>
        <p class="pii-shield-subtitle">${message}</p>
      </div>
    </div>
    
    <div class="pii-shield-actions">
      <button class="pii-shield-btn primary" id="close-success" style="width: 100%;">
        OK
      </button>
    </div>
  `;
  
  document.body.appendChild(successOverlay);
  
  // Auto close after 3 seconds or on click
  const closeBtn = document.getElementById('close-success');
  const closeFunction = () => {
    successOverlay.remove();
  };
  
  closeBtn.addEventListener('click', closeFunction);
  setTimeout(closeFunction, 3000);
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
  insertDocumentSummary();
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
// Proceed with upload
function proceedWithUpload() {
  console.log('Proceeding with upload...');
  proceedWithOriginalUpload();
}
// Old file input monitoring code removed - now using targeted injection system

// Old scanFile function removed - now using handleDocumentUpload

// New function to update overlay with results (prevents duplicate overlays)
function updateOverlayWithResults(findings) {
  if (!overlay) {
    createOverlay(findings);
    return;
  }

  // Update existing overlay instead of creating new one
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

  // Update overlay content
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
              ? 'No sensitive information detected - Ready to upload'
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
    <button class="pii-shield-btn secondary" id="skip-document">
      Skip This Document
    </button>
    <button class="pii-shield-btn danger" id="skip-tab">
      Skip This Tab
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

  // Re-attach event listeners
  attachOverlayEventListeners(findings, totalFindings > 0);
}

// Separate function for event listeners
// Add this function to content.js (place it after the updateOverlayWithResults function)
// Make sure your attachOverlayEventListeners function looks like this:
function attachOverlayEventListeners(findings, hasPII) {
  if (hasPII) {
    document.getElementById('skip-document')?.addEventListener('click', () => {
      console.log('Skip document button clicked!'); // Debug log
      skipCurrentDocument();
    });

    document.getElementById('skip-tab')?.addEventListener('click', () => {
      console.log('Skip tab button clicked!'); // Debug log
      skipCurrentTab();
    });

    document.getElementById('view-details')?.addEventListener('click', () => {
      removeOverlay();
      showSidebar(findings);
    });
  } else {
    document.getElementById('proceed-upload')?.addEventListener('click', () => {
      insertDocumentSummary();
      removeOverlay();
    });
  }
}

// Function to insert document summary into target element
function insertDocumentSummary() {
  if (window.piiShieldUploadContext) {
    const { file, targetElement } = window.piiShieldUploadContext;
    
    const summary = `Document: ${file.name} (${(file.size / 1024).toFixed(1)}KB) - Scanned ✅ No PII detected`;
    
    // Insert into target element based on its type
    if (targetElement.tagName === 'TEXTAREA') {
      // For textarea elements
      const currentValue = targetElement.value;
      targetElement.value = currentValue + (currentValue ? '\n\n' : '') + summary;
      targetElement.dispatchEvent(new Event('input', { bubbles: true }));
    } else if (targetElement.contentEditable === 'true') {
      // For contenteditable elements
      const selection = window.getSelection();
      const range = document.createRange();
      
      // Place cursor at end of content
      range.selectNodeContents(targetElement);
      range.collapse(false);
      selection.removeAllRanges();
      selection.addRange(range);
      
      // Insert content
      const textToInsert = (targetElement.innerText ? '\n\n' : '') + summary;
      document.execCommand('insertText', false, textToInsert);
    }
    
    // Clean up context
    delete window.piiShieldUploadContext;
  }
}

// New function to show scanning state
function createScanningOverlay() {
  removeOverlay();

  overlay = document.createElement('div');
  overlay.className = 'pii-shield-overlay glass';

  overlay.innerHTML = `
    <div class="pii-shield-header">
      <div class="pii-shield-icon safe scanning">
        <div style="animation: spin 1s linear infinite;">⟳</div>
      </div>
      <div>
        <h2 class="pii-shield-title">Scanning Document</h2>
        <p class="pii-shield-subtitle">Analyzing content for sensitive information...</p>
      </div>
    </div>
    
    <div style="text-align: center; padding: 20px;">
      <div style="width: 100%; background: #e5e7eb; border-radius: 8px; height: 6px; overflow: hidden;">
        <div style="width: 0%; height: 100%; background: linear-gradient(135deg, #3b82f6, #2563eb); border-radius: 8px; animation: progressBar 2s ease-in-out;"></div>
      </div>
      <p style="margin-top: 12px; font-size: 13px; color: #6b7280;">Please wait while we analyze your document...</p>
    </div>
  `;

  document.body.appendChild(overlay);
}

// Add spin animation to styles
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

    @keyframes spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }

    @keyframes progressBar {
      from { width: 0%; }
      to { width: 100%; }
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
      // Add this animation to your existing CSS in injectStyles()
      @keyframes bypassCountdown {
        from { width: 100%; }
        to { width: 0%; }
      }

    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }

    /* PII Shield Injection Button Styles */
    .pii-shield-inject-btn {
      width: 32px;
      height: 32px;
      border: none;
      border-radius: 50%;
      background: linear-gradient(135deg, #3b82f6, #2563eb);
      color: white;
      font-size: 16px;
      cursor: pointer;
      box-shadow: 0 2px 8px rgba(59, 130, 246, 0.3);
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: inherit;
    }

    .pii-shield-inject-btn:hover {
      transform: scale(1.1);
      box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
    }

    .pii-shield-button-container {
      pointer-events: none;
    }

    .pii-shield-button-container button {
      pointer-events: auto;
    }

    /* Upload Modal Styles */
    .pii-shield-upload-modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.5);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 999999;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    .pii-shield-upload-modal {
      background: white;
      border-radius: 16px;
      width: 500px;
      max-width: 90vw;
      max-height: 80vh;
      overflow: hidden;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      animation: modalSlideIn 0.3s ease-out;
    }

    @keyframes modalSlideIn {
      from {
        opacity: 0;
        transform: scale(0.9) translateY(-20px);
      }
      to {
        opacity: 1;
        transform: scale(1) translateY(0);
      }
    }

    .pii-shield-upload-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 20px 24px;
      border-bottom: 1px solid #e5e7eb;
      background: linear-gradient(135deg, #f9fafb, #f3f4f6);
    }

    .pii-shield-upload-header h3 {
      margin: 0;
      color: #1f2937;
      font-size: 18px;
      font-weight: 600;
    }

    .pii-shield-close-modal {
      width: 32px;
      height: 32px;
      border: none;
      border-radius: 8px;
      background: white;
      color: #6b7280;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 16px;
      transition: all 0.2s;
    }

    .pii-shield-close-modal:hover {
      background: #f3f4f6;
      color: #1f2937;
    }

    .pii-shield-upload-content {
      padding: 24px;
    }

    .pii-shield-upload-area {
      border: 2px dashed #d1d5db;
      border-radius: 12px;
      padding: 40px 20px;
      text-align: center;
      cursor: pointer;
      transition: all 0.2s;
      background: #f9fafb;
    }

    .pii-shield-upload-area:hover {
      border-color: #3b82f6;
      background: #eff6ff;
    }

    .pii-shield-upload-area.drag-over {
      border-color: #3b82f6;
      background: #eff6ff;
      transform: scale(1.02);
    }

    .pii-shield-upload-icon {
      font-size: 48px;
      margin-bottom: 16px;
    }

    .pii-shield-upload-prompt p {
      margin: 0 0 8px 0;
      color: #374151;
      font-weight: 500;
    }

    .pii-shield-upload-prompt small {
      color: #6b7280;
      font-size: 13px;
    }

    .pii-shield-scanning {
      text-align: center;
      padding: 20px;
    }

    .pii-shield-spinner {
      width: 32px;
      height: 32px;
      border: 3px solid #e5e7eb;
      border-top: 3px solid #3b82f6;
      border-radius: 50%;
      animation: spin 1s linear infinite;
      margin: 0 auto 16px;
    }

    .pii-shield-error {
      text-align: center;
      padding: 20px;
      color: #dc2626;
    }

    .pii-shield-error p {
      margin: 0 0 16px 0;
    }
  `;
  document.head.appendChild(style);
}

// Add this function to content.js:
function updateScanStats(findings) {
  // Send stats update to background script
  chrome.runtime.sendMessage({
    action: 'updateStats',
    findings: findings,
    scansCount: 1,
  });
}

// Monitor drag and drop
// if (!document.body.hasAttribute('data-pii-drop-monitored')) {
//   document.body.setAttribute('data-pii-drop-monitored', 'true');

//   document.body.addEventListener('drop', async (e) => {
//     const files = e.dataTransfer?.files;
//     if (files && files.length > 0) {
//       const file = files[0];

//       // Check if this is a file upload area
//       const target = e.target;
//       const isUploadArea =
//         target.matches(
//           'input[type="file"], .upload-area, .dropzone, [data-upload]'
//         ) || target.closest('.upload-area, .dropzone, [data-upload]');

//       if (isUploadArea) {
//         e.preventDefault();
//         e.stopPropagation();

//         // Show scanning overlay
//         createOverlay([]);

//         // Read and scan file
//         const content = await readFileContent(file);
//         const findings = scanForPII(content);

//         // Update overlay with results
//         setTimeout(() => {
//           createOverlay(findings);
//           detectedPII = findings;
//         }, 1000);
//       }
//     }
//   });

// }

// Add this function to content.js for debugging:
function testPIIPatterns() {
  const testText = `
    Test Document Content:
    Name: John Doe
    SSN: 123-45-6789
    Email: john.doe@example.com
    Phone: (555) 123-4567
    Credit Card: 4532 1234 5678 9012
    Bank Account: 141592653
    Another email: test@company.org
    IP: 192.168.1.1
    Date: 01/15/1990
  `;

  console.log('Testing PII patterns with sample text:');
  console.log(testText);

  const findings = scanForPII(testText);
  console.log('Test PII scan results:', findings);

  if (findings.length > 0) {
    createOverlay(findings);
  } else {
    console.log('No PII detected in test');
  }

  return findings;
}

// Expose test function globally for debugging
window.testPIIShield = testPIIPatterns;



// Get current tab ID
function getCurrentTabId() {
  return window.location.href + window.location.search;
}

// Generate file signature
function getFileSignature(file) {
  return `${file.name}_${file.size}_${file.lastModified}`;
}

// Check if file is exempted
async function isFileExempted(file) {
  if (!db) return false;
  
  const tabId = getCurrentTabId();
  const fileSignature = getFileSignature(file);
  const exemptionId = `${tabId}_${fileSignature}`;
  
  return new Promise((resolve) => {
    const transaction = db.transaction(['exemptions'], 'readonly');
    const store = transaction.objectStore('exemptions');
    const request = store.get(exemptionId);
    
    request.onsuccess = () => {
      if (request.result) {
        // Check if exemption is still valid (within 10 minutes)
        const exemptionAge = Date.now() - request.result.timestamp;
        const isValid = exemptionAge < 10 * 60 * 1000; // 10 minutes
        resolve(isValid);
      } else {
        resolve(false);
      }
    };
    
    request.onerror = () => resolve(false);
  });
}

// Check if tab is exempted
async function isTabExempted() {
  if (!db) return false;
  
  const tabId = getCurrentTabId();
  
  return new Promise((resolve) => {
    const transaction = db.transaction(['exemptedTabs'], 'readonly');
    const store = transaction.objectStore('exemptedTabs');
    const request = store.get(tabId);
    
    request.onsuccess = () => {
      if (request.result) {
        // Check if exemption is still valid (within 10 minutes)
        const exemptionAge = Date.now() - request.result.timestamp;
        const isValid = exemptionAge < 10 * 60 * 1000; // 10 minutes
        resolve(isValid);
      } else {
        resolve(false);
      }
    };
    
    request.onerror = () => resolve(false);
  });
}

// Add file exemption
async function addFileExemption(file) {
  if (!db) return;
  
  const tabId = getCurrentTabId();
  const fileSignature = getFileSignature(file);
  const exemptionId = `${tabId}_${fileSignature}`;
  
  const transaction = db.transaction(['exemptions'], 'readwrite');
  const store = transaction.objectStore('exemptions');
  
  store.put({
    id: exemptionId,
    tabId: tabId,
    fileSignature: fileSignature,
    fileName: file.name,
    timestamp: Date.now()
  });
}

// Add tab exemption
async function addTabExemption() {
  if (!db) return;
  
  const tabId = getCurrentTabId();
  
  const transaction = db.transaction(['exemptedTabs'], 'readwrite');
  const store = transaction.objectStore('exemptedTabs');
  
  store.put({
    tabId: tabId,
    timestamp: Date.now()
  });
}

// Clean up old exemptions
async function cleanupExemptions() {
  if (!db) return;
  
  const cutoffTime = Date.now() - 10 * 60 * 1000; // 10 minutes ago
  
  // Clean file exemptions
  const transaction1 = db.transaction(['exemptions'], 'readwrite');
  const store1 = transaction1.objectStore('exemptions');
  const index1 = store1.index('timestamp');
  const range1 = IDBKeyRange.upperBound(cutoffTime);
  
  index1.openCursor(range1).onsuccess = (event) => {
    const cursor = event.target.result;
    if (cursor) {
      cursor.delete();
      cursor.continue();
    }
  };
  
  // Clean tab exemptions
  const transaction2 = db.transaction(['exemptedTabs'], 'readwrite');
  const store2 = transaction2.objectStore('exemptedTabs');
  const index2 = store2.index('timestamp');
  const range2 = IDBKeyRange.upperBound(cutoffTime);
  
  index2.openCursor(range2).onsuccess = (event) => {
    const cursor = event.target.result;
    if (cursor) {
      cursor.delete();
      cursor.continue();
    }
  };
}


// PII Shield Button Injection System
function injectPIIShieldButtons() {
  // Get current domain for site-specific targeting
  const domain = window.location.hostname;
  
  // Site-specific selectors for better targeting
  const siteSelectors = {
    // Gmail
    'mail.google.com': [
      '[role="textbox"][contenteditable="true"]',
      '.Am.Al.editable',
      '[g_editable="true"]'
    ],
    // ChatGPT
    'chat.openai.com': [
      '[data-testid="textbox"]',
      '#prompt-textarea',
      'textarea[placeholder*="message"]'
    ],
    // Claude (Anthropic)
    'claude.ai': [
      '[data-testid="chat-input"]',
      'textarea[placeholder*="Talk to Claude"]',
      '[contenteditable="true"][role="textbox"]'
    ],
    // Slack
    'slack.com': [
      '[data-qa="message_input"]',
      '.ql-editor[contenteditable="true"]',
      '[role="textbox"][contenteditable="true"]'
    ],
    // Discord
    'discord.com': [
      '[class*="textArea"]',
      '[placeholder*="Message"]',
      '.markup [contenteditable="true"]'
    ],
    // WhatsApp Web
    'web.whatsapp.com': [
      '[data-testid="conversation-compose-box-input"]',
      '[contenteditable="true"][role="textbox"]'
    ],
    // Microsoft Teams
    'teams.microsoft.com': [
      '[data-tid="ckeditor"]',
      '[role="textbox"][contenteditable="true"]'
    ],
    // LinkedIn
    'linkedin.com': [
      '[role="textbox"][contenteditable="true"]',
      '.ql-editor[contenteditable="true"]'
    ],
    // Twitter/X
    'twitter.com': [
      '[data-testid="tweetTextarea_0"]',
      '[role="textbox"][contenteditable="true"]'
    ],
    'x.com': [
      '[data-testid="tweetTextarea_0"]',
      '[role="textbox"][contenteditable="true"]'
    ]
  };

  // Get selectors for current site or use generic ones
  let selectors = siteSelectors[domain] || [
    // Generic fallback selectors
    'textarea',
    'div[contenteditable="true"]',
    '[role="textbox"][contenteditable="true"]',
    '[contenteditable="true"]'
  ];

  // Always include some common patterns
  selectors = selectors.concat([
    'textarea',
    '[data-testid="textbox"]',
    'div[contenteditable="true"]'
  ]);

  // Remove duplicates
  selectors = [...new Set(selectors)];

  selectors.forEach(selector => {
    try {
      const elements = document.querySelectorAll(selector);
      elements.forEach(element => {
        if (!element.hasAttribute('data-pii-shield-injected') && isValidTextArea(element)) {
          injectButtonNearElement(element);
          element.setAttribute('data-pii-shield-injected', 'true');
        }
      });
    } catch (error) {
      console.log('Selector error:', selector, error);
    }
  });
}

function isValidTextArea(element) {
  // Check if element is visible and suitable for document upload
  const rect = element.getBoundingClientRect();
  const isVisible = rect.width > 50 && rect.height > 20;
  const isNotScript = !element.closest('script, style, noscript');
  const isNotHidden = getComputedStyle(element).display !== 'none';
  
  return isVisible && isNotScript && isNotHidden;
}

function injectButtonNearElement(targetElement) {
  // Create PII Shield button
  const button = document.createElement('button');
  button.className = 'pii-shield-inject-btn';
  button.innerHTML = '🛡️';
  button.title = 'PII Shield - Scan Document';
  button.type = 'button';
  
  // Position button relative to target element
  const rect = targetElement.getBoundingClientRect();
  const container = document.createElement('div');
  container.className = 'pii-shield-button-container';
  container.style.cssText = `
    position: absolute;
    z-index: 999999;
    top: ${window.scrollY + rect.bottom - 35}px;
    left: ${window.scrollX + rect.right - 35}px;
    pointer-events: auto;
  `;
  
  container.appendChild(button);
  document.body.appendChild(container);
  
  // Store reference to target element
  button.targetElement = targetElement;
  
  // Add click handler
  button.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    showDocumentUploadModal(targetElement);
  });
  
  // Update position on scroll/resize
  const updatePosition = () => {
    const newRect = targetElement.getBoundingClientRect();
    container.style.top = `${window.scrollY + newRect.bottom - 35}px`;
    container.style.left = `${window.scrollX + newRect.right - 35}px`;
  };
  
  window.addEventListener('scroll', updatePosition);
  window.addEventListener('resize', updatePosition);
  
  // Clean up when target element is removed
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      mutation.removedNodes.forEach((node) => {
        if (node === targetElement || (node.contains && node.contains(targetElement))) {
          container.remove();
          observer.disconnect();
        }
      });
    });
  });
  
  observer.observe(document.body, { childList: true, subtree: true });
}

function showDocumentUploadModal(targetElement) {
  // Remove any existing modal
  removeDocumentUploadModal();
  
  // Create modal overlay
  const modalOverlay = document.createElement('div');
  modalOverlay.className = 'pii-shield-upload-modal-overlay';
  modalOverlay.innerHTML = `
    <div class="pii-shield-upload-modal">
      <div class="pii-shield-upload-header">
        <h3>🛡️ PII Shield Document Scanner</h3>
        <button class="pii-shield-close-modal" type="button">✕</button>
      </div>
      <div class="pii-shield-upload-content">
        <div class="pii-shield-upload-area" id="pii-upload-area">
          <input type="file" id="pii-file-input" accept=".txt,.pdf,.doc,.docx,.csv,.json" style="display: none;">
          <div class="pii-shield-upload-prompt">
            <div class="pii-shield-upload-icon">📄</div>
            <p>Click to select or drag & drop your document</p>
            <small>Supported: .txt, .pdf, .doc, .docx, .csv, .json</small>
          </div>
        </div>
        <div class="pii-shield-upload-status" id="pii-upload-status" style="display: none;"></div>
      </div>
    </div>
  `;
  
  document.body.appendChild(modalOverlay);
  
  // Add event listeners
  const closeBtn = modalOverlay.querySelector('.pii-shield-close-modal');
  const fileInput = document.getElementById('pii-file-input');
  const uploadArea = document.getElementById('pii-upload-area');
  const statusDiv = document.getElementById('pii-upload-status');
  
  closeBtn.addEventListener('click', removeDocumentUploadModal);
  modalOverlay.addEventListener('click', (e) => {
    if (e.target === modalOverlay) {
      removeDocumentUploadModal();
    }
  });
  
  // File upload handling
  uploadArea.addEventListener('click', () => fileInput.click());
  
  fileInput.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (file) {
      await handleDocumentUpload(file, statusDiv, targetElement);
    }
  });
  
  // Drag and drop handling
  uploadArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadArea.classList.add('drag-over');
  });
  
  uploadArea.addEventListener('dragleave', () => {
    uploadArea.classList.remove('drag-over');
  });
  
  uploadArea.addEventListener('drop', async (e) => {
    e.preventDefault();
    uploadArea.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) {
      await handleDocumentUpload(file, statusDiv, targetElement);
    }
  });
}

async function handleDocumentUpload(file, statusDiv, targetElement) {
  try {
    // Show scanning status
    statusDiv.style.display = 'block';
    statusDiv.innerHTML = `
      <div class="pii-shield-scanning">
        <div class="pii-shield-spinner"></div>
        <p>Scanning "${file.name}" for sensitive information...</p>
      </div>
    `;
    
    // Store the file and target element for later use
    window.piiShieldUploadContext = {
      file: file,
      targetElement: targetElement
    };
    
    // Read and scan file
    const content = await readFileContent(file);
    const findings = scanForPII(content);
    
    // Hide modal and show results
    removeDocumentUploadModal();
    
    // Show scan results
    createOverlay(findings);
    detectedPII = findings;
    
    // Update stats
    updateScanStats(findings);
    
  } catch (error) {
    console.error('Error scanning document:', error);
    statusDiv.innerHTML = `
      <div class="pii-shield-error">
        <p>❌ Error scanning document: ${error.message}</p>
        <button onclick="removeDocumentUploadModal()" class="pii-shield-btn secondary">Close</button>
      </div>
    `;
  }
}

function removeDocumentUploadModal() {
  const modal = document.querySelector('.pii-shield-upload-modal-overlay');
  if (modal) {
    modal.remove();
  }
}

// Initialize
async function initialize() {
  if (!document.body) {
    setTimeout(initialize, 100);
    return;
  }

  try {
    await initDB();
    console.log('IndexedDB initialized successfully');
  } catch (error) {
    console.error('Failed to initialize IndexedDB:', error);
  }

  injectStyles();
  injectPIIShieldButtons();

  // Monitor for new elements and inject buttons
  const observer = new MutationObserver(() => {
    injectPIIShieldButtons();
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });

  setInterval(cleanupExemptions, 5 * 60 * 1000);
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
