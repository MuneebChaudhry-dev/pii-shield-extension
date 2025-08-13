# 🛡️ PII Shield - Chrome Extension

A powerful Chrome extension that detects and protects sensitive information (PII) before document uploads, preventing accidental data exposure.

## ✨ Features

### 🔍 Advanced PII Detection
- **Multi-format Support**: PDF, DOCX, TXT, Images (with OCR capability placeholders)
- **Comprehensive Detection Patterns**:
  - Social Security Numbers (SSN)
  - Credit Card Numbers
  - Email Addresses
  - Phone Numbers
  - Bank Account Numbers
  - CNIC Numbers
  - Passport Numbers
  - Medical Record Numbers
  - IP Addresses
  - Dates of Birth

### 🎨 Modern UI/UX Design
- **Glassmorphic Design**: Beautiful frosted glass effects with smooth animations
- **Color-Coded Alerts**:
  - 🟢 **Green**: Safe - No PII detected
  - 🟡 **Yellow**: Warning - Medium-risk data found
  - 🔴 **Red**: Danger - High-risk sensitive data detected
- **Interactive Sidebar**: Detailed review of detected PII with masking options
- **Real-time Scanning**: Instant analysis when files are selected or dropped

### 🔒 Security Features
- **Client-Side Processing**: All scanning happens locally in your browser
- **No Data Transmission**: Your sensitive data never leaves your device
- **Smart Masking**: Intelligent redaction patterns for different data types
- **One-Click Protection**: Easily mask all detected PII before upload

## 📦 Installation

### Method 1: Load Unpacked Extension (Development)

1. **Download the Extension Files**
   - Create a new folder called `pii-shield-extension`
   - Save all the provided files in this folder:
     - `manifest.json`
     - `content.js`
     - `background.js`
     - `popup.html`
     - `popup.js`

2. **Generate Icons**
   - Open the `icon-generator.html` file in your browser
   - Click "Download All Icons" button
   - Create an `icons` folder in your extension directory
   - Save all downloaded icons (icon16.png, icon32.png, icon48.png, icon128.png) in the `icons` folder

3. **Load the Extension in Chrome**
   - Open Chrome and navigate to `chrome://extensions/`
   - Enable "Developer mode" (toggle in top-right corner)
   - Click "Load unpacked"
   - Select your `pii-shield-extension` folder
   - The extension should now appear in your extensions list

4. **Pin the Extension**
   - Click the puzzle piece icon in Chrome's toolbar
   - Find "PII Shield - Document Protection"
   - Click the pin icon to keep it visible

## 🚀 Usage

### Basic Operation

1. **Automatic File Monitoring**
   - The extension automatically monitors all file upload inputs on web pages
   - When you select or drag-drop a file, it will be scanned automatically

2. **Manual Page Scanning**
   - Click the extension icon in the toolbar
   - Click "Scan Page" to scan the current page for PII

3. **Viewing Results**
   - After scanning, an overlay will appear showing:
     - Summary of detected PII
     - Severity levels and counts
     - Options to proceed or review details

4. **Protecting Data**
   - Click "View Details" to open the sidebar
   - Review each detected PII item
   - Click "Protect All" to mask sensitive data
   - Click "Ready to Upload" when satisfied

### Customization

1. **Toggle Detection Patterns**
   - Open the extension popup
   - In the "Detection Patterns" section, toggle specific PII types on/off
   - Changes are saved automatically

2. **Enable/Disable Extension**
   - Use the main toggle in the extension popup to pause/resume monitoring

## 🏗️ Architecture

### Component Structure

```
pii-shield-extension/
├── manifest.json          # Extension configuration
├── background.js          # Service worker for background tasks
├── content.js            # Content script for page interaction
├── popup.html            # Extension popup interface
├── popup.js              # Popup logic and controls
└── icons/               # Extension icons
    ├── icon16.png
    ├── icon32.png
    ├── icon48.png
    └── icon128.png
```

### Technical Flow

1. **File Detection**: Content script monitors file inputs and drag-drop events
2. **Content Extraction**: Files are read using FileReader API
3. **PII Scanning**: Regular expressions and pattern matching identify sensitive data
4. **User Notification**: Glassmorphic overlay displays results
5. **Data Protection**: Optional masking replaces sensitive data with safe placeholders
6. **Safe Upload**: Protected file can proceed to original upload flow

## 🔧 Development

### Adding New PII Patterns

Edit the `PII_PATTERNS` object in `content.js`:

```javascript
newPattern: {
  pattern: /your-regex-here/g,
  type: 'PATTERN_TYPE',
  severity: 'high|medium|low',
  label: 'Display Name'
}
```

### Customizing UI Colors

Modify the CSS color variables in `content.js`:
- Safe state: `#10b981` (green)
- Warning state: `#f59e0b` (yellow)
- Danger state: `#ef4444` (red)

## 🛠️ Troubleshooting

### Extension Not Working
1. Ensure Developer Mode is enabled in Chrome
2. Check console for errors: Right-click extension icon → "Inspect popup"
3. Reload the extension: chrome://extensions/ → Click refresh icon

### Icons Not Showing
1. Verify the `icons` folder exists in the extension directory
2. Ensure all icon files are named correctly (icon16.png, etc.)
3. Reload the extension after adding icons

### Scanning Not Triggering
1. Check if the extension is enabled (green toggle in popup)
2. Refresh the web page after installing the extension
3. Verify the website allows extensions (some sites block them)

## 🔒 Privacy & Security

- **No External Communication**: The extension never sends data to external servers
- **Local Processing Only**: All PII detection happens in your browser
- **No Data Storage**: Detected PII is not permanently stored
- **Open Source**: All code is transparent and auditable

## 📈 Future Enhancements

- [ ] OCR integration for image-based documents
- [ ] PDF.js integration for better PDF parsing
- [ ] Machine learning models for improved PII detection
- [ ] Custom PII pattern configuration UI
- [ ] Export scan reports
- [ ] Batch file processing
- [ ] Integration with cloud storage services
- [ ] Multi-language PII pattern support

## 📝 License

This extension is provided as-is for educational and personal use. Modify and distribute as needed for your requirements.

## 🤝 Contributing

Feel free to enhance the extension with:
- Additional PII patterns
- Improved detection algorithms
- UI/UX improvements
- Bug fixes and optimizations

## ⚠️ Disclaimer

While this extension helps detect common PII patterns, it should not be relied upon as the sole method of data protection. Always review documents manually before sharing sensitive information.

---

Built with ❤️ for data privacy and security