import { detectIOCs } from './modules/iocDetector';
import { highlightIOCs, removeHighlights, getHighlightedIOCs } from './modules/highlighter';

console.log('IOC Snatch.ai - Content script loaded');

let isScanning = false;
let currentHighlights = [];
let highlightColor = '#ff6b6b'; // Default highlight color

// Listen for messages from popup/background
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scan') {
    scanPage();
    sendResponse({ success: true });
  } else if (request.action === 'highlight') {
    highlightColor = request.color || highlightColor;
    highlightIOCs(request.iocs || currentHighlights, highlightColor);
    sendResponse({ success: true });
  } else if (request.action === 'removeHighlights') {
    removeHighlights();
    sendResponse({ success: true });
  } else if (request.action === 'getHighlightedIOCs') {
    const iocs = getHighlightedIOCs();
    sendResponse({ iocs });
  } else if (request.action === 'updateHighlightColor') {
    highlightColor = request.color || highlightColor;
    if (currentHighlights.length > 0) {
      removeHighlights();
      highlightIOCs(currentHighlights, highlightColor);
    }
    sendResponse({ success: true });
  }
  
  return true; // Keep the message channel open for async response
});

/**
 * Scans the current page for IOCs
 */
function scanPage() {
  if (isScanning) return;
  
  isScanning = true;
  
  // Get all text content from the page
  const bodyText = document.body.innerText || document.body.textContent || '';
  
  // Detect IOCs
  const detectedIOCs = detectIOCs(bodyText);
  currentHighlights = detectedIOCs;
  
  // Highlight them
  highlightIOCs(detectedIOCs, highlightColor);
  
  // Send results to popup
  chrome.runtime.sendMessage({
    action: 'iocsDetected',
    iocs: detectedIOCs,
    url: window.location.href,
    timestamp: new Date().toISOString(),
  });
  
  isScanning = false;
  
  console.log(`IOC Snatch.ai: Found ${detectedIOCs.length} IOCs`);
}

// Auto-scan on page load (with a small delay to ensure DOM is ready)
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    setTimeout(scanPage, 1000);
  });
} else {
  setTimeout(scanPage, 1000);
}

// Re-scan when page content changes (for SPAs)
let lastUrl = location.href;
new MutationObserver(() => {
  const url = location.href;
  if (url !== lastUrl) {
    lastUrl = url;
    setTimeout(() => {
      removeHighlights();
      scanPage();
    }, 1000);
  }
}).observe(document, { subtree: true, childList: true });
