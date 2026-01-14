/**
 * Highlighter module for marking IOCs on the page
 */

const HIGHLIGHT_CLASS = 'ioc-snatch-highlight';
const HIGHLIGHT_DATA_ATTR = 'data-ioc-value';
const HIGHLIGHT_TYPE_ATTR = 'data-ioc-type';

/**
 * Highlights IOCs on the page
 * @param {Array} iocs - Array of IOC objects with type and value
 * @param {string} highlightColor - CSS color for highlighting
 */
export function highlightIOCs(iocs, highlightColor = '#ff6b6b') {
  // Remove existing highlights first
  removeHighlights();
  
  if (!iocs || iocs.length === 0) return;
  
  // Create a list of IOCs with their search values
  // For de-fanged URLs, we need to search for the original de-fanged text on the page
  const iocSearchList = iocs.map(ioc => ({
    ioc: ioc,
    searchValue: ioc.originalValue || ioc.value, // Use original value for searching if it exists
  }));
  
  // Walk through all text nodes in the document
  const walker = document.createTreeWalker(
    document.body,
    NodeFilter.SHOW_TEXT,
    {
      acceptNode: function(node) {
        // Skip script and style tags
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        const tagName = parent.tagName.toLowerCase();
        if (tagName === 'script' || tagName === 'style' || tagName === 'noscript') {
          return NodeFilter.FILTER_REJECT;
        }
        // Skip already highlighted nodes
        if (parent.classList && parent.classList.contains(HIGHLIGHT_CLASS)) {
          return NodeFilter.FILTER_REJECT;
        }
        return NodeFilter.FILTER_ACCEPT;
      }
    }
  );
  
  const replacements = [];
  let node;
  
  // Collect all text nodes and their replacements
  while (node = walker.nextNode()) {
    const text = node.textContent;
    if (!text || text.trim().length === 0) continue;
    
    // Check each IOC value
    iocSearchList.forEach(({ ioc, searchValue }) => {
      const regex = new RegExp(escapeRegex(searchValue), 'gi');
      let match;
      
      while ((match = regex.exec(text)) !== null) {
        replacements.push({
          node: node,
          start: match.index,
          end: match.index + match[0].length,
          value: match[0],
          ioc: ioc,
        });
      }
    });
  }
  
  // Sort replacements by node and position (reverse order to avoid index shifting)
  replacements.sort((a, b) => {
    if (a.node !== b.node) {
      return 0; // Process nodes separately
    }
    return b.start - a.start; // Reverse order
  });
  
  // Group replacements by node
  const nodeReplacements = new Map();
  replacements.forEach(rep => {
    if (!nodeReplacements.has(rep.node)) {
      nodeReplacements.set(rep.node, []);
    }
    nodeReplacements.get(rep.node).push(rep);
  });
  
  // Apply replacements
  nodeReplacements.forEach((reps, textNode) => {
    const currentText = textNode.textContent;
    const fragments = [];
    
    // Sort replacements by start position
    reps.sort((a, b) => a.start - b.start);
    
    let lastIndex = 0;
    
    // Process each replacement
    reps.forEach(rep => {
      // Add text before this replacement
      if (rep.start > lastIndex) {
        fragments.push(document.createTextNode(currentText.substring(lastIndex, rep.start)));
      }
      
      // Add highlight span
      const highlightSpan = document.createElement('span');
      highlightSpan.className = HIGHLIGHT_CLASS;
      highlightSpan.setAttribute(HIGHLIGHT_DATA_ATTR, rep.ioc.value);
      highlightSpan.setAttribute(HIGHLIGHT_TYPE_ATTR, rep.ioc.type);
      highlightSpan.style.backgroundColor = highlightColor;
      highlightSpan.style.color = '#ffffff';
      highlightSpan.style.padding = '2px 4px';
      highlightSpan.style.borderRadius = '3px';
      highlightSpan.style.cursor = 'pointer';
      highlightSpan.style.fontWeight = 'bold';
      highlightSpan.textContent = rep.value;
      fragments.push(highlightSpan);
      
      lastIndex = rep.end;
    });
    
    // Add remaining text after last replacement
    if (lastIndex < currentText.length) {
      fragments.push(document.createTextNode(currentText.substring(lastIndex)));
    }
    
    // Replace the text node with fragments
    if (fragments.length > 0) {
      const parent = textNode.parentNode;
      fragments.forEach(fragment => {
        parent.insertBefore(fragment, textNode);
      });
      parent.removeChild(textNode);
    }
  });
}

/**
 * Escapes special regex characters
 */
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Removes all highlights from the page
 */
export function removeHighlights() {
  const highlights = document.querySelectorAll(`.${HIGHLIGHT_CLASS}`);
  highlights.forEach(highlight => {
    const parent = highlight.parentNode;
    const text = highlight.textContent;
    const textNode = document.createTextNode(text);
    parent.replaceChild(textNode, highlight);
    // Normalize adjacent text nodes
    parent.normalize();
  });
}

/**
 * Gets all highlighted IOCs from the page
 * @returns {Array} Array of IOC objects
 */
export function getHighlightedIOCs() {
  const highlights = document.querySelectorAll(`.${HIGHLIGHT_CLASS}`);
  const iocs = [];
  const seen = new Set();
  
  highlights.forEach(highlight => {
    const value = highlight.getAttribute(HIGHLIGHT_DATA_ATTR);
    const type = highlight.getAttribute(HIGHLIGHT_TYPE_ATTR);
    
    if (value && !seen.has(value)) {
      seen.add(value);
      iocs.push({
        type: type,
        value: value,
        id: `${type}-${value}-${Date.now()}-${Math.random()}`,
      });
    }
  });
  
  return iocs;
}
