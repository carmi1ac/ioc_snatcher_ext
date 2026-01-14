/**
 * IOC Detection Patterns
 * Detects various cybersecurity indicators of compromise
 */

export const IOC_TYPES = {
  IPV4: 'IPv4',
  IPV6: 'IPv6',
  CIDR: 'CIDR',
  DEFANGED_IP: 'Defanged IP',
  MD5: 'MD5',
  SHA1: 'SHA1',
  SHA256: 'SHA256',
  SHA512: 'SHA512',
  EMAIL: 'Email',
  DEFANGED_URL: 'Defanged URL',
  URL: 'URL',
  FILENAME: 'Filename',
};

/**
 * Detection patterns for different IOC types
 */
export const IOC_PATTERNS = {
  // CIDR ranges (must be checked before plain IPs to avoid duplicates)
  // IPv4 CIDR: IP address followed by / and subnet mask (0-32)
  [IOC_TYPES.CIDR]: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[12][0-9]|3[0-2])\b|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\/(?:[0-9]|[1-9][0-9]|1[01][0-9]|12[0-8])\b|\b(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\/(?:[0-9]|[1-9][0-9]|1[01][0-9]|12[0-8])\b/g,
  
  // De-fanged IP addresses (must be checked before regular IPs)
  // IPv4 with brackets around dots: 104.194.150[.]26 or 104[.]194[.]150[.]26
  [IOC_TYPES.DEFANGED_IP]: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.|\[\.\]|\(\.\))){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  
  // IPv4 address (excludes private/localhost ranges for better accuracy)
  // Exclude if already matched as CIDR or de-fanged
  [IOC_TYPES.IPV4]: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?!\/)\b/g,
  
  // IPv6 address (exclude if already matched as CIDR)
  [IOC_TYPES.IPV6]: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?!\/)\b|\b(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}(?!\/)\b/g,
  
  // MD5 hash (32 hex characters)
  [IOC_TYPES.MD5]: /\b[a-fA-F0-9]{32}\b/g,
  
  // SHA1 hash (40 hex characters)
  [IOC_TYPES.SHA1]: /\b[a-fA-F0-9]{40}\b/g,
  
  // SHA256 hash (64 hex characters)
  [IOC_TYPES.SHA256]: /\b[a-fA-F0-9]{64}\b/g,
  
  // SHA512 hash (128 hex characters)
  [IOC_TYPES.SHA512]: /\b[a-fA-F0-9]{128}\b/g,
  
  // Email address
  [IOC_TYPES.EMAIL]: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
  
  // De-fanged URLs (must be checked before regular URLs)
  // Patterns: hxxp://, hxxps://, ftxp://, and URLs with [.] or (.) instead of dots
  // Handles multi-part TLDs like .co.uk, .com.au, etc. with brackets anywhere in domain
  // Captures full URLs including paths, query strings (?key=value), fragments (#section), and file extensions
  [IOC_TYPES.DEFANGED_URL]: /\b(?:hxxps?|ftxp):\/\/[^\s<>"{}|\\^`]+|\b(?:https?|ftp|hxxps?|ftxp):\/\/[^\s<>"{}|\\^`]*[\[\(]\.?[\]\)][^\s<>"{}|\\^`]+/g,
  
  // URL (http/https/ftp) - exclude if already matched as de-fanged
  // Captures full URLs including paths (/path/to/file.html), query strings (?key=value&key2=value2), 
  // fragments (#section), ports (:80), and all valid URL characters
  // Stops at whitespace or clearly non-URL characters (<>"{}|\^`)
  [IOC_TYPES.URL]: /\b(?:https?|ftp):\/\/[^\s<>"{}|\\^`]+/g,
  
  // Filename with common suspicious extensions (more focused pattern)
  [IOC_TYPES.FILENAME]: /\b[\w\-_][\w\-_.]*\.(?:exe|dll|bat|cmd|com|pif|scr|vbs|js|jar|msi|sys|drv|bin|sh|ps1|app|deb|rpm|dmg|pkg|apk|ipa|zip|rar|7z|tar|gz|pdf|doc|docx|xls|xlsx|ppt|pptx|txt|log|csv|xml|json|html|htm|php|asp|aspx|jsp|py|rb|pl|bash|psm1|psd1|vbe|wsf|wsh|jse|war|ear|class|iso|img|dat|db|sqlite|mdb|accdb|bak|tmp|temp|old|backup|lock|pid|conf|config|ini|cfg|yaml|yml|env|properties|key|pem|crt|cert|p12|pfx|keystore|truststore|jks)\b/gi,
};

/**
 * Detects all IOCs in a given text string
 * @param {string} text - The text to scan
 * @returns {Array} Array of detected IOCs with type and value
 */
export function detectIOCs(text) {
  const detectedIOCs = [];
  const foundValues = new Set(); // To avoid duplicates
  
  // Order matters: CIDR should be checked first to avoid matching the IP part separately
  // De-fanged IPs should be checked before regular IPs
  // De-fanged URLs should be checked before regular URLs
  const detectionOrder = [
    IOC_TYPES.CIDR,
    IOC_TYPES.DEFANGED_IP,
    IOC_TYPES.IPV4,
    IOC_TYPES.IPV6,
    IOC_TYPES.MD5,
    IOC_TYPES.SHA1,
    IOC_TYPES.SHA256,
    IOC_TYPES.SHA512,
    IOC_TYPES.EMAIL,
    IOC_TYPES.DEFANGED_URL,
    IOC_TYPES.URL,
    IOC_TYPES.FILENAME,
  ];
  
  // Scan for each IOC type in order
  detectionOrder.forEach(type => {
    const pattern = IOC_PATTERNS[type];
    if (!pattern) return;
    
    const matches = text.match(pattern);
    
    if (matches) {
      matches.forEach(match => {
        const normalizedMatch = match.trim();
        // Avoid duplicates and very short matches
        // Also check if this match is part of a previously found CIDR
        if (normalizedMatch.length > 2 && !foundValues.has(normalizedMatch)) {
          // Check if this IP is part of a CIDR we already found
          let isPartOfCIDR = false;
          if (type === IOC_TYPES.IPV4 || type === IOC_TYPES.IPV6) {
            for (const foundValue of foundValues) {
              if (foundValue.includes('/') && foundValue.startsWith(normalizedMatch + '/')) {
                isPartOfCIDR = true;
                break;
              }
            }
          }
          
          if (!isPartOfCIDR) {
            // Normalize de-fanged URLs and IPs
            let finalValue = normalizedMatch;
            if (type === IOC_TYPES.DEFANGED_URL) {
              finalValue = normalizeDefangedURL(normalizedMatch);
            } else if (type === IOC_TYPES.DEFANGED_IP) {
              finalValue = normalizeDefangedIP(normalizedMatch);
            }
            
            // For regular URLs, check if they were already detected as de-fanged URLs
            if (type === IOC_TYPES.URL) {
              let wasDefanged = false;
              for (const foundValue of foundValues) {
                // Check if this URL matches a normalized de-fanged URL
                if (foundValue === normalizedMatch || foundValue === finalValue) {
                  wasDefanged = true;
                  break;
                }
              }
              if (wasDefanged) {
                return; // Skip this URL as it was already detected as de-fanged
              }
            }
            
            // For regular IPs, check if they were already detected as de-fanged IPs
            if (type === IOC_TYPES.IPV4 || type === IOC_TYPES.IPV6) {
              let wasDefanged = false;
              for (const foundValue of foundValues) {
                // Check if this IP matches a normalized de-fanged IP
                if (foundValue === normalizedMatch || foundValue === finalValue) {
                  wasDefanged = true;
                  break;
                }
              }
              if (wasDefanged) {
                return; // Skip this IP as it was already detected as de-fanged
              }
            }
            
            // Check if normalized value already exists (avoid duplicates)
            if (!foundValues.has(finalValue) && !foundValues.has(normalizedMatch)) {
              foundValues.add(finalValue);
              foundValues.add(normalizedMatch); // Also add original to avoid duplicate detection
              detectedIOCs.push({
                type: type,
                value: finalValue,
                originalValue: (type === IOC_TYPES.DEFANGED_URL || type === IOC_TYPES.DEFANGED_IP) ? normalizedMatch : undefined, // Keep original for display if needed
                id: `${type}-${finalValue}-${Date.now()}-${Math.random()}`,
              });
            }
          }
        }
      });
    }
  });
  
  return detectedIOCs;
}

/**
 * Normalizes de-fanged IP addresses back to their original form
 * @param {string} defangedIP - The de-fanged IP address
 * @returns {string} Normalized IP address
 */
function normalizeDefangedIP(defangedIP) {
  let normalized = defangedIP;
  
  // Replace [.] with . (handles brackets around dots - most common pattern)
  normalized = normalized.replace(/\[\.\]/g, '.');
  
  // Replace (.) with . (handles parentheses around dots)
  normalized = normalized.replace(/\(\.\)/g, '.');
  
  // Replace [dot] with . (handles bracket-word format)
  normalized = normalized.replace(/\[dot\]/gi, '.');
  
  // Replace (dot) with . (handles parenthesis-word format)
  normalized = normalized.replace(/\(dot\)/gi, '.');
  
  // Handle brackets with just a dot inside: [ . ] or [. ] or [ .] (with spaces)
  normalized = normalized.replace(/\[\s*\.\s*\]/g, '.');
  
  // Handle parentheses with just a dot inside: ( . ) or (. ) or ( .) (with spaces)
  normalized = normalized.replace(/\(\s*\.\s*\)/g, '.');
  
  return normalized;
}

/**
 * Normalizes de-fanged URLs back to their original form
 * @param {string} defangedUrl - The de-fanged URL
 * @returns {string} Normalized URL
 */
function normalizeDefangedURL(defangedUrl) {
  let normalized = defangedUrl;
  
  // Replace hxxp:// with http://
  normalized = normalized.replace(/^hxxp:\/\//i, 'http://');
  
  // Replace hxxps:// with https://
  normalized = normalized.replace(/^hxxps:\/\//i, 'https://');
  
  // Replace ftxp:// with ftp://
  normalized = normalized.replace(/^ftxp:\/\//i, 'ftp://');
  
  // Replace [.] with . (handles brackets around dots - most common pattern)
  normalized = normalized.replace(/\[\.\]/g, '.');
  
  // Replace (.) with . (handles parentheses around dots)
  normalized = normalized.replace(/\(\.\)/g, '.');
  
  // Replace [dot] with . (handles bracket-word format)
  normalized = normalized.replace(/\[dot\]/gi, '.');
  
  // Replace (dot) with . (handles parenthesis-word format)
  normalized = normalized.replace(/\(dot\)/gi, '.');
  
  // Handle brackets with just a dot inside: [ . ] or [. ] or [ .] (with spaces)
  normalized = normalized.replace(/\[\s*\.\s*\]/g, '.');
  
  // Handle parentheses with just a dot inside: ( . ) or (. ) or ( .) (with spaces)
  normalized = normalized.replace(/\(\s*\.\s*\)/g, '.');
  
  return normalized;
}

/**
 * Validates if a string is a specific IOC type
 * @param {string} value - The value to validate
 * @param {string} type - The IOC type to check
 * @returns {boolean}
 */
export function validateIOC(value, type) {
  if (!IOC_PATTERNS[type]) return false;
  const pattern = new RegExp(`^${IOC_PATTERNS[type].source.replace(/[gimuy]/g, '')}$`);
  return pattern.test(value);
}
