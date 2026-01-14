// Background service worker for IOC Snatch.ai
import OpenAI from 'openai';

console.log('IOC Snatch.ai - Background service worker loaded');

let openaiClient = null;

// Initialize OpenAI client with API key from storage
async function initializeOpenAI() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(['openaiApiKey'], (result) => {
      if (result.openaiApiKey && result.openaiApiKey.trim()) {
        openaiClient = new OpenAI({
          apiKey: result.openaiApiKey.trim(),
          dangerouslyAllowBrowser: true, // Required for browser extensions
        });
        resolve(true);
      } else {
        openaiClient = null;
        resolve(false);
      }
    });
  });
}

// Initialize on startup
initializeOpenAI();

// Listen for API key updates
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === 'sync' && changes.openaiApiKey) {
    initializeOpenAI();
  }
});

// Initialize default settings if they don't exist
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.get(['highlightColor', 'separator', 'savedLists', 'openaiApiKey'], (result) => {
    if (!result.highlightColor) {
      chrome.storage.sync.set({ highlightColor: '#ff6b6b' });
    }
    if (!result.separator) {
      chrome.storage.sync.set({ separator: 'comma' });
    }
    if (!result.savedLists) {
      chrome.storage.sync.set({ savedLists: [] });
    }
  });
});

/**
 * Analyzes IOCs using OpenAI to get risk scores from security sites
 * @param {Array} iocs - Array of IOC objects
 * @returns {Promise<Array>} Array of IOCs with risk scores
 */
async function analyzeIOCsWithOpenAI(iocs) {
  if (!openaiClient || iocs.length === 0) {
    return iocs;
  }

  try {
    // Format IOCs for the prompt
    const iocList = iocs.map((ioc, index) => `${index + 1}. ${ioc.type}: ${ioc.value}`).join('\n');

    const prompt = `You are a cybersecurity expert. Analyze the following Indicators of Compromise (IOCs) and provide risk scores based on information from security sites like VirusTotal, AbuseIPDB, URLhaus, and other threat intelligence sources.

For each IOC, provide:
1. A risk score from 0-100 (0 = safe, 100 = highly malicious)
2. A brief explanation of the risk
3. The most recent threat intelligence information available

IOCs to analyze:
${iocList}

Respond in JSON format only, with this structure:
{
  "results": [
    {
      "index": 1,
      "type": "IPv4",
      "value": "192.168.1.1",
      "riskScore": 85,
      "riskLevel": "High",
      "explanation": "Listed on multiple blacklists, associated with malware campaigns",
      "threatIntelligence": "Found in 15 malware samples on VirusTotal, flagged by AbuseIPDB"
    }
  ]
}`;

    // Calculate max_tokens based on number of IOCs (approximately 150 tokens per IOC)
    // Add buffer for JSON structure and ensure minimum of 4000 tokens
    const estimatedTokens = Math.max(4000, iocs.length * 150 + 500);
    const maxTokens = Math.min(16000, estimatedTokens); // Cap at 16k tokens (gpt-4o-mini limit)
    
    console.log(`Requesting analysis for ${iocs.length} IOCs with max_tokens: ${maxTokens}`);
    
    const completion = await openaiClient.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [
        {
          role: 'system',
          content: 'You are a cybersecurity expert specializing in threat intelligence and IOC analysis. Always respond with valid, complete JSON only. Ensure the JSON response is complete and properly closed.',
        },
        {
          role: 'user',
          content: prompt,
        },
      ],
      temperature: 0.3,
      max_tokens: maxTokens,
      response_format: { type: 'json_object' }, // Request JSON format explicitly
    });

    const responseText = completion.choices[0]?.message?.content || '';
    console.log('OpenAI response text length:', responseText.length);
    
    // Parse JSON response - handle multiple formats
    let analysisResult;
    try {
      let jsonText = responseText.trim();
      
      // Remove markdown code blocks if present - match the entire content between ```
      const codeBlockMatch = jsonText.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
      if (codeBlockMatch && codeBlockMatch[1]) {
        jsonText = codeBlockMatch[1].trim();
      }
      
      // If still no valid JSON, try to extract JSON object by finding balanced braces
      if (!jsonText.startsWith('{')) {
        const firstBrace = jsonText.indexOf('{');
        if (firstBrace !== -1) {
          jsonText = jsonText.substring(firstBrace);
        }
      }
      
      // Find the complete JSON object by matching balanced braces
      let braceCount = 0;
      let jsonStart = jsonText.indexOf('{');
      let jsonEnd = -1;
      
      if (jsonStart !== -1) {
        let inString = false;
        let escapeNext = false;
        
        for (let i = jsonStart; i < jsonText.length; i++) {
          const char = jsonText[i];
          
          if (escapeNext) {
            escapeNext = false;
            continue;
          }
          
          if (char === '\\') {
            escapeNext = true;
            continue;
          }
          
          if (char === '"') {
            inString = !inString;
            continue;
          }
          
          if (!inString) {
            if (char === '{') {
              braceCount++;
            } else if (char === '}') {
              braceCount--;
              if (braceCount === 0) {
                jsonEnd = i + 1;
                break;
              }
            }
          }
        }
        
        if (jsonEnd > jsonStart) {
          jsonText = jsonText.substring(jsonStart, jsonEnd);
        }
      }
      
      console.log('Extracted JSON text length:', jsonText.length);
      console.log('Extracted JSON (first 500):', jsonText.substring(0, 500));
      console.log('Extracted JSON (last 200):', jsonText.substring(Math.max(0, jsonText.length - 200)));
      
      analysisResult = JSON.parse(jsonText);
      console.log('Successfully parsed JSON - results count:', analysisResult.results?.length || 'N/A');
    } catch (parseError) {
      console.error('Failed to parse OpenAI response:', parseError);
      console.error('Error message:', parseError.message);
      
      // Try to extract partial results from the response
      try {
        console.log('Attempting to extract partial results...');
        const partialResults = [];
        
        // Find all complete JSON objects in the results array
        const resultsArrayMatch = responseText.match(/"results"\s*:\s*\[/);
        if (resultsArrayMatch) {
          const startPos = resultsArrayMatch.index + resultsArrayMatch[0].length;
          let braceDepth = 0;
          let currentObj = '';
          let inString = false;
          let escapeNext = false;
          let objStart = -1;
          
          for (let i = startPos; i < responseText.length; i++) {
            const char = responseText[i];
            
            if (escapeNext) {
              escapeNext = false;
              if (objStart !== -1) currentObj += char;
              continue;
            }
            
            if (char === '\\') {
              escapeNext = true;
              if (objStart !== -1) currentObj += char;
              continue;
            }
            
            if (char === '"') {
              inString = !inString;
              if (objStart !== -1) currentObj += char;
              continue;
            }
            
            if (!inString) {
              if (char === '{') {
                if (braceDepth === 0) {
                  objStart = i;
                  currentObj = '{';
                } else {
                  currentObj += char;
                }
                braceDepth++;
              } else if (char === '}') {
                braceDepth--;
                currentObj += char;
                if (braceDepth === 0 && objStart !== -1) {
                  try {
                    const parsed = JSON.parse(currentObj);
                    partialResults.push(parsed);
                    currentObj = '';
                    objStart = -1;
                  } catch (e) {
                    // Skip invalid objects
                  }
                }
              } else if (objStart !== -1) {
                currentObj += char;
              }
            } else if (objStart !== -1) {
              currentObj += char;
            }
            
            // Stop if we hit the closing bracket of the results array
            if (!inString && char === ']' && braceDepth === 0) {
              break;
            }
          }
          
          if (partialResults.length > 0) {
            console.log(`Extracted ${partialResults.length} complete result objects from partial JSON`);
            analysisResult = { results: partialResults };
          } else {
            throw new Error('Could not extract any complete result objects');
          }
        } else {
          throw parseError;
        }
      } catch (recoveryError) {
        console.error('Failed to recover partial results:', recoveryError);
        return iocs; // Return original IOCs if parsing fails completely
      }
    }

    // Extract results array - handle different response structures
    let resultsArray = null;
    if (analysisResult.results && Array.isArray(analysisResult.results)) {
      resultsArray = analysisResult.results;
    } else if (Array.isArray(analysisResult)) {
      resultsArray = analysisResult;
    } else if (analysisResult.data && Array.isArray(analysisResult.data)) {
      resultsArray = analysisResult.data;
    }

    if (!resultsArray || resultsArray.length === 0) {
      console.error('No results array found in analysis response. Structure:', Object.keys(analysisResult));
      return iocs;
    }

    console.log('Found results array with', resultsArray.length, 'items');

    // Merge analysis results with IOCs
    const analyzedIOCs = iocs.map((ioc, index) => {
      // Try multiple matching strategies
      let analysis = null;
      
      // Strategy 1: Match by index (1-based)
      analysis = resultsArray.find((r) => r.index === index + 1);
      
      // Strategy 2: Match by exact value
      if (!analysis) {
        analysis = resultsArray.find((r) => r.value === ioc.value);
      }
      
      // Strategy 3: Match by type and value
      if (!analysis) {
        analysis = resultsArray.find((r) => 
          r.type === ioc.type && r.value === ioc.value
        );
      }
      
      // Strategy 4: Match by value case-insensitive
      if (!analysis) {
        analysis = resultsArray.find((r) => 
          r.value && r.value.toLowerCase() === ioc.value.toLowerCase()
        );
      }
      
      // Strategy 5: Match by position in array (fallback)
      if (!analysis && index < resultsArray.length) {
        analysis = resultsArray[index];
      }
      
      if (analysis) {
        // Extract risk score - handle different field names
        let riskScore = analysis.riskScore !== undefined ? analysis.riskScore : 
                       analysis.risk_score !== undefined ? analysis.risk_score :
                       analysis.score !== undefined ? analysis.score : null;
        
        // Convert to number if it's a string
        if (riskScore !== null && riskScore !== undefined) {
          riskScore = Number(riskScore);
          // Validate range
          if (isNaN(riskScore) || riskScore < 0 || riskScore > 100) {
            console.warn(`Invalid risk score ${riskScore} for IOC ${ioc.value}, setting to null`);
            riskScore = null;
          }
        }
        
        // Extract risk level - handle different field names and calculate if missing
        let riskLevel = analysis.riskLevel || analysis.risk_level || analysis.level;
        if (!riskLevel && riskScore !== null && riskScore !== undefined) {
          if (riskScore >= 70) riskLevel = 'High';
          else if (riskScore >= 40) riskLevel = 'Medium';
          else riskLevel = 'Low';
        }
        if (!riskLevel) riskLevel = 'Unknown';
        
        // Extract explanation and threat intelligence
        const riskExplanation = analysis.explanation || analysis.riskExplanation || analysis.risk_explanation || analysis.reason || '';
        const threatIntelligence = analysis.threatIntelligence || analysis.threat_intelligence || analysis.intelligence || '';
        
        console.log(`Matched IOC ${ioc.value} with analysis:`, {
          riskScore,
          riskLevel,
          hasExplanation: !!riskExplanation,
          hasThreatIntel: !!threatIntelligence
        });
        
        return {
          ...ioc,
          riskScore,
          riskLevel,
          riskExplanation,
          threatIntelligence,
        };
      }
      
      console.warn('No analysis found for IOC:', ioc.value, 'at index', index);
      return ioc;
    });
    
    const withScores = analyzedIOCs.filter(ioc => ioc.riskScore !== null && ioc.riskScore !== undefined);
    console.log(`Analysis complete: ${withScores.length} of ${analyzedIOCs.length} IOCs have risk scores`);
    console.log('Sample analyzed IOCs:', analyzedIOCs.slice(0, 3).map(ioc => ({
      value: ioc.value.substring(0, 30),
      riskScore: ioc.riskScore,
      riskLevel: ioc.riskLevel
    })));
    
    return analyzedIOCs;
  } catch (error) {
    console.error('OpenAI analysis error:', error);
    return iocs; // Return original IOCs on error
  }
}

// Listen for messages from content scripts and popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'iocsDetected') {
    // Store detected IOCs for the current tab
    if (sender.tab) {
      chrome.storage.local.set({
        [`iocs_${sender.tab.id}`]: {
          iocs: request.iocs,
          url: request.url,
          timestamp: request.timestamp,
        },
      });
    }
    sendResponse({ success: true });
  } else if (request.action === 'analyzeIOCs') {
    // Analyze IOCs with OpenAI
    console.log('Received analyzeIOCs request for', request.iocs.length, 'IOCs');
    analyzeIOCsWithOpenAI(request.iocs)
      .then((analyzedIOCs) => {
        console.log('Analysis complete, sending response with', analyzedIOCs.length, 'IOCs');
        const withScores = analyzedIOCs.filter(ioc => ioc.riskScore !== null && ioc.riskScore !== undefined);
        console.log('IOCs with risk scores:', withScores.length);
        sendResponse({ success: true, iocs: analyzedIOCs });
      })
      .catch((error) => {
        console.error('Analysis error:', error);
        sendResponse({ success: false, error: error.message, iocs: request.iocs });
      });
    return true; // Keep the message channel open for async response
  } else if (request.action === 'checkOpenAIStatus') {
    // Check if OpenAI is configured
    chrome.storage.sync.get(['openaiApiKey'], (result) => {
      sendResponse({
        configured: !!(result.openaiApiKey && result.openaiApiKey.trim()),
        clientReady: !!openaiClient,
      });
    });
    return true;
  }

  return true; // Keep the message channel open for async response
});
