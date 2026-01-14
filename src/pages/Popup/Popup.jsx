import React, { useState, useEffect } from 'react';
import './Popup.css';

const IOC_TYPES = {
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

const Popup = () => {
  const [iocs, setIocs] = useState([]);
  const [selectedIocs, setSelectedIocs] = useState(new Set());
  const [savedLists, setSavedLists] = useState([]);
  const [highlightColor, setHighlightColor] = useState('#ff6b6b');
  const [separator, setSeparator] = useState('comma'); // 'comma', 'newline', 'space'
  const [currentUrl, setCurrentUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [activeTab, setActiveTab] = useState('scan'); // 'scan', 'list', 'saved', 'settings'
  const [filterTerm, setFilterTerm] = useState(''); // Filter/search term for IOCs
  const [listName, setListName] = useState(''); // Name for the current list
  const [openaiApiKey, setOpenaiApiKey] = useState(''); // OpenAI API key
  const [isAnalyzing, setIsAnalyzing] = useState(false); // Analysis in progress
  const [openaiConfigured, setOpenaiConfigured] = useState(false); // OpenAI configured status

  useEffect(() => {
    // Load settings from storage
    chrome.storage.sync.get(['highlightColor', 'separator', 'savedLists', 'openaiApiKey'], (result) => {
      if (result.highlightColor) setHighlightColor(result.highlightColor);
      if (result.separator) setSeparator(result.separator);
      if (result.savedLists) setSavedLists(result.savedLists);
      if (result.openaiApiKey) {
        setOpenaiApiKey(result.openaiApiKey);
        setOpenaiConfigured(true);
      }
    });

    // Check OpenAI status
    chrome.runtime.sendMessage({ action: 'checkOpenAIStatus' }, (response) => {
      if (response) {
        setOpenaiConfigured(response.configured);
      }
    });

    // Get current tab URL and request scan if valid
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        const url = tabs[0].url;
        setCurrentUrl(url);
        
        // Only request scan if URL is valid for content scripts
        if (url && !url.startsWith('chrome://') && !url.startsWith('chrome-extension://') && !url.startsWith('edge://')) {
          // Small delay to ensure content script is ready
          setTimeout(() => {
            requestScan();
          }, 100);
        }
      }
    });
  }, []);

  // Listen for IOC detection messages
  useEffect(() => {
    const listener = (message) => {
      if (message.action === 'iocsDetected') {
        setIocs(message.iocs || []);
        setIsScanning(false);
      }
    };
    chrome.runtime.onMessage.addListener(listener);
    return () => chrome.runtime.onMessage.removeListener(listener);
  }, []);

  const requestScan = () => {
    setIsScanning(true);
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        // Check if the URL is valid for content scripts (not chrome:// or extension pages)
        const url = tabs[0].url;
        if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('edge://')) {
          setIsScanning(false);
          setIocs([]);
          return;
        }
        
        chrome.tabs.sendMessage(tabs[0].id, { action: 'scan' }, (response) => {
          // Handle errors silently - content script might not be ready
          if (chrome.runtime.lastError) {
            setIsScanning(false);
            setIocs([]);
          }
        });
      }
    });
  };

  const toggleIOCSelection = (iocId) => {
    const newSelected = new Set(selectedIocs);
    if (newSelected.has(iocId)) {
      newSelected.delete(iocId);
    } else {
      newSelected.add(iocId);
    }
    setSelectedIocs(newSelected);
  };

  const selectAll = () => {
    // If filter is active, only select filtered IOCs; otherwise select all
    const iocsToSelect = filterTerm
      ? iocs.filter(ioc => 
          ioc.value.toLowerCase().includes(filterTerm.toLowerCase()) ||
          ioc.type.toLowerCase().includes(filterTerm.toLowerCase())
        )
      : iocs;
    setSelectedIocs(new Set(iocsToSelect.map(ioc => ioc.id)));
  };

  const deselectAll = () => {
    setSelectedIocs(new Set());
    setListName(''); // Clear list name when deselecting all
  };

  const addSelectedToList = () => {
    const selected = iocs.filter(ioc => selectedIocs.has(ioc.id));
    if (selected.length === 0) {
      alert('Please select at least one IOC to add.');
      return;
    }
    // This will be handled by the list management component
    setActiveTab('list');
  };

  const addAllToList = () => {
    if (iocs.length === 0) {
      alert('No IOCs detected. Please scan the page first.');
      return;
    }
    // If filter is active, only add filtered IOCs; otherwise add all
    const iocsToAdd = filterTerm
      ? iocs.filter(ioc => 
          ioc.value.toLowerCase().includes(filterTerm.toLowerCase()) ||
          ioc.type.toLowerCase().includes(filterTerm.toLowerCase())
        )
      : iocs;
    setSelectedIocs(new Set(iocsToAdd.map(ioc => ioc.id)));
    setActiveTab('list');
  };

  const updateHighlightColor = (color) => {
    setHighlightColor(color);
    chrome.storage.sync.set({ highlightColor: color });
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        const url = tabs[0].url;
        if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('edge://')) {
          return;
        }
        
        chrome.tabs.sendMessage(tabs[0].id, {
          action: 'updateHighlightColor',
          color: color,
        }, (response) => {
          // Handle errors silently
          if (chrome.runtime.lastError) {
            // Content script not available, ignore
          }
        });
      }
    });
  };

  const updateSeparator = (sep) => {
    setSeparator(sep);
    chrome.storage.sync.set({ separator: sep });
  };

  const saveOpenAIApiKey = () => {
    const apiKey = openaiApiKey.trim();
    if (apiKey) {
      chrome.storage.sync.set({ openaiApiKey: apiKey }, () => {
        setOpenaiConfigured(true);
        chrome.runtime.sendMessage({ action: 'checkOpenAIStatus' }, (response) => {
          if (response) {
            setOpenaiConfigured(response.configured);
          }
        });
        alert('OpenAI API key saved successfully!');
      });
    } else {
      chrome.storage.sync.remove('openaiApiKey', () => {
        setOpenaiConfigured(false);
        alert('API key removed.');
      });
    }
  };

  const analyzeIOCs = () => {
    if (!openaiConfigured) {
      alert('Please configure your OpenAI API key in Settings first.');
      return;
    }

    if (iocs.length === 0) {
      alert('No IOCs to analyze. Please scan the page first.');
      return;
    }

    // Determine which IOCs to analyze: selected ones if any, otherwise all
    const iocsToAnalyze = selectedIocs.size > 0 
      ? iocs.filter(ioc => selectedIocs.has(ioc.id))
      : iocs;

    if (iocsToAnalyze.length === 0) {
      alert('No IOCs selected to analyze. Please select IOCs or analyze all.');
      return;
    }

    setIsAnalyzing(true);
    chrome.runtime.sendMessage(
      { action: 'analyzeIOCs', iocs: iocsToAnalyze },
      (response) => {
        setIsAnalyzing(false);
        if (chrome.runtime.lastError) {
          console.error('Error sending message:', chrome.runtime.lastError);
          alert('Analysis failed: ' + chrome.runtime.lastError.message);
          return;
        }
        
        if (response && response.success) {
          console.log('Analysis response received:', response);
          console.log('IOCs with risk scores:', response.iocs.map(ioc => ({ 
            value: ioc.value, 
            riskScore: ioc.riskScore,
            riskLevel: ioc.riskLevel 
          })));
          
          // Create a map of analyzed IOCs by their ID for quick lookup
          const analyzedMap = new Map(response.iocs.map(ioc => [ioc.id, ioc]));
          
          // Update only the analyzed IOCs in the full list
          const updatedIOCs = iocs.map(ioc => {
            const analyzed = analyzedMap.get(ioc.id);
            return analyzed ? analyzed : ioc;
          });
          
          setIocs(updatedIOCs);
          const analyzedCount = response.iocs.filter(ioc => ioc.riskScore !== null && ioc.riskScore !== undefined).length;
          const analysisType = selectedIocs.size > 0 ? 'selected' : 'all';
          alert(`Analysis complete! Risk scores updated for ${analyzedCount} of ${iocsToAnalyze.length} ${analysisType} IOCs.`);
        } else {
          console.error('Analysis failed:', response);
          alert('Analysis failed. ' + (response?.error || 'Please check your API key and try again.'));
        }
      }
    );
  };

  const getSeparatorChar = () => {
    switch (separator) {
      case 'comma': return ', ';
      case 'newline': return '\n';
      case 'space': return ' ';
      default: return ', ';
    }
  };

  const exportToFile = (list) => {
    const content = list.iocs.map(ioc => ioc.value).join(getSeparatorChar());
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ioc_snatch_${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const saveList = () => {
    const selected = iocs.filter(ioc => selectedIocs.has(ioc.id));
    if (selected.length === 0) {
      alert('Please select IOCs to save.');
      return;
    }

    // Use custom name if provided, otherwise use default name
    const finalListName = listName.trim() || `IOC List - ${new Date().toLocaleString()}`;

    const newList = {
      id: Date.now().toString(),
      name: finalListName,
      iocs: selected,
      url: currentUrl,
      timestamp: new Date().toISOString(),
      date: new Date().toLocaleDateString(),
      time: new Date().toLocaleTimeString(),
    };

    const updatedLists = [...savedLists, newList];
    setSavedLists(updatedLists);
    chrome.storage.sync.set({ savedLists: updatedLists });
    setSelectedIocs(new Set());
    setListName(''); // Clear the list name input
    alert('List saved successfully!');
  };

  const deleteList = (listId) => {
    const updatedLists = savedLists.filter(list => list.id !== listId);
    setSavedLists(updatedLists);
    chrome.storage.sync.set({ savedLists: updatedLists });
  };

  const getTypeColor = (type) => {
    const colors = {
      [IOC_TYPES.IPV4]: '#4ecdc4',
      [IOC_TYPES.IPV6]: '#45b7d1',
      [IOC_TYPES.CIDR]: '#00d4aa',
      [IOC_TYPES.DEFANGED_IP]: '#16a085',
      [IOC_TYPES.MD5]: '#f7b731',
      [IOC_TYPES.SHA1]: '#f39c12',
      [IOC_TYPES.SHA256]: '#e67e22',
      [IOC_TYPES.SHA512]: '#d35400',
      [IOC_TYPES.EMAIL]: '#9b59b6',
      [IOC_TYPES.DEFANGED_URL]: '#e67e22',
      [IOC_TYPES.URL]: '#3498db',
      [IOC_TYPES.FILENAME]: '#e74c3c',
    };
    return colors[type] || '#95a5a6';
  };

  const getRiskColor = (riskScore) => {
    if (riskScore === null || riskScore === undefined) return '#95a5a6';
    if (riskScore >= 70) return '#e74c3c'; // High risk - red
    if (riskScore >= 40) return '#f39c12'; // Medium risk - orange
    return '#f7b731'; // Low risk - yellow
  };

  return (
    <div className="popup-container">
      <div className="popup-header">
        <h1 className="popup-title">IOC Snatch.ai</h1>
        <div className="tab-buttons">
          {[
            { id: 'scan', label: 'Scan' },
            { id: 'list', label: 'List' },
            { id: 'saved', label: 'Saved' },
            { id: 'settings', label: 'Settings', title: 'Settings' },
          ].map((tab) => (
            <button
              key={tab.id}
              className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => {
                console.log(`${tab.id} tab clicked`);
                setActiveTab(tab.id);
              }}
              title={tab.title || tab.label}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      <div className="popup-content">
        {activeTab === 'scan' && (
          <div className="scan-tab">
            <div className="settings-section">
              <label className="setting-label">
                Highlight Color:
                <input
                  id="highlight-color"
                  name="highlight-color"
                  type="color"
                  value={highlightColor}
                  onChange={(e) => updateHighlightColor(e.target.value)}
                  className="color-picker"
                />
              </label>
            </div>

            <div className="action-buttons">
              <button
                className="btn btn-primary"
                onClick={requestScan}
                disabled={isScanning}
              >
                {isScanning ? 'Scanning...' : 'Scan Page'}
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => {
                  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                    if (tabs[0]) {
                      const url = tabs[0].url;
                      if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('edge://')) {
                        return;
                      }
                      
                      chrome.tabs.sendMessage(tabs[0].id, { action: 'removeHighlights' }, (response) => {
                        // Handle errors silently
                        if (chrome.runtime.lastError) {
                          // Content script not available, ignore
                        }
                      });
                    }
                  });
                }}
              >
                Clear Highlights
              </button>
              {iocs.length > 0 && (
                <button
                  className="btn btn-secondary"
                  onClick={analyzeIOCs}
                  disabled={isAnalyzing || !openaiConfigured}
                  title={!openaiConfigured ? 'Configure OpenAI API key in Settings' : selectedIocs.size > 0 ? `Analyze ${selectedIocs.size} selected IOC(s)` : 'Analyze all IOCs'}
                >
                  {isAnalyzing 
                    ? 'Analyzing...' 
                    : selectedIocs.size > 0 
                      ? `Analyze Risk (${selectedIocs.size})` 
                      : 'Analyze Risk'}
                </button>
              )}
            </div>

            <div className="ioc-results">
              <div className="results-header">
                <h3>Detected IOCs ({iocs.length})</h3>
                {iocs.length > 0 && (
                  <div className="bulk-actions">
                    <button className="btn-small" onClick={selectAll}>Select All</button>
                    <button className="btn-small" onClick={deselectAll}>Deselect All</button>
                    <button className="btn-small btn-primary" onClick={addAllToList}>
                      Add All to List
                    </button>
                  </div>
                )}
              </div>

              {iocs.length > 0 && (
                <div className="filter-section">
                  <input
                    id="ioc-filter"
                    name="ioc-filter"
                    type="text"
                    placeholder="Filter IOCs by type or value..."
                    value={filterTerm}
                    onChange={(e) => setFilterTerm(e.target.value)}
                    className="filter-input"
                  />
                  {filterTerm && (
                    <button
                      className="filter-clear"
                      onClick={() => setFilterTerm('')}
                      title="Clear filter"
                    >
                      ×
                    </button>
                  )}
                </div>
              )}

              <div className="ioc-list">
                {iocs.length === 0 ? (
                  <p className="empty-state">No IOCs detected. Click "Scan Page" to begin.</p>
                ) : (() => {
                  // Filter IOCs based on filterTerm
                  const filteredIOCs = filterTerm
                    ? iocs.filter(ioc => 
                        ioc.value.toLowerCase().includes(filterTerm.toLowerCase()) ||
                        ioc.type.toLowerCase().includes(filterTerm.toLowerCase())
                      )
                    : iocs;
                  
                  if (filteredIOCs.length === 0 && filterTerm) {
                    return (
                      <p className="empty-state">
                        No IOCs match "{filterTerm}". Try a different search term.
                      </p>
                    );
                  }
                  
                  return (
                    <>
                      {filterTerm && filteredIOCs.length > 0 && (
                        <div className="filter-results-info">
                          Showing {filteredIOCs.length} of {iocs.length} IOCs
                        </div>
                      )}
                      {filteredIOCs.map((ioc) => (
                        <div
                          key={ioc.id}
                          className={`ioc-item ${selectedIocs.has(ioc.id) ? 'selected' : ''}`}
                          onClick={() => toggleIOCSelection(ioc.id)}
                        >
                          <input
                            id={`ioc-checkbox-${ioc.id}`}
                            name={`ioc-checkbox-${ioc.id}`}
                            type="checkbox"
                            checked={selectedIocs.has(ioc.id)}
                            onChange={() => toggleIOCSelection(ioc.id)}
                            className="ioc-checkbox"
                          />
                          <span
                            className="ioc-type-badge"
                            style={{ backgroundColor: getTypeColor(ioc.type) }}
                          >
                            {ioc.type}
                          </span>
                          <span className="ioc-value" title={ioc.value}>
                            {ioc.value}
                          </span>
                          <div className="ioc-risk-info">
                            {ioc.riskScore !== null && ioc.riskScore !== undefined && !isNaN(ioc.riskScore) ? (
                              <>
                                <span
                                  className="risk-score-badge"
                                  style={{ backgroundColor: getRiskColor(ioc.riskScore) }}
                                  title={ioc.riskExplanation || `Risk Score: ${ioc.riskScore}/100${ioc.threatIntelligence ? '\n\n' + ioc.threatIntelligence : ''}`}
                                >
                                  {Math.round(ioc.riskScore)}
                                </span>
                                {ioc.riskLevel && (
                                  <span 
                                    className="risk-level"
                                    style={{ backgroundColor: getRiskColor(ioc.riskScore) }}
                                  >
                                    {ioc.riskLevel}
                                  </span>
                                )}
                              </>
                            ) : (
                              <span className="risk-score-placeholder" title="Click 'Analyze Risk' to get risk scores">
                                —
                              </span>
                            )}
                          </div>
                        </div>
                      ))}
                    </>
                  );
                })()}
              </div>

              {selectedIocs.size > 0 && (
                <button className="btn btn-primary btn-block" onClick={addSelectedToList}>
                  Add Selected ({selectedIocs.size}) to List
                </button>
              )}
            </div>
          </div>
        )}

        {activeTab === 'list' && (
          <div className="list-tab">
            <div className="settings-section">
              <label className="setting-label">
                Export Separator:
                <select
                  id="export-separator"
                  name="export-separator"
                  value={separator}
                  onChange={(e) => updateSeparator(e.target.value)}
                  className="separator-select"
                >
                  <option value="comma">Comma (,)</option>
                  <option value="newline">New Line</option>
                  <option value="space">Space</option>
                </select>
              </label>
            </div>

            <div className="current-list">
              <h3>Current List ({selectedIocs.size} items)</h3>
              
              {selectedIocs.size > 0 && (
                <div className="list-name-section">
                  <label className="list-name-label">
                    List Name:
                    <input
                      id="list-name"
                      name="list-name"
                      type="text"
                      placeholder="Enter a name for this list..."
                      value={listName}
                      onChange={(e) => setListName(e.target.value)}
                      className="list-name-input"
                      maxLength={100}
                    />
                  </label>
                </div>
              )}

              <div className="list-items">
                {iocs
                  .filter((ioc) => selectedIocs.has(ioc.id))
                  .map((ioc) => (
                    <div key={ioc.id} className="list-item">
                      <span
                        className="ioc-type-badge"
                        style={{ backgroundColor: getTypeColor(ioc.type) }}
                      >
                        {ioc.type}
                      </span>
                      <span className="ioc-value">{ioc.value}</span>
                      <button
                        className="btn-remove"
                        onClick={() => {
                          const newSelected = new Set(selectedIocs);
                          newSelected.delete(ioc.id);
                          setSelectedIocs(newSelected);
                        }}
                      >
                        ×
                      </button>
                    </div>
                  ))}
              </div>

              {selectedIocs.size > 0 && (
                <div className="list-actions">
                  <button
                    className="btn btn-primary"
                    onClick={() => {
                      const selected = iocs.filter((ioc) => selectedIocs.has(ioc.id));
                      const content = selected.map((ioc) => ioc.value).join(getSeparatorChar());
                      const blob = new Blob([content], { type: 'text/plain' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = `ioc_snatch_${new Date().toISOString().split('T')[0]}.txt`;
                      document.body.appendChild(a);
                      a.click();
                      document.body.removeChild(a);
                      URL.revokeObjectURL(url);
                    }}
                  >
                    Export to File
                  </button>
                  <button className="btn btn-secondary" onClick={saveList}>
                    Save List
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'saved' && (
          <div className="saved-tab">
            <h3>Saved Lists ({savedLists.length})</h3>
            {savedLists.length === 0 ? (
              <p className="empty-state">No saved lists yet.</p>
            ) : (
              <div className="saved-lists">
                {savedLists.map((list) => (
                  <div key={list.id} className="saved-list-item">
                    <div className="saved-list-header">
                      <h4>{list.name}</h4>
                      <button
                        className="btn-delete"
                        onClick={() => deleteList(list.id)}
                      >
                        Delete
                      </button>
                    </div>
                    <div className="saved-list-info">
                      <p>
                        <strong>URL:</strong> {list.url}
                      </p>
                      <p>
                        <strong>Date:</strong> {list.date} at {list.time}
                      </p>
                      <p>
                        <strong>IOCs:</strong> {list.iocs.length}
                      </p>
                    </div>
                    <button
                      className="btn btn-primary btn-small"
                      onClick={() => exportToFile(list)}
                    >
                      Export
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'settings' && (
          <div className="settings-tab">
            <h3>Settings</h3>
            
            <div className="settings-section">
              <h4>OpenAI API Configuration</h4>
              <p className="settings-description">
                Configure your OpenAI API key to enable AI-powered risk analysis of IOCs.
                The extension uses GPT-4o-mini to check security sites and provide risk scores.
              </p>
              
              <label className="setting-label">
                OpenAI API Key:
                <input
                  id="openai-api-key"
                  name="openai-api-key"
                  type="password"
                  placeholder="sk-..."
                  value={openaiApiKey}
                  onChange={(e) => setOpenaiApiKey(e.target.value)}
                  className="api-key-input"
                />
              </label>
              
              <div className="api-key-actions">
                <button
                  className="btn btn-primary"
                  onClick={saveOpenAIApiKey}
                  disabled={!openaiApiKey.trim() && !openaiConfigured}
                >
                  {openaiConfigured && openaiApiKey.trim() ? 'Update Key' : 'Save Key'}
                </button>
                {openaiConfigured && (
                  <button
                    className="btn btn-secondary"
                    onClick={() => {
                      setOpenaiApiKey('');
                      chrome.storage.sync.remove('openaiApiKey', () => {
                        setOpenaiConfigured(false);
                        alert('API key removed.');
                      });
                    }}
                  >
                    Remove Key
                  </button>
                )}
              </div>
              
              {openaiConfigured && (
                <div className="status-indicator">
                  <span className="status-badge status-success">✓ Configured</span>
                </div>
              )}
              
              <p className="settings-note">
                <strong>Note:</strong> Your API key is stored locally in Chrome's sync storage.
                Get your API key from <a href="https://platform.openai.com/api-keys" target="_blank" rel="noopener noreferrer">OpenAI Platform</a>.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Popup;
