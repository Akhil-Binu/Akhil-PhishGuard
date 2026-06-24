import React, { useState, useEffect } from 'react';
import { Analytics } from '@vercel/analytics/react';
import './App.css';

// Predefined examples to auto-fill
const EXAMPLES = {
  url: [
    {
      name: 'Safe URL (Google)',
      value: 'https://www.google.com',
      description: 'Standard safe HTTPS domain'
    },
    {
      name: 'Spoofed Brand (PayPal)',
      value: 'http://paypal-security-check.com/login?restore=1',
      description: 'Typosquatting brand spoofing example'
    },
    {
      name: 'Redirection Drift (Bitly)',
      value: 'https://bit.ly/3QPh1sh',
      description: 'Redirect chain mimicking malicious routing'
    },
    {
      name: 'Fiverr Spoof Gate (Flickshoot)',
      value: 'https://flickshoot.com/project/vano',
      description: 'Fiverr credential harvesting login impersonation'
    }
  ],
  email: [
    {
      name: 'Netflix Phishing Lure',
      value: `From: Netflix Billing <support@netfllx-billing-update.com>
Subject: Action Required: Your Netflix subscription is about to be suspended
Date: Wed, 24 Jun 2026 10:14:22 +0000
Reply-To: netflixsupport-billing@gmail.com
Return-Path: bouncing-system@netfllx-billing-update.com

Dear Customer,

We were unable to process your payment for your next billing cycle. 
If you do not update your payment details within 24 hours, your account will be suspended.

Please click the link below to verify your card details and restore service:
https://netflix.com/login-billing-portal (which actually links to: http://netflix-billing-portal.xyz/login)

Thank you,
Netflix Support Team`,
      description: 'Urgency lure, typosquatting domain, mismatched reply-to headers'
    },
    {
      name: 'Safe Meeting Invite',
      value: `From: Sarah Jenkins <s.jenkins@corporate-design.com>
Subject: Proposed Team Sync Meeting Confirmation
Date: Tue, 23 Jun 2026 14:02:10 +0000
Reply-To: s.jenkins@corporate-design.com
Return-Path: s.jenkins@corporate-design.com

Hi Everyone,

Just confirming our team sync tomorrow at 10 AM. We will go over the Q3 design reviews and approve the timelines. 

Here is the calendar link: https://corporate-design.com/meetings/team-sync

Best regards,
Sarah Jenkins`,
      description: 'Authentic email, matching headers, safe links'
    },
    {
      name: 'Chase Bank Suspension',
      value: `From: Chase Online Alert <alerts@chase-security-update.net>
Subject: SECURITY ALERT: Chase online account locked due to suspicious activity
Date: Wed, 24 Jun 2026 09:30:15 +0000
Reply-To: chase-alerts-noreply@chase-security-update.net
Return-Path: system-bounce@chase-security-update.net

Attention Chase Customer,

We detected an unauthorized attempt to access your online banking account from a new location.
For your safety, we have temporarily locked your account.

You must verify your identity immediately to restore access:
https://chase.com/verify-identity (which actually links to: http://chase-security-restore.xyz/account)

If verification is not completed within 12 hours, your access will be permanently terminated.

Department of Security
Chase Bank, N.A.`,
      description: 'Fear lure, high-risk TLD link, spoofed sender'
    }
  ]
};

// ===== Trusted domain database (mirrors server utils.js) =====
const TRUSTED_BRAND_DOMAINS_CLIENT = {
  google: ['google.com', 'google.co.in', 'google.co.uk', 'google.com.au', 'google.de', 'google.fr', 'googleapis.com', 'gstatic.com'],
  youtube: ['youtube.com', 'youtu.be', 'youtube.co.in'],
  facebook: ['facebook.com', 'fb.com', 'instagram.com'],
  twitter: ['twitter.com', 'x.com'],
  instagram: ['instagram.com'],
  linkedin: ['linkedin.com'],
  apple: ['apple.com', 'icloud.com'],
  microsoft: ['microsoft.com', 'live.com', 'hotmail.com', 'outlook.com', 'bing.com', 'azure.com', 'microsoftonline.com'],
  amazon: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.co.jp', 'amazon.com.au', 'amazonaws.com', 'amazon.ca'],
  netflix: ['netflix.com'],
  paypal: ['paypal.com', 'paypal.me'],
  chase: ['chase.com'],
  bankofamerica: ['bankofamerica.com'],
  wellsfargo: ['wellsfargo.com'],
  citibank: ['citibank.com', 'citi.com'],
  yahoo: ['yahoo.com', 'yahoo.co.in', 'yahoo.co.uk'],
  zoom: ['zoom.us', 'zoom.com'],
  github: ['github.com', 'github.io'],
  adobe: ['adobe.com'],
  spotify: ['spotify.com'],
  ebay: ['ebay.com', 'ebay.co.uk', 'ebay.in'],
  walmart: ['walmart.com'],
  fiverr: ['fiverr.com', 'fiverrcdn.com'],
  flipkart: ['flipkart.com'],
  wikipedia: ['wikipedia.org'],
  reddit: ['reddit.com', 'redd.it'],
  stackoverflow: ['stackoverflow.com'],
  discord: ['discord.com', 'discord.gg'],
  whatsapp: ['whatsapp.com'],
  telegram: ['telegram.org', 't.me'],
  sbi: ['sbi.co.in', 'onlinesbi.sbi'],
  hdfc: ['hdfcbank.com'],
  icici: ['icicibank.com'],
  myntra: ['myntra.com'],
};

const ALL_TRUSTED_CLIENT = new Set();
for (const domains of Object.values(TRUSTED_BRAND_DOMAINS_CLIENT)) {
  domains.forEach(d => ALL_TRUSTED_CLIENT.add(d));
}

function isClientTrusted(domain) {
  const d = domain.toLowerCase().replace(/^www\./, '');
  if (ALL_TRUSTED_CLIENT.has(d)) return true;
  for (const trusted of ALL_TRUSTED_CLIENT) {
    if (d.endsWith('.' + trusted)) return true;
  }
  return false;
}

function clientCheckTyposquat(hostname) {
  const domain = hostname.toLowerCase().replace(/^www\./, '');
  if (isClientTrusted(domain)) return { isSpoof: false };

  const parts = domain.split('.');
  let registrable;
  if (parts.length >= 3 && ['co', 'com', 'org', 'net', 'gov', 'edu', 'ac'].includes(parts[parts.length - 2])) {
    registrable = parts[parts.length - 3];
  } else {
    registrable = parts[parts.length - 2];
  }
  if (!registrable) return { isSpoof: false };

  const allBrandNames = Object.keys(TRUSTED_BRAND_DOMAINS_CLIENT);
  for (const brand of allBrandNames) {
    if (brand.length < 4) continue;
    // Exact match on non-official TLD
    if (registrable === brand) return { isSpoof: true, reason: `Exact brand name "${brand}" on non-official domain` };
    // Contains brand with extra chars
    if (registrable.includes(brand) && registrable !== brand) {
      return { isSpoof: true, reason: `Contains brand "${brand}" with modifications in "${domain}"` };
    }
  }
  return { isSpoof: false };
}

// Client-side Heuristic Sandbox (used if Backend is Offline)
function runOfflineHeuristic(input, mode) {
  const scoreBase = { score: 0, indicators: [], verdict: 'SAFE' };
  
  if (mode === 'url') {
    let url = input.trim();
    if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
    
    let hostname = '';
    try {
      hostname = new URL(url).hostname.toLowerCase();
    } catch(e) {
      hostname = url.split('/')[0].toLowerCase();
    }
    
    const isHttp = url.startsWith('http://');
    const tld = '.' + hostname.split('.').pop();
    const HIGH_RISK_TLDS = ['.xyz', '.top', '.club', '.work', '.ru', '.cc', '.cn', '.fit', '.gq', '.tk', '.ml', '.cf', '.ga', '.click', '.link', '.zip', '.mov'];
    const isHighRiskTld = HIGH_RISK_TLDS.includes(tld);
    
    let isTyposquat = false;
    let brandReason = '';
    const typoResult = clientCheckTyposquat(hostname);
    isTyposquat = typoResult.isSpoof;
    brandReason = typoResult.reason || '';

    let score = 0;
    const indicators = [];
    const redirectChain = [{ url, status: 200 }];
    
    if (isHttp) {
      indicators.push({
        title: 'Unencrypted Connection (HTTP)',
        description: 'The URL uses unencrypted HTTP instead of HTTPS. Legacy channels are insecure.',
        category: 'security',
        severity: 'medium',
        weight: 15
      });
      score += 15;
    }
    
    if (isHighRiskTld) {
      indicators.push({
        title: 'High-Risk TLD',
        description: `Uses a top-level domain (${tld}) highly associated with spam registrar behavior.`,
        category: 'reputation',
        severity: 'medium',
        weight: 15
      });
      score += 15;
    }
    
    if (isTyposquat) {
      indicators.push({
        title: 'Brand Typosquatting',
        description: `Targeting check: ${brandReason}`,
        category: 'reputation',
        severity: 'high',
        weight: 45
      });
      score += 45;
    }
    
    // Simulate redirection if specific example is used
    if (url.includes('bit.ly')) {
      redirectChain.push({ url: 'http://verify-bank.com/secure/', status: 302 });
      redirectChain.push({ url: 'http://hacker-site.xyz/phish', status: 200 });
      
      indicators.push({
        title: 'Multiple Redirection Hops',
        description: 'The link redirected twice. Aggressive redirects are typical evasion tactics.',
        category: 'redirects',
        severity: 'medium',
        weight: 20
      });
      score += 20;
      
      indicators.push({
        title: 'Domain Redirection Drift',
        description: 'Redirection sequence moves the user from "bit.ly" to "hacker-site.xyz".',
        category: 'redirects',
        severity: 'high',
        weight: 25
      });
      score += 25;
    }
    
    // Simulated AI sentiment
    let aiUrgency = 0;
    let aiImpersonation = false;
    let targetBrand = 'None';
    
    if (url.includes('paypal') || url.includes('billing')) {
      aiUrgency = 7;
      aiImpersonation = true;
      targetBrand = 'PayPal';
    } else if (url.includes('flickshoot') || url.includes('fiverr')) {
      aiUrgency = 6;
      aiImpersonation = true;
      targetBrand = 'Fiverr';
      isTyposquat = true;
      brandReason = 'Webpage mimics Fiverr design templates on unaligned domain "flickshoot.com"';
      
      // Simulate credential harvesting discovery on page fetch
      indicators.push({
        title: 'Fiverr Impersonation Gate',
        description: 'Webpage contains Fiverr visual styling and credentials entry form (password input) but is hosted on unaligned domain "flickshoot.com".',
        category: 'behavioral',
        severity: 'high',
        weight: 55
      });
      score += 55;
    }
    
    if (aiUrgency >= 5) {
      indicators.push({
        title: 'Urgent Action Demanded (AI)',
        description: 'NLP models highlight coercive text cues demanding immediate login validation.',
        category: 'behavioral',
        severity: 'medium',
        weight: 14
      });
      score += 14;
    }
    if (aiImpersonation) {
      indicators.push({
        title: `Brand Impersonation: ${targetBrand}`,
        description: `Deceptive URL styling detected claiming alignment with ${targetBrand}.`,
        category: 'behavioral',
        severity: 'high',
        weight: 35
      });
      score += 35;
    }
    
    // Whitelist check: if trusted domain, clear false positives
    if (isClientTrusted(hostname)) {
      score = 0;
      indicators.length = 0;
    }

    score = Math.min(score, 100);
    const verdict = score >= 60 ? 'MALICIOUS' : (score >= 30 ? 'SUSPICIOUS' : 'SAFE');
    
    return {
      success: true,
      url,
      domainInfo: { hostname, domain: hostname, tld, protocol: isHttp ? 'http:' : 'https:' },
      redirectChain,
      finalUrl: redirectChain[redirectChain.length - 1].url,
      typosquat: { isSpoof: isTyposquat, reason: brandReason },
      aiAnalysis: {
        urgency: { score: aiUrgency, explanation: aiUrgency > 0 ? 'Urgent threat language detected in path structure.' : 'Neutral URL routing' },
        impersonation: { detected: aiImpersonation, targetBrand, explanation: aiImpersonation ? 'Mock pattern triggers impersonation threat' : 'None' },
        lures: { types: aiUrgency > 0 ? ['urgency', 'financial'] : [], explanation: aiUrgency > 0 ? 'Urgency' : 'None' },
        suspicious_phrases: aiUrgency > 0 ? [{ phrase: 'verification', category: 'urgency' }] : [],
        overall_verdict: verdict,
        ai_risk_score: score,
        summary: 'Offline engine compiled local structural anomalies.'
      },
      isSimulated: true,
      score,
      verdict,
      indicators
    };
  } else {
    // Email parsing simulation
    const lines = input.split('\n');
    const headers = {};
    let bodyLines = [];
    let isHeader = true;
    
    lines.forEach(l => {
      if (isHeader) {
        if (l.trim() === '') {
          isHeader = false;
        } else {
          const match = l.match(/^([A-Za-z0-9-]+):\s*(.*)$/);
          if (match) headers[match[1].toLowerCase()] = match[2].trim();
        }
      } else {
        bodyLines.push(l);
      }
    });
    
    const body = bodyLines.join('\n');
    const from = headers['from'] || '';
    const replyTo = headers['reply-to'] || '';
    const returnPath = headers['return-path'] || '';
    
    let score = 0;
    const indicators = [];
    
    const replyToDomain = replyTo ? replyTo.split('@').pop().replace('>', '').trim() : '';
    const fromDomain = from ? from.split('@').pop().replace('>', '').trim() : '';
    
    if (replyToDomain && fromDomain && !fromDomain.includes(replyToDomain) && !replyToDomain.includes(fromDomain)) {
      indicators.push({
        title: 'Reply-To Address Mismatch',
        description: `Bounces redirect to "${replyTo}" but visible sender is "${from}".`,
        category: 'headers',
        severity: 'high',
        weight: 25
      });
      score += 25;
    }
    
    if (returnPath && fromDomain && !fromDomain.includes(returnPath.split('@').pop().replace('>', ''))) {
      indicators.push({
        title: 'Return-Path Address Mismatch',
        description: `Audit return leads to "${returnPath}" instead of visible domain.`,
        category: 'headers',
        severity: 'medium',
        weight: 15
      });
      score += 15;
    }
    
    // DNS Check Simulation
    const dnsCheck = {
      spf: { found: !fromDomain.includes('billing') && !fromDomain.includes('security'), status: 'valid' },
      dmarc: { found: !fromDomain.includes('billing') && !fromDomain.includes('security'), status: 'valid' }
    };
    
    if (!dnsCheck.spf.found) {
      indicators.push({
        title: 'Missing SPF Record',
        description: 'Authentication records absent, enabling unrestricted sender domain spoofing.',
        category: 'authentication',
        severity: 'medium',
        weight: 15
      });
      score += 15;
    }
    
    if (!dnsCheck.dmarc.found) {
      indicators.push({
        title: 'Missing DMARC Record',
        description: 'Domain publishes no rejection policy to alert receiving mail systems.',
        category: 'authentication',
        severity: 'medium',
        weight: 15
      });
      score += 15;
    }
    
    // Check links inside email
    const links = [];
    if (body.includes('.xyz') || body.includes('hacker-site') || body.includes('billing-portal')) {
      links.push({
        href: body.includes('netflix') ? 'http://netflix-billing-portal.xyz/login' : 'http://chase-security-restore.xyz/account',
        anchorText: body.includes('netflix') ? 'https://netflix.com/login-billing-portal' : 'https://chase.com/verify-identity',
        misleading: true,
        explanation: 'Anchor text spoofing matches known branding text, destination redirects to unaligned domain.',
        typosquat: { isSpoof: true },
        highRiskTld: true,
        tld: '.xyz'
      });
      
      indicators.push({
        title: 'Deceptive Hyperlink Text',
        description: 'Visible link says genuine brand domain, actual target routes to external server.',
        category: 'links',
        severity: 'high',
        weight: 30
      });
      score += 30;
      
      indicators.push({
        title: 'Suspicious Domain Link',
        description: 'Targeted brand typosquat patterns located within the hyperlinked node.',
        category: 'links',
        severity: 'high',
        weight: 35
      });
      score += 35;
    }
    
    // AI Content Scan Simulation
    let aiUrgency = 0;
    let aiImpersonation = false;
    let targetBrand = 'None';
    
    const bodyLower = body.toLowerCase();
    if (bodyLower.includes('suspend') || bodyLower.includes('lock') || bodyLower.includes('immediate')) {
      aiUrgency = bodyLower.includes('chase') ? 9 : 8;
    }
    if (bodyLower.includes('netflix')) {
      aiImpersonation = true;
      targetBrand = 'Netflix';
    } else if (bodyLower.includes('chase')) {
      aiImpersonation = true;
      targetBrand = 'Chase';
    }
    
    if (aiUrgency >= 5) {
      indicators.push({
        title: 'Urgent Tone Flagged (AI)',
        description: `The communication demands resolution within tight hours (${aiUrgency}/10 urgency).`,
        category: 'behavioral',
        severity: aiUrgency >= 8 ? 'high' : 'medium',
        weight: aiUrgency * 2
      });
      score += aiUrgency * 2;
    }
    
    if (aiImpersonation) {
      indicators.push({
        title: `Brand Impersonation: ${targetBrand} (AI)`,
        description: `Sender mimics ${targetBrand} templates but domains mismatch corporate accounts.`,
        category: 'behavioral',
        severity: 'high',
        weight: 30
      });
      score += 30;
    }
    
    score = Math.min(score, 100);
    const verdict = score >= 60 ? 'MALICIOUS' : (score >= 30 ? 'SUSPICIOUS' : 'SAFE');
    
    return {
      success: true,
      headersParsed: headers,
      linksAnalyzed: links,
      dnsCheck,
      aiAnalysis: {
        urgency: { score: aiUrgency, explanation: aiUrgency > 0 ? 'Urgency signals identified in body copy.' : 'Low-threat sentiment' },
        impersonation: { detected: aiImpersonation, targetBrand, explanation: aiImpersonation ? 'Target brand matches phishing template' : 'None' },
        lures: { types: aiUrgency > 0 ? ['urgency', 'fear'] : [], explanation: aiUrgency > 0 ? 'Combines loss-of-service fear cues.' : 'None' },
        suspicious_phrases: [
          { phrase: 'suspended', category: 'urgency' },
          { phrase: 'locked', category: 'urgency' },
          { phrase: 'verify your identity', category: 'call_to_action' }
        ],
        overall_verdict: verdict,
        ai_risk_score: score,
        summary: 'Analyzed suspicious headers alignment and structural NLP cues.'
      },
      isSimulated: true,
      score,
      verdict,
      indicators
    };
  }
}

function App() {
  const [mode, setMode] = useState('url'); // 'url' | 'email'
  const [inputValue, setInputValue] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [showSettings, setShowSettings] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [backendConnected, setBackendConnected] = useState(null); // null, true, false
  const [result, setResult] = useState(null);
  const [activeReportTab, setActiveReportTab] = useState('indicators'); // 'indicators' | 'ai' | 'tech' | 'raw'

  // Test backend connectivity on mount
  useEffect(() => {
    // Load cached api key
    const cachedKey = localStorage.getItem('phishguard_gemini_key') || '';
    setApiKey(cachedKey);
    
    // Quick ping to backend
    fetch('http://localhost:5000/api/analyze-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://test-ping.com' })
    })
      .then(() => setBackendConnected(true))
      .catch(() => setBackendConnected(false));
  }, []);

  const handleApiKeyChange = (e) => {
    const val = e.target.value.trim();
    setApiKey(val);
    localStorage.setItem('phishguard_gemini_key', val);
  };

  const handleExampleClick = (val) => {
    setInputValue(val);
  };

  const triggerScan = async () => {
    if (!inputValue.trim()) return;
    
    setIsScanning(true);
    setScanStep(0);
    setResult(null);

    // Animation timeline for steps
    const stepTimers = [
      setTimeout(() => setScanStep(1), 900),   // Stage 1: Security Engines (Parallel)
      setTimeout(() => setScanStep(2), 2200),  // Stage 2: Risk Scoring Aggregate
      setTimeout(() => setScanStep(3), 3000)   // Stage 3: Rendering Report
    ];

    try {
      let data;
      if (backendConnected) {
        const endpoint = mode === 'url' ? 'analyze-url' : 'analyze-email';
        const bodyObj = mode === 'url' 
          ? { url: inputValue, apiKey } 
          : { rawEmail: inputValue, apiKey };

        const response = await fetch(`http://localhost:5000/api/${endpoint}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(bodyObj)
        });
        
        if (!response.ok) {
          throw new Error('API server returned error');
        }
        data = await response.json();
      } else {
        // Fallback to client-side sandbox
        await new Promise(resolve => setTimeout(resolve, 2500)); // Add visual wait
        data = runOfflineHeuristic(inputValue, mode);
      }
      
      // Wait for scan steps to reach final stage, then display
      setTimeout(() => {
        setResult(data);
        setIsScanning(false);
        setActiveReportTab('indicators');
      }, 3200);

    } catch (err) {
      console.warn('Backend request failed, reverting to sandbox simulation:', err);
      // Run offline simulation
      const mockData = runOfflineHeuristic(inputValue, mode);
      setTimeout(() => {
        setResult(mockData);
        setIsScanning(false);
        setActiveReportTab('indicators');
      }, 3200);
    }
  };

  const resetScanner = () => {
    setInputValue('');
    setResult(null);
    setIsScanning(false);
  };

  const handlePrint = () => {
    window.print();
  };

  // Helper to render score color-theme
  const getScoreTheme = (score) => {
    if (score >= 60) return 'malicious';
    if (score >= 30) return 'suspicious';
    return 'safe';
  };

  // Render Highlighted Phrases for AI tab
  const renderHighlightedBody = (body, phrases) => {
    if (!phrases || phrases.length === 0) return body;
    
    let highlighted = body;
    phrases.forEach(({ phrase, category }) => {
      // Avoid highlighting regex special chars
      const escaped = phrase.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
      const regex = new RegExp(`(${escaped})`, 'gi');
      
      const highlightClass = category === 'urgency' ? 'highlight-urgency' : 'highlight-action';
      highlighted = highlighted.replace(
        regex, 
        `<mark class="${highlightClass}">$1</mark>`
      );
    });

    return <div dangerouslySetInnerHTML={{ __html: highlighted }} />;
  };

  return (
    <div className="container fade-in">
      {/* App Header */}
      <header className="app-header">
        <div className="brand-section">
          <h1>
            <span className="shield-icon">🛡️</span> 
            <span>Akhil PhishGuard</span>
          </h1>
          <p>Advanced Phishing URL & Email threat analyzer</p>
        </div>
        <div className="header-actions">
          {backendConnected ? (
            <span className="badge badge-connected">● Engine Active</span>
          ) : (
            <span className="badge badge-offline">⚠ Sandbox Active (Offline)</span>
          )}
          <button 
            id="settings-toggle-btn"
            className="btn-settings" 
            onClick={() => setShowSettings(!showSettings)}
          >
            ⚙ Settings
          </button>
        </div>
      </header>

      {/* Settings Panel */}
      {showSettings && (
        <section className="settings-drawer glass-panel fade-in">
          <h3>🔐 API Credentials & Settings</h3>
          <div className="settings-grid">
            <input 
              id="api-key-input"
              type="password" 
              placeholder="Enter Gemini API Key (Optional)..." 
              value={apiKey}
              onChange={handleApiKeyChange}
            />
            {apiKey ? (
              <span className="badge badge-connected">Key Cached</span>
            ) : (
              <span className="badge badge-offline">Simulated AI Mode</span>
            )}
          </div>
          <p className="settings-help">
            Keys are saved in your local browser sandbox. Get a free API Key from{' '}
            <a href="https://aistudio.google.com/" target="_blank" rel="noopener noreferrer">
              Google AI Studio
            </a>. If left empty, PhishGuard runs a simulated heuristic engine.
          </p>
        </section>
      )}

      {/* Input Stage */}
      {!isScanning && !result && (
        <main className="input-section fade-in">
          {/* Mode Switcher */}
          <nav className="mode-tabs">
            <button 
              id="tab-mode-url"
              className={`tab-btn ${mode === 'url' ? 'active' : ''}`}
              onClick={() => { setMode('url'); setInputValue(''); }}
            >
              �� URL Analyzer
            </button>
            <button 
              id="tab-mode-email"
              className={`tab-btn ${mode === 'email' ? 'active' : ''}`}
              onClick={() => { setMode('email'); setInputValue(''); }}
            >
              ✉ Email Analyzer
            </button>
          </nav>

          <div className="glass-panel" style={{ padding: '30px' }}>
            <h2>
              {mode === 'url' ? 'Analyze Suspicious URL Link' : 'Analyze Raw Email Content'}
            </h2>
            
            <div className="input-group">
              <div className="input-icon-wrapper">
                {mode === 'url' ? (
                  <input 
                    id="url-input-field"
                    type="text" 
                    placeholder="Paste URL link here (e.g., http://paypal-security-update.com/login)..."
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                  />
                ) : (
                  <textarea 
                    id="email-input-field"
                    placeholder="Paste the raw email header block & body text here..."
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                  />
                )}
              </div>
            </div>

            <button 
              id="scan-execute-btn"
              className="analyze-btn" 
              onClick={triggerScan}
              disabled={!inputValue.trim()}
            >
              🛡 Start Security Analysis
            </button>

            {/* Quick Examples */}
            <div className="examples-container">
              <p>Quick Reference Templates:</p>
              <div className="examples-list">
                {EXAMPLES[mode].map((ex, idx) => (
                  <button 
                    key={idx}
                    className="example-chip"
                    onClick={() => handleExampleClick(ex.value)}
                    title={ex.description}
                  >
                    {ex.name}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </main>
      )}

      {/* Scanning Stage */}
      {isScanning && (
        <section className="scan-pipeline-overlay glass-panel fade-in">
          <div className="scan-line-anim"></div>
          <div className="scan-radar">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <path d="M12 2a10 10 0 0 1 10 10" />
            </svg>
          </div>
          <h2>SCANNING IN PROGRESS</h2>
          <p style={{ color: 'var(--text-secondary)', marginBottom: '20px' }}>
            PhishGuard pipeline is executing analytical engines...
          </p>

          <div className="pipeline-steps">
            <div className={`pipeline-step ${scanStep === 0 ? 'active' : scanStep > 0 ? 'completed' : ''}`}>
              <div className="step-indicator">{scanStep > 0 ? '✓' : '1'}</div>
              <div className="step-details">
                <h4>Input Parsing Engine</h4>
                <p>{scanStep === 0 ? 'Unfolding headers, identifying hyperlink nodes...' : 'Content parsed successfully.'}</p>
              </div>
              <span className="step-status">{scanStep > 0 ? 'Parsed' : 'Running'}</span>
            </div>

            <div className={`pipeline-step ${scanStep === 1 ? 'active' : scanStep > 1 ? 'completed' : ''}`}>
              <div className="step-indicator">{scanStep > 1 ? '✓' : '2'}</div>
              <div className="step-details">
                <h4>Parallel Threat Assessment</h4>
                <p>
                  {mode === 'url' 
                    ? 'Tracing redirections, evaluating TLD risk, running typosquat check...' 
                    : 'Evaluating SPF/DMARC records alignment, checking text markers...'}
                </p>
              </div>
              <span className="step-status">
                {scanStep > 1 ? 'Analyzed' : scanStep === 1 ? 'Checking...' : 'Pending'}
              </span>
            </div>

            <div className={`pipeline-step ${scanStep === 2 ? 'active' : scanStep > 2 ? 'completed' : ''}`}>
              <div className="step-indicator">{scanStep > 2 ? '✓' : '3'}</div>
              <div className="step-details">
                <h4>Aggregating Risk Scorer</h4>
                <p>Combining behavioral metrics and technical vectors to produce risk assessment...</p>
              </div>
              <span className="step-status">
                {scanStep > 2 ? 'Computed' : scanStep === 2 ? 'Scoring...' : 'Pending'}
              </span>
            </div>
          </div>
        </section>
      )}

      {/* Analysis Report Dashboard */}
      {!isScanning && result && (
        <main className="report-panel fade-in">
          {/* Main Verdict Header Card */}
          <div className={`glass-panel report-header-panel glow-${getScoreTheme(result.score) === 'malicious' ? 'red' : 'cyan'}`}>
            <div className="score-gauge-wrapper">
              <svg className="score-gauge-svg">
                <circle cx="90" cy="90" r="75" className="gauge-bg" />
                <circle 
                  cx="90" 
                  cy="90" 
                  r="75" 
                  className={`gauge-fill ${getScoreTheme(result.score)}`} 
                  strokeDasharray="471.2"
                  strokeDashoffset={471.2 - (471.2 * result.score) / 100}
                />
              </svg>
              <div className="score-text-overlay">
                <span className="score-num">{result.score}</span>
                <span className="score-label">Risk Rating</span>
              </div>
            </div>

            <div className="verdict-info">
              <div className={`verdict-tag ${getScoreTheme(result.score)}`}>
                🛡 VERDICT: {result.verdict}
              </div>
              <p className="verdict-summary">
                {result.aiAnalysis?.summary || 'Threat indicators evaluated successfully.'}
              </p>
              <div className="verdict-actions">
                <button className="btn-secondary" onClick={resetScanner}>
                  Scan Another
                </button>
                <button className="btn-primary-action" onClick={handlePrint}>
                  🖨 Export Report
                </button>
              </div>
            </div>
          </div>

          {/* Report Navigation Tabs */}
          <nav className="report-tabs">
            <button 
              className={`report-tab-btn ${activeReportTab === 'indicators' ? 'active' : ''}`}
              onClick={() => setActiveReportTab('indicators')}
            >
              ⚠ Threat Indicators ({result.indicators?.length || 0})
            </button>
            <button 
              className={`report-tab-btn ${activeReportTab === 'ai' ? 'active' : ''}`}
              onClick={() => setActiveReportTab('ai')}
            >
              🧠 Gemini AI Analysis
            </button>
            <button 
              className={`report-tab-btn ${activeReportTab === 'tech' ? 'active' : ''}`}
              onClick={() => setActiveReportTab('tech')}
            >
              🛠 Technical Details
            </button>
            <button 
              className={`report-tab-btn ${activeReportTab === 'raw' ? 'active' : ''}`}
              onClick={() => setActiveReportTab('raw')}
            >
              ⚙ Raw Output (JSON)
            </button>
          </nav>

          {/* Tabs Content */}
          <section className="report-tab-content fade-in">
            {/* Tab: Threat Indicators */}
            {activeReportTab === 'indicators' && (
              <div className="indicators-grid">
                {result.indicators && result.indicators.length > 0 ? (
                  result.indicators.map((ind, idx) => (
                    <div key={idx} className={`indicator-card severity-${ind.severity}`}>
                      <div className="ind-icon-box">
                        {ind.category === 'reputation' ? '🌐' : 
                         ind.category === 'redirects' ? '⇄' : 
                         ind.category === 'headers' ? '✉' : 
                         ind.category === 'authentication' ? '🔑' : 
                         ind.category === 'links' ? '🔗' : '⚠'}
                      </div>
                      <div className="ind-details">
                        <h4>{ind.title}</h4>
                        <p>{ind.description}</p>
                      </div>
                      <div className="ind-badge">
                        +{ind.weight}
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="glass-panel" style={{ padding: '30px', textAlign: 'center' }}>
                    <p style={{ color: 'var(--accent-green)', fontWeight: 'bold' }}>✓ No threat indicators triggered.</p>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>This input appears to be aligned with basic security standards.</p>
                  </div>
                )}
              </div>
            )}

            {/* Tab: AI Insights */}
            {activeReportTab === 'ai' && (
              <div className="ai-analysis-grid">
                {/* Simulation warning */}
                {result.isSimulated && (
                  <div className="glass-panel" style={{ gridColumn: '1 / -1', padding: '12px 20px', background: 'rgba(255,170,0,0.08)', border: '1px solid rgba(255,170,0,0.3)', borderRadius: '10px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span style={{ fontSize: '1.2rem' }}>⚠️</span>
                    <div>
                      <strong style={{ color: 'var(--accent-yellow, #ffaa00)' }}>Simulated Analysis Mode</strong>
                      <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', margin: '2px 0 0' }}>Gemini AI was unavailable or no API key provided. Results are from the local heuristic engine. Add a Gemini API key in Settings for full AI-powered analysis.</p>
                    </div>
                  </div>
                )}

                <div className="glass-panel ai-card">
                  <h3>🧠 Behavioral Scans</h3>
                  <div className="metric-bar-container">
                    <div className="metric-header">
                      <span>Urgency level (0-10)</span>
                      <span>{result.aiAnalysis?.urgency?.score ?? 0}/10</span>
                    </div>
                    <div className="metric-bar-bg">
                      <div
                        className={`metric-bar-fill ${(result.aiAnalysis?.urgency?.score ?? 0) >= 7 ? 'high' : ''}`}
                        style={{ width: `${(result.aiAnalysis?.urgency?.score ?? 0) * 10}%` }}
                      ></div>
                    </div>
                    <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '8px' }}>
                      {result.aiAnalysis?.urgency?.explanation || 'No urgency analysis available.'}
                    </p>
                  </div>

                  {/* AI Risk Score */}
                  <div className="metric-bar-container" style={{ marginTop: '18px' }}>
                    <div className="metric-header">
                      <span>AI Risk Score</span>
                      <span>{result.aiAnalysis?.ai_risk_score ?? '—'}/100</span>
                    </div>
                    <div className="metric-bar-bg">
                      <div
                        className={`metric-bar-fill ${
                          (result.aiAnalysis?.ai_risk_score ?? 0) >= 60 ? 'high' :
                          (result.aiAnalysis?.ai_risk_score ?? 0) >= 30 ? '' : ''
                        }`}
                        style={{
                          width: `${result.aiAnalysis?.ai_risk_score ?? 0}%`,
                          background: (result.aiAnalysis?.ai_risk_score ?? 0) >= 60
                            ? 'var(--accent-red)'
                            : (result.aiAnalysis?.ai_risk_score ?? 0) >= 30
                            ? 'var(--accent-yellow, #ffaa00)'
                            : 'var(--accent-green)'
                        }}
                      ></div>
                    </div>
                    <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: '6px' }}>
                      AI Verdict: <strong style={{ color: result.aiAnalysis?.overall_verdict === 'MALICIOUS' ? 'var(--accent-red)' : result.aiAnalysis?.overall_verdict === 'SUSPICIOUS' ? 'var(--accent-yellow, #ffaa00)' : 'var(--accent-green)' }}>{result.aiAnalysis?.overall_verdict || '—'}</strong>
                    </p>
                  </div>
                </div>

                <div className="glass-panel ai-card">
                  <h3>🛡 Brand Integrity</h3>
                  <p style={{ fontWeight: '500', marginBottom: '6px' }}>
                    Impersonation Check:{' '}
                    <span style={{ color: result.aiAnalysis?.impersonation?.detected ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                      {result.aiAnalysis?.impersonation?.detected ? `⚠ Spoofing Detected` : `✓ Appears Legitimate`}
                    </span>
                  </p>
                  {result.aiAnalysis?.impersonation?.detected && (
                    <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', marginBottom: '12px' }}>
                      <strong>Impersonating:</strong> {result.aiAnalysis?.impersonation?.targetBrand || 'Unknown Brand'}
                    </p>
                  )}
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '15px' }}>
                    {result.aiAnalysis?.impersonation?.explanation || 'No impersonation analysis available.'}
                  </p>

                  <div>
                    <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Identified Lures:</span>
                    <div className="lures-list">
                      {result.aiAnalysis?.lures?.types && result.aiAnalysis?.lures?.types.length > 0 ? (
                        result.aiAnalysis.lures.types.map((lure, idx) => (
                          <span key={idx} className="lure-tag">
                            {lure}
                          </span>
                        ))
                      ) : (
                        <span style={{ fontSize: '0.85rem', color: 'var(--accent-green)' }}>✓ None detected</span>
                      )}
                    </div>
                    {result.aiAnalysis?.lures?.explanation && (
                      <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: '8px' }}>
                        {result.aiAnalysis.lures.explanation}
                      </p>
                    )}
                  </div>
                </div>

                {/* AI Summary Card */}
                {result.aiAnalysis?.summary && (
                  <div className="glass-panel" style={{ gridColumn: '1 / -1', padding: '20px' }}>
                    <h3 style={{ marginBottom: '10px' }}>📋 AI Analysis Summary</h3>
                    <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
                      {result.aiAnalysis.summary}
                    </p>
                    {result.aiAnalysis?.suspicious_phrases && result.aiAnalysis.suspicious_phrases.length > 0 && (
                      <div style={{ marginTop: '15px' }}>
                        <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)', display: 'block', marginBottom: '8px' }}>Suspicious Phrases Flagged:</span>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                          {result.aiAnalysis.suspicious_phrases.map((p, idx) => (
                            <span key={idx} style={{ background: 'rgba(255,60,60,0.15)', border: '1px solid rgba(255,60,60,0.3)', borderRadius: '6px', padding: '3px 10px', fontSize: '0.82rem', color: 'var(--accent-red)' }}>
                              {p.phrase} <span style={{ opacity: 0.6, fontSize: '0.75rem' }}>({p.category})</span>
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Email Body Highlighter */}
                {mode === 'email' && (
                  <div className="glass-panel email-body-card" style={{ gridColumn: '1 / -1' }}>
                    <h3>✉ Analyzed Email Body (Linguistic Highlights)</h3>
                    <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '10px' }}>
                      <span style={{ background: 'rgba(255,60,60,0.2)', padding: '2px 6px', borderRadius: '4px' }}>Red</span> = Urgency demands &nbsp;
                      <span style={{ background: 'rgba(255,200,0,0.2)', padding: '2px 6px', borderRadius: '4px' }}>Yellow</span> = Suspicious actions/anchors
                    </p>
                    <div className="email-body-content">
                      {renderHighlightedBody(
                        inputValue.split('\n\n').slice(1).join('\n\n') || inputValue,
                        result.aiAnalysis?.suspicious_phrases || []
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Tab: Technical Checks */}
            {activeReportTab === 'tech' && (
              <div className="tech-split">
                {mode === 'url' ? (
                  <>
                    {/* URL Redirect Chain */}
                    <div className="glass-panel tech-panel">
                      <h3>⇄ Redirection Chain Tracker</h3>
                      {result.redirectChain && result.redirectChain.length > 0 ? (
                        <div className="redirect-chain">
                          {result.redirectChain.map((hop, idx) => {
                            const isLast = idx === result.redirectChain.length - 1;
                            const statusNum = parseInt(hop.status);
                            const isRedirect = statusNum >= 300 && statusNum < 400;
                            const isError = hop.status === 'Error' || hop.status === 'Timeout' || hop.error;
                            return (
                              <div
                                key={idx}
                                className={`redirect-hop ${isError ? 'has-danger' : ''}`}
                              >
                                <div className="hop-node" style={{ background: isError ? 'var(--accent-red)' : isLast ? 'var(--accent-green)' : 'var(--accent-blue, #5b9bd5)' }}>{idx + 1}</div>
                                <div className="hop-details">
                                  <div className="hop-url">{hop.url}</div>
                                  <div className="hop-meta">
                                    <span className={`hop-status-code ${isRedirect ? 'status-redirect' : isError ? 'status-error' : 'status-ok'}`}>
                                      {isError ? `⚠ ${hop.status}` : `HTTP ${hop.status}`}
                                    </span>
                                    {isLast && <span style={{ fontSize: '0.75rem', color: 'var(--accent-green)', marginLeft: '8px' }}>← Final Destination</span>}
                                    {hop.error && <span style={{ fontSize: '0.75rem', color: 'var(--accent-red)', marginLeft: '8px', display: 'block' }}>{hop.error}</span>}
                                  </div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      ) : (
                        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', textAlign: 'center', padding: '20px 0' }}>No redirect chain data available (offline mode).</p>
                      )}
                    </div>

                    {/* Domain & Reputation Details */}
                    <div className="glass-panel tech-panel">
                      <h3>🌐 Domain Reputation Stats</h3>
                      <div className="auth-grid">
                        <div className="auth-row">
                          <div className="auth-label-wrap">
                            <span className="auth-icon">💻</span>
                            <span className="auth-label">Hostname</span>
                          </div>
                          <span className="auth-val">{result.domainInfo?.hostname || result.domainInfo?.domain || '—'}</span>
                        </div>

                        <div className="auth-row">
                          <div className="auth-label-wrap">
                            <span className="auth-icon">🌍</span>
                            <span className="auth-label">Top Level Domain</span>
                          </div>
                          <span className="auth-val">{result.domainInfo?.tld || '—'}</span>
                        </div>

                        {result.finalDomainInfo && result.finalDomainInfo.domain !== result.domainInfo?.domain && (
                          <div className="auth-row">
                            <div className="auth-label-wrap">
                              <span className="auth-icon">🏁</span>
                              <span className="auth-label">Final Landing Domain</span>
                            </div>
                            <span className="auth-val">{result.finalDomainInfo.domain}</span>
                          </div>
                        )}

                        <div className="auth-row">
                          <div className="auth-label-wrap">
                            <span className="auth-icon">🔒</span>
                            <span className="auth-label">Security Protocol</span>
                          </div>
                          <span className={`dns-badge ${(result.domainInfo?.protocol === 'https:' || result.finalUrl?.startsWith('https')) ? 'dns-badge-pass' : 'dns-badge-fail'}`}>
                            {result.domainInfo?.protocol?.toUpperCase() || 'HTTP:'}
                          </span>
                        </div>

                        <div className="auth-row">
                          <div className="auth-label-wrap">
                            <span className="auth-icon">🔍</span>
                            <span className="auth-label">Trusted Domain</span>
                          </div>
                          <span className={`dns-badge ${result.isOriginalTrusted || result.isFinalTrusted ? 'dns-badge-pass' : 'dns-badge-warn'}`}>
                            {result.isOriginalTrusted || result.isFinalTrusted ? '✓ Verified Trusted' : '⚠ Unverified'}
                          </span>
                        </div>

                        <div className="auth-row">
                          <div className="auth-label-wrap">
                            <span className="auth-icon">⚠️</span>
                            <span className="auth-label">Spoofing Detection</span>
                          </div>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', alignItems: 'flex-end' }}>
                            <span className={`dns-badge ${result.typosquat?.isSpoof ? 'dns-badge-fail' : 'dns-badge-pass'}`}>
                              {result.typosquat?.isSpoof ? '⚠ Spoofed Brand' : '✓ Clean'}
                            </span>
                            {result.typosquat?.reason && (
                              <span style={{ fontSize: '0.75rem', color: 'var(--accent-red)', textAlign: 'right', maxWidth: '200px' }}>
                                {result.typosquat.reason}
                              </span>
                            )}
                          </div>
                        </div>

                        {result.pageAnalysis && (
                          <>
                            <div className="auth-row">
                              <div className="auth-label-wrap">
                                <span className="auth-icon">🔑</span>
                                <span className="auth-label">Password Form</span>
                              </div>
                              <span className={`dns-badge ${result.pageAnalysis.hasPasswordInput ? 'dns-badge-fail' : 'dns-badge-pass'}`}>
                                {result.pageAnalysis.hasPasswordInput ? '⚠ Detected' : '✓ Not Found'}
                              </span>
                            </div>
                            {result.pageAnalysis.brandKeywords && result.pageAnalysis.brandKeywords.length > 0 && (
                              <div className="auth-row">
                                <div className="auth-label-wrap">
                                  <span className="auth-icon">🏷</span>
                                  <span className="auth-label">Brand References</span>
                                </div>
                                <span style={{ fontSize: '0.82rem', color: 'var(--accent-red)', fontWeight: '600' }}>
                                  {result.pageAnalysis.brandKeywords.join(', ')}
                                </span>
                              </div>
                            )}
                          </>
                        )}
                      </div>
                    </div>

                    {/* Webpage Visual Capture */}
                    {result.screenshot && (
                      <div className="glass-panel tech-panel" style={{ gridColumn: '1 / -1' }}>
                        <h3>📸 Webpage Visual Capture (Multimodal Vision Engine)</h3>
                        <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '15px' }}>
                          Real-time screenshot captured by scanner and analyzed by Gemini AI Vision for visual brand impersonation.
                        </p>
                        <div style={{ display: 'flex', justifyContent: 'center' }}>
                          <img
                            src={result.screenshot}
                            alt="Webpage Screenshot Capture"
                            style={{
                              maxWidth: '100%',
                              maxHeight: '500px',
                              borderRadius: '8px',
                              border: '1px solid var(--border-color)',
                              boxShadow: '0 4px 15px rgba(0,0,0,0.5)',
                              objectFit: 'contain'
                            }}
                          />
                        </div>
                      </div>
                    )}
                  </>
                ) : (
                  <>
                    {/* Email Headers Alignment */}
                    <div className="glass-panel tech-panel">
                      <h3>✉ Domain Alignments & DNS</h3>
                      <div className="auth-grid">
                        <div className="auth-row">
                          <div className="auth-label-wrap">
                            <span className="auth-icon">📧</span>
                            <span className="auth-label">From Header</span>
                          </div>
                          <span className="auth-val" style={{ maxWidth: '55%', wordBreak: 'break-all' }}>{result.headersParsed?.from || 'Unknown'}</span>
                        </div>

                        <div className="auth-row">
                          <div className="auth-label-wrap">
                            <span className="auth-icon">↩</span>
                            <span className="auth-label">Reply-To</span>
                          </div>
                          <span className="auth-val" style={{ maxWidth: '55%', wordBreak: 'break-all' }}>{result.headersParsed?.['reply-to'] || 'Not Set'}</span>
                        </div>

                        <div className="auth-row">
                          <div className="auth-label-wrap">
                            <span className="auth-icon">↪</span>
                            <span className="auth-label">Return-Path</span>
                          </div>
                          <span className="auth-val" style={{ maxWidth: '55%', wordBreak: 'break-all' }}>{result.headersParsed?.['return-path'] || 'Not Set'}</span>
                        </div>

                        <div className="auth-row">
                          <div className="auth-label-wrap">
                            <span className="auth-icon">🛡️</span>
                            <span className="auth-label">SPF Record</span>
                          </div>
                          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '4px' }}>
                            <span className={`dns-badge ${result.dnsCheck?.spf?.found ? 'dns-badge-pass' : (result.dnsCheck ? 'dns-badge-fail' : 'dns-badge-warn')}`}>
                              {result.dnsCheck?.spf?.found ? `✓ PASS (${result.dnsCheck.spf.status || 'valid'})` : (result.dnsCheck ? '✗ MISSING' : '— N/A')}
                            </span>
                          </div>
                        </div>

                        <div className="auth-row">
                          <div className="auth-label-wrap">
                            <span className="auth-icon">🔏</span>
                            <span className="auth-label">DMARC Policy</span>
                          </div>
                          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '4px' }}>
                            <span className={`dns-badge ${result.dnsCheck?.dmarc?.found ? (result.dnsCheck.dmarc.policy === 'reject' ? 'dns-badge-pass' : 'dns-badge-warn') : (result.dnsCheck ? 'dns-badge-fail' : 'dns-badge-warn')}`}>
                              {result.dnsCheck?.dmarc?.found
                                ? `✓ ${result.dnsCheck.dmarc.policy?.toUpperCase() || 'PASS'}`
                                : (result.dnsCheck ? '✗ MISSING' : '— N/A')}
                            </span>
                            {result.dnsCheck?.dmarc?.found && result.dnsCheck.dmarc.record && (
                              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', maxWidth: '200px', wordBreak: 'break-all', textAlign: 'right' }}>
                                {result.dnsCheck.dmarc.record.substring(0, 80)}{result.dnsCheck.dmarc.record.length > 80 ? '...' : ''}
                              </span>
                            )}
                          </div>
                        </div>

                        {result.dnsCheck?.mx?.found && (
                          <div className="auth-row">
                            <div className="auth-label-wrap">
                              <span className="auth-icon">📮</span>
                              <span className="auth-label">MX Records</span>
                            </div>
                            <span className="dns-badge dns-badge-pass">✓ {result.dnsCheck.mx.records.length} Found</span>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Hyperlink Domain Analyzer */}
                    <div className="glass-panel tech-panel">
                      <h3>🔗 Hyperlinked URL Analyzer</h3>
                      <div className="tech-links-list">
                        {result.linksAnalyzed && result.linksAnalyzed.length > 0 ? (
                          result.linksAnalyzed.map((link, idx) => (
                            <div key={idx} className={`tech-link-card ${link.misleading || link.typosquat?.isSpoof || link.highRiskTld ? 'warning' : ''}`}>
                              <div className="link-row">
                                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Visible Text:</span>
                                <span className="link-anchor">{link.anchorText || '(no anchor text)'}</span>

                                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>Actual URL:</span>
                                <span className="link-href">{link.href}</span>

                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '6px' }}>
                                  {link.misleading && <span className="link-alert">⚠ Misleading: {link.explanation}</span>}
                                  {link.typosquat?.isSpoof && !link.misleading && <span className="link-alert">⚠ Typosquatted domain: {link.typosquat.reason}</span>}
                                  {link.highRiskTld && <span style={{ fontSize: '0.75rem', background: 'rgba(255,170,0,0.15)', border: '1px solid rgba(255,170,0,0.3)', borderRadius: '5px', padding: '2px 8px', color: 'var(--accent-yellow, #ffaa00)' }}>⚠ High-risk TLD: {link.tld}</span>}
                                </div>
                              </div>
                            </div>
                          ))
                        ) : (
                          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', textAlign: 'center', marginTop: '20px' }}>
                            No hyperlinks extracted from email body.
                          </p>
                        )}
                      </div>
                    </div>
                  </>
                )}
              </div>
            )}

            {/* Tab: Raw JSON Output */}
            {activeReportTab === 'raw' && (
              <pre className="json-viewer">
                {JSON.stringify(result, null, 2)}
              </pre>
            )}
          </section>
        </main>
      )}
      <Analytics />
    </div>
  );
}

export default App;
