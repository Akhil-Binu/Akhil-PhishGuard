import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { GoogleGenerativeAI } from '@google/generative-ai';
import {
  extractDomainInfo,
  checkTyposquatting,
  traceRedirects,
  parseRawEmail,
  extractEmailAddress,
  verifyDomainDNS,
  extractAndAnalyzeLinks,
  runLocalHeuristicAnalysis,
  analyzeHtmlContent,
  checkThreatDatabase
} from './utils.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Logger middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Gemini AI analysis runner
async function runGeminiAnalysis(content, isEmail, apiKey, screenshotBase64 = null) {
  const key = apiKey || process.env.GEMINI_API_KEY;
  if (!key) {
    throw new Error('No Gemini API key available');
  }

  const genAI = new GoogleGenerativeAI(key);
  const model = genAI.getGenerativeModel({
    model: 'gemini-1.5-flash',
    generationConfig: { responseMimeType: 'application/json' }
  });

  const prompt = isEmail
    ? `Analyze the following email for phishing indicators. Break down the urgency (score 0-10, where 10 is extremely urgent/threatening), brand impersonation (is it claiming to be Netflix, Paypal, Chase, etc. but has indicators of forgery?), psychological lures (e.g. fear, greed, urgency, authority, trust), and extract suspicious phrases. Output your response as a JSON object matching this schema:
    {
      "urgency": { "score": number, "explanation": "string" },
      "impersonation": { "detected": boolean, "targetBrand": "string", "explanation": "string" },
      "lures": { "types": ["string"], "explanation": "string" },
      "suspicious_phrases": [ { "phrase": "string", "category": "string" } ],
      "overall_verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS",
      "ai_risk_score": number (0-100),
      "summary": "string"
    }

    Email text or headers to analyze:
    ${content}`
    : `Analyze the following URL, domain details, and attached screenshot of the webpage for potential phishing, brand spoofing, or deceptive routing.
    Examine the screenshot's visual layout and text to see if it mimics a popular corporate login/home page (like Fiverr, Netflix, PayPal, Chase, Microsoft, Amazon, Google, etc.).
    If the webpage visual design mimics a popular brand but the URL domain is NOT that legitimate brand's domain (e.g. hosts a Fiverr login on flickshoot.com), classify it as a MALICIOUS spoof immediately.
    Output your response as a JSON object matching this schema:
    {
      "urgency": { "score": number, "explanation": "string" },
      "impersonation": { "detected": boolean, "targetBrand": "string", "explanation": "string" },
      "lures": { "types": ["string"], "explanation": "string" },
      "suspicious_phrases": [ { "phrase": "string", "category": "string" } ],
      "overall_verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS",
      "ai_risk_score": number (0-100),
      "summary": "string"
    }

    URL context to analyze:
    ${content}`;

  const parts = [prompt];
  if (screenshotBase64) {
    parts.push({
      inlineData: {
        data: screenshotBase64,
        mimeType: 'image/png'
      }
    });
  }

  const result = await model.generateContent(parts);
  const responseText = result.response.text();
  return JSON.parse(responseText);
}

// Route: Analyze URL
app.post('/api/analyze-url', async (req, res) => {
  const { url, apiKey } = req.body;
  if (!url) {
    return res.status(400).json({ error: 'URL parameter is required' });
  }

  try {
    const domainInfo = extractDomainInfo(url);
    if (domainInfo.error) {
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    // Query threat intelligence database early
    const threatFeed = checkThreatDatabase(url);

    // 1. Trace redirects
    const redirectChain = await traceRedirects(url);
    const finalUrl = redirectChain[redirectChain.length - 1].url;
    const finalDomainInfo = extractDomainInfo(finalUrl);

    // 2. Typosquatting check on original and final domains
    const typosquat = checkTyposquatting(domainInfo.domain);
    const finalTyposquat = checkTyposquatting(finalDomainInfo.domain);

    // 3. Webpage Content Analysis (Credential harvesting & Visual screenshot scan)
    let webpageContent = '';
    let pageAnalysis = { hasPasswordInput: false, hasLoginForm: false, keywordsFound: [], strippedText: '' };
    let screenshotBase64 = null;
    
    // Fetch the final landing page content and capture webpage visual screenshot in parallel
    try {
      const pageRes = await fetch(finalUrl, {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
      });
      if (pageRes.ok) {
        webpageContent = await pageRes.text();
        pageAnalysis = analyzeHtmlContent(webpageContent, finalDomainInfo.domain);
      }

      // Fetch visual screenshot from Microlink API
      const screenshotApiUrl = `https://api.microlink.io?url=${encodeURIComponent(finalUrl)}&screenshot=true&embed=screenshot.url`;
      const screenshotRes = await fetch(screenshotApiUrl);
      if (screenshotRes.ok) {
        const buffer = await screenshotRes.arrayBuffer();
        screenshotBase64 = Buffer.from(buffer).toString('base64');
      }
    } catch (e) {
      console.warn('Could not fetch webpage content or visual screenshot:', e.message);
    }

    // 4. AI / Heuristics analysis
    let aiAnalysis;
    let isSimulated = false;

    const contextStr = `Original URL: ${url}\nDomain: ${domainInfo.domain}\nTLD: ${domainInfo.tld}\nProtocol: ${domainInfo.protocol}\nRedirect Chain: ${JSON.stringify(redirectChain)}\nFinal Domain: ${finalDomainInfo.domain}\nWebpage Text Snippet: ${pageAnalysis.strippedText}\nHas Password Fields: ${pageAnalysis.hasPasswordInput}`;

    try {
      aiAnalysis = await runGeminiAnalysis(contextStr, false, apiKey, screenshotBase64);
    } catch (e) {
      console.warn('Falling back to local heuristic url analysis:', e.message);
      if (threatFeed) {
        aiAnalysis = {
          urgency: { score: 8, explanation: `Threat intelligence signature flags this URL as an active phishing page targeting ${threatFeed.brand} customers.` },
          impersonation: { detected: true, targetBrand: threatFeed.brand, explanation: `Webpage spoofing: Visually mimics ${threatFeed.brand} login portals on an unaligned domain.` },
          lures: { types: ['urgency', 'credential_harvest'], explanation: `Uses simulated ${threatFeed.brand} interfaces to collect credentials.` },
          suspicious_phrases: [{ phrase: 'login', category: 'urgency' }, { phrase: 'password', category: 'action' }],
          overall_verdict: 'MALICIOUS',
          ai_risk_score: 95,
          summary: `Offline heuristic: Flagged in threat signature database as targeting ${threatFeed.brand}.`
        };
      } else {
        aiAnalysis = runLocalHeuristicAnalysis(contextStr, false);
      }
      isSimulated = true;
    }

    // 4. Calculate Risk Score and compile threat indicators
    let score = 0;
    const indicators = [];

    if (threatFeed) {
      indicators.push({
        title: `Threat Intel Signature Match`,
        description: threatFeed.details,
        category: 'reputation',
        severity: 'high',
        weight: 95
      });
      score += 95;
    }

    // High-risk TLDs
    const HIGH_RISK_TLDS = new Set(['.xyz', '.top', '.club', '.work', '.ru', '.cc', '.cn', '.fit', '.gq', '.tk', '.ml', '.cf', '.ga', '.click', '.link', '.zip', '.mov']);

    if (typosquat.isSpoof) {
      indicators.push({
        title: 'Brand Typosquatting',
        description: `The domain matches standard phishing typosquat patterns: ${typosquat.reason}`,
        category: 'reputation',
        severity: 'high',
        weight: 45
      });
      score += 45;
    }

    if (HIGH_RISK_TLDS.has(domainInfo.tld)) {
      indicators.push({
        title: 'High-Risk TLD',
        description: `The URL uses a top-level domain (${domainInfo.tld}) commonly abused for malicious activities.`,
        category: 'reputation',
        severity: 'medium',
        weight: 15
      });
      score += 15;
    }

    // Heuristics: scan landing page HTML credentials and brand keywords matching
    const brandNames = ['fiverr', 'netflix', 'paypal', 'chase', 'microsoft', 'amazon'];
    brandNames.forEach(brand => {
      if (pageAnalysis.hasPasswordInput && pageAnalysis.keywordsFound.includes(brand) && !finalDomainInfo.domain.includes(brand)) {
        indicators.push({
          title: `${brand.charAt(0).toUpperCase() + brand.slice(1)} Impersonation Gate`,
          description: `Webpage hosts password forms and Fiverr/brand keywords, but resolves to unaligned domain "${finalDomainInfo.domain}". This points to phishing credential harvesting.`,
          category: 'behavioral',
          severity: 'high',
          weight: 55
        });
        score += 55;
      }
    });

    if (redirectChain.length > 2) {
      indicators.push({
        title: 'Multiple Redirection Hops',
        description: `The URL redirected ${redirectChain.length - 1} times. Multiple redirect chains are frequently used to mask destination servers.`,
        category: 'redirects',
        severity: 'medium',
        weight: 20
      });
      score += 20;
    }

    if (domainInfo.domain !== finalDomainInfo.domain) {
      indicators.push({
        title: 'Domain Redirection Drift',
        description: `The link redirects from "${domainInfo.domain}" to a completely different domain "${finalDomainInfo.domain}".`,
        category: 'redirects',
        severity: 'high',
        weight: 25
      });
      score += 25;
    }

    if (domainInfo.protocol === 'http:') {
      indicators.push({
        title: 'Unencrypted Connection (HTTP)',
        description: 'This site does not use HTTPS. Legitimate login or payment pages always use SSL/TLS encryption.',
        category: 'security',
        severity: 'medium',
        weight: 15
      });
      score += 15;
    }

    // AI indicators
    if (aiAnalysis.urgency && aiAnalysis.urgency.score >= 5) {
      indicators.push({
        title: 'Urgent Demand Detected',
        description: aiAnalysis.urgency.explanation,
        category: 'behavioral',
        severity: aiAnalysis.urgency.score >= 8 ? 'high' : 'medium',
        weight: aiAnalysis.urgency.score * 2
      });
      score += aiAnalysis.urgency.score * 2;
    }

    if (aiAnalysis.impersonation && aiAnalysis.impersonation.detected) {
      indicators.push({
        title: `Impersonation Warning: ${aiAnalysis.impersonation.targetBrand}`,
        description: aiAnalysis.impersonation.explanation,
        category: 'behavioral',
        severity: 'high',
        weight: 35
      });
      score += 35;
    }

    // Heuristics checks inside AI response
    if (aiAnalysis.ai_risk_score) {
      // Add weight if AI score is high and not already captured
      if (aiAnalysis.ai_risk_score > 60 && score < 50) {
        score += 20;
      }
    }

    score = Math.min(score, 100);

    let verdict = 'SAFE';
    if (score >= 60) verdict = 'MALICIOUS';
    else if (score >= 30) verdict = 'SUSPICIOUS';

    res.json({
      success: true,
      url,
      domainInfo,
      redirectChain,
      finalUrl,
      typosquat,
      aiAnalysis,
      isSimulated,
      score,
      verdict,
      indicators,
      screenshot: screenshotBase64 ? `data:image/png;base64,${screenshotBase64}` : null
    });
  } catch (error) {
    console.error('Error analyzing URL:', error);
    res.status(500).json({ error: 'Server error during URL analysis', details: error.message });
  }
});

// Route: Analyze Email
app.post('/api/analyze-email', async (req, res) => {
  const { rawEmail, apiKey } = req.body;
  if (!rawEmail) {
    return res.status(400).json({ error: 'Email content is required' });
  }

  try {
    // 1. Parse raw text into headers and body
    const emailData = parseRawEmail(rawEmail);
    const headers = emailData.headers;
    const body = emailData.body;

    const fromHeader = headers['from'] || '';
    const fromAddr = extractEmailAddress(fromHeader);
    const fromInfo = extractDomainInfo(fromAddr);

    // 2. Perform DNS Authentication Checks
    let dnsCheck = null;
    if (fromInfo.domain) {
      dnsCheck = await verifyDomainDNS(fromInfo.domain);
    }

    // 3. Extract and analyze links inside the body
    const links = extractAndAnalyzeLinks(body, fromInfo.domain);

    // 4. Run AI Analysis
    let aiAnalysis;
    let isSimulated = false;

    const contextStr = `From: ${fromHeader} (${fromAddr})
Subject: ${headers['subject'] || 'No Subject'}
Reply-To: ${headers['reply-to'] || 'None'}
Return-Path: ${headers['return-path'] || 'None'}
SPF/DMARC: ${JSON.stringify(dnsCheck)}
Links Extracted: ${JSON.stringify(links)}
Body Content:
${body}`;

    try {
      aiAnalysis = await runGeminiAnalysis(contextStr, true, apiKey);
    } catch (e) {
      console.warn('Falling back to local heuristic email analysis:', e.message);
      aiAnalysis = runLocalHeuristicAnalysis(body, true, headers);
      isSimulated = true;
    }

    // 5. Aggregate Risk Scoring & Indicators
    let score = 0;
    const indicators = [];

    // Header checks
    const replyTo = extractEmailAddress(headers['reply-to'] || '');
    const returnPath = extractEmailAddress(headers['return-path'] || '');

    if (replyTo && fromInfo.domain) {
      const replyToInfo = extractDomainInfo(replyTo);
      if (replyToInfo.domain && fromInfo.domain !== replyToInfo.domain) {
        indicators.push({
          title: 'Reply-To Address Mismatch',
          description: `Replies are routed to "${replyTo}" which belongs to a different domain than the sender "${fromInfo.domain}".`,
          category: 'headers',
          severity: 'high',
          weight: 25
        });
        score += 25;
      }
    }

    if (returnPath && fromInfo.domain) {
      const returnPathInfo = extractDomainInfo(returnPath);
      if (returnPathInfo.domain && fromInfo.domain !== returnPathInfo.domain) {
        indicators.push({
          title: 'Return-Path Address Mismatch',
          description: `Bounce-backs and delivery status reports are routed to "${returnPath}" instead of the visible sender domain "${fromInfo.domain}".`,
          category: 'headers',
          severity: 'medium',
          weight: 15
        });
        score += 15;
      }
    }

    // Check email authentication
    if (dnsCheck) {
      if (!dnsCheck.spf.found) {
        indicators.push({
          title: 'Missing SPF Record',
          description: `The sender domain "${fromInfo.domain}" does not specify SPF records. Mail systems cannot verify if this server is authorized to send emails for them.`,
          category: 'authentication',
          severity: 'medium',
          weight: 15
        });
        score += 15;
      }
      if (!dnsCheck.dmarc.found) {
        indicators.push({
          title: 'Missing DMARC Record',
          description: `The sender domain "${fromInfo.domain}" has no DMARC policy. This allows attackers to forge emails using this domain name easily.`,
          category: 'authentication',
          severity: 'medium',
          weight: 15
        });
        score += 15;
      }
    }

    // Check link alerts
    const misleadingLinks = links.filter(l => l.misleading);
    if (misleadingLinks.length > 0) {
      indicators.push({
        title: 'Deceptive Hyperlink Text',
        description: `Found ${misleadingLinks.length} URL link(s) where the visual anchor text mimics one website, but the actual hyperlink destination leads elsewhere.`,
        category: 'links',
        severity: 'high',
        weight: 30
      });
      score += 30;
    }

    const typosquatLinks = links.filter(l => l.typosquat && l.typosquat.isSpoof);
    if (typosquatLinks.length > 0) {
      indicators.push({
        title: 'Suspicious Domain Link',
        description: `The email contains links that use brand typosquatting (e.g. mimicking well-known brands to fool recipients).`,
        category: 'links',
        severity: 'high',
        weight: 35
      });
      score += 35;
    }

    const highRiskTldLinks = links.filter(l => l.highRiskTld);
    if (highRiskTldLinks.length > 0) {
      indicators.push({
        title: 'High-Risk TLD in Links',
        description: `Links in the email direct to domains registered under high-risk TLDs like ${Array.from(new Set(highRiskTldLinks.map(l => l.tld))).join(', ')}.`,
        category: 'links',
        severity: 'medium',
        weight: 15
      });
      score += 15;
    }

    // AI indicators
    if (aiAnalysis.urgency && aiAnalysis.urgency.score >= 5) {
      indicators.push({
        title: 'Urgent Tone Flagged',
        description: aiAnalysis.urgency.explanation,
        category: 'behavioral',
        severity: aiAnalysis.urgency.score >= 8 ? 'high' : 'medium',
        weight: aiAnalysis.urgency.score * 2
      });
      score += aiAnalysis.urgency.score * 2;
    }

    if (aiAnalysis.impersonation && aiAnalysis.impersonation.detected) {
      indicators.push({
        title: `Brand Impersonation: ${aiAnalysis.impersonation.targetBrand}`,
        description: aiAnalysis.impersonation.explanation,
        category: 'behavioral',
        severity: 'high',
        weight: 30
      });
      score += 30;
    }

    if (aiAnalysis.lures && aiAnalysis.lures.types && aiAnalysis.lures.types.length > 0) {
      indicators.push({
        title: 'Psychological Manipulation Lure',
        description: aiAnalysis.lures.explanation,
        category: 'behavioral',
        severity: 'medium',
        weight: 15
      });
      score += 15;
    }

    // Fallback alerts if simulated local heuristics
    if (isSimulated && aiAnalysis.alerts) {
      // Avoid duplicates but pull in any extra alerts if any
    }

    score = Math.min(score, 100);

    let verdict = 'SAFE';
    if (score >= 60) verdict = 'MALICIOUS';
    else if (score >= 30) verdict = 'SUSPICIOUS';

    res.json({
      success: true,
      headersParsed: headers,
      linksAnalyzed: links,
      dnsCheck,
      aiAnalysis,
      isSimulated,
      score,
      verdict,
      indicators
    });
  } catch (error) {
    console.error('Error analyzing email:', error);
    res.status(500).json({ error: 'Server error during email analysis', details: error.message });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`Akhil PhishGuard Backend is running on port ${PORT}`);
  console.log(`====================================================`);
});
