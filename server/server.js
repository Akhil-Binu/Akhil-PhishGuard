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
  runLocalHeuristicAnalysis
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
async function runGeminiAnalysis(content, isEmail, apiKey) {
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
    : `Analyze the following URL and domain details for potential phishing, brand spoofing, or deceptive routing. Output your response as a JSON object matching this schema:
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

  const result = await model.generateContent(prompt);
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

    // 1. Trace redirects
    const redirectChain = await traceRedirects(url);
    const finalUrl = redirectChain[redirectChain.length - 1].url;
    const finalDomainInfo = extractDomainInfo(finalUrl);

    // 2. Typosquatting check on original and final domains
    const typosquat = checkTyposquatting(domainInfo.domain);
    const finalTyposquat = checkTyposquatting(finalDomainInfo.domain);

    // 3. AI / Heuristics analysis
    let aiAnalysis;
    let isSimulated = false;

    const contextStr = `Original URL: ${url}\nDomain: ${domainInfo.domain}\nTLD: ${domainInfo.tld}\nProtocol: ${domainInfo.protocol}\nRedirect Chain: ${JSON.stringify(redirectChain)}\nFinal Domain: ${finalDomainInfo.domain}`;

    try {
      aiAnalysis = await runGeminiAnalysis(contextStr, false, apiKey);
    } catch (e) {
      console.warn('Falling back to local heuristic url analysis:', e.message);
      aiAnalysis = runLocalHeuristicAnalysis(contextStr, false);
      isSimulated = true;
    }

    // 4. Calculate Risk Score and compile threat indicators
    let score = 0;
    const indicators = [];

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
      indicators
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
