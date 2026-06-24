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
  checkThreatDatabase,
  isWhitelistedDomain
} from './utils.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '5mb' }));

// Logger middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ===== Gemini AI Analysis =====
async function runGeminiAnalysis(content, isEmail, apiKey, screenshotBase64 = null) {
  const key = apiKey || process.env.GEMINI_API_KEY;
  if (!key || key.trim() === '') {
    throw new Error('No Gemini API key provided');
  }

  const genAI = new GoogleGenerativeAI(key.trim());
  
  // Use gemini-2.0-flash for both text-only and multimodal vision
  const modelName = 'gemini-2.0-flash';
  const model = genAI.getGenerativeModel({
    model: modelName,
    generationConfig: {
      responseMimeType: 'application/json',
      temperature: 0.1,
    }
  });

  const JSON_SCHEMA = `{
  "urgency": { "score": <number 0-10>, "explanation": "<string>" },
  "impersonation": { "detected": <boolean>, "targetBrand": "<string or None>", "explanation": "<string>" },
  "lures": { "types": ["<string>"], "explanation": "<string>" },
  "suspicious_phrases": [{ "phrase": "<string>", "category": "<string>" }],
  "overall_verdict": "<SAFE|SUSPICIOUS|MALICIOUS>",
  "ai_risk_score": <number 0-100>,
  "summary": "<string>"
}`;

  let prompt;
  if (isEmail) {
    prompt = `You are a cybersecurity expert specializing in email phishing detection. Analyze the following email content for phishing indicators.

Examine:
1. Sender address alignment with claimed brand
2. Urgency/fear/pressure tactics (score 0-10 where 10 = extreme)
3. Brand impersonation (does it claim to be Netflix, PayPal, Amazon, Chase, etc. but shows forgery signs?)
4. Psychological lures (fear, greed, urgency, authority, scarcity)
5. Suspicious links or requests for credentials

Output ONLY a JSON object matching this exact schema:
${JSON_SCHEMA}

Email content to analyze:
${content}`;
  } else {
    prompt = `You are a cybersecurity expert specializing in URL and phishing website detection. Analyze the following URL and webpage information for phishing indicators.

${screenshotBase64 ? `A screenshot of the webpage has been attached. IMPORTANT: If the screenshot visually shows a login page or design that mimics a well-known brand (like Fiverr, Netflix, PayPal, Chase, Microsoft, Amazon, Google, etc.) but the domain in the URL is NOT that brand's official domain, classify this as MALICIOUS impersonation immediately with ai_risk_score >= 85.` : ''}

Key checks to perform:
1. Does the URL domain match any claimed brand identity?
2. Does the page content suggest credential harvesting?
3. Are there redirect chains obscuring the true destination?
4. What is the overall phishing risk?

Output ONLY a JSON object matching this exact schema:
${JSON_SCHEMA}

URL context to analyze:
${content}`;
  }

  const parts = [{ text: prompt }];
  
  if (screenshotBase64 && screenshotBase64.length > 100) {
    parts.push({
      inlineData: {
        data: screenshotBase64,
        mimeType: 'image/png'
      }
    });
  }

  const result = await model.generateContent(parts);
  const responseText = result.response.text();
  
  // Parse JSON - handle cases where AI wraps in markdown code blocks
  let parsed;
  try {
    parsed = JSON.parse(responseText);
  } catch {
    // Try extracting JSON from markdown code block
    const jsonMatch = responseText.match(/```(?:json)?\s*([\s\S]+?)\s*```/);
    if (jsonMatch) {
      parsed = JSON.parse(jsonMatch[1]);
    } else {
      // Try finding raw JSON object
      const objMatch = responseText.match(/\{[\s\S]+\}/);
      if (objMatch) {
        parsed = JSON.parse(objMatch[0]);
      } else {
        throw new Error('Could not parse Gemini JSON response');
      }
    }
  }
  
  return parsed;
}

// ===== Capture webpage screenshot via Microlink API (returns URL, then fetch image) =====
async function captureScreenshot(pageUrl) {
  try {
    // Microlink API returns JSON with screenshot URL
    const apiUrl = `https://api.microlink.io?url=${encodeURIComponent(pageUrl)}&screenshot=true&meta=false&timeout=20000`;
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 25000);
    
    const apiRes = await fetch(apiUrl, {
      signal: controller.signal,
      headers: { 'x-api-key': process.env.MICROLINK_API_KEY || '' }
    });
    clearTimeout(timeoutId);
    
    if (!apiRes.ok) {
      console.warn('Microlink API responded with:', apiRes.status);
      return null;
    }
    
    const apiJson = await apiRes.json();
    
    // Microlink returns { data: { screenshot: { url: '...', width, height } } }
    const screenshotUrl = apiJson?.data?.screenshot?.url;
    if (!screenshotUrl) {
      console.warn('No screenshot URL in Microlink response:', JSON.stringify(apiJson).substring(0, 200));
      return null;
    }
    
    // Now fetch the actual image bytes from that URL
    const imgController = new AbortController();
    const imgTimeout = setTimeout(() => imgController.abort(), 15000);
    
    const imgRes = await fetch(screenshotUrl, { signal: imgController.signal });
    clearTimeout(imgTimeout);
    
    if (!imgRes.ok) {
      console.warn('Could not fetch screenshot image from URL:', screenshotUrl);
      return null;
    }
    
    const buffer = await imgRes.arrayBuffer();
    return Buffer.from(buffer).toString('base64');
  } catch (err) {
    console.warn('Screenshot capture failed:', err.message);
    return null;
  }
}

// ===== Route: Analyze URL =====
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

    // Quick threat feed check
    const threatFeed = checkThreatDatabase(url);

    // 1. Trace redirects
    const redirectChain = await traceRedirects(url);
    const finalHop = redirectChain[redirectChain.length - 1];
    const finalUrl = finalHop.url;
    const finalDomainInfo = extractDomainInfo(finalUrl);

    // 2. Typosquatting check
    const typosquat = checkTyposquatting(domainInfo.domain);
    const finalTyposquat = checkTyposquatting(finalDomainInfo.domain);

    // 3. Whitelist check early — if it's a known trusted domain, skip aggressive checks
    const isOriginalTrusted = isWhitelistedDomain(domainInfo.domain);
    const isFinalTrusted = isWhitelistedDomain(finalDomainInfo.domain);

    // 4. Fetch webpage content + screenshot in parallel
    let webpageContent = '';
    let pageAnalysis = {
      hasPasswordInput: false, hasLoginForm: false,
      keywordsFound: [], brandKeywords: [], strippedText: '', formCount: 0
    };
    let screenshotBase64 = null;

    try {
      const [pageResult, screenshotResult] = await Promise.allSettled([
        // Fetch page HTML
        (async () => {
          const controller = new AbortController();
          const t = setTimeout(() => controller.abort(), 12000);
          const r = await fetch(finalUrl, {
            method: 'GET',
            signal: controller.signal,
            headers: {
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
              'Accept-Language': 'en-US,en;q=0.5',
            }
          });
          clearTimeout(t);
          if (r.ok) return await r.text();
          return '';
        })(),
        // Capture screenshot
        captureScreenshot(finalUrl)
      ]);

      if (pageResult.status === 'fulfilled' && pageResult.value) {
        webpageContent = pageResult.value;
        pageAnalysis = analyzeHtmlContent(webpageContent, finalDomainInfo.domain);
      }
      if (screenshotResult.status === 'fulfilled' && screenshotResult.value) {
        screenshotBase64 = screenshotResult.value;
      }
    } catch (e) {
      console.warn('Content/screenshot fetch warning:', e.message);
    }

    // 5. Build context string for AI analysis
    const contextStr = [
      `Original URL: ${url}`,
      `Domain: ${domainInfo.domain}`,
      `TLD: ${domainInfo.tld}`,
      `Protocol: ${domainInfo.protocol}`,
      `Is Trusted Domain: ${isOriginalTrusted}`,
      `Redirect Chain (${redirectChain.length} hops): ${redirectChain.map(h => `${h.url} [${h.status}]`).join(' → ')}`,
      `Final Landing Domain: ${finalDomainInfo.domain}`,
      `Final URL is Trusted: ${isFinalTrusted}`,
      `Has Password Input: ${pageAnalysis.hasPasswordInput}`,
      `Has Login Form: ${pageAnalysis.hasLoginForm}`,
      `Brand Keywords on Page: ${pageAnalysis.brandKeywords.join(', ') || 'None'}`,
      `Threat Intel Match: ${threatFeed ? `YES - ${threatFeed.details}` : 'No'}`,
      `Webpage Text Snippet: ${pageAnalysis.strippedText.substring(0, 3000)}`
    ].join('\n');

    // 6. AI / Heuristics analysis
    let aiAnalysis;
    let isSimulated = false;

    try {
      aiAnalysis = await runGeminiAnalysis(contextStr, false, apiKey, screenshotBase64);
      console.log(`Gemini analysis complete: verdict=${aiAnalysis.overall_verdict}, score=${aiAnalysis.ai_risk_score}`);
    } catch (e) {
      console.warn('Gemini failed, using local heuristics:', e.message);
      isSimulated = true;

      if (threatFeed) {
        aiAnalysis = {
          urgency: { score: 8, explanation: `Threat intelligence database flags this URL as an active phishing campaign targeting ${threatFeed.brand} users.` },
          impersonation: { detected: true, targetBrand: threatFeed.brand, explanation: `URL matches known phishing signature for ${threatFeed.brand} spoofing.` },
          lures: { types: ['urgency', 'credential_harvest'], explanation: `Simulates ${threatFeed.brand} interfaces to collect login credentials.` },
          suspicious_phrases: [{ phrase: 'login', category: 'urgency' }, { phrase: 'password', category: 'action' }],
          overall_verdict: 'MALICIOUS',
          ai_risk_score: 90,
          summary: `Offline threat database: Confirmed phishing campaign targeting ${threatFeed.brand} customers.`,
          isLocalFallback: true
        };
      } else if (pageAnalysis.hasPasswordInput && pageAnalysis.brandKeywords.length > 0 && !isFinalTrusted) {
        const brand = pageAnalysis.brandKeywords[0];
        aiAnalysis = {
          urgency: { score: 7, explanation: 'Webpage hosts credential-capture form with brand-spoofing keywords.' },
          impersonation: { detected: true, targetBrand: brand, explanation: `Page visually references "${brand}" but hosted on unrelated domain "${finalDomainInfo.domain}".` },
          lures: { types: ['credential_harvest', 'urgency'], explanation: 'Login form designed to capture user credentials under false pretense.' },
          suspicious_phrases: [{ phrase: brand, category: 'brand_impersonation' }, { phrase: 'login', category: 'urgency' }],
          overall_verdict: 'MALICIOUS',
          ai_risk_score: 80,
          summary: `Local heuristic: Password form detected referencing "${brand}" on non-official domain — high phishing probability.`,
          isLocalFallback: true
        };
      } else {
        aiAnalysis = runLocalHeuristicAnalysis(contextStr, false);
      }
    }

    // 7. Build indicators and calculate final risk score
    let score = 0;
    const indicators = [];

    // Threat feed match (highest priority)
    if (threatFeed) {
      indicators.push({
        title: `Threat Intelligence Match: ${threatFeed.brand}`,
        description: threatFeed.details,
        category: 'reputation',
        severity: 'high',
        weight: 90
      });
      score += 90;
    }

    // Typosquatting check (only if NOT whitelisted)
    if (!isOriginalTrusted && typosquat.isSpoof) {
      indicators.push({
        title: 'Brand Typosquatting Detected',
        description: `${typosquat.reason}. The domain appears to be impersonating a legitimate brand to deceive users.`,
        category: 'reputation',
        severity: 'high',
        weight: 50
      });
      score += 50;
    }

    if (!isFinalTrusted && finalTyposquat.isSpoof && finalDomainInfo.domain !== domainInfo.domain) {
      indicators.push({
        title: 'Final Domain Typosquatting',
        description: `The redirect destination "${finalDomainInfo.domain}" appears to impersonate a legitimate brand. ${finalTyposquat.reason}`,
        category: 'reputation',
        severity: 'high',
        weight: 45
      });
      score += 45;
    }

    // High-risk TLD
    const HIGH_RISK_TLDS = new Set(['.xyz', '.top', '.club', '.work', '.ru', '.cc', '.cn', '.fit', '.gq', '.tk', '.ml', '.cf', '.ga', '.click', '.link', '.zip', '.mov', '.win', '.bid', '.download', '.cheap', '.online', '.site', '.website', '.space']);
    if (HIGH_RISK_TLDS.has(domainInfo.tld)) {
      indicators.push({
        title: 'High-Risk Top-Level Domain',
        description: `The domain uses TLD "${domainInfo.tld}" which is heavily abused for spam, malware, and phishing campaigns.`,
        category: 'reputation',
        severity: 'medium',
        weight: 20
      });
      score += 20;
    }

    // Credential harvesting + brand mismatch
    if (pageAnalysis.hasPasswordInput && pageAnalysis.brandKeywords.length > 0 && !isFinalTrusted) {
      const detectedBrand = pageAnalysis.brandKeywords[0];
      indicators.push({
        title: `${detectedBrand.charAt(0).toUpperCase() + detectedBrand.slice(1)} Credential Harvesting Gate`,
        description: `The webpage contains a password form and references the "${detectedBrand}" brand, but is hosted on "${finalDomainInfo.domain}" — not ${detectedBrand}'s official domain. This is a classic phishing credential harvester.`,
        category: 'behavioral',
        severity: 'high',
        weight: 60
      });
      score += 60;
    } else if (pageAnalysis.hasPasswordInput && !isFinalTrusted && pageAnalysis.hasLoginForm) {
      indicators.push({
        title: 'Suspicious Login Form',
        description: `The page contains a login form with password field on a potentially unvetted domain.`,
        category: 'behavioral',
        severity: 'medium',
        weight: 20
      });
      score += 20;
    }

    // Redirect chain
    let domainDriftCount = 0;
    for (let i = 0; i < redirectChain.length - 1; i++) {
      const fromDom = extractDomainInfo(redirectChain[i].url).domain;
      const toDom = extractDomainInfo(redirectChain[i + 1].url).domain;
      if (fromDom && toDom && fromDom !== toDom) domainDriftCount++;
    }

    if (redirectChain.length > 2 && domainDriftCount > 0) {
      indicators.push({
        title: 'Multi-Domain Redirect Chain',
        description: `URL redirected ${redirectChain.length - 1} times, crossing ${domainDriftCount} different domain(s). Legitimate sites rarely chain redirects across multiple domains.`,
        category: 'redirects',
        severity: domainDriftCount >= 2 ? 'high' : 'medium',
        weight: domainDriftCount >= 2 ? 30 : 15
      });
      score += domainDriftCount >= 2 ? 30 : 15;
    } else if (redirectChain.length > 1 && domainInfo.domain !== finalDomainInfo.domain) {
      indicators.push({
        title: 'Domain Redirection Drift',
        description: `The link starts at "${domainInfo.domain}" but redirects to a completely different domain "${finalDomainInfo.domain}".`,
        category: 'redirects',
        severity: 'medium',
        weight: 15
      });
      score += 15;
    }

    // HTTP (no encryption)
    if (finalDomainInfo.protocol === 'http:') {
      indicators.push({
        title: 'Unencrypted HTTP Connection',
        description: 'The landing page uses unencrypted HTTP. Legitimate modern websites use HTTPS. Data transmitted is visible to network eavesdroppers.',
        category: 'security',
        severity: 'medium',
        weight: 15
      });
      score += 15;
    }

    // AI-derived indicators (only add if not already captured by heuristics)
    if (aiAnalysis.urgency && aiAnalysis.urgency.score >= 5) {
      indicators.push({
        title: 'Urgent Demand Detected (AI)',
        description: aiAnalysis.urgency.explanation,
        category: 'behavioral',
        severity: aiAnalysis.urgency.score >= 8 ? 'high' : 'medium',
        weight: Math.round(aiAnalysis.urgency.score * 2)
      });
      score += Math.round(aiAnalysis.urgency.score * 2);
    }

    if (aiAnalysis.impersonation && aiAnalysis.impersonation.detected && !threatFeed) {
      const alreadyFlagged = indicators.some(i => i.category === 'behavioral' && i.title.includes('Harvesting'));
      if (!alreadyFlagged) {
        indicators.push({
          title: `Brand Impersonation Detected: ${aiAnalysis.impersonation.targetBrand} (AI)`,
          description: aiAnalysis.impersonation.explanation,
          category: 'behavioral',
          severity: 'high',
          weight: 40
        });
        score += 40;
      }
    }

    // Incorporate AI risk score as a weighted factor
    if (aiAnalysis.ai_risk_score && aiAnalysis.ai_risk_score > 50) {
      const aiBoost = Math.round((aiAnalysis.ai_risk_score - 50) * 0.4);
      if (aiBoost > 0 && score < aiAnalysis.ai_risk_score) {
        score += aiBoost;
      }
    }

    // Override: if final domain is whitelisted, nullify heuristic false positives
    if (isOriginalTrusted && isFinalTrusted) {
      score = 0;
      indicators.length = 0;
    } else if (isFinalTrusted && score > 0 && !threatFeed && !typosquat.isSpoof) {
      // Landing page is trusted but origin had some flags (e.g., redirector service)
      score = Math.min(score, 15); // Cap at low suspicious
      while (indicators.length > 1) indicators.pop();
    }

    score = Math.min(Math.round(score), 100);
    const verdict = score >= 60 ? 'MALICIOUS' : (score >= 30 ? 'SUSPICIOUS' : 'SAFE');

    const isSpoofed = (!isOriginalTrusted && typosquat.isSpoof) ||
      (!isFinalTrusted && finalTyposquat.isSpoof) ||
      !!threatFeed ||
      (aiAnalysis?.impersonation?.detected === true && aiAnalysis?.ai_risk_score > 50);

    const spoofInfo = {
      isSpoof: isSpoofed,
      reason: typosquat.isSpoof && !isOriginalTrusted
        ? typosquat.reason
        : (finalTyposquat.isSpoof && !isFinalTrusted
          ? finalTyposquat.reason
          : (threatFeed
            ? `Threat Intel: Spoofing "${threatFeed.brand}" brand`
            : (aiAnalysis?.impersonation?.detected
              ? `AI detected impersonation of "${aiAnalysis.impersonation.targetBrand}"`
              : '')))
    };

    res.json({
      success: true,
      url,
      domainInfo,
      redirectChain,
      finalUrl,
      finalDomainInfo,
      isOriginalTrusted,
      isFinalTrusted,
      typosquat: spoofInfo,
      pageAnalysis: {
        hasPasswordInput: pageAnalysis.hasPasswordInput,
        hasLoginForm: pageAnalysis.hasLoginForm,
        brandKeywords: pageAnalysis.brandKeywords,
        formCount: pageAnalysis.formCount
      },
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

// ===== Route: Analyze Email =====
app.post('/api/analyze-email', async (req, res) => {
  const { rawEmail, apiKey } = req.body;
  if (!rawEmail) {
    return res.status(400).json({ error: 'Email content is required' });
  }

  try {
    const emailData = parseRawEmail(rawEmail);
    const headers = emailData.headers;
    const body = emailData.body;

    const fromHeader = headers['from'] || '';
    const fromAddr = extractEmailAddress(fromHeader);
    const fromInfo = extractDomainInfo(fromAddr);

    // DNS authentication checks
    let dnsCheck = null;
    if (fromInfo.domain) {
      dnsCheck = await verifyDomainDNS(fromInfo.domain);
    }

    // Extract and analyze links inside the body
    const links = extractAndAnalyzeLinks(body, fromInfo.domain);

    // Build context string for AI
    const contextStr = [
      `From: ${fromHeader}`,
      `From Address: ${fromAddr}`,
      `From Domain: ${fromInfo.domain}`,
      `Subject: ${headers['subject'] || 'No Subject'}`,
      `Reply-To: ${headers['reply-to'] || 'None'}`,
      `Return-Path: ${headers['return-path'] || 'None'}`,
      `X-Mailer: ${headers['x-mailer'] || 'Unknown'}`,
      `SPF Check: ${dnsCheck ? (dnsCheck.spf.found ? `PASS (${dnsCheck.spf.status})` : 'FAIL - No SPF record') : 'Not checked'}`,
      `DMARC Check: ${dnsCheck ? (dnsCheck.dmarc.found ? `PASS (policy: ${dnsCheck.dmarc.policy})` : 'FAIL - No DMARC record') : 'Not checked'}`,
      `Links Found: ${links.length} (${links.filter(l => l.misleading).length} misleading, ${links.filter(l => l.typosquat?.isSpoof).length} typosquatting)`,
      `Body Content:\n${body}`
    ].join('\n');

    let aiAnalysis;
    let isSimulated = false;

    try {
      aiAnalysis = await runGeminiAnalysis(contextStr, true, apiKey);
      console.log(`Gemini email analysis: verdict=${aiAnalysis.overall_verdict}, score=${aiAnalysis.ai_risk_score}`);
    } catch (e) {
      console.warn('Gemini email analysis failed, using local heuristics:', e.message);
      aiAnalysis = runLocalHeuristicAnalysis(contextStr, true, headers);
      isSimulated = true;
    }

    // Risk scoring
    let score = 0;
    const indicators = [];

    const replyTo = extractEmailAddress(headers['reply-to'] || '');
    const returnPath = extractEmailAddress(headers['return-path'] || '');

    // Header mismatch checks
    if (replyTo && fromInfo.domain) {
      const replyToInfo = extractDomainInfo(replyTo);
      if (replyToInfo.domain && fromInfo.domain !== replyToInfo.domain) {
        indicators.push({
          title: 'Reply-To Address Mismatch',
          description: `Replies route to "${replyTo}" (domain: ${replyToInfo.domain}), but the visible sender is "${fromInfo.domain}". This header manipulation is a classic phishing tactic to capture reply data.`,
          category: 'headers',
          severity: 'high',
          weight: 30
        });
        score += 30;
      }
    }

    if (returnPath && fromInfo.domain) {
      const returnPathInfo = extractDomainInfo(returnPath);
      if (returnPathInfo.domain && fromInfo.domain !== returnPathInfo.domain) {
        indicators.push({
          title: 'Return-Path Domain Mismatch',
          description: `Bounce-back messages route to "${returnPath}" (domain: ${returnPathInfo.domain}) instead of the visible sender domain "${fromInfo.domain}". This suggests the email infrastructure is controlled by a third party.`,
          category: 'headers',
          severity: 'medium',
          weight: 20
        });
        score += 20;
      }
    }

    // DNS authentication failures
    if (dnsCheck) {
      if (!dnsCheck.spf.found) {
        indicators.push({
          title: 'Missing SPF Record',
          description: `The sender domain "${fromInfo.domain}" has no SPF record. Without SPF, any server can forge emails from this domain and mail servers cannot verify authenticity.`,
          category: 'authentication',
          severity: 'medium',
          weight: 20
        });
        score += 20;
      }
      if (!dnsCheck.dmarc.found) {
        indicators.push({
          title: 'Missing DMARC Policy',
          description: `"${fromInfo.domain}" publishes no DMARC record. DMARC tells receiving servers how to handle forged emails. Without it, spoofed emails pass freely.`,
          category: 'authentication',
          severity: 'medium',
          weight: 20
        });
        score += 20;
      } else if (dnsCheck.dmarc.policy === 'none') {
        indicators.push({
          title: 'Weak DMARC Policy (None)',
          description: `DMARC policy is set to "none" — emails will not be rejected even if they fail authentication checks. This provides minimal protection.`,
          category: 'authentication',
          severity: 'low',
          weight: 10
        });
        score += 10;
      }
    }

    // Link analysis
    const misleadingLinks = links.filter(l => l.misleading);
    if (misleadingLinks.length > 0) {
      indicators.push({
        title: 'Deceptive Hyperlinks Detected',
        description: `Found ${misleadingLinks.length} link(s) where the visible text shows one domain but the actual destination is different. Example: Appears to link to "${misleadingLinks[0].anchorText}" but goes to "${misleadingLinks[0].href}".`,
        category: 'links',
        severity: 'high',
        weight: 35
      });
      score += 35;
    }

    const typosquatLinks = links.filter(l => l.typosquat?.isSpoof);
    if (typosquatLinks.length > 0) {
      indicators.push({
        title: 'Typosquatted Domain in Links',
        description: `${typosquatLinks.length} link(s) point to domains that impersonate well-known brands through typosquatting (e.g., slight misspellings or added words).`,
        category: 'links',
        severity: 'high',
        weight: 40
      });
      score += 40;
    }

    const highRiskTldLinks = links.filter(l => l.highRiskTld);
    if (highRiskTldLinks.length > 0) {
      const tlds = [...new Set(highRiskTldLinks.map(l => l.tld))].join(', ');
      indicators.push({
        title: 'High-Risk TLD Links',
        description: `Email contains ${highRiskTldLinks.length} link(s) using high-risk TLDs (${tlds}) which are frequently registered for phishing and spam operations.`,
        category: 'links',
        severity: 'medium',
        weight: 20
      });
      score += 20;
    }

    // AI behavioral indicators
    if (aiAnalysis.urgency && aiAnalysis.urgency.score >= 5) {
      indicators.push({
        title: 'Urgent/Threatening Language (AI)',
        description: aiAnalysis.urgency.explanation,
        category: 'behavioral',
        severity: aiAnalysis.urgency.score >= 8 ? 'high' : 'medium',
        weight: Math.round(aiAnalysis.urgency.score * 2)
      });
      score += Math.round(aiAnalysis.urgency.score * 2);
    }

    if (aiAnalysis.impersonation && aiAnalysis.impersonation.detected) {
      indicators.push({
        title: `Brand Impersonation: ${aiAnalysis.impersonation.targetBrand} (AI)`,
        description: aiAnalysis.impersonation.explanation,
        category: 'behavioral',
        severity: 'high',
        weight: 35
      });
      score += 35;
    }

    if (aiAnalysis.lures && aiAnalysis.lures.types && aiAnalysis.lures.types.length > 0) {
      indicators.push({
        title: 'Psychological Manipulation Tactics (AI)',
        description: `${aiAnalysis.lures.explanation} Lure types: ${aiAnalysis.lures.types.join(', ')}.`,
        category: 'behavioral',
        severity: 'medium',
        weight: 15
      });
      score += 15;
    }

    // AI score boost
    if (aiAnalysis.ai_risk_score > 50 && score < aiAnalysis.ai_risk_score) {
      const boost = Math.round((aiAnalysis.ai_risk_score - score) * 0.3);
      score += boost;
    }

    score = Math.min(Math.round(score), 100);
    const verdict = score >= 60 ? 'MALICIOUS' : (score >= 30 ? 'SUSPICIOUS' : 'SAFE');

    res.json({
      success: true,
      headersParsed: headers,
      fromInfo,
      dnsCheck,
      linksAnalyzed: links,
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

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start Server
app.listen(PORT, () => {
  console.log('====================================================');
  console.log(`  Akhil PhishGuard Backend running on port ${PORT}`);
  console.log('====================================================');
});
