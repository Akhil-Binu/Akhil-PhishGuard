import dns from 'dns';
import { promisify } from 'util';

const resolveTxtAsync = promisify(dns.resolveTxt);

const POPULAR_DOMAINS = [
  'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com', 
  'linkedin.com', 'apple.com', 'microsoft.com', 'amazon.com', 'netflix.com', 
  'paypal.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com', 
  'yahoo.com', 'gmail.com', 'outlook.com', 'zoom.us', 'salesforce.com', 
  'github.com', 'adobe.com', 'spotify.com', 'ebay.com', 'walmart.com', 'chase.com'
];

const HIGH_RISK_TLDS = new Set([
  '.xyz', '.top', '.club', '.work', '.ru', '.cc', '.cn', '.fit', '.gq', '.tk', 
  '.ml', '.cf', '.ga', '.click', '.link', '.zip', '.mov', '.win', '.bid', '.download'
]);

// Compute Levenshtein distance between two strings
function levenshteinDistance(a, b) {
  const tmp = [];
  let i, j, alen = a.length, blen = b.length;
  if (alen === 0) return blen;
  if (blen === 0) return alen;
  for (i = 0; i <= alen; i++) tmp[i] = [i];
  for (j = 0; j <= blen; j++) tmp[0][j] = j;
  for (i = 1; i <= alen; i++) {
    for (j = 1; j <= blen; j++) {
      tmp[i][j] = Math.min(
        tmp[i - 1][j] + 1,
        tmp[i][j - 1] + 1,
        tmp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return tmp[alen][blen];
}

// Helper to extract domain and TLD from URL
export function extractDomainInfo(urlStr) {
  try {
    // Add protocol if missing
    let formattedUrl = urlStr.trim();
    if (!/^https?:\/\//i.test(formattedUrl)) {
      formattedUrl = 'http://' + formattedUrl;
    }
    const parsed = new URL(formattedUrl);
    const hostname = parsed.hostname.toLowerCase();
    
    // Extract main domain (e.g., mail.google.com -> google.com)
    const parts = hostname.split('.');
    let domain = hostname;
    let tld = '';
    
    if (parts.length >= 2) {
      tld = '.' + parts[parts.length - 1];
      // Check for double TLDs like .co.uk
      if (parts.length >= 3 && (parts[parts.length - 2] === 'co' || parts[parts.length - 2] === 'com' || parts[parts.length - 2] === 'org' || parts[parts.length - 2] === 'net')) {
        domain = parts.slice(-3).join('.');
        tld = '.' + parts.slice(-2).join('.');
      } else {
        domain = parts.slice(-2).join('.');
      }
    }
    
    return {
      hostname,
      domain,
      tld,
      path: parsed.pathname + parsed.search,
      protocol: parsed.protocol
    };
  } catch (e) {
    return { hostname: '', domain: '', tld: '', path: '', protocol: '', error: true };
  }
}

// Typosquatting and Brand impersonation check
export function checkTyposquatting(domain) {
  if (!domain) return { isSpoof: false };
  
  const domainLower = domain.toLowerCase();
  
  // Check if it's directly one of the popular domains
  if (POPULAR_DOMAINS.includes(domainLower)) {
    return { isSpoof: false, matchedBrand: domainLower, exact: true };
  }
  
  // Check if it contains a brand domain but with extra characters
  for (const brand of POPULAR_DOMAINS) {
    const brandName = brand.split('.')[0];
    
    // If it contains the brand name and isn't the brand domain itself
    if (domainLower.includes(brandName)) {
      // Exclude cases like "chase" in "chasebank" if they are safe, but in security context,
      // "paypal-security-update.com" contains "paypal" and is suspicious.
      // So if it contains the brand name, but the domain isn't exactly the brand, we flag it.
      return {
        isSpoof: true,
        matchedBrand: brand,
        reason: `Contains brand name "${brandName}" in domain "${domainLower}"`
      };
    }
    
    // Calculate Levenshtein distance on the domain name part
    const inputBrandName = domainLower.split('.')[0];
    const dist = levenshteinDistance(inputBrandName, brandName);
    
    if (dist > 0 && dist <= 2) {
      return {
        isSpoof: true,
        matchedBrand: brand,
        reason: `Looks very similar to "${brand}" (Levenshtein distance: ${dist})`
      };
    }
  }
  
  return { isSpoof: false };
}

// Trace URL redirects
export async function traceRedirects(startUrl, maxRedirects = 5) {
  let currentUrl = startUrl.trim();
  if (!/^https?:\/\//i.test(currentUrl)) {
    currentUrl = 'http://' + currentUrl;
  }
  
  const chain = [];
  let redirectsCount = 0;
  
  while (redirectsCount < maxRedirects) {
    try {
      chain.push({ url: currentUrl, status: 200 }); // Default, updated on next step
      
      const response = await fetch(currentUrl, {
        method: 'GET',
        redirect: 'manual', // Do not automatically follow
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
      });
      
      chain[chain.length - 1].status = response.status;
      
      // If redirect status (300-399)
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (!location) {
          break; // Redirect without location header
        }
        
        // Handle relative URLs
        let nextUrl = location;
        if (!/^https?:\/\//i.test(location)) {
          const origin = new URL(currentUrl).origin;
          nextUrl = new URL(location, origin).href;
        }
        
        currentUrl = nextUrl;
        redirectsCount++;
      } else {
        break; // Reached final URL
      }
    } catch (error) {
      chain[chain.length - 1].status = 'Error / Blocked';
      chain[chain.length - 1].error = error.message;
      break;
    }
  }
  
  return chain;
}

// Parse Raw Email Headers & Body
export function parseRawEmail(rawText) {
  if (!rawText) return null;
  
  const lines = rawText.split(/\r?\n/);
  const headers = {};
  let bodyLines = [];
  let isHeaderSection = true;
  let currentHeaderKey = null;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    
    if (isHeaderSection) {
      if (line.trim() === '') {
        isHeaderSection = false;
        continue;
      }
      
      // Header continuation line (starts with space or tab)
      if (/^\s/.test(line) && currentHeaderKey) {
        headers[currentHeaderKey] += ' ' + line.trim();
      } else {
        const match = line.match(/^([A-Za-z0-9-]+):\s*(.*)$/);
        if (match) {
          currentHeaderKey = match[1].toLowerCase();
          headers[currentHeaderKey] = match[2].trim();
        } else {
          // If we encounter a line that doesn't look like a header in the header section
          // it might be a body without empty line separator.
          isHeaderSection = false;
          bodyLines.push(line);
        }
      }
    } else {
      bodyLines.push(line);
    }
  }
  
  const body = bodyLines.join('\n');
  return { headers, body };
}

// Extracts emails from headers like "John Doe <john@example.com>"
export function extractEmailAddress(headerValue) {
  if (!headerValue) return '';
  const match = headerValue.match(/<([^>]+)>/) || headerValue.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  return match ? match[1].trim().toLowerCase() : headerValue.trim().toLowerCase();
}

// DNS lookup for SPF/DMARC TXT records
export async function verifyDomainDNS(domain) {
  const result = {
    spf: { found: false, record: '', status: 'missing' },
    dmarc: { found: false, record: '', status: 'missing' }
  };
  
  if (!domain) return result;
  
  try {
    // Lookup SPF record
    const txtRecords = await resolveTxtAsync(domain).catch(() => []);
    for (const recordArray of txtRecords) {
      const record = recordArray.join('');
      if (record.startsWith('v=spf1')) {
        result.spf.found = true;
        result.spf.record = record;
        result.spf.status = 'valid'; // Simplistic status
        break;
      }
    }
    
    // Lookup DMARC record
    const dmarcRecords = await resolveTxtAsync(`_dmarc.${domain}`).catch(() => []);
    for (const recordArray of dmarcRecords) {
      const record = recordArray.join('');
      if (record.startsWith('v=DMARC1')) {
        result.dmarc.found = true;
        result.dmarc.record = record;
        result.dmarc.status = 'valid';
        break;
      }
    }
  } catch (error) {
    // DNS resolution failure (domain might not exist or network issue)
  }
  
  return result;
}

// Extract links from HTML/Text body and analyze them
export function extractAndAnalyzeLinks(body, senderDomain) {
  const links = [];
  
  // HTML Link regex: <a href="url">text</a>
  const htmlLinkRegex = /<a\s+(?:[^>]*?\s+)?href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let match;
  
  const seenUrls = new Set();
  
  while ((match = htmlLinkRegex.exec(body)) !== null) {
    const href = match[1].trim();
    const anchorText = match[2].replace(/<[^>]+>/g, '').trim(); // Strip internal HTML tags
    seenUrls.add(href);
    
    links.push({
      href,
      anchorText,
      isHtml: true
    });
  }
  
  // Plain text URL regex
  const textUrlRegex = /https?:\/\/[^\s<>'"]+/gi;
  while ((match = textUrlRegex.exec(body)) !== null) {
    const url = match[0].trim();
    if (!seenUrls.has(url)) {
      links.push({
        href: url,
        anchorText: url,
        isHtml: false
      });
      seenUrls.add(url);
    }
  }
  
  // Analyze links
  const analyzedLinks = links.map(link => {
    const hrefInfo = extractDomainInfo(link.href);
    let misleading = false;
    let explanation = '';
    
    // Check if the anchor text itself looks like a URL but points to a different domain
    if (/^https?:\/\//i.test(link.anchorText) || link.anchorText.includes('.')) {
      const anchorInfo = extractDomainInfo(link.anchorText);
      if (anchorInfo.domain && hrefInfo.domain && anchorInfo.domain !== hrefInfo.domain) {
        misleading = true;
        explanation = `Anchor text displays "${anchorInfo.domain}" but link goes to "${hrefInfo.domain}"`;
      }
    }
    
    // Check typosquatting on the destination domain
    const typoCheck = checkTyposquatting(hrefInfo.domain);
    const highRiskTld = HIGH_RISK_TLDS.has(hrefInfo.tld);
    
    return {
      ...link,
      domain: hrefInfo.domain,
      tld: hrefInfo.tld,
      misleading,
      explanation,
      typosquat: typoCheck,
      highRiskTld
    };
  });
  
  return analyzedLinks;
}

// Local rules-based heuristic scoring engine (Fallback for Gemini AI)
export function runLocalHeuristicAnalysis(text, isEmail = true, parsedHeaders = null) {
  const alerts = [];
  let score = 0;
  
  // Combine body and subject/from/reply-to headers if available for keyword scans
  let scanText = text || '';
  if (parsedHeaders) {
    if (parsedHeaders.subject) scanText += ' ' + parsedHeaders.subject;
    if (parsedHeaders.from) scanText += ' ' + parsedHeaders.from;
    if (parsedHeaders['reply-to']) scanText += ' ' + parsedHeaders['reply-to'];
  }
  const textLower = scanText.toLowerCase();
  
  // Urgency detection
  const urgencyKeywords = [
    'immediate', 'suspend', 'disabled', 'unauthorized', 
    'verify', 'locked', 'urgent', '24 hours', 'action required',
    'close your', 'security alert', 'compromised', 'expire'
  ];
  let urgencyHits = 0;
  urgencyKeywords.forEach(kw => {
    if (textLower.includes(kw)) urgencyHits++;
  });
  
  const urgencyScore = Math.min(urgencyHits * 2, 10);
  if (urgencyScore >= 4) {
    alerts.push({
      category: 'urgency',
      title: 'Urgent Tone Detected',
      description: `Found several urgency-inducing keywords. Phishing emails frequently pressure victims to act quickly.`,
      severity: urgencyScore >= 7 ? 'high' : 'medium',
      weight: urgencyScore * 2
    });
    score += urgencyScore * 2;
  }
  
  // Impersonation detection
  let impersonationBrand = null;
  const brandKeywords = {
    'netflix': ['netflix'],
    'paypal': ['paypal'],
    'chase': ['chase bank', 'chase online', 'chase'],
    'microsoft': ['microsoft', 'office 365', 'outlook'],
    'bank of america': ['bank of america', 'bofa'],
    'amazon': ['amazon support', 'amazon prime', 'amazon']
  };
  
  for (const [brand, kws] of Object.entries(brandKeywords)) {
    if (kws.some(kw => textLower.includes(kw))) {
      impersonationBrand = brand;
      break;
    }
  }
  
  // Lures detection
  const lureTypes = [];
  if (urgencyScore > 0) lureTypes.push('urgency');
  if (textLower.includes('reward') || textLower.includes('prize') || textLower.includes('refund') || textLower.includes('invoice')) {
    lureTypes.push('financial/greed');
    alerts.push({
      category: 'lure',
      title: 'Financial Lure Detected',
      description: 'Mentions rewards, prizes, refunds, or unexpected invoices, which are standard hooks to steal credentials or install malware.',
      severity: 'medium',
      weight: 15
    });
    score += 15;
  }
  
  // Header anomalies (if email and headers are parsed)
  if (isEmail && parsedHeaders) {
    const fromAddr = extractEmailAddress(parsedHeaders['from'] || '');
    const replyToAddr = extractEmailAddress(parsedHeaders['reply-to'] || '');
    const returnPathAddr = extractEmailAddress(parsedHeaders['return-path'] || '');
    
    const fromInfo = extractDomainInfo(fromAddr);
    const replyToInfo = extractDomainInfo(replyToAddr);
    const returnPathInfo = extractDomainInfo(returnPathAddr);
    
    if (replyToAddr && fromInfo.domain && replyToInfo.domain && fromInfo.domain !== replyToInfo.domain) {
      alerts.push({
        category: 'header',
        title: 'Reply-To Address Mismatch',
        description: `Replies are routed to "${replyToAddr}" instead of sender domain "${fromInfo.domain}". This is highly indicative of spoofing.`,
        severity: 'high',
        weight: 25
      });
      score += 25;
    }
    
    if (returnPathAddr && fromInfo.domain && returnPathInfo.domain && fromInfo.domain !== returnPathInfo.domain) {
      alerts.push({
        category: 'header',
        title: 'Return-Path Domain Mismatch',
        description: `Bounces will be sent to "${returnPathAddr}" rather than the sender's apparent domain "${fromInfo.domain}".`,
        severity: 'medium',
        weight: 15
      });
      score += 15;
    }
    
    // Check if brand mentioned in body matches from domain
    if (impersonationBrand && fromInfo.domain) {
      const cleanBrandDomain = impersonationBrand.replace(/\s+/g, '') + '.com';
      if (!fromInfo.domain.includes(impersonationBrand.replace(/\s+/g, ''))) {
        alerts.push({
          category: 'impersonation',
          title: 'Brand Impersonation Detected',
          description: `The email body references "${impersonationBrand}", but the sender domain is "${fromInfo.domain}".`,
          severity: 'high',
          weight: 30
        });
        score += 30;
      }
    }
  }
  
  // Cap score to 100
  score = Math.min(score, 100);
  
  return {
    urgency: {
      score: urgencyScore,
      explanation: urgencyScore > 0 ? `Identified ${urgencyHits} urgent phrases in text.` : 'No critical urgency cues found.'
    },
    impersonation: {
      detected: !!impersonationBrand,
      targetBrand: impersonationBrand || 'None',
      explanation: impersonationBrand 
        ? `Linguistic cues suggest impersonation of ${impersonationBrand}.`
        : 'No specific brand impersonation detected in body text.'
    },
    lures: {
      types: lureTypes,
      explanation: lureTypes.length > 0 ? `Psychological triggers identified: ${lureTypes.join(', ')}.` : 'No classic psychological triggers detected.'
    },
    suspicious_phrases: urgencyKeywords
      .filter(kw => textLower.includes(kw))
      .map(kw => ({ phrase: kw, category: 'urgency' })),
    overall_verdict: score >= 60 ? 'MALICIOUS' : (score >= 30 ? 'SUSPICIOUS' : 'SAFE'),
    ai_risk_score: score,
    summary: score >= 60 
      ? 'Heuristic analysis flags this content as highly suspicious with multiple indicators of phishing.'
      : (score >= 30 ? 'Content contains some warning signs but no definitive proof of phishing.' : 'No major indicators of phishing detected.'),
    alerts
  };
}
