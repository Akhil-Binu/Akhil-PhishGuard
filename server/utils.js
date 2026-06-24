import dns from 'dns';
import { promisify } from 'util';

const resolveTxtAsync = promisify(dns.resolveTxt);

// === TRUSTED BRAND DATABASE ===
// Maps brand name -> list of ALL legitimate domains for that brand
const TRUSTED_BRAND_DOMAINS = {
  google: ['google.com', 'google.co.in', 'google.co.uk', 'google.com.au', 'google.de', 'google.fr', 'google.co.jp', 'googleapis.com', 'gstatic.com', 'googlevideo.com'],
  youtube: ['youtube.com', 'youtu.be', 'youtube.co.in', 'youtube.co.uk'],
  facebook: ['facebook.com', 'fb.com', 'fbcdn.net', 'instagram.com'],
  twitter: ['twitter.com', 'x.com', 't.co'],
  instagram: ['instagram.com'],
  linkedin: ['linkedin.com'],
  apple: ['apple.com', 'icloud.com', 'appleid.apple.com'],
  microsoft: ['microsoft.com', 'live.com', 'hotmail.com', 'outlook.com', 'bing.com', 'azure.com', 'microsoftonline.com'],
  amazon: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.co.jp', 'amazon.com.au', 'amazonaws.com', 'amazon.ca', 'amazon.it', 'amazon.es', 'amazon.com.mx'],
  netflix: ['netflix.com', 'nflximg.net', 'nflxvideo.net'],
  paypal: ['paypal.com', 'paypal.me'],
  chase: ['chase.com', 'jpmorganchase.com'],
  bankofamerica: ['bankofamerica.com', 'bac.com'],
  wellsfargo: ['wellsfargo.com'],
  citibank: ['citibank.com', 'citi.com'],
  yahoo: ['yahoo.com', 'yahoo.co.in', 'yahoo.co.uk', 'yahoo.com.au'],
  zoom: ['zoom.us', 'zoom.com'],
  salesforce: ['salesforce.com', 'force.com'],
  github: ['github.com', 'github.io', 'githubusercontent.com'],
  adobe: ['adobe.com', 'adobelogin.com'],
  spotify: ['spotify.com', 'scdn.co'],
  ebay: ['ebay.com', 'ebay.co.uk', 'ebay.in', 'ebay.com.au'],
  walmart: ['walmart.com'],
  fiverr: ['fiverr.com', 'fiverrcdn.com'],
  flipkart: ['flipkart.com', 'flipkartimg.com', 'fkimg.com'],
  wikipedia: ['wikipedia.org', 'wikimedia.org'],
  reddit: ['reddit.com', 'redd.it', 'redditmedia.com', 'redditstatic.com'],
  stackoverflow: ['stackoverflow.com'],
  dropbox: ['dropbox.com'],
  discord: ['discord.com', 'discord.gg', 'discordapp.com'],
  whatsapp: ['whatsapp.com', 'web.whatsapp.com'],
  telegram: ['telegram.org', 't.me'],
  twitch: ['twitch.tv'],
  steam: ['steampowered.com', 'steamcommunity.com'],
  nvidia: ['nvidia.com'],
  intel: ['intel.com'],
  amd: ['amd.com'],
  myntra: ['myntra.com'],
  samsung: ['samsung.com'],
  sony: ['sony.com'],
  apple: ['apple.com'],
  hp: ['hp.com', 'hpe.com'],
  dell: ['dell.com'],
  lenovo: ['lenovo.com'],
  tcs: ['tcs.com'],
  infosys: ['infosys.com'],
  wipro: ['wipro.com'],
  sbi: ['sbi.co.in', 'onlinesbi.sbi'],
  hdfc: ['hdfcbank.com', 'hdfc.com'],
  icici: ['icicibank.com'],
  axisbank: ['axisbank.com'],
  kotak: ['kotakbank.com'],
};

// Build a flat set of ALL trusted domains for O(1) lookup
const ALL_TRUSTED_DOMAINS = new Set();
const BRAND_DOMAIN_MAP = new Map(); // domain -> brand name

for (const [brand, domains] of Object.entries(TRUSTED_BRAND_DOMAINS)) {
  for (const d of domains) {
    ALL_TRUSTED_DOMAINS.add(d);
    BRAND_DOMAIN_MAP.set(d, brand);
  }
}

// Also get brand names for substring matching
const ALL_BRAND_NAMES = Object.keys(TRUSTED_BRAND_DOMAINS);

const HIGH_RISK_TLDS = new Set([
  '.xyz', '.top', '.club', '.work', '.ru', '.cc', '.cn', '.fit', '.gq', '.tk',
  '.ml', '.cf', '.ga', '.click', '.link', '.zip', '.mov', '.win', '.bid', '.download',
  '.cheap', '.online', '.site', '.website', '.space', '.host', '.store'
]);

// Compute Levenshtein distance between two strings
function levenshteinDistance(a, b) {
  if (a === b) return 0;
  const alen = a.length, blen = b.length;
  if (alen === 0) return blen;
  if (blen === 0) return alen;
  
  const tmp = [];
  for (let i = 0; i <= alen; i++) tmp[i] = [i];
  for (let j = 0; j <= blen; j++) tmp[0][j] = j;
  
  for (let i = 1; i <= alen; i++) {
    for (let j = 1; j <= blen; j++) {
      tmp[i][j] = Math.min(
        tmp[i - 1][j] + 1,
        tmp[i][j - 1] + 1,
        tmp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return tmp[alen][blen];
}

// Check if domain is a globally trusted brand domain
export function isWhitelistedDomain(domain) {
  if (!domain) return false;
  const domainLower = domain.toLowerCase().replace(/^www\./, '');
  
  // Direct match
  if (ALL_TRUSTED_DOMAINS.has(domainLower)) return true;
  
  // Check if it's a subdomain of a trusted domain
  for (const trusted of ALL_TRUSTED_DOMAINS) {
    if (domainLower.endsWith('.' + trusted)) return true;
  }
  
  return false;
}

// Helper to extract domain and TLD from URL
export function extractDomainInfo(urlStr) {
  try {
    let formattedUrl = urlStr.trim();
    if (!/^https?:\/\//i.test(formattedUrl)) {
      formattedUrl = 'http://' + formattedUrl;
    }
    const parsed = new URL(formattedUrl);
    const hostname = parsed.hostname.toLowerCase().replace(/^www\./, '');

    // Extract main domain (strip subdomains)
    const parts = hostname.split('.');
    let domain = hostname;
    let tld = '';

    if (parts.length >= 2) {
      // Handle well-known double TLDs like .co.uk, .co.in, .com.au
      const secondLast = parts[parts.length - 2];
      const last = parts[parts.length - 1];
      
      if (parts.length >= 3 && ['co', 'com', 'org', 'net', 'gov', 'edu', 'ac'].includes(secondLast)) {
        domain = parts.slice(-3).join('.');
        tld = '.' + parts.slice(-2).join('.');
      } else {
        domain = parts.slice(-2).join('.');
        tld = '.' + last;
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
// Returns: { isSpoof, matchedBrand, reason, type }
export function checkTyposquatting(domain) {
  if (!domain) return { isSpoof: false };

  const domainLower = domain.toLowerCase().replace(/^www\./, '');

  // 1. Direct trust check — if it's in our trusted list, it's NOT a spoof
  if (ALL_TRUSTED_DOMAINS.has(domainLower)) {
    return { isSpoof: false, matchedBrand: BRAND_DOMAIN_MAP.get(domainLower), exact: true };
  }
  // Also check subdomain of trusted
  for (const trusted of ALL_TRUSTED_DOMAINS) {
    if (domainLower.endsWith('.' + trusted)) {
      return { isSpoof: false, matchedBrand: BRAND_DOMAIN_MAP.get(trusted), exact: true };
    }
  }

  // Extract just the "brand part" of the domain (before TLD)
  const parts = domainLower.split('.');
  // Get the registrable domain name part (e.g., "paypal-security" from "paypal-security.com")
  let registrableName;
  if (parts.length >= 3 && ['co', 'com', 'org', 'net', 'gov', 'edu', 'ac'].includes(parts[parts.length - 2])) {
    // e.g., amazon.co.in -> brand part is "amazon"
    registrableName = parts[parts.length - 3];
  } else {
    registrableName = parts[parts.length - 2];
  }

  if (!registrableName) return { isSpoof: false };

  // 2. Check for EXACT brand name as registrable name but on a different TLD
  // e.g., "amazon.xyz", "paypal.cc" - EXACT brand name match
  for (const brand of ALL_BRAND_NAMES) {
    if (registrableName === brand) {
      // The registrable name IS exactly the brand, but on an unusual TLD
      // This is likely squatting unless it's in our trusted list (already checked above)
      return {
        isSpoof: true,
        matchedBrand: brand,
        reason: `Exact brand name "${brand}" on non-official domain "${domainLower}"`,
        type: 'brand_on_wrong_tld'
      };
    }
  }

  // 3. Check for brand name as PREFIX/SUFFIX with suspicious additions
  // e.g., "paypal-security-update.com", "amazon-support.com", "netfllx-billing.com"
  for (const brand of ALL_BRAND_NAMES) {
    if (brand.length < 4) continue; // Skip very short brand names to avoid false positives
    
    if (registrableName.includes(brand)) {
      // It contains the brand name — check for separators indicating it's a spoof
      const withoutBrand = registrableName.replace(brand, '');
      if (withoutBrand.length > 0) {
        // Has extra stuff around the brand name: suspicious
        return {
          isSpoof: true,
          matchedBrand: brand,
          reason: `Contains brand name "${brand}" with modifications: "${domainLower}"`,
          type: 'brand_with_additions'
        };
      }
    }
  }

  // 4. Levenshtein distance check for typos
  // e.g., "paypa1.com", "netlfix.com", "amazzon.com"
  for (const brand of ALL_BRAND_NAMES) {
    if (brand.length < 4) continue;
    const dist = levenshteinDistance(registrableName, brand);
    const threshold = brand.length <= 5 ? 1 : 2; // Shorter brands need tighter threshold
    if (dist > 0 && dist <= threshold) {
      return {
        isSpoof: true,
        matchedBrand: brand,
        reason: `Very similar to "${brand}" (edit distance: ${dist}) — possible typosquatting`,
        type: 'typosquat'
      };
    }
  }

  return { isSpoof: false };
}

// Trace URL redirects
export async function traceRedirects(startUrl, maxRedirects = 7) {
  let currentUrl = startUrl.trim();
  if (!/^https?:\/\//i.test(currentUrl)) {
    currentUrl = 'http://' + currentUrl;
  }

  const chain = [];
  let redirectsCount = 0;
  const seen = new Set();

  while (redirectsCount < maxRedirects) {
    if (seen.has(currentUrl)) {
      chain.push({ url: currentUrl, status: 'Loop Detected', error: 'Redirect loop' });
      break;
    }
    seen.add(currentUrl);

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);
      
      const response = await fetch(currentUrl, {
        method: 'GET',
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
        }
      });
      clearTimeout(timeoutId);

      chain.push({ url: currentUrl, status: response.status });

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (!location) break;

        let nextUrl = location;
        if (!/^https?:\/\//i.test(location)) {
          try {
            nextUrl = new URL(location, currentUrl).href;
          } catch {
            nextUrl = new URL(currentUrl).origin + '/' + location.replace(/^\//, '');
          }
        }
        currentUrl = nextUrl;
        redirectsCount++;
      } else {
        break;
      }
    } catch (error) {
      if (error.name === 'AbortError') {
        chain.push({ url: currentUrl, status: 'Timeout', error: 'Request timed out (8s)' });
      } else {
        chain.push({ url: currentUrl, status: 'Error', error: error.message });
      }
      break;
    }
  }

  if (chain.length === 0) {
    chain.push({ url: currentUrl, status: 'Unknown' });
  }

  return chain;
}

// Parse Raw Email Headers & Body
export function parseRawEmail(rawText) {
  if (!rawText) return { headers: {}, body: '' };

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

      if (/^\s/.test(line) && currentHeaderKey) {
        headers[currentHeaderKey] += ' ' + line.trim();
      } else {
        const match = line.match(/^([A-Za-z0-9-]+):\s*(.*)$/);
        if (match) {
          currentHeaderKey = match[1].toLowerCase();
          headers[currentHeaderKey] = match[2].trim();
        } else {
          isHeaderSection = false;
          bodyLines.push(line);
        }
      }
    } else {
      bodyLines.push(line);
    }
  }

  return { headers, body: bodyLines.join('\n') };
}

// Extracts email address from header like "John Doe <john@example.com>"
export function extractEmailAddress(headerValue) {
  if (!headerValue) return '';
  const match = headerValue.match(/<([^>]+)>/) || headerValue.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  return match ? match[1].trim().toLowerCase() : headerValue.trim().toLowerCase();
}

// DNS lookup for SPF/DMARC TXT records
export async function verifyDomainDNS(domain) {
  const result = {
    spf: { found: false, record: '', status: 'missing' },
    dmarc: { found: false, record: '', status: 'missing' },
    mx: { found: false, records: [] }
  };

  if (!domain) return result;

  try {
    // SPF
    const txtRecords = await resolveTxtAsync(domain).catch(() => []);
    for (const recordArray of txtRecords) {
      const record = recordArray.join('');
      if (record.startsWith('v=spf1')) {
        result.spf.found = true;
        result.spf.record = record;
        result.spf.status = record.includes('~all') ? 'softfail_policy' : record.includes('-all') ? 'strict' : 'valid';
        break;
      }
    }

    // DMARC
    const dmarcRecords = await resolveTxtAsync(`_dmarc.${domain}`).catch(() => []);
    for (const recordArray of dmarcRecords) {
      const record = recordArray.join('');
      if (record.startsWith('v=DMARC1')) {
        result.dmarc.found = true;
        result.dmarc.record = record;
        const pMatch = record.match(/p=([^;]+)/);
        result.dmarc.policy = pMatch ? pMatch[1] : 'none';
        result.dmarc.status = result.dmarc.policy === 'reject' ? 'strict' : result.dmarc.policy === 'quarantine' ? 'moderate' : 'weak';
        break;
      }
    }

    // MX records
    const mxRecords = await promisify(dns.resolveMx)(domain).catch(() => []);
    if (mxRecords.length > 0) {
      result.mx.found = true;
      result.mx.records = mxRecords.map(r => r.exchange);
    }
  } catch (error) {
    // DNS resolution failure
  }

  return result;
}

// Extract links from HTML/Text body and analyze them
export function extractAndAnalyzeLinks(body, senderDomain) {
  const links = [];
  const seenUrls = new Set();

  // HTML Link regex
  const htmlLinkRegex = /<a\s+(?:[^>]*?\s+)?href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let match;

  while ((match = htmlLinkRegex.exec(body)) !== null) {
    const href = match[1].trim();
    const anchorText = match[2].replace(/<[^>]+>/g, '').trim();
    seenUrls.add(href);
    links.push({ href, anchorText, isHtml: true });
  }

  // Plain text URL regex
  const textUrlRegex = /https?:\/\/[^\s<>'"]+/gi;
  while ((match = textUrlRegex.exec(body)) !== null) {
    const url = match[0].trim();
    if (!seenUrls.has(url)) {
      links.push({ href: url, anchorText: url, isHtml: false });
      seenUrls.add(url);
    }
  }

  return links.map(link => {
    const hrefInfo = extractDomainInfo(link.href);
    let misleading = false;
    let explanation = '';

    if (/^https?:\/\//i.test(link.anchorText) || (link.anchorText.includes('.') && link.anchorText.length < 100)) {
      const anchorInfo = extractDomainInfo(link.anchorText);
      if (anchorInfo.domain && hrefInfo.domain && anchorInfo.domain !== hrefInfo.domain) {
        misleading = true;
        explanation = `Anchor text displays "${anchorInfo.domain}" but link goes to "${hrefInfo.domain}"`;
      }
    }

    const typoCheck = checkTyposquatting(hrefInfo.domain);
    const highRiskTld = HIGH_RISK_TLDS.has(hrefInfo.tld);
    const isWhitelisted = isWhitelistedDomain(hrefInfo.domain);

    return {
      ...link,
      domain: hrefInfo.domain,
      tld: hrefInfo.tld,
      misleading: misleading && !isWhitelisted,
      explanation,
      typosquat: isWhitelisted ? { isSpoof: false } : typoCheck,
      highRiskTld
    };
  });
}

// Analyze webpage HTML structure for credential harvesting fields & keywords
export function analyzeHtmlContent(html, domain) {
  const result = {
    hasPasswordInput: false,
    hasLoginForm: false,
    hasEmailInput: false,
    keywordsFound: [],
    brandKeywords: [],
    strippedText: '',
    formCount: 0
  };

  if (!html) return result;

  const htmlLower = html.toLowerCase();

  // Check for password input elements
  if (htmlLower.includes('type="password"') || htmlLower.includes("type='password'") ||
    htmlLower.includes('name="password"') || htmlLower.includes("name='password'") ||
    htmlLower.includes('id="password"') || htmlLower.includes("id='password'")) {
    result.hasPasswordInput = true;
  }

  // Check for email inputs
  if (htmlLower.includes('type="email"') || htmlLower.includes("type='email'")) {
    result.hasEmailInput = true;
  }

  // Count forms
  const formMatches = htmlLower.match(/<form/g);
  result.formCount = formMatches ? formMatches.length : 0;

  // Login forms
  if (result.formCount > 0 && (htmlLower.includes('login') || htmlLower.includes('sign in') || htmlLower.includes('signin'))) {
    result.hasLoginForm = true;
  }

  // Check for brand and session keywords
  const brandTargets = [
    'fiverr', 'paypal', 'netflix', 'chase', 'amazon', 'microsoft', 'google',
    'apple', 'instagram', 'facebook', 'twitter', 'linkedin', 'ebay', 'walmart',
    'flipkart', 'hdfc', 'sbi', 'icici', 'axis bank', 'spotify', 'discord'
  ];

  const actionKeywords = ['login', 'sign in', 'signin', 'log in', 'password', 'authorize', 'verify your account', 'confirm your account', 'update payment'];

  brandTargets.forEach(kw => {
    if (htmlLower.includes(kw)) result.brandKeywords.push(kw);
  });
  actionKeywords.forEach(kw => {
    if (htmlLower.includes(kw)) result.keywordsFound.push(kw);
  });

  // Strip HTML for text analysis
  let text = html
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  result.strippedText = text.substring(0, 6000);
  return result;
}

// Local rules-based heuristic scoring engine (Fallback for Gemini AI)
export function runLocalHeuristicAnalysis(contextText, isEmail = true, parsedHeaders = null) {
  let score = 0;
  const alerts = [];

  let scanText = contextText || '';
  if (parsedHeaders) {
    if (parsedHeaders.subject) scanText += ' ' + parsedHeaders.subject;
    if (parsedHeaders.from) scanText += ' ' + parsedHeaders.from;
    if (parsedHeaders['reply-to']) scanText += ' ' + parsedHeaders['reply-to'];
  }
  const textLower = scanText.toLowerCase();

  // Urgency detection
  const urgencyKeywords = [
    'immediate', 'suspend', 'suspended', 'disabled', 'unauthorized',
    'verify', 'locked', 'urgent', '24 hours', '12 hours', 'action required',
    'close your', 'security alert', 'compromised', 'expire', 'immediately',
    'account will be', 'unusual activity', 'confirm your', 'restricted'
  ];
  let urgencyHits = 0;
  urgencyKeywords.forEach(kw => {
    if (textLower.includes(kw)) urgencyHits++;
  });
  const urgencyScore = Math.min(urgencyHits * 1.5, 10);

  // Impersonation detection
  let impersonationBrand = null;
  const brandKeywords = {
    'Netflix': ['netflix'],
    'PayPal': ['paypal'],
    'Chase Bank': ['chase bank', 'chase online', 'jpmorgan chase'],
    'Microsoft': ['microsoft', 'office 365', 'microsoft 365'],
    'Bank of America': ['bank of america', 'bofa'],
    'Amazon': ['amazon prime', 'amazon support', 'amazon order', 'amazon account'],
    'Fiverr': ['fiverr'],
    'Flipkart': ['flipkart'],
    'Apple': ['apple id', 'icloud'],
    'Google': ['google account', 'gmail account'],
    'HDFC Bank': ['hdfc bank', 'hdfc'],
    'SBI': ['state bank of india', 'sbi'],
    'ICICI': ['icici bank', 'icici'],
    'Myntra': ['myntra'],
  };

  for (const [brand, kws] of Object.entries(brandKeywords)) {
    if (kws.some(kw => new RegExp(`\\b${kw}\\b`, 'i').test(textLower))) {
      impersonationBrand = brand;
      break;
    }
  }

  // Lures detection
  const lureTypes = [];
  if (urgencyScore >= 4) lureTypes.push('urgency');

  let financialLure = false;
  if (textLower.includes('reward') || textLower.includes('prize') || textLower.includes('refund') ||
    textLower.includes('invoice') || textLower.includes('payment') || textLower.includes('subscription')) {
    lureTypes.push('financial');
    financialLure = true;
    score += 10;
  }

  // Header anomalies
  if (isEmail && parsedHeaders) {
    const fromAddr = extractEmailAddress(parsedHeaders['from'] || '');
    const replyToAddr = extractEmailAddress(parsedHeaders['reply-to'] || '');
    const returnPathAddr = extractEmailAddress(parsedHeaders['return-path'] || '');

    const fromInfo = extractDomainInfo(fromAddr);
    const replyToInfo = extractDomainInfo(replyToAddr);
    const returnPathInfo = extractDomainInfo(returnPathAddr);

    if (replyToAddr && fromInfo.domain && replyToInfo.domain && fromInfo.domain !== replyToInfo.domain) {
      score += 25;
    }
    if (returnPathAddr && fromInfo.domain && returnPathInfo.domain && fromInfo.domain !== returnPathInfo.domain) {
      score += 15;
    }
    if (impersonationBrand && fromInfo.domain) {
      const brandKey = impersonationBrand.toLowerCase().replace(/\s+/g, '');
      if (!fromInfo.domain.includes(brandKey.substring(0, Math.min(brandKey.length, 6)))) {
        score += 30;
      }
    }
  }

  // Add urgency to score
  if (urgencyScore >= 4) score += urgencyScore * 2;

  score = Math.min(score, 100);

  // Build suspicious phrases list
  const suspiciousPhrases = urgencyKeywords
    .filter(kw => textLower.includes(kw))
    .slice(0, 8)
    .map(kw => ({ phrase: kw, category: 'urgency' }));

  return {
    urgency: {
      score: urgencyScore,
      explanation: urgencyScore >= 4
        ? `Found ${urgencyHits} urgency-inducing keywords like "suspend", "verify", "immediate action". High-pressure tactics are a hallmark of phishing.`
        : 'No significant urgency cues found.'
    },
    impersonation: {
      detected: !!impersonationBrand,
      targetBrand: impersonationBrand || 'None',
      explanation: impersonationBrand
        ? `Linguistic cues and brand references strongly suggest impersonation of ${impersonationBrand}.`
        : 'No specific brand impersonation detected in the content.'
    },
    lures: {
      types: lureTypes,
      explanation: lureTypes.length > 0
        ? `Psychological triggers identified: ${lureTypes.join(', ')}. These manipulate victims into taking hasty action.`
        : 'No classic psychological manipulation patterns detected.'
    },
    suspicious_phrases: suspiciousPhrases,
    overall_verdict: score >= 60 ? 'MALICIOUS' : (score >= 30 ? 'SUSPICIOUS' : 'SAFE'),
    ai_risk_score: score,
    summary: score >= 60
      ? 'Local heuristic engine flags this as highly suspicious with multiple phishing indicators including urgency manipulation and potential brand impersonation.'
      : (score >= 30
        ? 'Some warning signs detected. Treat with caution and verify through official channels.'
        : 'No major phishing indicators detected. Content appears relatively normal.'),
    alerts,
    isLocalFallback: true
  };
}

// Local Threat Intelligence Database (Known Phishing Campaigns)
export function checkThreatDatabase(urlStr) {
  if (!urlStr) return null;
  const urlLower = urlStr.toLowerCase();

  const THREAT_SIGNATURE_DB = [
    {
      pattern: 'flickshoot.com/project/vano',
      brand: 'Fiverr',
      details: 'Active Fiverr credential harvesting campaign hosted on user portfolio platform flickshoot.com/project/vano. Page visually mimics Fiverr login.'
    },
    {
      pattern: 'paypal-security-check',
      brand: 'PayPal',
      details: 'PayPal account security phishing URL using brand name with "security-check" suffix.'
    },
    {
      pattern: 'netflix-billing-portal',
      brand: 'Netflix',
      details: 'Netflix billing phishing redirect portal.'
    },
    {
      pattern: 'chase-security-restore',
      brand: 'Chase',
      details: 'Chase Bank account restore phishing portal.'
    },
    {
      pattern: 'amazon-security-update',
      brand: 'Amazon',
      details: 'Amazon account security phishing update portal.'
    }
  ];

  for (const item of THREAT_SIGNATURE_DB) {
    if (urlLower.includes(item.pattern)) {
      return item;
    }
  }
  return null;
}
