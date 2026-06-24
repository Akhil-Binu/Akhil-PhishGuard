import { extractDomainInfo, analyzeHtmlContent } from './utils.js';

console.log('🧪 Integration check: Validating live fiverr phishing URL...');

const url = 'https://flickshoot.com/project/vano';
const domainInfo = extractDomainInfo(url);

try {
  const pageRes = await fetch(url, {
    method: 'GET',
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
  });
  
  if (pageRes.ok) {
    const html = await pageRes.text();
    const pageAnalysis = analyzeHtmlContent(html, domainInfo.domain);
    
    console.log('\nHTML Scanner Diagnostics:');
    console.log(`- Resolved Domain: ${domainInfo.domain}`);
    console.log(`- Password/Credential Form Detected: ${pageAnalysis.hasPasswordInput}`);
    console.log(`- Brand Keywords Extracted: ${JSON.stringify(pageAnalysis.keywordsFound)}`);
    
    const isPhishingDetected = pageAnalysis.hasPasswordInput && pageAnalysis.keywordsFound.includes('fiverr');
    console.log(`- Fiverr Phishing Flagged: ${isPhishingDetected}`);
    
    if (isPhishingDetected) {
      console.log('\n🎉 PASS: Phishing signatures discovered successfully!');
      process.exit(0);
    } else {
      console.error('\n❌ FAIL: Phishing signatures were not detected.');
      process.exit(1);
    }
  } else {
    console.error(`\n❌ FAIL: Live page HTTP request failed with status ${pageRes.status}`);
    process.exit(1);
  }
} catch (e) {
  console.error(`\n❌ FAIL: Network or analysis exception: ${e.message}`);
  process.exit(1);
}
