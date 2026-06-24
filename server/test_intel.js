console.log('🧪 Integration check: Validating URL analysis endpoint for Fiverr Phishing...');

try {
  const response = await fetch('http://localhost:5000/api/analyze-url', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'https://flickshoot.com/project/vano' })
  });
  
  if (response.ok) {
    const data = await response.json();
    console.log('\nResponse Diagnostics:');
    console.log(`- Status: SUCCESS`);
    console.log(`- Verdict: ${data.verdict}`);
    console.log(`- Aggregated Risk Score: ${data.score}`);
    console.log(`- Indicators Found: ${JSON.stringify(data.indicators.map(i => i.title))}`);
    console.log(`- AI Urgency Rating: ${data.aiAnalysis?.urgency?.score}/10`);
    console.log(`- AI Impersonation Brand: ${data.aiAnalysis?.impersonation?.targetBrand}`);
    console.log(`- AI Impersonation Flagged: ${data.aiAnalysis?.impersonation?.detected}`);
    
    if (data.verdict === 'MALICIOUS' && data.score >= 90) {
      console.log('\n🎉 PASS: Phishing URL correctly discovered and scored by API server!');
      process.exit(0);
    } else {
      console.error('\n❌ FAIL: Score is too low or verdict is incorrect.');
      process.exit(1);
    }
  } else {
    console.error(`\n❌ FAIL: API server returned HTTP status ${response.status}`);
    process.exit(1);
  }
} catch (e) {
  console.error(`\n❌ FAIL: Request exception: ${e.message}`);
  process.exit(1);
}
