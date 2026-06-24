console.log('🧪 Integration check: Validating whitelist rules for Flipkart...');

try {
  const response = await fetch('http://localhost:5000/api/analyze-url', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'http://flipkart.com' })
  });
  
  if (response.ok) {
    const data = await response.json();
    console.log('\nResponse Diagnostics:');
    console.log(`- Verdict: ${data.verdict}`);
    console.log(`- Aggregated Risk Score: ${data.score}`);
    console.log(`- Indicators Found: ${JSON.stringify(data.indicators)}`);
    console.log(`- Redirection Hops: ${data.redirectChain.length}`);
    
    if (data.verdict === 'SAFE' && data.score === 0) {
      console.log('\n🎉 PASS: Whitelist override correctly flags Flipkart as SAFE (score 0)!');
      process.exit(0);
    } else {
      console.error('\n❌ FAIL: Incorrect verdict or score.');
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
