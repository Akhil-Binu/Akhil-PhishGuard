console.log('🧪 Testing Microlink Screenshot API...');

const url = 'https://www.google.com';
const screenshotApiUrl = `https://api.microlink.io?url=${encodeURIComponent(url)}&screenshot=true&embed=screenshot.url`;

try {
  console.log(`Fetching screenshot directly from: ${screenshotApiUrl}`);
  const response = await fetch(screenshotApiUrl);
  
  if (response.ok) {
    const buffer = await response.arrayBuffer();
    const base64Image = Buffer.from(buffer).toString('base64');
    console.log('🎉 SUCCESS!');
    console.log(`- Content Type: ${response.headers.get('content-type')}`);
    console.log(`- Base64 Length: ${base64Image.length}`);
    console.log(`- Sample: ${base64Image.substring(0, 50)}...`);
    process.exit(0);
  } else {
    console.error(`❌ FAIL: API returned status ${response.status}`);
    process.exit(1);
  }
} catch (e) {
  console.error(`❌ FAIL: Exception occurred: ${e.message}`);
  process.exit(1);
}
