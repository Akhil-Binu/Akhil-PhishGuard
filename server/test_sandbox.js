import {
  extractDomainInfo,
  checkTyposquatting,
  parseRawEmail,
  extractEmailAddress,
  runLocalHeuristicAnalysis
} from './utils.js';

console.log('🧪 Starting Akhil PhishGuard Unit Verification Tests...\n');

let failedTests = 0;
let passedTests = 0;

function assert(condition, message) {
  if (condition) {
    console.log(` ✅ PASS: ${message}`);
    passedTests++;
  } else {
    console.error(` ❌ FAIL: ${message}`);
    failedTests++;
  }
}

// Test 1: URL domain extraction
try {
  const info1 = extractDomainInfo('https://mail.google.com/mail/u/0/');
  assert(info1.hostname === 'mail.google.com', 'Hostname extraction matches');
  assert(info1.domain === 'google.com', 'Main domain resolution matches');
  assert(info1.tld === '.com', 'TLD resolution matches');
  assert(info1.protocol === 'https:', 'Protocol matches');

  const info2 = extractDomainInfo('http://paypa1-security-check.com');
  assert(info2.domain === 'paypa1-security-check.com', 'Complex domain resolution matches');
  assert(info2.protocol === 'http:', 'Insecure protocol matches');
} catch (e) {
  console.error('Test 1 crashed:', e);
  failedTests++;
}

// Test 2: Typosquatting matching
try {
  const squat1 = checkTyposquatting('paypa1.com');
  assert(squat1.isSpoof === true, 'paypa1.com correctly flagged as typosquat spoof');
  
  const squat2 = checkTyposquatting('paypal-security-update.com');
  assert(squat2.isSpoof === true, 'paypal-security-update.com flagged as containing brand name');
  assert(squat2.matchedBrand === 'paypal.com', 'Identified paypal.com as target brand');

  const squat3 = checkTyposquatting('google.com');
  assert(squat3.isSpoof === false, 'google.com is not flagged as spoof');
} catch (e) {
  console.error('Test 2 crashed:', e);
  failedTests++;
}

// Test 3: Email parsing
try {
  const rawEmail = `From: Test Sender <sender@phish-domain.com>
Reply-To: actual-hacker@gmail.com
Subject: Test phishing alert
Return-Path: bounce@attacker.net

Dear customer,
We need you to click this link: http://netflix-billing-portal.xyz/login`;

  const parsed = parseRawEmail(rawEmail);
  assert(parsed.headers['from'] === 'Test Sender <sender@phish-domain.com>', 'From header extracted');
  assert(parsed.headers['reply-to'] === 'actual-hacker@gmail.com', 'Reply-To header extracted');
  assert(parsed.headers['subject'] === 'Test phishing alert', 'Subject header extracted');
  
  const fromAddr = extractEmailAddress(parsed.headers['from']);
  assert(fromAddr === 'sender@phish-domain.com', 'From email address extracted correctly');
} catch (e) {
  console.error('Test 3 crashed:', e);
  failedTests++;
}

// Test 4: Local heuristic scoring engine
try {
  const parsedEmail = parseRawEmail(`From: Netflix Billing <support@netfllx-billing-update.com>
Subject: Action Required: Your Netflix subscription is about to be suspended
Reply-To: netflixsupport-billing@gmail.com
Return-Path: bouncing-system@netfllx-billing-update.com

Dear Customer,
We were unable to process your payment. Update your credit card details immediately within 24 hours.`);

  const analysis = runLocalHeuristicAnalysis(parsedEmail.body, true, parsedEmail.headers);
  assert(analysis.urgency.score >= 5, 'Urgent tone correctly detected in body');
  assert(analysis.impersonation.detected === true, 'Netflix brand impersonation detected');
  assert(analysis.impersonation.targetBrand === 'netflix', 'Impersonation correctly targets netflix');
  assert(analysis.ai_risk_score >= 60, 'Scoring engine outputs Malicious rating (>60)');
} catch (e) {
  console.error('Test 4 crashed:', e);
  failedTests++;
}

console.log(`\n📊 Verification Summary: Passed: ${passedTests}, Failed: ${failedTests}`);
if (failedTests > 0) {
  process.exit(1);
} else {
  console.log(' 🎉 All unit verification tests completed successfully!');
  process.exit(0);
}
