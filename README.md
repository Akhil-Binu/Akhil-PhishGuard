# 🛡️ Akhil PhishGuard

> **An AI-powered phishing URL & email analyzer built for security professionals and students.**  
> Combines Google Gemini multimodal AI with local heuristic engines to detect phishing sites, brand impersonation, email spoofing, and credential-harvesting attacks in real time.

---

## 📸 Preview

| URL Scanner | Email Analyzer |
|---|---|
| Scans redirect chains, detects typosquatting, captures screenshots for visual AI analysis | Parses raw email headers, checks SPF/DMARC/MX records, flags misleading hyperlinks |

---

## ✨ Features

### 🔗 URL Analysis
- **Redirect Chain Tracing** — Follows every HTTP hop to reveal the true final destination
- **Brand Typosquatting Detection** — Identifies domains impersonating PayPal, Amazon, Netflix, Fiverr, Google, Microsoft and 30+ other brands using edit-distance algorithms
- **Trusted Domain Database** — 50+ official brand domains across all country TLDs (e.g. `amazon.in`, `amazon.co.uk`, `google.co.in`) to prevent false positives
- **Live HTML Content Analysis** — Detects login forms, password fields, and brand keyword references in scraped page content
- **Real-time Screenshot Capture** — Uses Microlink API to take live webpage screenshots, sent to Gemini Vision for visual brand impersonation analysis
- **High-Risk TLD Detection** — Flags domains on abuse-prone TLDs (`.xyz`, `.tk`, `.top`, `.cc`, `.ru`, etc.)
- **Threat Intelligence Database** — Built-in list of known phishing URL patterns cross-referenced on every scan
- **HTTPS Protocol Check** — Detects unencrypted HTTP landing pages

### 📧 Email Analysis
- **Raw Email Header Parser** — Extracts and analyzes `From`, `Reply-To`, `Return-Path`, `X-Mailer` and more
- **DNS Authentication Checks** — Live SPF, DMARC policy, and MX record lookups for the sender domain
- **Header Mismatch Detection** — Flags Reply-To / Return-Path routing to different domains than the sender
- **Hyperlink Analyzer** — Detects misleading anchor text (visible URL ≠ actual href) and typosquatted link destinations
- **Email Body Linguistic Highlighter** — Visually highlights urgency phrases and suspicious anchors in the parsed email body

### 🤖 AI-Powered Analysis (Gemini 2.0 Flash)
- **Multimodal Vision** — Screenshot + URL context sent together to Gemini for comprehensive analysis
- **Urgency Score** — 0–10 rating of psychological pressure tactics
- **Brand Impersonation Detection** — AI identifies which brand is being spoofed and explains how
- **Lure Classification** — Tags manipulation categories: `credential_harvest`, `fear`, `greed`, `authority`, `scarcity`
- **Suspicious Phrase Extraction** — Pulls out exact phrases used to deceive users
- **Local Fallback Engine** — Full heuristic analysis runs offline when no API key is provided

### 📊 Risk Scoring
| Score Range | Verdict | Color |
|-------------|---------|-------|
| 0 – 29 | ✅ SAFE | Green |
| 30 – 59 | ⚠️ SUSPICIOUS | Yellow |
| 60 – 100 | 🚨 MALICIOUS | Red |

Scores are composed from weighted indicators:
| Signal | Weight |
|--------|--------|
| Threat Intelligence match | +90 pts |
| Brand credential harvesting (password form + brand keyword on non-official domain) | +60 pts |
| Typosquatting detected | +50 pts |
| Misleading hyperlinks in email | +35 pts |
| AI impersonation detected | +40 pts |
| Missing SPF record | +20 pts |
| Missing DMARC record | +20 pts |
| High-risk TLD | +20 pts |
| Multi-domain redirect chain | +15–30 pts |
| Unencrypted HTTP | +15 pts |

---

## 🛠️ Tech Stack

### Frontend
| Tech | Role |
|------|------|
| React 19 | UI framework |
| Vite 8 | Build tool & dev server |
| Vanilla CSS | Glassmorphism dark-mode design system |
| Vercel Analytics | Usage tracking |

### Backend
| Tech | Role |
|------|------|
| Node.js (ESM) | Runtime |
| Express 4 | REST API server |
| `@google/generative-ai` | Gemini 2.0 Flash AI (text + vision) |
| Microlink API | Headless screenshot capture |
| Node `dns/promises` | SPF, DMARC, MX record resolution |
| `dotenv` | Environment variable management |

---

## 📁 Project Structure

```
Akhil PhishGuard/
├── src/                        # React frontend
│   ├── App.jsx                 # Main application component (~1350 lines)
│   ├── App.css                 # Glassmorphism design system
│   ├── index.css               # Global base styles
│   └── main.jsx                # React entry point
├── server/                     # Express backend
│   ├── server.js               # API routes & Gemini orchestration
│   ├── utils.js                # Heuristic engine & DNS utilities
│   └── package.json            # Server dependencies
├── public/                     # Static assets
├── index.html                  # Root HTML template
├── package.json                # Frontend dependencies
├── vite.config.js              # Vite configuration
└── .env                        # Environment variables (not committed)
```

---

## 🚀 Getting Started

### Prerequisites
- **Node.js** v18+ 
- **npm** v9+
- **Gemini API Key** — Free tier available at [Google AI Studio](https://aistudio.google.com/)
- **Microlink API Key** *(optional)* — Required for screenshot capture, free tier at [microlink.io](https://microlink.io)

### 1. Clone the Repository
```bash
git clone https://github.com/Akhil-Binu/Akhil-PhishGuard.git
cd "Akhil PhishGuard"
```

### 2. Install Frontend Dependencies
```bash
npm install
```

### 3. Install Backend Dependencies
```bash
cd server
npm install
```

### 4. Configure Environment Variables
Create `server/.env`:
```env
GEMINI_API_KEY=your_gemini_api_key_here
MICROLINK_API_KEY=your_microlink_api_key_here   # Optional
PORT=5000
```

### 5. Start the Backend Server
```bash
# From the /server directory
node server.js
```
Backend runs on → `http://localhost:5000`

### 6. Start the Frontend Dev Server
```bash
# From the root directory
npm run dev
```
Frontend runs on → `http://localhost:5173`

---

## 🔌 API Reference

### `POST /api/analyze-url`
Analyze a URL for phishing indicators.

**Request Body:**
```json
{
  "url": "https://example.com/login",
  "apiKey": "optional-gemini-key-to-override-env"
}
```

**Response:**
```json
{
  "success": true,
  "url": "https://example.com/login",
  "score": 85,
  "verdict": "MALICIOUS",
  "domainInfo": { "domain": "example.com", "tld": ".com", "protocol": "https:" },
  "redirectChain": [{ "url": "...", "status": 301 }],
  "finalUrl": "https://real-landing.net/steal",
  "isOriginalTrusted": false,
  "isFinalTrusted": false,
  "typosquat": { "isSpoof": true, "reason": "Contains brand 'paypal' with modifications" },
  "pageAnalysis": { "hasPasswordInput": true, "brandKeywords": ["paypal"], "formCount": 1 },
  "aiAnalysis": {
    "urgency": { "score": 8, "explanation": "..." },
    "impersonation": { "detected": true, "targetBrand": "PayPal", "explanation": "..." },
    "lures": { "types": ["credential_harvest", "fear"], "explanation": "..." },
    "overall_verdict": "MALICIOUS",
    "ai_risk_score": 92,
    "summary": "..."
  },
  "indicators": [{ "title": "...", "description": "...", "severity": "high", "category": "behavioral" }],
  "screenshot": "data:image/png;base64,...",
  "isSimulated": false
}
```

---

### `POST /api/analyze-email`
Analyze raw email content for phishing.

**Request Body:**
```json
{
  "rawEmail": "From: support@paypa1.com\nSubject: Account Suspended!\n\nYour account...",
  "apiKey": "optional-gemini-key"
}
```

**Response:**
```json
{
  "success": true,
  "score": 78,
  "verdict": "MALICIOUS",
  "headersParsed": { "from": "...", "reply-to": "...", "return-path": "..." },
  "fromInfo": { "domain": "paypa1.com" },
  "dnsCheck": {
    "spf": { "found": false },
    "dmarc": { "found": false, "policy": null },
    "mx": { "found": true, "records": ["mail.paypa1.com"] }
  },
  "linksAnalyzed": [{ "href": "...", "anchorText": "...", "misleading": true, "typosquat": { "isSpoof": true } }],
  "aiAnalysis": { "..." },
  "indicators": [{ "..." }],
  "isSimulated": false
}
```

---

### `GET /api/health`
```json
{ "status": "ok", "timestamp": "2026-06-24T07:00:00.000Z" }
```

---

## 🌐 Deployment

### Frontend — Vercel (Recommended)
The frontend is configured for zero-config Vercel deployment.

```bash
npm run build      # Outputs to /dist
```

Set the following in Vercel → Project Settings → Environment Variables:
> *(None required for frontend — API key is entered by the user in-app)*

### Backend — Any Node.js Host
The backend (`/server`) can be deployed to:
- **Railway**, **Render**, **Fly.io**, **Heroku**
- Any VPS with Node.js 18+

Set these environment variables on your host:
```
GEMINI_API_KEY=...
MICROLINK_API_KEY=...    # Optional
PORT=5000
```

Update the frontend API base URL in `src/App.jsx` to point to your deployed backend:
```js
const BACKEND = 'https://your-backend.railway.app';
```

---

## 🔒 Security & Privacy

- **No data stored** — All analysis happens in-memory per request; nothing is persisted
- **API keys are user-supplied** — The Gemini API key is entered client-side per session and sent only to your own backend; it is never stored
- **Screenshot capture is opt-in** — Screenshots are taken via Microlink only during active analysis and not cached
- **CORS locked** — Backend only accepts requests from configured origins in production

---

## 🧪 Running Tests

The `/server` directory includes test scripts for key detection scenarios:

```bash
cd server

# Test legitimate site (should return SAFE)
node test_amazon.js

# Test known phishing URL (should return MALICIOUS)
node test_fiverr.js

# Test sandbox with multiple URLs
node test_sandbox.js
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Commit your changes: `git commit -m "feat: add your feature"`
4. Push and open a Pull Request

---

## 📄 License

MIT License © 2026 Akhil Binu

---

## 🙏 Acknowledgements

- [Google Gemini](https://deepmind.google/technologies/gemini/) — Multimodal AI analysis
- [Microlink](https://microlink.io/) — Headless browser screenshot API
- [React](https://react.dev/) — Frontend framework
- [Vite](https://vitejs.dev/) — Build tooling
- [Vercel](https://vercel.com/) — Frontend hosting
