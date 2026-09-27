# ◈ Nyx OSINT

A full-featured Open Source Intelligence tool built for **Cloudflare Pages + Workers**.  
Search emails, usernames, breaches, and IP/domains — all from a clean dark-themed web UI.

---

## Features

| Module | What it does |
|---|---|
| **Email Intelligence** | MX records, provider detection, disposable check, Gravatar lookup, local-part pattern analysis |
| **Breach Check** | Queries HaveIBeenPwned v3, BreachDirectory, and LeakCheck for breach history |
| **Paste Check** | Searches HaveIBeenPwned paste database (requires HIBP key) |
| **Username Search** | Scans 55+ platforms — social media, dev tools, gaming, creative, forums |
| **IP / Domain Lookup** | Geolocation, ASN/ISP, VPN/Tor/proxy detection, DNS records, AbuseIPDB threat score |
| **Export** | Download results as JSON, CSV, or a self-contained HTML report |
| **History** | Recent searches saved locally in your browser (never sent anywhere) |

---

## Deploy to Cloudflare Pages (5 minutes)

### Option A — GitHub (recommended)

1. Push this folder to a GitHub repo
2. Go to [Cloudflare Dashboard → Pages](https://dash.cloudflare.com/) → **Create a project**
3. Connect your GitHub repo
4. Build settings:
   - **Framework preset:** None
   - **Build command:** *(leave empty)*
   - **Build output directory:** `public`
5. Click **Save and Deploy**

### Option B — Wrangler CLI

```bash
# Install Wrangler
npm install -g wrangler

# Login to Cloudflare
wrangler login

# Deploy
wrangler pages deploy public --project-name=nyx-osint
```

---

## Intelligence Sources

### Free — No Key Required (all active by default)

| Source | Records | What it covers |
|---|---|---|
| **XposedOrNot** | 11.6B+ / 779 breaches | Named, verified breaches with analytics, risk scores, timelines |
| **BreachDirectory** | 18B+ | Credential dumps — returns breach source names + partial hash hints |
| **LeakCheck** | Large multi-source index | Named breach sources + exposed data categories |
| **HudsonRock Cavalier** | 30M+ infostealer logs | Detects malware-compromised devices — not just breaches |
| **HIBP Pwned Passwords** | 800M+ passwords | Password mode only, k-anonymity, always free |
| **Local Breach DB** | 100+ major breaches | Domain cross-reference, built into the app |

**Combined coverage: ~30 billion records with zero API keys required.**

### Optional paid upgrades (not included)
If you want to go even further, Dehashed ($5/mo) and Snusbase add billions more records. Add keys via Cloudflare env secrets — the code already handles them gracefully if absent.

| Secret | Service |
|---|---|
| `HIBP_API_KEY` | HaveIBeenPwned named breach detail (~$3.50/mo) |
| `ABUSEIPDB_KEY` | IP threat scoring (free tier) |
| `NUMVERIFY_KEY` | Phone carrier lookup (free tier) |

---

## Project Structure

```
Nyx Osint/
├── public/               ← Static frontend (Cloudflare Pages serves this)
│   ├── index.html        ← Main UI
│   ├── style.css         ← Dark theme stylesheet
│   └── app.js            ← Frontend logic
├── functions/            ← Cloudflare Workers (auto-deployed as Pages Functions)
│   ├── _middleware.js    ← CORS + security headers
│   └── api/
│       ├── breach.js     ← /api/breach
│       ├── paste.js      ← /api/paste
│       ├── email.js      ← /api/email
│       ├── username.js   ← /api/username
│       └── ip.js         ← /api/ip
└── wrangler.toml         ← Cloudflare config
```

---

## Usage

1. Open your deployed Cloudflare Pages URL
2. Pick a mode from the top nav: **Email**, **Username**, **Breach DB**, or **IP / Domain**
3. Enter your target and click **Search**
4. Optionally paste your HIBP API key for full breach data
5. Export results with the **⬇ Export** button

---

## Privacy

- No data is logged or stored server-side
- Browser history is stored only in your own `localStorage` — clear it any time
- API keys entered in the UI are sent only to the Worker and forwarded to the respective API — never persisted

---

## Legal

This tool is for **authorized security research and personal data protection only**.  
Do not use it to look up information about others without their consent.  
Users are solely responsible for compliance with applicable laws.

---

## License

MIT
