/**
 * Cloudflare Pages Function: /api/breach
 *
 * Queries FOUR large, completely FREE, no-key-required breach databases
 * simultaneously. Combined coverage: 30B+ records.
 *
 * ┌─────────────────────┬──────────────────┬────────────────────────────────┐
 * │ Source              │ Records          │ What it covers                 │
 * ├─────────────────────┼──────────────────┼────────────────────────────────┤
 * │ XposedOrNot         │ 11.6B+ (779 DBs) │ Named breaches + analytics     │
 * │ BreachDirectory     │ 18B+             │ Credential dumps, hash hints   │
 * │ LeakCheck           │ Large index      │ Multi-source, named breaches   │
 * │ HudsonRock Cavalier │ 30M+             │ Infostealer / malware logs     │
 * └─────────────────────┴──────────────────┴────────────────────────────────┘
 *
 * No API keys. No paid tiers. Deploy and it works.
 */

export async function onRequestPost(context) {
  const { request } = context;

  try {
    const body  = await request.json();
    const email = (body.email || '').trim().toLowerCase();

    if (!email || !isEmail(email)) return jsonError('Invalid email address', 400);

    const domain = email.split('@')[1];

    // Fire all four sources at the same time
    const settled = await Promise.allSettled([
      checkXposedOrNot(email),
      checkBreachDirectory(email),
      checkLeakCheck(email),
      checkHudsonRock(email),
    ]);

    const allBreaches  = [];
    let   sourcesOk    = 0;
    let   sourcesTotal = 4;

    for (const s of settled) {
      const r = s.status === 'fulfilled'
        ? s.value
        : { source: 'Unknown', error: s.reason?.message || 'Failed', breaches: [] };

      if (!r.error) sourcesOk++;
      allBreaches.push(...(r.breaches || []));
    }

    // Deduplicate: normalised name only (hide internal source names)
    const seen   = new Set();
    const unique = allBreaches.filter(b => {
      const key = (b.name || '').toLowerCase().replace(/[\s_-]+/g, '');
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    // Sort: infostealers first (most urgent), then most recent date
    unique.sort((a, b) => {
      const ai = a.isInfostealer ? -1 : 0;
      const bi = b.isInfostealer ? -1 : 0;
      if (ai !== bi) return ai - bi;
      return (b.date || '0000').localeCompare(a.date || '0000');
    });

    // Overwrite all source labels — everything shows as "Nyx Data"
    unique.forEach(b => { b.source = 'Nyx Data'; });

    // Cross-reference our curated local DB by the email domain
    const dbMatches = await crossReferenceDB(domain, context);

    const summary = {
      total:         unique.length,
      infostealers:  unique.filter(b => b.isInfostealer).length,
      breachRecords: unique.filter(b => !b.isInfostealer).length,
      dbMatches:     dbMatches.length,
      sourcesQueried:   sourcesTotal,
      sourcesResponded: sourcesOk,
    };

    // Single unified status shown to frontend
    const sourceStatus = [{
      source: 'Nyx Data',
      status: `${unique.length} result(s) across ${sourcesOk}/${sourcesTotal} sources`,
      count:  unique.length,
    }];

    return json({ breaches: unique, dbMatches, sourceStatus, domain, summary });

  } catch (err) {
    return jsonError(err.message || 'Internal error', 500);
  }
}

// ─────────────────────────────────────────────────────────────
// SOURCE 1 — XposedOrNot
// 11.6 billion+ exposed records across 779+ verified breaches.
// Free, no key, open source. Two endpoints used:
//   /v1/check-email/:email  → list of breach names this email appears in
//   /v1/breach-analytics    → risk score, timeline, data categories
// ─────────────────────────────────────────────────────────────
async function checkXposedOrNot(email) {
  const SOURCE = 'XposedOrNot';
  try {
    // Hit both endpoints in parallel for richer data
    const [checkRes, analyticsRes] = await Promise.allSettled([
      fetch(`https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`, {
        headers: { 'User-Agent': 'Nyx-OSINT/1.0', 'Accept': 'application/json' },
        signal: AbortSignal.timeout(12000),
      }),
      fetch(`https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(email)}`, {
        headers: { 'User-Agent': 'Nyx-OSINT/1.0', 'Accept': 'application/json' },
        signal: AbortSignal.timeout(12000),
      }),
    ]);

    // Parse check-email — returns { breaches: [['BreachName', ...]] } or { Error: 'Not found' }
    let breachNames = [];
    if (checkRes.status === 'fulfilled' && checkRes.value.ok) {
      try {
        const data = await checkRes.value.json();
        // XposedOrNot returns breaches as array of arrays: [["Breach1","Breach2",...]]
        if (Array.isArray(data.breaches?.[0])) {
          breachNames = data.breaches[0];
        } else if (Array.isArray(data.breaches)) {
          breachNames = data.breaches;
        }
      } catch { /* parse error — continue with analytics */ }
    }

    // Parse breach-analytics — returns richer per-breach metadata
    let analyticsMap = {};
    if (analyticsRes.status === 'fulfilled' && analyticsRes.value.ok) {
      try {
        const data = await analyticsRes.value.json();
        // Structure: { BreachMetrics: { xposed_breaches: { ... } }, ... }
        const xb = data?.BreachMetrics?.xposed_breaches;
        if (xb && typeof xb === 'object') {
          analyticsMap = xb; // keyed by breach name
        }
      } catch { /* analytics parse error — use names only */ }
    }

    if (breachNames.length === 0 && Object.keys(analyticsMap).length === 0) {
      return { source: SOURCE, breaches: [] };
    }

    // Merge: names list + analytics metadata
    const allNames = breachNames.length > 0
      ? breachNames
      : Object.keys(analyticsMap);

    const breaches = allNames.map(name => {
      const meta = analyticsMap[name] || {};
      return {
        name:        name,
        date:        meta.year    ? String(meta.year)       : (meta.date || 'Unknown'),
        pwnCount:    meta.records ? Number(meta.records)    : null,
        dataClasses: Array.isArray(meta.xposed_data)
          ? meta.xposed_data
          : (meta.exposed_data ? [meta.exposed_data] : ['Email']),
        domain:      meta.domain  || null,
        passwordRisk:meta.password_risk || null,
        source:      SOURCE,
        logo:        meta.logo_path || null,
      };
    });

    return { source: SOURCE, breaches };
  } catch {
    return { source: SOURCE, error: 'Unavailable', breaches: [] };
  }
}

// ─────────────────────────────────────────────────────────────
// SOURCE 2 — BreachDirectory
// 18 billion+ records from thousands of credential dumps.
// Free public API — returns source names and partial password hints.
// ─────────────────────────────────────────────────────────────
async function checkBreachDirectory(email) {
  const SOURCE = 'BreachDirectory';
  try {
    const res = await fetch(
      `https://breachdirectory.org/api?func=auto&term=${encodeURIComponent(email)}`,
      {
        headers: { 'User-Agent': 'Nyx-OSINT/1.0', 'Accept': 'application/json' },
        signal: AbortSignal.timeout(12000),
      }
    );

    if (!res.ok) return { source: SOURCE, error: `HTTP ${res.status}`, breaches: [] };

    const data = await res.json();
    if (!data?.result || !Array.isArray(data.result)) {
      return { source: SOURCE, breaches: [] };
    }

    const breaches = data.result.map(r => ({
      name:         (r.sources || []).join(', ') || 'Unknown credential dump',
      date:         'Unknown',
      pwnCount:     null,
      dataClasses:  ['Email', 'Password (hashed)'],
      passwordHint: r.password || null,  // partial hash hint, not plaintext
      source:       SOURCE,
    }));

    return { source: SOURCE, breaches };
  } catch {
    return { source: SOURCE, error: 'Unavailable', breaches: [] };
  }
}

// ─────────────────────────────────────────────────────────────
// SOURCE 3 — LeakCheck
// Free public endpoint. Returns breach source names and data categories
// without exposing raw credentials. No key required.
// ─────────────────────────────────────────────────────────────
async function checkLeakCheck(email) {
  const SOURCE = 'LeakCheck';
  try {
    const res = await fetch(
      `https://leakcheck.io/api/public?check=${encodeURIComponent(email)}`,
      {
        headers: { 'User-Agent': 'Nyx-OSINT/1.0', 'Accept': 'application/json' },
        signal: AbortSignal.timeout(12000),
      }
    );

    if (!res.ok) return { source: SOURCE, error: `HTTP ${res.status}`, breaches: [] };

    const data = await res.json();
    if (!data?.found) return { source: SOURCE, breaches: [] };

    const breaches = (data.sources || []).map(s => ({
      name:        s.name || 'Unknown',
      date:        s.date || 'Unknown',
      pwnCount:    null,
      dataClasses: s.entries ? Object.keys(s.entries) : ['Email'],
      source:      SOURCE,
    }));

    return { source: SOURCE, breaches };
  } catch {
    return { source: SOURCE, error: 'Unavailable', breaches: [] };
  }
}

// ─────────────────────────────────────────────────────────────
// SOURCE 4 — HudsonRock Cavalier
// 30M+ infostealer / malware credential logs. Free, no key.
// Uniquely tells you if a device was compromised by a stealer trojan —
// not just "appeared in a breach" but "credentials actively stolen."
// ─────────────────────────────────────────────────────────────
async function checkHudsonRock(email) {
  const SOURCE = 'HudsonRock';
  try {
    const res = await fetch(
      `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login?login=${encodeURIComponent(email)}`,
      {
        headers: { 'User-Agent': 'Nyx-OSINT/1.0', 'Accept': 'application/json' },
        signal: AbortSignal.timeout(12000),
      }
    );

    if (!res.ok) return { source: SOURCE, error: `HTTP ${res.status}`, breaches: [] };

    const data = await res.json();
    if (!data || (!data.stealers?.length && !data.total)) {
      return { source: SOURCE, breaches: [] };
    }

    const breaches = (data.stealers || []).map(s => ({
      name:          `Infostealer: ${s.stealer_family || 'Unknown malware'}`,
      date:          s.date_compromised ? s.date_compromised.split('T')[0] : 'Unknown',
      pwnCount:      null,
      dataClasses:   ['Credentials', 'Browser data', 'Saved passwords', 'System info'],
      computerName:  s.computer_name    || null,
      os:            s.operating_system || null,
      malware:       s.stealer_family   || null,
      source:        SOURCE,
      isInfostealer: true,
    }));

    return { source: SOURCE, breaches };
  } catch {
    return { source: SOURCE, error: 'Unavailable', breaches: [] };
  }
}

// ─────────────────────────────────────────────────────────────
// LOCAL DB — Cross-reference curated breach database by domain
// Matches the email's domain against our 100+ company breach index.
// Always runs, zero latency (fetches our own static file).
// ─────────────────────────────────────────────────────────────
async function crossReferenceDB(emailDomain, context) {
  try {
    const url  = new URL(context.request.url);
    const base = `${url.protocol}//${url.host}`;
    const res  = await fetch(`${base}/breachdb.json`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return [];

    const db = await res.json();
    return db.filter(b =>
      b.domain && emailDomain && (
        b.domain.toLowerCase() === emailDomain.toLowerCase() ||
        emailDomain.toLowerCase().endsWith('.' + b.domain.toLowerCase())
      )
    );
  } catch {
    return [];
  }
}

// ── Helpers ───────────────────────────────────────────────────
function isEmail(s) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type':                'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

function jsonError(msg, status = 400) {
  return json({ error: msg }, status);
}
