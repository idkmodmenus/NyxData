/**
 * Cloudflare Pages Function: /api/ip
 * IP geolocation + threat intel + DNS records for domains
 *
 * Uses:
 *  - ip-api.com (free, no key needed)
 *  - AbuseIPDB (optional, needs env.ABUSEIPDB_KEY)
 *  - Cloudflare DNS-over-HTTPS for domain DNS records
 */

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const body   = await request.json();
    const target = (body.target || '').trim().toLowerCase();

    if (!target) return jsonError('No target provided', 400);

    const isIP     = /^(\d{1,3}\.){3}\d{1,3}$/.test(target) || /^[0-9a-f:]+$/i.test(target);
    const isDomain = !isIP && /^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(target);

    if (!isIP && !isDomain) {
      return jsonError('Enter a valid IP address or domain name', 400);
    }

    // If domain, resolve to IP first
    let lookupTarget = target;
    let resolvedIP   = null;
    if (isDomain) {
      resolvedIP = await resolveToIP(target);
      if (resolvedIP) lookupTarget = resolvedIP;
    }

    const [geoData, abuseData, dnsData] = await Promise.all([
      lookupGeo(lookupTarget),
      env.ABUSEIPDB_KEY ? lookupAbuse(lookupTarget, env.ABUSEIPDB_KEY) : null,
      isDomain ? lookupDNS(target) : null,
    ]);

    // ip-api also returns vpn/proxy info in paid plan; use heuristics from free plan
    const result = {
      ip:          lookupTarget,
      originalInput: target,
      resolvedIP,
      hostname:    geoData.reverse || geoData.hostname || null,
      org:         geoData.org   || geoData.isp || null,
      asn:         geoData.as    || null,
      country:     geoData.country || null,
      countryCode: geoData.countryCode || null,
      region:      geoData.regionName || null,
      city:        geoData.city  || null,
      timezone:    geoData.timezone || null,
      lat:         geoData.lat   || null,
      lon:         geoData.lon   || null,
      hosting:     geoData.hosting || false,
      proxy:       geoData.proxy  || false,
      vpn:         geoData.vpn   || false,
      tor:         geoData.tor   || false,
      abuse:       abuseData,
      dns:         dnsData || {},
    };

    // Country flag emoji
    if (result.countryCode) {
      result.countryFlag = countryFlag(result.countryCode);
    }

    return json(result);
  } catch (err) {
    return jsonError(err.message || 'Internal error', 500);
  }
}

// ── ip-api.com ────────────────────────────────────────────────

async function lookupGeo(ip) {
  try {
    const fields = 'status,message,continent,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,reverse,hosting,proxy,vpn,tor';
    const res = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=${fields}`,
      { headers: { 'User-Agent': 'Nyx-OSINT/1.0' }, signal: AbortSignal.timeout(8000) }
    );
    if (!res.ok) return {};
    return await res.json();
  } catch {
    return {};
  }
}

// ── AbuseIPDB ─────────────────────────────────────────────────

async function lookupAbuse(ip, apiKey) {
  try {
    const res = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      {
        headers: { 'Key': apiKey, 'Accept': 'application/json', 'User-Agent': 'Nyx-OSINT/1.0' },
        signal: AbortSignal.timeout(8000),
      }
    );
    if (!res.ok) return null;
    const data = await res.json();
    const d = data?.data;
    if (!d) return null;
    return {
      confidence: d.abuseConfidenceScore || 0,
      totalReports: d.totalReports || 0,
      isp: d.isp || null,
      domain: d.domain || null,
      usageType: d.usageType || null,
      lastReported: d.lastReportedAt || null,
    };
  } catch {
    return null;
  }
}

// ── DNS records ───────────────────────────────────────────────

async function lookupDNS(domain) {
  const TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME'];
  const doh   = 'https://cloudflare-dns.com/dns-query';
  const out   = {};

  await Promise.all(TYPES.map(async type => {
    try {
      const res = await fetch(`${doh}?name=${encodeURIComponent(domain)}&type=${type}`, {
        headers: { 'Accept': 'application/dns-json' },
        signal: AbortSignal.timeout(5000),
      });
      if (!res.ok) return;
      const data = await res.json();
      if (!data.Answer?.length) return;
      out[type] = data.Answer.map(a => a.data.replace(/\.$/, ''));
    } catch { /* skip */ }
  }));

  return out;
}

// ── Resolve domain to IP ──────────────────────────────────────

async function resolveToIP(domain) {
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,
      { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(5000) }
    );
    if (!res.ok) return null;
    const data = await res.json();
    return data.Answer?.[0]?.data || null;
  } catch {
    return null;
  }
}

// ── Country code → flag emoji ─────────────────────────────────

function countryFlag(cc) {
  return cc.toUpperCase().split('').map(c => String.fromCodePoint(0x1F1E0 - 65 + c.charCodeAt(0))).join('');
}

// ── Response helpers ──────────────────────────────────────────

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
  });
}

function jsonError(msg, status = 400) {
  return json({ error: msg }, status);
}
