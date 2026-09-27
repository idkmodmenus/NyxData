/**
 * Cloudflare Pages Function: /api/phone
 *
 * Phone number intelligence:
 *  1. numverify.com free tier (basic validation + carrier)
 *  2. Abstract API free tier (geo + carrier + line type)
 *  3. Internal format parsing (always runs, no key needed)
 */

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const body  = await request.json();
    const phone = sanitizePhone(body.phone || '');

    if (!phone || phone.length < 7) return jsonError('Invalid phone number', 400);

    const numverifyKey = env.NUMVERIFY_KEY || '';
    const abstractKey  = env.ABSTRACTAPI_PHONE_KEY || '';

    const [parsed, numverify, abstractResult] = await Promise.allSettled([
      parsePhone(phone),
      numverifyKey ? checkNumverify(phone, numverifyKey)   : Promise.resolve({ source: 'Numverify', skipped: true }),
      abstractKey  ? checkAbstractAPI(phone, abstractKey) : Promise.resolve({ source: 'AbstractAPI', skipped: true }),
    ]);

    const result = {
      input:      phone,
      parsed:     parsed.status === 'fulfilled' ? parsed.value : null,
      numverify:  numverify.status === 'fulfilled' ? numverify.value : { source: 'Numverify', error: 'Failed' },
      abstract:   abstractResult.status === 'fulfilled' ? abstractResult.value : { source: 'AbstractAPI', error: 'Failed' },
    };

    // Merge best available data
    const merged = mergePhoneData(result);
    return json({ ...merged, raw: result });

  } catch (err) {
    return jsonError(err.message || 'Internal error', 500);
  }
}

// ── Basic phone parsing (no external API needed) ──────────────
async function parsePhone(phone) {
  const cleaned = phone.replace(/\D/g, '');
  const isUS    = cleaned.length === 10 || (cleaned.length === 11 && cleaned[0] === '1');

  let countryCode = null;
  let national    = cleaned;

  if (phone.startsWith('+')) {
    // Extract country code from E.164 format
    const dialPrefixes = {
      '1': 'US/CA', '44': 'UK', '61': 'AU', '49': 'DE', '33': 'FR',
      '81': 'JP', '86': 'CN', '91': 'IN', '55': 'BR', '52': 'MX',
      '34': 'ES', '39': 'IT', '31': 'NL', '46': 'SE', '47': 'NO',
      '45': 'DK', '41': 'CH', '43': 'AT', '32': 'BE', '351': 'PT',
      '7': 'RU', '380': 'UA', '48': 'PL', '420': 'CZ', '36': 'HU',
      '40': 'RO', '30': 'GR', '90': 'TR', '972': 'IL', '966': 'SA',
      '971': 'AE', '20': 'EG', '27': 'ZA', '234': 'NG', '254': 'KE',
      '82': 'KR', '65': 'SG', '60': 'MY', '66': 'TH', '62': 'ID',
      '63': 'PH', '64': 'NZ', '54': 'AR', '56': 'CL', '57': 'CO',
    };

    const digits = phone.replace('+', '');
    for (const [code, country] of Object.entries(dialPrefixes).sort((a, b) => b[0].length - a[0].length)) {
      if (digits.startsWith(code)) {
        countryCode = `+${code}`;
        national    = digits.slice(code.length);
        return { countryCode, national, country, cleaned: digits, isValid: national.length >= 6 };
      }
    }
  }

  return {
    countryCode: isUS ? '+1' : null,
    national,
    country: isUS ? 'US/CA' : null,
    cleaned,
    isValid: cleaned.length >= 7 && cleaned.length <= 15,
  };
}

// ── Numverify ─────────────────────────────────────────────────
async function checkNumverify(phone, key) {
  try {
    const res = await fetch(
      `http://apilayer.net/api/validate?access_key=${key}&number=${encodeURIComponent(phone)}&format=1`,
      { headers: { 'User-Agent': 'Nyx-OSINT/1.0' }, signal: AbortSignal.timeout(8000) }
    );
    if (!res.ok) return { source: 'Numverify', error: `HTTP ${res.status}` };

    const d = await res.json();
    if (d.error) return { source: 'Numverify', error: d.error.info || 'API error' };

    return {
      source:        'Numverify',
      valid:         d.valid,
      number:        d.number,
      localFormat:   d.local_format,
      intlFormat:    d.international_format,
      countryPrefix: d.country_prefix,
      countryCode:   d.country_code,
      countryName:   d.country_name,
      location:      d.location,
      carrier:       d.carrier,
      lineType:      d.line_type,
    };
  } catch {
    return { source: 'Numverify', error: 'Unavailable' };
  }
}

// ── AbstractAPI ───────────────────────────────────────────────
async function checkAbstractAPI(phone, key) {
  try {
    const res = await fetch(
      `https://phonevalidation.abstractapi.com/v1/?api_key=${key}&phone=${encodeURIComponent(phone)}`,
      { headers: { 'User-Agent': 'Nyx-OSINT/1.0' }, signal: AbortSignal.timeout(8000) }
    );
    if (!res.ok) return { source: 'AbstractAPI', error: `HTTP ${res.status}` };

    const d = await res.json();
    return {
      source:      'AbstractAPI',
      valid:       d.valid,
      format:      d.format,
      country:     d.country,
      phone:       d.phone,
      type:        d.type,
      carrier:     d.carrier,
      timezones:   d.timezones,
    };
  } catch {
    return { source: 'AbstractAPI', error: 'Unavailable' };
  }
}

// ── Merge best available data ─────────────────────────────────
function mergePhoneData({ input, parsed, numverify, abstract }) {
  const nv = numverify?.source === 'Numverify' && !numverify.error ? numverify : null;
  const ab = abstract?.source  === 'AbstractAPI' && !abstract.error ? abstract : null;

  return {
    phone:       nv?.intlFormat || ab?.phone || input,
    valid:       nv?.valid ?? ab?.valid ?? parsed?.isValid ?? null,
    countryCode: nv?.countryPrefix || parsed?.countryCode || null,
    countryName: nv?.countryName || ab?.country?.name || parsed?.country || null,
    location:    nv?.location || null,
    carrier:     nv?.carrier || ab?.carrier?.name || null,
    lineType:    nv?.lineType || ab?.type || null,
    timezones:   ab?.timezones || null,
  };
}

function sanitizePhone(p) {
  return p.replace(/[^\d+\-\s().]/g, '').trim().slice(0, 20);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
  });
}
function jsonError(msg, status = 400) { return json({ error: msg }, status); }
