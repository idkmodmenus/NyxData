/**
 * Cloudflare Pages Function: /api/email
 * Email intelligence: MX records, domain check, Gravatar, disposable detection
 *
 * Note: Cloudflare Workers don't have the 'dns' Node module.
 * We use the Cloudflare DNS-over-HTTPS API instead.
 */

const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com','guerrillamail.com','10minutemail.com','tempmail.com',
  'throwaway.email','yopmail.com','sharklasers.com','guerrillamailblock.com',
  'grr.la','guerrillamail.info','guerrillamail.biz','guerrillamail.de',
  'guerrillamail.net','guerrillamail.org','spam4.me','trashmail.com',
  'trashmail.me','trashmail.at','trashmail.io','dispostable.com',
  'mailnull.com','spamgourmet.com','spamgourmet.net','spamgourmet.org',
  'dodgeit.com','spamex.com','nospamfor.us','maildrop.cc','discard.email',
  'tempinbox.com','spamfree24.org','fakeinbox.com','tempemail.net',
  'sneakemail.com','mailexpire.com','binkmail.com','mailmetrash.com',
  'trashmail.at','spam.la','guerrillamail.com','discard.email',
  'mailnull.com','maildrop.cc','throwam.com','fakeinbox.com',
]);

export async function onRequestPost(context) {
  const { request } = context;

  try {
    const body  = await request.json();
    const email = (body.email || '').trim().toLowerCase();

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return jsonError('Invalid email address', 400);
    }

    const [local, domain] = email.split('@');

    const [mxData, gravatar] = await Promise.all([
      lookupMX(domain),
      lookupGravatar(email),
    ]);

    // Provider detection from MX
    let providerGuess = 'Unknown';
    if (mxData.records.length > 0) {
      const mx = mxData.records[0].exchange.toLowerCase();
      if (mx.includes('google') || mx.includes('gmail'))             providerGuess = 'Google (Gmail / Workspace)';
      else if (mx.includes('outlook') || mx.includes('microsoft') || mx.includes('hotmail')) providerGuess = 'Microsoft (Outlook / 365)';
      else if (mx.includes('yahoo'))                                  providerGuess = 'Yahoo Mail';
      else if (mx.includes('proton'))                                 providerGuess = 'ProtonMail';
      else if (mx.includes('icloud') || mx.includes('apple'))        providerGuess = 'Apple iCloud';
      else if (mx.includes('zoho'))                                   providerGuess = 'Zoho Mail';
      else if (mx.includes('mailgun'))                                providerGuess = 'Mailgun (transactional)';
      else if (mx.includes('sendgrid'))                               providerGuess = 'SendGrid (transactional)';
      else providerGuess = `Custom (${mxData.records[0].exchange})`;
    }

    // Local part patterns
    const patterns = [];
    if (/^\d+$/.test(local))                          patterns.push('Numeric only');
    if (/^[a-z]+\.[a-z]+$/i.test(local))              patterns.push('FirstName.LastName pattern');
    if (/^[a-z]+[0-9]+$/i.test(local))                patterns.push('Name+Numbers pattern');
    if (/noreply|no-reply|donotreply/i.test(local))   patterns.push('No-reply address');
    if (/admin|webmaster|info|support/i.test(local))  patterns.push('Generic / service address');
    if (local.length <= 4)                             patterns.push('Very short local part');

    return json({
      email,
      local,
      domain,
      localPatterns:  patterns,
      mxRecords:      mxData.records,
      hasMX:          mxData.records.length > 0,
      dnsResolvable:  mxData.resolvable,
      isDisposable:   DISPOSABLE_DOMAINS.has(domain),
      providerGuess,
      gravatar,
    });

  } catch (err) {
    return jsonError(err.message || 'Internal error', 500);
  }
}

// ── DNS-over-HTTPS MX lookup ──────────────────────────────────

async function lookupMX(domain) {
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=MX`,
      { headers: { 'Accept': 'application/dns-json' } }
    );

    if (!res.ok) return { records: [], resolvable: false };

    const data = await res.json();
    if (!data.Answer || data.Answer.length === 0) {
      // Try A record to see if domain exists at all
      const aRes = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,
        { headers: { 'Accept': 'application/dns-json' } }
      );
      const aData = aRes.ok ? await aRes.json() : {};
      return { records: [], resolvable: !!(aData.Answer?.length) };
    }

    // MX answer format: "10 aspmx.l.google.com."
    const records = data.Answer
      .filter(a => a.type === 15) // MX type
      .map(a => {
        const parts = a.data.split(' ');
        return {
          priority: parseInt(parts[0], 10) || 0,
          exchange: (parts[1] || '').replace(/\.$/, ''),
        };
      })
      .sort((a, b) => a.priority - b.priority);

    return { records, resolvable: true };
  } catch {
    return { records: [], resolvable: false };
  }
}

// ── Gravatar ──────────────────────────────────────────────────

async function lookupGravatar(email) {
  const hash = await md5(email.trim().toLowerCase());
  const url  = `https://www.gravatar.com/${hash}.json`;

  try {
    const res = await fetch(url, { headers: { 'User-Agent': 'Nyx-OSINT/1.0' } });
    if (res.status === 404) return { hasGravatar: false, hash };

    const data  = await res.json().catch(() => null);
    const entry = data?.entry?.[0];

    return {
      hasGravatar:  true,
      hash,
      profileUrl:   `https://www.gravatar.com/${hash}`,
      displayName:  entry?.displayName,
      thumbnailUrl: entry?.thumbnailUrl,
      aboutMe:      entry?.aboutMe,
    };
  } catch {
    return { hasGravatar: false, hash };
  }
}

// ── MD5 in Workers (WebCrypto doesn't support MD5 — use SubtleCrypto SHA-1 fallback or pure JS) ──

async function md5(str) {
  // Pure JS MD5 implementation (RFC 1321)
  // Needed because Gravatar uses MD5 and WebCrypto doesn't support it
  function safeAdd(x, y) {
    const lsw = (x & 0xFFFF) + (y & 0xFFFF);
    return (((x >> 16) + (y >> 16) + (lsw >> 16)) << 16) | (lsw & 0xFFFF);
  }
  function bitRotateLeft(num, cnt) { return (num << cnt) | (num >>> (32 - cnt)); }
  function md5cmn(q, a, b, x, s, t) { return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b); }
  function md5ff(a, b, c, d, x, s, t) { return md5cmn((b & c) | (~b & d), a, b, x, s, t); }
  function md5gg(a, b, c, d, x, s, t) { return md5cmn((b & d) | (c & ~d), a, b, x, s, t); }
  function md5hh(a, b, c, d, x, s, t) { return md5cmn(b ^ c ^ d, a, b, x, s, t); }
  function md5ii(a, b, c, d, x, s, t) { return md5cmn(c ^ (b | ~d), a, b, x, s, t); }

  function md5cycle(x, k) {
    let a = x[0], b = x[1], c = x[2], d = x[3];
    a = md5ff(a, b, c, d, k[0],  7,  -680876936);  d = md5ff(d, a, b, c, k[1],  12, -389564586);
    c = md5ff(c, d, a, b, k[2],  17,  606105819);  b = md5ff(b, c, d, a, k[3],  22, -1044525330);
    a = md5ff(a, b, c, d, k[4],  7,  -176418897);  d = md5ff(d, a, b, c, k[5],  12,  1200080426);
    c = md5ff(c, d, a, b, k[6],  17, -1473231341); b = md5ff(b, c, d, a, k[7],  22, -45705983);
    a = md5ff(a, b, c, d, k[8],  7,   1770035416); d = md5ff(d, a, b, c, k[9],  12, -1958414417);
    c = md5ff(c, d, a, b, k[10], 17, -42063);      b = md5ff(b, c, d, a, k[11], 22, -1990404162);
    a = md5ff(a, b, c, d, k[12], 7,   1804603682); d = md5ff(d, a, b, c, k[13], 12, -40341101);
    c = md5ff(c, d, a, b, k[14], 17, -1502002290); b = md5ff(b, c, d, a, k[15], 22,  1236535329);
    a = md5gg(a, b, c, d, k[1],  5,  -165796510);  d = md5gg(d, a, b, c, k[6],  9,  -1069501632);
    c = md5gg(c, d, a, b, k[11], 14,  643717713);  b = md5gg(b, c, d, a, k[0],  20, -373897302);
    a = md5gg(a, b, c, d, k[5],  5,  -701558691);  d = md5gg(d, a, b, c, k[10], 9,   38016083);
    c = md5gg(c, d, a, b, k[15], 14, -660478335);  b = md5gg(b, c, d, a, k[4],  20, -405537848);
    a = md5gg(a, b, c, d, k[9],  5,   568446438);  d = md5gg(d, a, b, c, k[14], 9,  -1019803690);
    c = md5gg(c, d, a, b, k[3],  14, -187363961);  b = md5gg(b, c, d, a, k[8],  20,  1163531501);
    a = md5gg(a, b, c, d, k[13], 5,  -1444681467); d = md5gg(d, a, b, c, k[2],  9,  -51403784);
    c = md5gg(c, d, a, b, k[7],  14,  1735328473); b = md5gg(b, c, d, a, k[12], 20, -1926607734);
    a = md5hh(a, b, c, d, k[5],  4,  -378558);     d = md5hh(d, a, b, c, k[8],  11, -2022574463);
    c = md5hh(c, d, a, b, k[11], 16,  1839030562); b = md5hh(b, c, d, a, k[14], 23, -35309556);
    a = md5hh(a, b, c, d, k[1],  4,  -1530992060); d = md5hh(d, a, b, c, k[4],  11,  1272893353);
    c = md5hh(c, d, a, b, k[7],  16, -155497632);  b = md5hh(b, c, d, a, k[10], 23, -1094730640);
    a = md5hh(a, b, c, d, k[13], 4,   681279174);  d = md5hh(d, a, b, c, k[0],  11, -358537222);
    c = md5hh(c, d, a, b, k[3],  16, -722521979);  b = md5hh(b, c, d, a, k[6],  23,  76029189);
    a = md5hh(a, b, c, d, k[9],  4,  -640364487);  d = md5hh(d, a, b, c, k[12], 11, -421815835);
    c = md5hh(c, d, a, b, k[15], 16,  530742520);  b = md5hh(b, c, d, a, k[2],  23, -995338651);
    a = md5ii(a, b, c, d, k[0],  6,  -198630844);  d = md5ii(d, a, b, c, k[7],  10,  1126891415);
    c = md5ii(c, d, a, b, k[14], 15, -1416354905); b = md5ii(b, c, d, a, k[5],  21, -57434055);
    a = md5ii(a, b, c, d, k[12], 6,   1700485571); d = md5ii(d, a, b, c, k[3],  10, -1894986606);
    c = md5ii(c, d, a, b, k[10], 15, -1051523);    b = md5ii(b, c, d, a, k[1],  21, -2054922799);
    a = md5ii(a, b, c, d, k[8],  6,   1873313359); d = md5ii(d, a, b, c, k[15], 10, -30611744);
    c = md5ii(c, d, a, b, k[6],  15, -1560198380); b = md5ii(b, c, d, a, k[13], 21,  1309151649);
    a = md5ii(a, b, c, d, k[4],  6,  -145523070);  d = md5ii(d, a, b, c, k[11], 10, -1120210379);
    c = md5ii(c, d, a, b, k[2],  15,  718787259);  b = md5ii(b, c, d, a, k[9],  21, -343485551);
    x[0] = safeAdd(a, x[0]); x[1] = safeAdd(b, x[1]);
    x[2] = safeAdd(c, x[2]); x[3] = safeAdd(d, x[3]);
    return x;
  }

  function md5blk(s) {
    const md5blks = [];
    for (let i = 0; i < 64; i += 4) {
      md5blks[i >> 2] = s.charCodeAt(i) + (s.charCodeAt(i+1) << 8) + (s.charCodeAt(i+2) << 16) + (s.charCodeAt(i+3) << 24);
    }
    return md5blks;
  }

  const length8 = str.length * 8;
  str += '\x80';
  while (str.length % 64 !== 56) str += '\0';
  str += String.fromCharCode(length8 & 0xFF, (length8 >>> 8) & 0xFF, (length8 >>> 16) & 0xFF, (length8 >>> 24) & 0xFF, 0, 0, 0, 0);

  let x = [1732584193, -271733879, -1732584194, 271733878];
  for (let i = 0; i < str.length; i += 64) {
    x = md5cycle(x, md5blk(str.substring(i, i+64)));
  }

  return x.map(n => {
    const hex = (n < 0 ? n + 4294967296 : n).toString(16);
    return hex.padStart(8, '0').match(/../g).reverse().join('');
  }).join('');
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
  });
}

function jsonError(msg, status = 400) {
  return json({ error: msg }, status);
}
