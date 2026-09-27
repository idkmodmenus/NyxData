/**
 * Cloudflare Pages Function: /api/password
 *
 * Uses the HIBP k-anonymity Pwned Passwords API.
 * The password is hashed client-side (SHA-1), only the first 5 chars
 * are sent to this worker, which forwards to HIBP. The full hash
 * never leaves the browser — completely private.
 *
 * No API key required. Free and unlimited.
 */

export async function onRequestPost(context) {
  const { request } = context;

  try {
    const body   = await request.json();
    const prefix = (body.prefix || '').trim().toUpperCase();

    if (!prefix || prefix.length !== 5 || !/^[0-9A-F]{5}$/.test(prefix)) {
      return jsonError('Invalid hash prefix — must be 5 hex characters', 400);
    }

    const res = await fetch(
      `https://api.pwnedpasswords.com/range/${prefix}`,
      {
        headers: {
          'User-Agent': 'Nyx-OSINT/1.0',
          'Add-Padding': 'true', // pads response to prevent timing attacks
        },
        signal: AbortSignal.timeout(8000),
      }
    );

    if (!res.ok) return jsonError(`HIBP API returned ${res.status}`, res.status);

    const text    = await res.text();
    const entries = text.trim().split('\n').map(line => {
      const [suffix, count] = line.split(':');
      return { suffix: suffix.trim(), count: parseInt(count.trim(), 10) };
    });

    return json({ prefix, entries });

  } catch (err) {
    return jsonError(err.message || 'Internal error', 500);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
  });
}
function jsonError(msg, status = 400) { return json({ error: msg }, status); }
