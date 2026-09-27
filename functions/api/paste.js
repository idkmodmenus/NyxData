/**
 * Cloudflare Pages Function: /api/paste
 * Checks HaveIBeenPwned paste database
 */

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const body   = await request.json();
    const email  = (body.email  || '').trim().toLowerCase();
    const apiKey = (body.apiKey || '').trim() || (env.HIBP_API_KEY || '');

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return jsonError('Invalid email address', 400);
    }

    if (!apiKey) {
      return json({ pastes: [], note: 'HIBP API key required for paste lookup' });
    }

    const res = await fetch(
      `https://haveibeenpwned.com/api/v3/pasteaccount/${encodeURIComponent(email)}`,
      {
        headers: {
          'hibp-api-key': apiKey,
          'User-Agent':   'Nyx-OSINT/1.0',
          'Accept':       'application/json',
        },
      }
    );

    if (res.status === 404) return json({ pastes: [] });
    if (res.status === 401) return jsonError('Invalid HIBP API key', 401);
    if (res.status === 429) return jsonError('Rate limited — wait a moment', 429);
    if (!res.ok)            return jsonError(`HTTP ${res.status}`, res.status);

    const data   = await res.json();
    const pastes = (data || []).map(p => ({
      source:     p.Source,
      id:         p.Id,
      title:      p.Title || 'Untitled',
      date:       p.Date,
      emailCount: p.EmailCount,
    }));

    return json({ pastes });
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

function jsonError(msg, status = 400) {
  return json({ error: msg }, status);
}
