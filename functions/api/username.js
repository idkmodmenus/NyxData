/**
 * Cloudflare Pages Function: /api/username
 * Checks 60+ social platforms for a given username
 */

const PLATFORMS = [
  // Social
  { name: 'Twitter/X',      url: 'https://twitter.com/{u}',                        check: 'not404' },
  { name: 'Instagram',      url: 'https://www.instagram.com/{u}/',                  check: 'not404' },
  { name: 'TikTok',         url: 'https://www.tiktok.com/@{u}',                    check: 'not404' },
  { name: 'Facebook',       url: 'https://www.facebook.com/{u}',                   check: 'not404' },
  { name: 'Snapchat',       url: 'https://www.snapchat.com/add/{u}',               check: 'not404' },
  { name: 'Pinterest',      url: 'https://www.pinterest.com/{u}/',                 check: 'not404' },
  { name: 'Reddit',         url: 'https://www.reddit.com/user/{u}',                check: 'not404' },
  { name: 'Tumblr',         url: 'https://{u}.tumblr.com/',                        check: 'not404' },
  { name: 'Mastodon',       url: 'https://mastodon.social/@{u}',                   check: 'not404' },
  // Dev
  { name: 'GitHub',         url: 'https://github.com/{u}',                         check: 'not404' },
  { name: 'GitLab',         url: 'https://gitlab.com/{u}',                         check: 'not404' },
  { name: 'Bitbucket',      url: 'https://bitbucket.org/{u}/',                     check: 'not404' },
  { name: 'Stack Overflow', url: 'https://stackoverflow.com/users/{u}',            check: 'not404' },
  { name: 'HackerNews',     url: 'https://news.ycombinator.com/user?id={u}',       check: 'bodyNotContains:No such user' },
  { name: 'Dev.to',         url: 'https://dev.to/{u}',                             check: 'not404' },
  { name: 'CodePen',        url: 'https://codepen.io/{u}',                         check: 'not404' },
  { name: 'Replit',         url: 'https://replit.com/@{u}',                        check: 'not404' },
  { name: 'npm',            url: 'https://www.npmjs.com/~{u}',                     check: 'not404' },
  { name: 'PyPI',           url: 'https://pypi.org/user/{u}/',                     check: 'not404' },
  { name: 'Docker Hub',     url: 'https://hub.docker.com/u/{u}/',                  check: 'not404' },
  { name: 'Hashnode',       url: 'https://hashnode.com/@{u}',                      check: 'not404' },
  // Professional
  { name: 'LinkedIn',       url: 'https://www.linkedin.com/in/{u}',                check: 'not404' },
  { name: 'Keybase',        url: 'https://keybase.io/{u}',                         check: 'not404' },
  // Gaming
  { name: 'Steam',          url: 'https://steamcommunity.com/id/{u}',              check: 'bodyNotContains:The specified profile' },
  { name: 'Twitch',         url: 'https://www.twitch.tv/{u}',                      check: 'not404' },
  { name: 'Roblox',         url: 'https://www.roblox.com/user.aspx?username={u}',  check: 'not404' },
  { name: 'Chess.com',      url: 'https://www.chess.com/member/{u}',               check: 'not404' },
  // Creative
  { name: 'Medium',         url: 'https://medium.com/@{u}',                        check: 'not404' },
  { name: 'Substack',       url: 'https://{u}.substack.com',                       check: 'not404' },
  { name: 'Behance',        url: 'https://www.behance.net/{u}',                    check: 'not404' },
  { name: 'Dribbble',       url: 'https://dribbble.com/{u}',                       check: 'not404' },
  { name: 'DeviantArt',     url: 'https://www.deviantart.com/{u}',                 check: 'not404' },
  { name: 'SoundCloud',     url: 'https://soundcloud.com/{u}',                     check: 'not404' },
  { name: 'Last.fm',        url: 'https://www.last.fm/user/{u}',                   check: 'not404' },
  { name: 'YouTube',        url: 'https://www.youtube.com/@{u}',                   check: 'not404' },
  { name: 'Vimeo',          url: 'https://vimeo.com/{u}',                          check: 'not404' },
  { name: 'Flickr',         url: 'https://www.flickr.com/people/{u}/',             check: 'not404' },
  // Community
  { name: 'Quora',          url: 'https://www.quora.com/profile/{u}',              check: 'not404' },
  { name: 'ProductHunt',    url: 'https://www.producthunt.com/@{u}',               check: 'not404' },
  { name: 'Wikipedia',      url: 'https://en.wikipedia.org/wiki/User:{u}',         check: 'not404' },
  // Other
  { name: 'Patreon',        url: 'https://www.patreon.com/{u}',                    check: 'not404' },
  { name: 'Ko-fi',          url: 'https://ko-fi.com/{u}',                          check: 'not404' },
  { name: 'Linktree',       url: 'https://linktr.ee/{u}',                          check: 'not404' },
  { name: 'About.me',       url: 'https://about.me/{u}',                           check: 'not404' },
  { name: 'Gravatar',       url: 'https://en.gravatar.com/{u}',                    check: 'not404' },
  { name: 'Fiverr',         url: 'https://www.fiverr.com/{u}',                     check: 'not404' },
  { name: 'Etsy',           url: 'https://www.etsy.com/shop/{u}',                  check: 'not404' },
  { name: 'Ebay',           url: 'https://www.ebay.com/usr/{u}',                   check: 'not404' },
  { name: 'Telegram',       url: 'https://t.me/{u}',                               check: 'not404' },
  { name: 'Venmo',          url: 'https://venmo.com/{u}',                          check: 'not404' },
  { name: 'Trello',         url: 'https://trello.com/{u}',                         check: 'not404' },
  { name: 'Notion',         url: 'https://www.notion.so/@{u}',                     check: 'not404' },
  { name: 'Spotify',        url: 'https://open.spotify.com/user/{u}',              check: 'not404' },
  { name: 'Bandcamp',       url: 'https://bandcamp.com/{u}',                       check: 'not404' },
  { name: 'AngelList',      url: 'https://angel.co/u/{u}',                         check: 'not404' },
  { name: 'Disqus',         url: 'https://disqus.com/by/{u}/',                     check: 'not404' },
];

export async function onRequestPost(context) {
  const { request } = context;

  try {
    const body     = await request.json();
    const username = (body.username || '').trim();

    if (!username || username.length < 1 || username.length > 64) {
      return jsonError('Invalid username', 400);
    }
    if (!/^[a-zA-Z0-9._\-]+$/.test(username)) {
      return jsonError('Username contains invalid characters', 400);
    }

    // Run checks in batches of 10 to respect Workers CPU limits
    const BATCH = 10;
    const results = [];

    for (let i = 0; i < PLATFORMS.length; i += BATCH) {
      const batch = PLATFORMS.slice(i, i + BATCH);
      const batchResults = await Promise.all(
        batch.map(p => checkPlatform(username, p))
      );
      results.push(...batchResults);
    }

    return json({ results, total: results.length, found: results.filter(r => r.found).length });

  } catch (err) {
    return jsonError(err.message || 'Internal error', 500);
  }
}

async function checkPlatform(username, platform) {
  const url = platform.url.replace(/\{u\}/g, encodeURIComponent(username));

  try {
    const [checkType, ...rest] = platform.check.split(':');
    const searchStr = rest.join(':');

    if (checkType === 'not404') {
      const res = await fetch(url, {
        method: 'HEAD',
        redirect: 'follow',
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; Nyx-OSINT/1.0)' },
        signal: AbortSignal.timeout(8000),
      });
      const found = res.status !== 404 && res.status !== 410 && res.status < 500;
      return { platform: platform.name, url, found };
    }

    if (checkType === 'bodyNotContains' || checkType === 'bodyContains') {
      const res = await fetch(url, {
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; Nyx-OSINT/1.0)' },
        signal: AbortSignal.timeout(10000),
      });
      if (!res.ok && res.status === 404) return { platform: platform.name, url, found: false };
      const text    = await res.text();
      const has     = text.toLowerCase().includes(searchStr.toLowerCase());
      const found   = checkType === 'bodyContains' ? has : !has;
      return { platform: platform.name, url, found: found && res.status < 400 };
    }

    return { platform: platform.name, url, found: false };
  } catch {
    return { platform: platform.name, url, found: false };
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
