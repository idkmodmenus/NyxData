/**
 * Cloudflare Pages Middleware
 * Handles CORS preflight for all /api/* routes
 */

export async function onRequest(context) {
  const { request, next } = context;

  // Handle OPTIONS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin':  '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age':       '86400',
      },
    });
  }

  const response = await next();

  // Add security headers to all responses
  const newHeaders = new Headers(response.headers);
  newHeaders.set('X-Content-Type-Options', 'nosniff');
  newHeaders.set('X-Frame-Options', 'DENY');
  newHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  newHeaders.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

  return new Response(response.body, {
    status:  response.status,
    headers: newHeaders,
  });
}
