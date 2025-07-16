export interface Env {}

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === '/api/health') {
      return new Response(JSON.stringify({ status: 'ok' }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return new Response('Not Found', { status: 404 });
  },
};
