# Next.js (App Router & Pages Router) · React SPAs

## Mental model
- **Route Handlers (`app/**/route.ts`), Pages API routes and Server Actions are public HTTP endpoints.** Each one authenticates, authorizes and validates on its own. `"use server"` functions can be called by anyone who finds the action id.
- **Middleware is a convenience, not a security boundary.** Matchers miss paths, and unpatched versions allowed a full bypass with the `x-middleware-subrequest` header (CVE-2025-29927, fixed in 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3). Re-check the session + role in every page/handler/action that needs it.
- **Everything passed from a Server Component to a Client Component is serialized to the browser.** Don't pass whole DB rows (password hashes, emails of others, internal flags) — select the fields you need.
- `NEXT_PUBLIC_*` values are inlined into the JS bundle at build time → only public values.

## Data access layer (recommended pattern)
```ts
// lib/dal.ts
import 'server-only';                       // build fails if a client component imports this
import { cache } from 'react';
import { auth } from '@/auth';              // Auth.js v5 (or getServerSession / supabase.auth.getUser())

export const requireUser = cache(async () => {
  const session = await auth();
  if (!session?.user) throw new Error('UNAUTHENTICATED');
  return session.user;
});
export async function requireAdmin() {
  const user = await requireUser();
  if (user.role !== 'admin') throw new Error('FORBIDDEN');
  return user;
}
export async function getOrderForUser(orderId: string) {
  const user = await requireUser();
  return db.order.findFirst({ where: { id: orderId, userId: user.id }, select: { id: true, total: true, status: true } });
}
```

## Server Action with validation + authorization
```ts
'use server';
import { z } from 'zod';
import { requireUser } from '@/lib/dal';

const UpdateProfile = z.object({ name: z.string().trim().min(1).max(80), bio: z.string().max(500).optional() }).strict();

export async function updateProfile(formData: FormData) {
  const user = await requireUser();
  const data = UpdateProfile.parse(Object.fromEntries(formData));   // role/isAdmin can't sneak in (.strict())
  await db.user.update({ where: { id: user.id }, data });
}
```
Server Actions compare `Origin` with `Host` (CSRF protection). Behind a proxy/CDN with different hosts set `experimental.serverActions.allowedOrigins` (Next 14) / `serverActions.allowedOrigins` (15). Body limit: `serverActions.bodySizeLimit` (default 1 MB).

## Route Handler guard
```ts
// app/api/admin/users/route.ts
import { NextResponse } from 'next/server';
import { requireAdmin } from '@/lib/dal';
export async function GET() {
  try { await requireAdmin(); } catch { return NextResponse.json({ error: 'forbidden' }, { status: 403 }); }
  const users = await db.user.findMany({ select: { id: true, email: true, role: true } });
  return NextResponse.json(users);
}
```

## Security headers (next.config.js) + CSP nonce (middleware)
```js
// next.config.js
const securityHeaders = [
  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
];
module.exports = {
  poweredByHeader: false,
  productionBrowserSourceMaps: false,
  images: { remotePatterns: [{ protocol: 'https', hostname: 'images.example-cdn.com' }] }, // never hostname: '**'
  async headers() { return [{ source: '/(.*)', headers: securityHeaders }]; },
};
```
```ts
// middleware.ts — nonce-based CSP (pages using it must be dynamically rendered)
import { NextResponse, type NextRequest } from 'next/server';
export function middleware(req: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');
  const csp = [
    "default-src 'self'", `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`, "style-src 'self' 'unsafe-inline'",
    "img-src 'self' blob: data:", "font-src 'self'", "object-src 'none'", "base-uri 'self'", "form-action 'self'",
    "frame-ancestors 'none'", 'upgrade-insecure-requests',
  ].join('; ');
  const headers = new Headers(req.headers);
  headers.set('x-nonce', nonce);
  headers.set('Content-Security-Policy', csp);
  const res = NextResponse.next({ request: { headers } });
  res.headers.set('Content-Security-Policy', csp);
  return res;
}
export const config = { matcher: [{ source: '/((?!api|_next/static|_next/image|favicon.ico).*)' }] };
```
Add third-party origins (analytics, Stripe.js `https://js.stripe.com`, Sentry) explicitly. Start with `Content-Security-Policy-Report-Only` if unsure.

## Auth.js / next-auth
- Strong `AUTH_SECRET`/`NEXTAUTH_SECRET` (`openssl rand -base64 48`); rotating it logs everyone out.
- Put the role into the token/session in `callbacks.jwt`/`callbacks.session`, read it from the DB on sign-in (never from the client).
- Credentials provider = you own hashing (argon2/bcrypt), rate limiting and lockout.
- Validate `callbackUrl` / redirects (only relative or your origin). `trustHost: true` only behind a trusted proxy.

## Rate limiting
```ts
// lib/ratelimit.ts — Upstash (serverless) or swap for a Redis/memory limiter on a single VPS process
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';
export const loginLimiter = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(5, '1 m'), prefix: 'rl:login' });
// in the handler/action:
const ip = (await headers()).get('x-forwarded-for')?.split(',')[0]?.trim() ?? 'unknown';
const { success } = await loginLimiter.limit(`${ip}:${email.toLowerCase()}`);
if (!success) return NextResponse.json({ error: 'Too many attempts' }, { status: 429 });
```
On a VPS behind Nginx, also add `limit_req` (assets/nginx/rate-limit.conf). Only trust `x-forwarded-for` when your proxy sets it.

## Caching pitfalls (data leaks between users)
Personalised pages/handlers must be dynamic (`cookies()`/`headers()` usage, `export const dynamic = 'force-dynamic'`, `cache: 'no-store'`); `unstable_cache`/`fetch` cache keys must include the user id; CDN must not cache responses with `Set-Cookie` or user data (`Cache-Control: private, no-store`).

## Uploads in route handlers
```ts
const form = await req.formData();
const file = form.get('file');
if (!(file instanceof File) || file.size > 5 * 1024 * 1024) return NextResponse.json({ error: 'bad file' }, { status: 400 });
const buf = Buffer.from(await file.arrayBuffer());
const { fileTypeFromBuffer } = await import('file-type');               // ESM-only package
const type = await fileTypeFromBuffer(buf);
if (!type || !['image/png', 'image/jpeg', 'image/webp'].includes(type.mime)) return NextResponse.json({ error: 'type' }, { status: 400 });
const key = `${crypto.randomUUID()}.${type.ext}`;                        // never the original name
// store in private storage (S3/Supabase private bucket) — not in /public
```

## Checks specific to Next.js
- `npm ls next` → patched version of your major; re-run `npm audit` (Next advisories are frequent).
- `grep -rn "NEXT_PUBLIC_" .env* src app | grep -iE "secret|service|private|password"` → must be empty.
- After `next build`: grep `.next/static` for secrets (S02).
- `dangerouslySetInnerHTML` only with DOMPurify (`isomorphic-dompurify` on the server).
- `redirect()`/`NextResponse.redirect()` targets from user input → allow-list.
- Self-hosted: `next start` behind Nginx with `NODE_ENV=production`; don't expose the Node port publicly.

## React SPA (Vite/CRA) specifics
Every `VITE_*`/`REACT_APP_*` variable is public. An SPA has no server secrets at all — anything secret needs a backend (API, serverless function, Supabase Edge Function). Client-side route guards are UX only; the API must enforce auth.
