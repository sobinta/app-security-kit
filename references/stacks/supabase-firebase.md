# Supabase · Firebase (Backend-as-a-Service)

With a BaaS the browser talks to the database directly, so **the database rules ARE the backend's security**. The anon/publishable key is public by design; it is only safe when every table, view, function and bucket is locked down.

## Supabase

### Keys
| Key | Where it may live | Notes |
|---|---|---|
| `anon` / `sb_publishable_…` | browser, mobile | safe only with RLS everywhere |
| `service_role` / `sb_secret_…` | server only (env) | **bypasses RLS**; never `NEXT_PUBLIC_`, never in a client bundle or mobile app |
| JWT secret / signing keys | Supabase dashboard | rotating invalidates sessions |

If `service_role` ever reached a client, a repo or a bundle: rotate it (new API keys / JWT secret in the dashboard), redeploy, and assume all data was readable and writable.

### Row Level Security (every table in exposed schemas, usually `public`)
```sql
alter table public.documents enable row level security;

-- read own rows
create policy "documents: owner can read" on public.documents
  for select to authenticated using ((select auth.uid()) = user_id);
-- insert only as yourself
create policy "documents: owner can insert" on public.documents
  for insert to authenticated with check ((select auth.uid()) = user_id);
-- update own rows, can't move them to someone else
create policy "documents: owner can update" on public.documents
  for update to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
-- staff/admin via a roles table (not via user-editable metadata)
create policy "documents: staff can read" on public.documents
  for select to authenticated using (exists (select 1 from public.staff s where s.user_id = (select auth.uid())));
```
- `using (true)` only for intentionally public data (e.g. published blog posts), and then only `for select`.
- Never base authorization on `raw_user_meta_data`/`user_metadata` (users can edit it). Use a table or `app_metadata` (server-set) / custom claims via Auth hooks.
- Multi-tenant: policies check membership (`exists (select 1 from members m where m.org_id = documents.org_id and m.user_id = (select auth.uid()))`) and the org id column is not client-editable to another org (`with check`).
- Wrap `auth.uid()` as `(select auth.uid())` — same meaning, much faster on big tables.

### Things that silently bypass RLS
- **Views** run with the owner's rights by default → `create view … with (security_invoker = true)` (Postgres 15+) or revoke access to them from `anon, authenticated`.
- **`security definer` functions** (and RPCs exposed through PostgREST) → keep them in a non-exposed schema, `set search_path = ''`, check `auth.uid()` inside, and `revoke execute on function … from anon, public` when not meant to be public.
- Tables created via SQL editor/migrations have **no RLS until you enable it**.
- `grant all … to anon` / `authenticated` beyond the defaults.

### Audit queries
```sql
-- tables without RLS in public
select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind = 'r' and not c.relrowsecurity;
-- all policies
select schemaname, tablename, policyname, roles, cmd, qual, with_check from pg_policies order by tablename;
-- security definer functions in exposed schemas
select p.proname, n.nspname from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where p.prosecdef and n.nspname in ('public');
-- views without security_invoker
select c.relname, c.reloptions from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind = 'v';
```
Also run the dashboard **Security Advisor** / `supabase db lint`, and test as the anon key:
```bash
curl -s "$SUPABASE_URL/rest/v1/documents?select=*" -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"   # expect [] or 401
```
Test policies as a specific user in SQL: `set local role authenticated; set local request.jwt.claims = '{"sub":"<user-uuid>"}'; select * from documents;` (inside a transaction).

### Storage
Private buckets for anything personal (passports, contracts, invoices); policies on `storage.objects` scoped by `bucket_id` and path prefix (`(storage.foldername(name))[1] = (select auth.uid())::text`); short-lived signed URLs (`createSignedUrl(path, 300)`); size + MIME limits on the bucket; never a public bucket for user documents.

### Auth settings
Email confirmation on; secure email change (confirm both addresses); OTP/magic-link expiry ≤ 1 h; redirect-URL allow-list (no wildcards on production); MFA (TOTP) for staff; leaked-password protection and minimum password length/strength; CAPTCHA (Turnstile/hCaptcha) on signup/sign-in if abused; auth rate limits reviewed.

### Server code (`@supabase/ssr`, Next.js)
- On the server, make authorization decisions with `supabase.auth.getUser()` (re-validates with the Auth server) or `getClaims()` (verifies the JWT signature) — **not** `getSession()`, which just reads the cookie.
- The service-role client lives in a `server-only` module, created per request, never exported to client components.
- Edge Functions: verify the JWT (default) and check roles; keep secrets in function secrets.

### Realtime
`postgres_changes` respects RLS on the table; Broadcast/Presence on private channels need Realtime authorization policies — don't broadcast sensitive data on public channels.

## Firebase

### Firestore rules (deny by default)
```
rules_version = '2';
service cloud.firestore {
  match /databases/{db}/documents {
    match /users/{uid} {
      allow read, update: if request.auth != null && request.auth.uid == uid
                          && !request.resource.data.diff(resource.data).affectedKeys().hasAny(['role', 'credits']);
      allow create: if request.auth != null && request.auth.uid == uid;
    }
    match /orders/{orderId} {
      allow read: if request.auth != null && resource.data.userId == request.auth.uid;
      allow write: if false;                       // only Cloud Functions (Admin SDK) write orders/prices
    }
  }
}
```
Never `allow read, write: if true;` or `if request.auth != null` alone on shared collections. Storage rules: check `request.auth.uid` path segment, `request.resource.size < 5 * 1024 * 1024`, `request.resource.contentType.matches('image/.*')`. RTDB: no `".read": true` at the root.

### Other Firebase points
- Web API key is public by design → restrict it (HTTP referrers, allowed APIs) in Google Cloud console.
- Admin SDK / service-account JSON: server only, never in the repo (rotate if it was).
- App Check to reduce abuse from scripts; budget alerts.
- Prices, roles, credits: only written by Cloud Functions; clients send intents.
- Test with the Emulator Suite + `@firebase/rules-unit-testing`.
