# PHP · Laravel · WordPress · Joomla (incl. cleaning a hacked site)

## Plain PHP essentials
```php
// DB: PDO with real prepared statements
$pdo = new PDO($dsn, $user, $pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]);
$stmt = $pdo->prepare('SELECT id, name FROM products WHERE name LIKE ?');
$stmt->execute(['%' . $q . '%']);
// Output: always escape
echo htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
// Passwords
$hash = password_hash($password, PASSWORD_ARGON2ID);      // or PASSWORD_DEFAULT (bcrypt)
if (!password_verify($password, $row['password_hash'])) { /* generic error */ }
// Sessions
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
session_start(); session_regenerate_id(true);               // after login
// Tokens
$token = bin2hex(random_bytes(32));                          // never rand()/mt_rand()/uniqid()
```
php.ini (production): `display_errors=Off`, `log_errors=On`, `expose_php=Off`, `allow_url_include=Off`, `session.cookie_httponly=1`, `session.cookie_secure=1`, `session.use_strict_mode=1`, `upload_max_filesize`/`post_max_size` sized to need; `disable_functions=exec,passthru,shell_exec,system,proc_open,popen` if the app doesn't need them.
Web root must be a `public/` folder; `.env`, `vendor/`, `composer.json`, `storage/` outside it. Uploads: deny PHP execution in the upload folder (Nginx: `location ^~ /uploads/ { location ~ \.php$ { return 403; } }`).

## Laravel
- `.env`: `APP_ENV=production`, `APP_DEBUG=false`, strong `APP_KEY` (`php artisan key:generate`), `SESSION_SECURE_COOKIE=true`, `SESSION_SAME_SITE=lax`; then `php artisan config:cache route:cache view:cache`.
- Validation: `$request->validate([...])` / FormRequest; `$fillable` (never `$guarded = []`); policies/gates (`$this->authorize('update', $order)`) and scoped queries (`$request->user()->orders()->findOrFail($id)`).
- Blade `{{ }}` escapes; audit `{!! !!}`. Query builder/Eloquent bindings; `whereRaw('x = ?', [$v])` only with bindings.
- Rate limiting: `RateLimiter::for('login', fn ($r) => Limit::perMinute(5)->by($r->input('email').$r->ip()))` + `->middleware('throttle:login')`; Fortify/Breeze have login throttling.
- CSRF: `VerifyCsrfToken` with an empty `$except` (webhooks excepted only with signature checks).
- Uploads: `'file' => 'required|file|mimes:jpg,png,pdf|max:5120'`, `store('docs', 'private')`, `Storage::temporaryUrl()` for downloads.
- Security headers via middleware or Nginx; `composer audit`; remove `telescope`/`debugbar` from production (or lock them down); Ignition must never be reachable in production.

## WordPress
- Core, themes, plugins updated (enable auto-updates for minor + trusted plugins); delete unused plugins/themes (deactivated code is still reachable).
- `wp-config.php`: unique salts (regenerate after an incident), `define('DISALLOW_FILE_EDIT', true); define('WP_DEBUG', false); define('WP_DEBUG_DISPLAY', false); define('FORCE_SSL_ADMIN', true);`, file mode 600/640; DB user without global privileges; non-default table prefix doesn't hurt.
- Login: 2FA for all admins/editors, login rate limiting (plugin or Nginx `limit_req` on `wp-login.php`), disable XML-RPC if unused (`location = /xmlrpc.php { deny all; }`), no `admin` username, minimal number of admins.
- Uploads: block PHP execution in `wp-content/uploads/`; file permissions 644 files / 755 dirs, owned by a deploy user (web server user should not own everything).
- REST API: check that `wp-json/wp/v2/users` doesn't leak usernames if that matters; custom endpoints need `permission_callback`.
- Backups off-server; WAF (Wordfence/Cloudflare) as an extra layer, not a substitute.

## Joomla
- Joomla core + every extension (component/module/plugin/template) updated via **System → Update**; uninstall unused extensions; check for extensions without updates for years (abandoned = replace).
- Global Configuration: Error Reporting **None**, Debug **No**, Force HTTPS **Entire Site**, session handler database, Gzip as needed; strong `$secret`; `configuration.php` permissions 444 (read-only) after saving.
- Rename `htaccess.txt` → `.htaccess` (Apache) — it contains Joomla's exploit-blocking rules; on Nginx replicate them. Make sure the `installation/` folder is gone.
- Administrator: Multi-factor Authentication (Joomla 4/5 built-in), few Super Users, strong unique passwords, optional extra protection of `/administrator` (HTTP auth or IP allow-list at the server).
- Disable user registration if not needed; review user groups/ACL; turn off unused web services/API (Joomla 4+ `api/`) or require tokens.
- Media/uploads: restrict allowed extensions (Media Manager options), no PHP execution in `images/`, `media/`, `tmp/`, `cache/`.

## Cleaning a compromised PHP/CMS site (incident response)
1. **Contain:** maintenance mode or take offline; change hosting/FTP/SFTP/SSH/control-panel passwords from a clean device; snapshot the whole site + DB for forensics (keep it offline).
2. **Find the extent:** `scan_code_patterns.py` (X12 rules: `eval(base64_decode`, `assert($_POST`, `preg_replace /e`, `$_POST['x'](`, FilesMan/WSO/b374k markers); list recently modified PHP files (`find . -name '*.php' -newermt '2026-01-01' -printf '%TY-%Tm-%Td %p\n' | sort`); PHP files inside upload/media/cache/tmp folders; unknown admin users; `.htaccess` redirects/`auto_prepend_file`; cron jobs; DB content with `<script`, iframe or spam links (`SELECT … WHERE content LIKE '%<script%'`); server access logs for POSTs to odd PHP files.
3. **Rebuild clean:** fresh core from the official source, reinstall extensions from vendors, restore only data/uploads (after scanning) and configuration values (re-typed, not copied files); remove anything you can't explain.
4. **Rotate everything:** DB password, CMS salts/secrets, all admin passwords (force reset for users), API keys, SMTP, payment keys; revoke sessions.
5. **Fix the entry point:** outdated extension? weak admin password? stolen FTP credentials? world-writable files? Patch it or the attacker returns.
6. **Harden + monitor:** steps above, file-integrity monitoring, WAF, off-site backups, alerts; request Google Search Console review if blacklisted.
Treat database dumps and user data as potentially exfiltrated — check notification duties (GDPR 72 h) if personal data was exposed.
