# Python · Django · Flask · FastAPI

## Django
Run `python manage.py check --deploy` — it lists most misconfigurations. Production settings:
```python
DEBUG = False                                   # from env; default False
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]   # fail fast if missing
ALLOWED_HOSTS = ["example.com", "www.example.com"]
CSRF_TRUSTED_ORIGINS = ["https://example.com"]
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")   # only behind a proxy that sets it
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
PASSWORD_HASHERS = ["django.contrib.auth.hashers.Argon2PasswordHasher",   # pip install argon2-cffi
                    "django.contrib.auth.hashers.PBKDF2PasswordHasher"]
DATA_UPLOAD_MAX_MEMORY_SIZE = 2_621_440
FILE_UPLOAD_MAX_MEMORY_SIZE = 2_621_440
```
- Keep `CsrfViewMiddleware`; remove stray `@csrf_exempt`.
- ORM by default; raw SQL only as `cursor.execute("… WHERE id = %s", [pk])`, never f-strings; avoid `.extra()`.
- Templates auto-escape; audit `|safe`, `mark_safe`, `{% autoescape off %}`.
- Authorization: `@login_required` + object ownership (`get_object_or_404(Order, pk=pk, user=request.user)`); DRF `permission_classes` on every view, `IsAuthenticated` default in settings.
- Rate limiting: `django-axes` (login lockout) and/or `django-ratelimit`; DRF `DEFAULT_THROTTLE_RATES`.
- CSP: `django-csp`. Admin: move `/admin/` to an unguessable path is *not* security — add 2FA (`django-otp`) and IP allow-listing.
- Uploads: validate extension + content (Pillow `Image.verify()`), size, random names, `MEDIA_ROOT` not executable, serve private files via views with permission checks.

## Flask
```python
app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],
    SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
)
from flask_wtf.csrf import CSRFProtect; CSRFProtect(app)
from flask_limiter import Limiter; from flask_limiter.util import get_remote_address
limiter = Limiter(get_remote_address, app=app, storage_uri=os.environ.get("REDIS_URL", "memory://"))
@app.post("/login")
@limiter.limit("5/minute")
def login(): ...
from flask_talisman import Talisman; Talisman(app, content_security_policy={"default-src": "'self'"})
```
- Never `app.run(debug=True)` in production (Werkzeug debugger = remote code execution). Use gunicorn/uwsgi.
- Passwords: `werkzeug.security.generate_password_hash` (scrypt/pbkdf2) or `argon2-cffi`.
- Uploads: `secure_filename` + extension allow-list + content check + random name; `send_from_directory` for downloads.
- Jinja: avoid `|safe`/`Markup()` on user data; never `render_template_string(user_input)` (SSTI).
- Behind a proxy: `werkzeug.middleware.proxy_fix.ProxyFix(app.wsgi_app, x_for=1, x_proto=1)`.

## FastAPI
```python
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["api.example.com"])
app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True,
                   allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Authorization", "Content-Type"])
```
- Pydantic models for every body (`model_config = ConfigDict(extra="forbid")`), `Field(ge=1, le=10)` for ranges; `response_model` so internal fields (password_hash) never leak.
- Auth dependency on every router: `router = APIRouter(dependencies=[Depends(get_current_user)])`; role checks as dependencies; ownership checks in queries.
- JWT (python-jose/pyjwt): `jwt.decode(token, key, algorithms=["HS256"])`, short `exp`, never `options={"verify_signature": False}`.
- Rate limiting: `slowapi` or at Nginx. Security headers: middleware or Nginx (`assets/nginx`).
- SQLAlchemy: bound parameters (`text("… WHERE id = :id").bindparams(id=x)`); never f-strings in `text()`.
- Run with `uvicorn --proxy-headers --forwarded-allow-ips=127.0.0.1` behind Nginx; docs (`/docs`, `/openapi.json`) off or protected in production if the API is private (`FastAPI(docs_url=None, redoc_url=None, openapi_url=None)`).

## Python dependency audit
`pip install pip-audit && pip-audit -r requirements.txt` (or `pip-audit` inside the venv); pin with hashes for production (`pip-compile --generate-hashes`); `safety`/`osv-scanner` as alternatives. Don't use `pickle`/`yaml.load` on untrusted data; `defusedxml` for XML.
