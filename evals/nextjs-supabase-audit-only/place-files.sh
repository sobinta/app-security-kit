#!/usr/bin/env bash
# Scaffold for the visa-portal test project (Next.js 14 + Supabase).
# Plants a committed .env.local whose service_role key uses the NEXT_PUBLIC_ prefix.
# The JWT-shaped keys are generated here, so no literal key lives in the repo.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
cp -R "$HERE/files/." .
cd visa-portal
# manifest stored as *.fixture so GitHub/Dependabot do not alert on this deliberately vulnerable sample
mv package.json.fixture package.json

make_jwt() {
python3 - "$1" <<'PY'
import base64, json, sys, hashlib
role = sys.argv[1]
b = lambda d: base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()
h = b({"alg": "HS256", "typ": "JWT"})
p = b({"iss": "supabase", "ref": "qzvlkxmbtwrnpodhaycs", "role": role, "iat": 1756700000, "exp": 2072276000})
sig = base64.urlsafe_b64encode(hashlib.sha256((h + p + role).encode()).digest()).rstrip(b"=").decode()
print(f"{h}.{p}.{sig}")
PY
}
ANON="$(make_jwt anon)"
SERVICE="$(make_jwt service_role)"
P1="sk"; P2="test"
cat > .env.local <<EOF
NEXT_PUBLIC_SUPABASE_URL=https://qzvlkxmbtwrnpodhaycs.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=${ANON}
NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=${SERVICE}
STRIPE_SECRET_KEY=${P1}_${P2}_51PqR$(printf 'mT4nV8bX2cZ6qW9e%.0s' 1 2)
OPENAI_API_KEY=${P1}-proj-$(printf 'Hh3Jk8Lm2Np5Qr7St%.0s' 1 2 3)
EOF

export GIT_AUTHOR_NAME="Portal Dev" GIT_AUTHOR_EMAIL="dev@visaportal.example"
export GIT_COMMITTER_NAME="Portal Dev" GIT_COMMITTER_EMAIL="dev@visaportal.example"
git init -q
git checkout -q -b main 2>/dev/null || true
git add -A
GIT_AUTHOR_DATE="2026-09-01T12:00:00" GIT_COMMITTER_DATE="2026-09-01T12:00:00" git commit -qm "visa portal v0.3"
echo "visa-portal scaffolded"
