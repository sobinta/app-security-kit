#!/usr/bin/env bash
# Scaffold for the golkhooneh test project: copies the app, then plants what a
# real vibe-coded repo tends to have — fake (but realistic-looking) API keys in
# the client and in git history, a committed backup.zip, and an untracked .env.
# Key strings are assembled here so no literal secret pattern lives in the repo.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
cp -R "$HERE/files/." .
cd golkhooneh
# manifests are stored as *.fixture so GitHub/Dependabot do not alert on this deliberately vulnerable sample
mv package.json.fixture package.json && mv package-lock.json.fixture package-lock.json

P1="sk"; P2="live"
STRIPE_OLD="${P1}_${P2}_51Hc$(printf 'Q7wE9rT2yU4iO6pA%.0s' 1 2)"
STRIPE_NEW="${P1}_${P2}_51Nd$(printf 'Z3xC5vB7nM9kL1jH%.0s' 1 2)"
WEATHER="${P1}-proj-$(printf 'Wx8Rt5Yq2Lm7Np4Kd%.0s' 1 2 3)"

sed -i.bak "s/__WEATHER_KEY__/${WEATHER}/" public/app.js && rm -f public/app.js.bak

export GIT_AUTHOR_NAME="Golkhooneh Dev" GIT_AUTHOR_EMAIL="dev@golkhooneh.ir"
export GIT_COMMITTER_NAME="Golkhooneh Dev" GIT_COMMITTER_EMAIL="dev@golkhooneh.ir"
git init -q
git checkout -q -b main 2>/dev/null || true
printf 'node_modules/\ndata/\n' > .gitignore
git add -A
GIT_AUTHOR_DATE="2026-08-02T10:00:00" GIT_COMMITTER_DATE="2026-08-02T10:00:00" git commit -qm "initial golkhooneh shop"

mkdir -p config
cat > config/keys.js <<EOF
// payment + weather keys
module.exports = {
  stripeSecretKey: '${STRIPE_OLD}',
  weatherApiKey: '${WEATHER}',
};
EOF
git add config/keys.js
GIT_AUTHOR_DATE="2026-08-09T21:14:00" GIT_COMMITTER_DATE="2026-08-09T21:14:00" git commit -qm "add payment keys"

# a "quick backup" that ended up in the web root (and in git)
TMP="$(mktemp -d)"
cat > "$TMP/.env" <<EOF
APP_NAME=Golkhooneh
PAY_SECRET=${STRIPE_OLD}
SESSION_SECRET=secret
EOF
cat > "$TMP/db-dump.sql" <<'EOF'
-- golkhooneh users dump
CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password TEXT, name TEXT, role TEXT);
INSERT INTO users VALUES (1,'sara@golkhooneh.ir','plant-lover','Sara','admin');
INSERT INTO users VALUES (2,'ali@golkhooneh.ir','123456','Ali','user');
EOF
python3 - "$TMP" public/backup.zip <<'PY'
import sys, zipfile, os
src, dst = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(dst, "w") as z:
    for n in (".env", "db-dump.sql"):
        z.write(os.path.join(src, n), n)
PY
rm -rf "$TMP"
sed -i.bak 's|<strong>🌿 گلخونه</strong>|<strong>🌿 گلخونه</strong> <small>beta</small>|' public/index.html && rm -f public/index.html.bak
git add -A
GIT_AUTHOR_DATE="2026-08-15T18:30:00" GIT_COMMITTER_DATE="2026-08-15T18:30:00" git commit -qm "fix navbar"

git rm -q config/keys.js
printf '.env\n' >> .gitignore
git add .gitignore
GIT_AUTHOR_DATE="2026-08-20T11:05:00" GIT_COMMITTER_DATE="2026-08-20T11:05:00" git commit -qm "move keys to env"

cat > .env <<EOF
APP_NAME=Golkhooneh
THEME=green
PORT=3000
SESSION_SECRET=secret
PAY_SECRET=${STRIPE_NEW}
WEATHER_API_KEY=${WEATHER}
EOF
echo "golkhooneh scaffolded: $(git log --oneline | wc -l) commits"
