#!/usr/bin/env bash
set -eu
cp -R "$(dirname "$0")/files/." .
cd shop-api
export GIT_AUTHOR_NAME="Shop Dev" GIT_AUTHOR_EMAIL="dev@golkhooneh.ir" GIT_COMMITTER_NAME="Shop Dev" GIT_COMMITTER_EMAIL="dev@golkhooneh.ir"
git init -q && (git checkout -q -b main 2>/dev/null || true)
printf 'node_modules/\n' > .gitignore
git add -A && git commit -qm "shop api"
echo "shop-api scaffolded"
