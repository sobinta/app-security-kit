#!/usr/bin/env python3
"""Detect a project's stack and security-relevant features so the audit can
load the right references and skip steps that don't apply (N/A).

Usage:
  python3 detect_stack.py <project_dir> [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import iter_files, read_text, write_json  # noqa: E402

FEATURES = {
    "auth": ["next-auth", "@auth/", "@supabase/ssr", "@supabase/auth-helpers", "@clerk/", "auth0", "passport", "lucia",
             "better-auth", "iron-session", "express-session", "jsonwebtoken", "jose", "firebase", "django.contrib.auth",
             "flask-login", "flask_login", "fastapi-users", "laravel/sanctum", "laravel/breeze", "laravel/fortify"],
    "payments": ["stripe", "@stripe/", "paypal", "braintree", "mollie", "lemonsqueezy", "@paddle/", "zarinpal", "idpay",
                 "nextpay", "razorpay", "adyen", "square", "laravel/cashier"],
    "uploads": ["multer", "formidable", "busboy", "express-fileupload", "uploadthing", "@uploadthing/", "react-dropzone",
                "filepond", "@aws-sdk/client-s3", "cloudinary", "storage.from(", "move_uploaded_file", "UploadFile",
                "FileField", "request.files"],
    "email": ["nodemailer", "resend", "@sendgrid/", "mailgun", "postmark", "@react-email/", "smtplib", "PHPMailer",
              "symfony/mailer"],
    "ai": ["openai", "@anthropic-ai/sdk", "anthropic", "@ai-sdk/", "\"ai\"", "langchain", "@langchain/", "@google/generative-ai",
           "groq-sdk", "ollama", "replicate"],
    "websockets": ["socket.io", "\"ws\"", "@socket.io/", "pusher", "ably", "channels", "websockets", "ratchet"],
    "telegram": ["telegraf", "node-telegram-bot-api", "grammy", "@telegram-apps/", "aiogram", "python-telegram-bot",
                 "telegram.WebApp", "initData"],
    "graphql": ["graphql", "@apollo/", "apollo-server", "graphene", "strawberry", "lighthouse-php"],
    "realtime_db": ["firebase", "firestore", "@supabase/realtime-js", "supabase.channel("],
}
FRAMEWORKS = {
    "nextjs": ["\"next\""], "react": ["\"react\""], "vue": ["\"vue\""], "nuxt": ["\"nuxt\""], "svelte": ["\"svelte\""],
    "sveltekit": ["@sveltejs/kit"], "astro": ["\"astro\""], "remix": ["@remix-run/"], "angular": ["@angular/core"],
    "express": ["\"express\""], "fastify": ["\"fastify\""], "koa": ["\"koa\""], "hono": ["\"hono\""], "nestjs": ["@nestjs/core"],
    "vite": ["\"vite\""], "react-native": ["\"react-native\""], "expo": ["\"expo\""], "electron": ["\"electron\""],
    "django": ["django"], "flask": ["flask"], "fastapi": ["fastapi"], "laravel": ["laravel/framework"],
    "symfony": ["symfony/framework-bundle"],
}
DATA = {
    "supabase": ["@supabase/"], "firebase": ["firebase"], "prisma": ["prisma", "@prisma/client"], "drizzle": ["drizzle-orm"],
    "postgres": ["\"pg\"", "postgres", "psycopg", "asyncpg"], "mysql": ["mysql2", "\"mysql\"", "pymysql", "mysqlclient"],
    "mongodb": ["mongodb", "mongoose", "pymongo", "motor"], "sqlite": ["sqlite3", "better-sqlite3", "node:sqlite"],
    "redis": ["redis", "ioredis", "@upstash/redis"], "sequelize": ["sequelize"], "typeorm": ["typeorm"], "knex": ["knex"],
}
REFS = {
    "nextjs": "references/stacks/nextjs.md", "react": "references/stacks/nextjs.md",
    "express": "references/stacks/node-express.md", "fastify": "references/stacks/node-express.md",
    "koa": "references/stacks/node-express.md", "hono": "references/stacks/node-express.md",
    "nestjs": "references/stacks/node-express.md", "vite": "references/stacks/nextjs.md",
    "supabase": "references/stacks/supabase-firebase.md", "firebase": "references/stacks/supabase-firebase.md",
    "django": "references/stacks/python.md", "flask": "references/stacks/python.md", "fastapi": "references/stacks/python.md",
    "laravel": "references/stacks/php-cms.md", "symfony": "references/stacks/php-cms.md", "php": "references/stacks/php-cms.md",
    "wordpress": "references/stacks/php-cms.md", "joomla": "references/stacks/php-cms.md",
    "react-native": "references/stacks/mobile.md", "expo": "references/stacks/mobile.md", "flutter": "references/stacks/mobile.md",
    "vps": "references/stacks/vps-docker-nginx.md",
}


def detect(root: Path) -> dict:
    root = root.resolve()
    blob_parts = []
    for name in ("package.json", "requirements.txt", "pyproject.toml", "Pipfile", "composer.json", "go.mod", "Gemfile",
                 "pubspec.yaml"):
        for p in [root / name] + list(root.glob(f"*/{name}"))[:10]:
            if p.exists() and "node_modules" not in p.parts:
                blob_parts.append(read_text(p))
    deps_blob = "\n".join(blob_parts)
    code_blob = []
    n = 0
    for p in iter_files(root, max_bytes=300_000):
        if p.suffix.lower() in {".js", ".jsx", ".ts", ".tsx", ".py", ".php", ".vue", ".svelte", ".mjs", ".cjs"}:
            code_blob.append(read_text(p)[:20000])
            n += 1
            if n > 1500:
                break
    code = "\n".join(code_blob)
    all_text = deps_blob + "\n" + code

    def has_any(needles, text):
        return any(x.lower() in text.lower() for x in needles)

    frameworks = [k for k, v in FRAMEWORKS.items() if has_any(v, deps_blob)]
    data = [k for k, v in DATA.items() if has_any(v, deps_blob)]
    features = [k for k, v in FEATURES.items() if has_any(v, all_text)]
    languages = []
    if (root / "package.json").exists() or list(root.glob("*/package.json")):
        languages.append("javascript/typescript")
    if any((root / f).exists() for f in ("requirements.txt", "pyproject.toml", "Pipfile", "manage.py")):
        languages.append("python")
    if (root / "composer.json").exists() or list(root.glob("*.php")) or (root / "index.php").exists():
        languages.append("php")
    if (root / "pubspec.yaml").exists():
        languages.append("dart")
        frameworks.append("flutter")
    if (root / "wp-config.php").exists() or (root / "wp-content").is_dir():
        frameworks.append("wordpress")
    if (root / "configuration.php").exists() and (root / "administrator").is_dir():
        frameworks.append("joomla")
    if (root / "supabase").is_dir() and "supabase" not in data:
        data.append("supabase")
    if (root / "firebase.json").exists() and "firebase" not in data:
        data.append("firebase")
    infra = []
    checks = {
        "docker": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"],
        "pm2": ["ecosystem.config.js", "ecosystem.config.cjs", "ecosystem.json"],
        "vercel": ["vercel.json", ".vercel"], "netlify": ["netlify.toml", "_headers"],
        "github-actions": [".github/workflows"], "nginx": ["nginx.conf", "nginx", "deploy/nginx.conf"],
    }
    for k, files in checks.items():
        if any((root / f).exists() for f in files):
            infra.append(k)
    if list(root.glob("**/*.conf"))[:1] and any("server {" in read_text(p) for p in list(root.glob("**/*.conf"))[:20]
                                                 if "node_modules" not in p.parts):
        infra.append("nginx")
    has_middleware = any((root / p).exists() for p in ("middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js"))
    own_password_auth = bool(re.search(r"bcrypt|argon2|password_hash|hashPassword|CredentialsProvider|signInWithPassword|"
                                       r"/login|/signin|def login", all_text, re.I))
    managed_auth = [x for x in ("supabase", "firebase", "clerk", "auth0", "next-auth") if x in all_text.lower()]

    refs = sorted({REFS[k] for k in frameworks + data if k in REFS} |
                  ({REFS["php"]} if "php" in languages else set()) |
                  ({REFS["vps"]} if {"docker", "pm2", "nginx"} & set(infra) else set()))
    not_applicable = {}
    if "payments" not in features and not re.search(r"price|checkout|order|cart", all_text, re.I):
        not_applicable["S19"] = "no payments/prices detected"
    if "uploads" not in features and not re.search(r"upload|multipart|FormData", all_text, re.I):
        not_applicable["S18"] = "no file uploads detected"
    if not own_password_auth and managed_auth:
        not_applicable["S05"] = f"passwords handled by managed auth ({', '.join(managed_auth)}) — verify its settings instead"
        not_applicable["S17"] = f"reset flow handled by managed auth ({', '.join(managed_auth)}) — verify token expiry setting"
    return {
        "root": str(root), "languages": sorted(set(languages)), "frameworks": sorted(set(frameworks)),
        "data_stores": sorted(set(data)), "features": sorted(set(features)), "infra": sorted(set(infra)),
        "nextjs_middleware": has_middleware, "own_password_auth": own_password_auth, "managed_auth": managed_auth,
        "references_to_read": refs + ["references/checklist-27.md", "references/extra-checks.md"],
        "probably_not_applicable": not_applicable,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("project")
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    res = detect(Path(a.project))
    print(json.dumps(res, indent=2, ensure_ascii=False))
    if a.json:
        write_json(Path(a.json), res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
