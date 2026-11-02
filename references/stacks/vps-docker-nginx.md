# VPS (Ubuntu) · Nginx · PM2 · Docker

Commands that change the server are **owner-approved actions**: show them, explain the effect, and run them only when the user agrees (a firewall mistake can lock everyone out of SSH).

## Base hardening (Ubuntu 22.04/24.04)
```bash
# non-root deploy user with sudo, SSH keys only
adduser deploy && usermod -aG sudo deploy
mkdir -p /home/deploy/.ssh && cp ~/.ssh/authorized_keys /home/deploy/.ssh/ && chown -R deploy:deploy /home/deploy/.ssh && chmod 700 /home/deploy/.ssh
# /etc/ssh/sshd_config.d/hardening.conf
#   PermitRootLogin no
#   PasswordAuthentication no
#   KbdInteractiveAuthentication no
#   MaxAuthTries 3
sshd -t && systemctl reload ssh            # test config first; keep the current session open while testing a new login

# firewall
ufw default deny incoming && ufw default allow outgoing
ufw allow OpenSSH && ufw allow 80/tcp && ufw allow 443/tcp
ufw enable && ufw status verbose

# brute-force protection + automatic security updates
apt install -y fail2ban unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades
```
Check what is listening publicly: `ss -tulpn` — databases/Redis/Node ports must be on `127.0.0.1` (or a private network), not `0.0.0.0`.

## Docker pitfalls
- **Published ports bypass ufw** (Docker writes its own iptables rules). Use `"127.0.0.1:5432:5432"` or no `ports:` at all for DB/Redis; only the reverse proxy publishes 80/443.
- No secrets in `Dockerfile` `ENV`/`ARG` (they stay in image layers); use `env_file:` / Docker secrets at runtime.
- `.dockerignore`: `.env*`, `.git`, `node_modules`, backups, dumps.
- Run as non-root (`USER node`), pin base images, `docker scout cves`/`trivy image` for image CVEs, `restart: unless-stopped`, resource limits (`mem_limit`, `cpus`) so one container can't starve the host.

## PM2
```js
// ecosystem.config.js
module.exports = { apps: [{
  name: 'web', script: 'node_modules/next/dist/bin/next', args: 'start -p 3000',   // or server.js
  instances: 'max', exec_mode: 'cluster',             // cluster ⇒ rate-limit/session stores must be shared (Redis)
  max_memory_restart: '600M',
  env_production: { NODE_ENV: 'production', PORT: 3000 },
}]};
```
`pm2 start ecosystem.config.js --env production`, `pm2 save`, `pm2 startup` (as the deploy user), `pm2 install pm2-logrotate`. The app listens on `127.0.0.1` only; Nginx is the public entry.

## Nginx
Use `assets/nginx/security-headers.conf` (headers, dotfile/backup blocking) and `assets/nginx/rate-limit.conf` (limit_req zones, body size, timeouts). Skeleton:
```nginx
server { listen 80; listen [::]:80; server_name example.com www.example.com; return 301 https://$host$request_uri; }
server {
  listen 443 ssl; listen [::]:443 ssl; http2 on;
  server_name example.com www.example.com;
  ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
  ssl_protocols TLSv1.2 TLSv1.3;
  include snippets/security-headers.conf;
  include snippets/rate-limit-server.conf;
  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;          # websockets / Socket.IO
    proxy_set_header Connection "upgrade";
  }
}
```
(`http2 on;` needs nginx ≥ 1.25.1; older: `listen 443 ssl http2;`.) Validate with `nginx -t` before `systemctl reload nginx`. **`add_header` inheritance:** if a `location` defines its own `add_header`, the server-level ones are dropped for that location — include the snippet there too. Behind Cloudflare, restore real client IPs (`set_real_ip_from <cloudflare ranges>; real_ip_header CF-Connecting-IP;`) or rate limits hit Cloudflare's IPs.

TLS: `certbot --nginx -d example.com -d www.example.com`; `certbot renew --dry-run`; monitor expiry (`check_live.py` reports days left).

## Databases on the VPS
Postgres/MySQL bound to `127.0.0.1`; app user with only needed privileges; strong passwords; `pg_hba.conf` `scram-sha-256`; Redis `bind 127.0.0.1` + `requirepass` (or ACL users) + `protected-mode yes`; MongoDB auth enabled.

## Backups (tested!)
```bash
# nightly logical backup, encrypted, kept off-server (restic/rclone to S3/Backblaze/another provider)
pg_dump -Fc "$DATABASE_URL" > /var/backups/app-$(date +%F).dump
restic -r s3:s3.eu-central-1.amazonaws.com/my-backups backup /var/backups /srv/app/uploads
restic forget --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune
```
Write down RPO/RTO and do a real restore into a scratch DB at least once (and after big changes).

## Monitoring
Uptime check (UptimeRobot/Better Stack/Kuma), TLS expiry, disk space (`df -h` alerts), `pm2 monit`/`docker stats`, Sentry for app errors, fail2ban jails for nginx auth/limit_req (`nginx-limit-req`), log review of 401/403/429 spikes.
