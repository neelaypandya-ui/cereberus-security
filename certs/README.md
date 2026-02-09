# TLS Certificates

Place your TLS certificate and key in this directory:

- `cereberus.crt` — Certificate file
- `cereberus.key` — Private key file

## Self-Signed (Development)

```bash
openssl req -x509 -newkey rsa:4096 -keyout cereberus.key -out cereberus.crt \
  -days 365 -nodes -subj "/CN=cereberus.local"
```

## Let's Encrypt (Production)

```bash
certbot certonly --standalone -d your-domain.com
cp /etc/letsencrypt/live/your-domain.com/fullchain.pem ./cereberus.crt
cp /etc/letsencrypt/live/your-domain.com/privkey.pem ./cereberus.key
```

**Note:** `.crt` and `.key` files are excluded from version control via `.gitignore`.
