# certs/

TLS certificates for the nginx reverse proxy (soc-dashboard container).

Files in this directory are **gitignored** (`*.pem`). Each developer generates their own.

## Generate (one-time)

```bash
mkcert -install
mkcert -cert-file certs/localhost.pem -key-file certs/localhost-key.pem localhost 127.0.0.1
```

Run from the project root. Certificates expire after ~2 years.

## Required files

| File | Purpose |
|------|---------|
| `localhost.pem` | TLS certificate (public) |
| `localhost-key.pem` | Private key |

Both are mounted read-only into the dashboard container at `/etc/nginx/certs/`.
nginx will fail to start if either file is missing.
