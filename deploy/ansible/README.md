# Ansible Role: psina

Deploys the [psina](https://github.com/foxcool/psina) authentication service via Docker Compose behind Traefik.

## Requirements

- Docker + Docker Compose v2
- Traefik running with an external `proxy` network
- Ansible collections: `community.docker`

```bash
ansible-galaxy collection install community.docker
```

## Role Variables

| Variable | Default | Description |
|---|---|---|
| `psina_version` | `latest` | Image tag to deploy |
| `psina_image` | `ghcr.io/foxcool/psina:{{ psina_version }}` | Full image reference |
| `psina_app_dir` | `/opt/psina` | Working directory on host |
| `psina_http_port` | `8080` | Container HTTP port |
| `psina_platform_domain` | `auth.example.com` | Domain for Traefik routing |
| `psina_db_user` | `psina` | PostgreSQL username |
| `psina_db_password` | `psina_password` | PostgreSQL password |
| `psina_db_name` | `psina` | PostgreSQL database name |
| `psina_jwt_private_key` | `""` | PEM content of RS256 private key (empty = ephemeral, dev only) |
| `psina_cookie_enabled` | `true` | Enable cookie-based token delivery |
| `psina_cookie_domain` | `""` | Cookie domain (empty = exact match) |
| `psina_cookie_secure` | `true` | Secure cookie flag |
| `psina_cookie_samesite` | `strict` | SameSite policy (`strict` or `lax` for SSO) |
| `psina_traefik_middlewares` | `""` | Additional Traefik middlewares (e.g. `tailscale-only@file`) |
| `psina_backup_dir` | `/opt/backups` | Directory for database backups |
| `psina_backup_retention_days` | `30` | Days to keep backup files |
| `psina_auto_backup` | `true` | Run backup task automatically with deploy |
| `psina_log_level` | `INFO` | Log level (`DEBUG`, `INFO`, `WARN`, `ERROR`) |

## Tags

| Tag | Action |
|---|---|
| `deploy` | Pull image and start/update services |
| `backup` | Dump database and rotate old backups |
| `destroy` | Stop containers, remove volumes and app dir |

`destroy` has the `never` tag — it will not run unless explicitly requested.

## Examples

### Standalone (minimal)

```yaml
# playbook.yml
- hosts: myserver
  roles:
    - role: psina
      vars:
        psina_platform_domain: "auth.myapp.com"
        psina_db_password: "{{ vault_psina_db_password }}"
        psina_jwt_private_key: "{{ vault_psina_jwt_key }}"
```

### With Tailscale access restriction

```yaml
- hosts: myserver
  roles:
    - role: psina
      vars:
        psina_platform_domain: "auth.internal.myapp.com"
        psina_traefik_middlewares: "tailscale-only@file"
        psina_db_password: "{{ vault_psina_db_password }}"
        psina_jwt_private_key: "{{ vault_psina_jwt_key }}"
```

### Cross-subdomain SSO (lax cookies)

```yaml
- hosts: myserver
  roles:
    - role: psina
      vars:
        psina_platform_domain: "auth.myapp.com"
        psina_cookie_domain: ".myapp.com"
        psina_cookie_samesite: "lax"
        psina_db_password: "{{ vault_psina_db_password }}"
        psina_jwt_private_key: "{{ vault_psina_jwt_key }}"
```

### Run backup only

```bash
ansible-playbook playbook.yml --tags backup
```

### Destroy (removes data!)

```bash
ansible-playbook playbook.yml --tags destroy
```

## Traefik Integration

The role configures psina to handle:

- `Host(domain) && PathPrefix(/auth.v1.)` — Connect RPC endpoints
- `Host(domain) && PathPrefix(/.well-known)` — JWKS public key endpoint

The service runs on `h2c` (HTTP/2 cleartext) scheme, required for Connect RPC protocol.

### ForwardAuth middleware example

```yaml
# traefik/middlewares.yml
http:
  middlewares:
    psina-auth:
      forwardAuth:
        address: "http://psina:8080/auth.v1.AuthService/Verify"
        authRequestHeaders:
          - "Authorization"
        authResponseHeaders:
          - "X-User-Id"
          - "X-User-Email"
```

### KrakenD JWKS validation

```json
{
  "extra_config": {
    "auth/validator": {
      "alg": "RS256",
      "jwk_url": "http://psina:8080/.well-known/jwks.json",
      "cache": true
    }
  }
}
```
