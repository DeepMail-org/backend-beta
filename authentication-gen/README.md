# DeepMail Authentication Generators

## Admin script

`admin_token_manager.py` supports:

- `bootstrap-admin --username --email --fingerprint --db-path --jwt-secret`
- `issue-code --username --email --phone [--role analyst|admin|superadmin]`
- `list-tokens`
- `revoke --jti <token-jti>`
- `rotate-weekly`

Required env:

- `DEEPMAIL_ADMIN_TOKEN` (admin JWT)
- `DEEPMAIL_JWT_SECRET` (for bootstrap only)
- `DEEPMAIL_API_BASE` (default `http://127.0.0.1:3001/api/v1`)
- `DEEPMAIL_CLIENT_CERT_FP` (required if mTLS enforcement enabled)

## User script

`user_token_gen.py --username ... --email ... --phone ... --code ... --fingerprint ... [--save ./token.txt]`

- Redeems one-time 8-char code and returns JWT.
- Reuse/invalid attempts fail with auth error (`token is used`).

## Security notes

- Keep admin tokens off disk where possible.
- Use mTLS-terminated reverse proxy and pass client-cert fingerprint header.
- Rotate signing secrets periodically and audit `auth_audit` events.
- Prefer secret file or command providers in backend (`DEEPMAIL_JWT_SECRET_FILE` / `DEEPMAIL_JWT_SECRET_CMD`) instead of plaintext env.
