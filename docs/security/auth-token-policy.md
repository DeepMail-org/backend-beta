# DeepMail In-House Auth Token Security Policy

## Scope

Applies to all `/api/v1/auth/*` and `/api/v1/admin/*` endpoints.

## Controls

1. **mTLS enforcement (LAN)**
   - Requests must include a trusted client certificate fingerprint header (`x-client-cert-fingerprint`) from an mTLS-terminating gateway.
   - Configure trusted fingerprints with `DEEPMAIL__SECURITY__TRUSTED_CLIENT_CERT_FINGERPRINTS`.

2. **One-time OTP redemption**
   - OTP is 8-character alphanumeric.
   - OTP can be used only once and expires quickly.
   - Reuse/invalid/locked OTP returns auth failure (`token is used`).

3. **Per-user and per-IP rate limiting**
   - OTP redemption applies both user-scoped and IP-scoped token bucket controls.
   - Lockout cooldown is applied after max invalid attempts.

4. **JWT hardening**
   - Required claims: `sub`, `jti`, `role`, `iss`, `aud`, `cnf`, `exp`.
   - Strict issuer and audience checks are mandatory.
   - Device fingerprint binding (`cnf`) is enforced via `x-device-fingerprint`.

5. **Token registry / revocation**
   - Every issued JWT is registered by `jti` + token hash.
   - Validation checks active status, non-revoked state, expiry, and device binding.
   - Weekly rotation supported by admin endpoint.

6. **SIEM-forwarded immutable audit trail**
   - Auth events are written to `auth_audit` with immutable hash chaining.
   - Events are also logged to tracing target `siem.auth` for collector forwarding.

## Secret management

- Prefer not storing long-lived secrets directly in `.env`.
- Use one of:
  - `DEEPMAIL_JWT_SECRET_FILE` (mounted secret file)
  - `DEEPMAIL_JWT_SECRET_CMD` (OS keyring/HSM fetch command wrapper)

## Incident response

- Revoke token by JTI: `POST /api/v1/admin/auth/revoke/:jti`
- Force weekly expiry: `POST /api/v1/admin/auth/rotate-weekly`
- Monitor abnormal events: repeated `otp_redeem_failed` and lockout triggers.
