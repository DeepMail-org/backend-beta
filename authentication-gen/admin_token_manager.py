#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request


def call(method: str, path: str, token: str, body: dict | None = None):
    base = os.environ.get("DEEPMAIL_API_BASE", "http://127.0.0.1:3001/api/v1")
    cert_fp = os.environ.get("DEEPMAIL_CLIENT_CERT_FP", "")
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(base + path, method=method, data=data)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    if cert_fp:
        req.add_header("x-client-cert-fingerprint", cert_fp)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.getcode(), json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        payload = e.read().decode("utf-8", errors="ignore")
        print(payload or str(e), file=sys.stderr)
        sys.exit(1)


def _b64(obj: dict) -> bytes:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def make_jwt(
    username: str, role: str, fingerprint: str, secret: str, issuer: str, audience: str
):
    header = {"alg": "HS256", "typ": "JWT"}
    jti = hashlib.sha256(f"{username}:{time.time_ns()}".encode("utf-8")).hexdigest()[
        :32
    ]
    exp = int(time.time()) + 7 * 24 * 3600
    payload = {
        "sub": username,
        "role": role,
        "jti": jti,
        "iss": issuer,
        "aud": audience,
        "cnf": fingerprint,
        "exp": exp,
    }
    segments = [_b64(header), _b64(payload)]
    sig = hmac.new(secret.encode("utf-8"), b".".join(segments), hashlib.sha256).digest()
    token = b".".join(segments + [base64.urlsafe_b64encode(sig).rstrip(b"=")]).decode(
        "utf-8"
    )
    return token, jti, exp


def bootstrap_admin_token(
    db_path: str,
    username: str,
    email: str,
    fingerprint: str,
    secret: str,
    issuer: str,
    audience: str,
):
    token, jti, exp = make_jwt(username, "admin", fingerprint, secret, issuer, audience)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT OR IGNORE INTO users (id, username, email, password_hash, role, is_active) VALUES (?, ?, ?, ?, 'admin', 1)",
            (username, username, email, "bootstrap-admin"),
        )
        conn.execute(
            "INSERT OR REPLACE INTO auth_tokens (jti, user_id, token_hash, role, expires_at, status, device_fingerprint, first_seen_ip, last_seen_at) VALUES (?, ?, ?, 'admin', datetime(?, 'unixepoch'), 'active', ?, '127.0.0.1', datetime('now'))",
            (jti, username, token_hash, exp, fingerprint),
        )
        conn.commit()
    finally:
        conn.close()
    return token


def main():
    parser = argparse.ArgumentParser(description="DeepMail admin token manager")
    parser.add_argument(
        "--admin-token", default=os.environ.get("DEEPMAIL_ADMIN_TOKEN", "")
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    bootstrap = sub.add_parser(
        "bootstrap-admin", help="Create initial admin token in DB"
    )
    bootstrap.add_argument("--username", required=True)
    bootstrap.add_argument("--email", required=True)
    bootstrap.add_argument("--fingerprint", required=True)
    bootstrap.add_argument(
        "--db-path", default=os.environ.get("DEEPMAIL_DB_PATH", "data/deepmail.db")
    )
    bootstrap.add_argument(
        "--jwt-secret", default=os.environ.get("DEEPMAIL_JWT_SECRET", "")
    )
    bootstrap.add_argument(
        "--issuer", default=os.environ.get("DEEPMAIL_JWT_ISSUER", "deepmail-inhouse")
    )
    bootstrap.add_argument(
        "--audience",
        default=os.environ.get("DEEPMAIL_JWT_AUDIENCE", "deepmail-clients"),
    )

    issue = sub.add_parser("issue-code", help="Issue one-time code")
    issue.add_argument("--username", required=True)
    issue.add_argument("--email", required=True)
    issue.add_argument("--phone", required=True)
    issue.add_argument("--role", default="analyst")

    sub.add_parser("list-tokens", help="List generated tokens")

    revoke = sub.add_parser("revoke", help="Revoke token by JTI")
    revoke.add_argument("--jti", required=True)

    sub.add_parser("rotate-weekly", help="Expire overdue tokens")

    args = parser.parse_args()

    if args.cmd == "bootstrap-admin":
        if not args.jwt_secret:
            print(
                "--jwt-secret (or DEEPMAIL_JWT_SECRET) required for bootstrap",
                file=sys.stderr,
            )
            sys.exit(2)
        token = bootstrap_admin_token(
            args.db_path,
            args.username,
            args.email,
            args.fingerprint,
            args.jwt_secret,
            args.issuer,
            args.audience,
        )
        print(json.dumps({"admin_token": token}, indent=2))
        return

    if not args.admin_token:
        print(
            "admin token required via --admin-token or DEEPMAIL_ADMIN_TOKEN",
            file=sys.stderr,
        )
        sys.exit(2)

    if args.cmd == "issue-code":
        _, out = call(
            "POST",
            "/auth/otp/issue",
            args.admin_token,
            {
                "username": args.username,
                "email": args.email,
                "phone": args.phone,
                "role": args.role,
            },
        )
        print(json.dumps(out, indent=2))
    elif args.cmd == "list-tokens":
        _, out = call("GET", "/admin/auth/tokens", args.admin_token)
        print(json.dumps(out, indent=2))
    elif args.cmd == "revoke":
        _, out = call("POST", f"/admin/auth/revoke/{args.jti}", args.admin_token)
        print(json.dumps(out, indent=2))
    elif args.cmd == "rotate-weekly":
        _, out = call("POST", "/admin/auth/rotate-weekly", args.admin_token)
        print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
