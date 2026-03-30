#!/usr/bin/env python3
import argparse
import json
import os
import stat
import sys
import urllib.request
import urllib.error


def redeem(username: str, email: str, phone: str, code: str, fingerprint: str):
    base = os.environ.get("DEEPMAIL_API_BASE", "http://127.0.0.1:3001/api/v1")
    cert_fp = os.environ.get("DEEPMAIL_CLIENT_CERT_FP", "")
    body = json.dumps(
        {
            "username": username,
            "email": email,
            "phone": phone,
            "code": code,
            "device_fingerprint": fingerprint,
        }
    ).encode("utf-8")
    req = urllib.request.Request(base + "/auth/redeem", method="POST", data=body)
    req.add_header("Content-Type", "application/json")
    req.add_header("x-device-fingerprint", fingerprint)
    if cert_fp:
        req.add_header("x-client-cert-fingerprint", cert_fp)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        payload = e.read().decode("utf-8", errors="ignore")
        print(payload or str(e), file=sys.stderr)
        sys.exit(1)


def save_token(path: str, token: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(token)
        f.write("\n")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def main():
    parser = argparse.ArgumentParser(description="DeepMail user token generator")
    parser.add_argument("--username", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--phone", required=True)
    parser.add_argument("--code", required=True)
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--save", default="")
    args = parser.parse_args()

    out = redeem(args.username, args.email, args.phone, args.code, args.fingerprint)
    token = out.get("token", "")
    if not token:
        print("No token returned", file=sys.stderr)
        sys.exit(2)
    print(json.dumps(out, indent=2))
    if args.save:
        save_token(args.save, token)
        print(f"saved token to {args.save}")


if __name__ == "__main__":
    main()
