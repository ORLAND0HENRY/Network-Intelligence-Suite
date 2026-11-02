"""Perform one credential-free availability check against a loopback URL.

This legacy script name is retained, but password guessing is intentionally
not supported. Only localhost/loopback destinations are accepted.
"""

from __future__ import annotations

import argparse
import ipaddress
from urllib.parse import urlsplit

import requests


ALLOWED_HOSTNAMES = {"localhost"}


def is_loopback_url(url: str) -> bool:
    """Accept only HTTP(S) URLs whose hostname is localhost or a loopback IP."""
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        if parsed.username is not None or parsed.password is not None:
            return False
        hostname = parsed.hostname.rstrip(".").lower()
        if hostname in ALLOWED_HOSTNAMES:
            return True
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "url",
        nargs="?",
        default="http://127.0.0.1:8000/login/",
        help="local HTTP(S) endpoint (default: %(default)s)",
    )
    args = parser.parse_args()

    if not is_loopback_url(args.url):
        parser.error("only localhost or a loopback IP address is allowed")

    try:
        response = requests.get(args.url, timeout=5, allow_redirects=False)
    except requests.RequestException as exc:
        print(f"[!] Local endpoint unavailable: {exc}")
        return 1

    print(f"[+] Local endpoint responded with HTTP {response.status_code}.")
    if 300 <= response.status_code < 400:
        print("[!] Redirect was not followed.")
    return 0 if response.status_code < 500 else 1


if __name__ == "__main__":
    raise SystemExit(main())
