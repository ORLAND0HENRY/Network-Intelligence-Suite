"""Credential-free availability check restricted to a loopback URL."""

from __future__ import annotations

import argparse
import ipaddress
from urllib.parse import urlsplit

import requests

ALLOWED_HOSTNAMES = {"localhost"}


def is_loopback_url(url: str) -> bool:
    """Accept HTTP(S) URLs pointing only to localhost or a loopback IP."""
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        if parsed.username is not None or parsed.password is not None:
            return False
        hostname = parsed.hostname.rstrip(".").lower()
        return hostname in ALLOWED_HOSTNAMES or ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def main(argv: list[str] | None = None) -> int:
    """Make one credential-free request to a local endpoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", nargs="?", default="http://127.0.0.1:8000/login/", help="local HTTP(S) endpoint")
    args = parser.parse_args(argv)
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
