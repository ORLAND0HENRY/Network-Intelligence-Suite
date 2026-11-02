"""Legacy compatibility wrapper; prefer ``nis-health-check``.

Password guessing is intentionally not implemented.
"""

from network_intelligence.health import is_loopback_url, main

if __name__ == "__main__":
    raise SystemExit(main())
