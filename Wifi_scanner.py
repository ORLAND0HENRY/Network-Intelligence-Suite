"""Compatibility wrapper; prefer ``nis-scan`` or ``nis scan``."""

from network_intelligence.scanner import *  # noqa: F403
from network_intelligence.scanner import main

if __name__ == "__main__":
    raise SystemExit(main())
