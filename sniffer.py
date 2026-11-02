"""Compatibility wrapper; prefer ``nis-monitor`` or ``nis monitor``."""

from network_intelligence.monitor import *  # noqa: F403
from network_intelligence.monitor import main

if __name__ == "__main__":
    raise SystemExit(main())
