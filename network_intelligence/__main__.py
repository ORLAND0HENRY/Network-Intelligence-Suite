"""Allow running the suite with ``python -m network_intelligence``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
