"""Print the SHA-256 hex digest of a file to stdout.

Usage: python3 scripts/sha256_print.py <path>
Called by Makefile _zip_artifact target to print and verify the artifact hash.
"""

import hashlib
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: sha256_print.py <file>", file=sys.stderr)
        sys.exit(1)
    path = Path(sys.argv[1])
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    print(f"SHA-256: {digest}")


if __name__ == "__main__":
    main()
