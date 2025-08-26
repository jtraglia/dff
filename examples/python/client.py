#!/usr/bin/env python3
"""Example DFF client that implements SHA256 hashing."""

import sys
import hashlib
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "python"))

from dff import Client


def process_sha(method: str, inputs: list[bytes]) -> bytes:
    """Process function for SHA256 hashing.

    Args:
        method: The fuzzing method (should be "sha")
        inputs: List of byte arrays to hash

    Returns:
        SHA256 hash of the first input

    Raises:
        ValueError: If method is not "sha" or no inputs provided
    """
    if method != "sha":
        raise ValueError(f"Unknown method: {method}")

    if not inputs:
        raise ValueError("No inputs provided")

    return hashlib.sha256(inputs[0]).digest()


def main() -> None:
    """Main entry point."""
    logging.basicConfig(level=logging.INFO)

    name = sys.argv[1] if len(sys.argv) > 1 else "python"

    client = Client(name, process_sha)

    try:
        client.connect()
        client.run()
    except KeyboardInterrupt:
        print("\nShutdown requested")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        client.close()


if __name__ == "__main__":
    main()