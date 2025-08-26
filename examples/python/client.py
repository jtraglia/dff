#!/usr/bin/env python3

import dff
import hashlib
import sys


def process_func(method: str, inputs: list[bytes]) -> bytes:
    """An example process function."""
    match method:
        case "sha":
            return hashlib.sha256(inputs[0]).digest()
        case _:
            raise ValueError(f"Unknown method: {method}")


def main() -> None:
    """Main entry point."""
    client = dff.Client("python", process_func)

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
