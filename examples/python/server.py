#!/usr/bin/env python3

import dff
import random
import sys


def data_provider() -> list[bytes]:
    """Generate random data for fuzzing."""
    MIN_SIZE = 1 * 1024 * 1024  # 1 MB
    MAX_SIZE = 4 * 1024 * 1024  # 4 MB

    # Use a deterministic seed that increments
    if not hasattr(data_provider, "seed_counter"):
        data_provider.seed_counter = 1
    seed = data_provider.seed_counter
    data_provider.seed_counter += 1

    # Generate random data with deterministic seed
    random.seed(seed)
    size = random.randint(MIN_SIZE, MAX_SIZE)
    data = random.randbytes(size)

    return [data]


def main() -> None:
    """Main entry point."""
    server = dff.Server("sha")

    try:
        server.run(data_provider)
    except KeyboardInterrupt:
        print("\nShutdown requested")
    except Exception as e:
        print(f"Server error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
