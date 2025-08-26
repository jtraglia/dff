#!/usr/bin/env python3
"""Example DFF server that provides random data for SHA256 fuzzing."""

import sys
import random
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "python"))

from dff import Server


def data_provider() -> list[bytes]:
    """Generate random data for fuzzing.
    
    Returns:
        List containing a single random byte array
    """
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
    
    # Generate random bytes efficiently using random.randbytes (Python 3.9+)
    # or random.getrandbits for older versions
    try:
        data = random.randbytes(size)  # Fast method for Python 3.9+
    except AttributeError:
        # Fallback for Python < 3.9 - still much faster than per-byte generation
        data = bytearray(size)
        for i in range(0, size, 1024):
            chunk_size = min(1024, size - i)
            chunk = random.getrandbits(chunk_size * 8).to_bytes(chunk_size, 'little')
            data[i:i+chunk_size] = chunk
        data = bytes(data)
    
    return [data]


def main() -> None:
    """Main entry point."""
    server = Server("sha")
    
    try:
        server.run(data_provider)
    except KeyboardInterrupt:
        print("\nShutdown requested")
    except Exception as e:
        print(f"Server error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()