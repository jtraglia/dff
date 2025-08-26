# DFF Python Implementation

A Python implementation of the DFF (Differential Fuzzing Framework) that uses Unix domain sockets
and System V shared memory for high-performance IPC.

## Installation

```bash
pip install dff-py
```

## Requirements

- Python 3.9 or higher
- Linux or macOS

### Linux

```bash
sudo sysctl -w kernel.shmmax=104857600
sudo sysctl -w kernel.shmall=256000
```

### macOS

```bash
sudo sysctl -w kern.sysv.shmmax=104857600
sudo sysctl -w kern.sysv.shmall=256000
```

## Usage

### Example Client

```python
import sys
import hashlib
from pathlib import Path

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
    client = Client("python", process_sha)

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
```

### Example Server

```python
import sys
import random
from pathlib import Path

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
    data = random.randbytes(size)

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
```
