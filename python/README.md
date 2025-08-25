# DFF Python Implementation

A Python implementation of the DFF (Differential Fuzzing Framework) that uses Unix domain sockets and System V shared memory for high-performance IPC.

## Installation

### From PyPI (once published)

```bash
pip install dff
```

### From Source

```bash
cd python
pip install -e .
```

## Requirements

- Python 3.8 or higher
- Linux or macOS (Windows is not supported due to Unix domain sockets and System V shared memory)
- System configured for 100 MiB shared memory segments (see main README)

## Usage

### Client

```python
from dff import Client

def process_func(method: str, inputs: list[bytes]) -> bytes:
    """Process function that handles fuzzing inputs."""
    if method != "sha":
        raise ValueError(f"Unknown method: {method}")
    
    # Process the first input (matching Go/Java behavior)
    import hashlib
    return hashlib.sha256(inputs[0]).digest()

# Create and run client
client = Client("python", process_func)
client.connect()
client.run()
```

### Server

```python
from dff import Server

def provider() -> list[bytes]:
    """Generate fuzzing inputs."""
    import random
    size = random.randint(1024, 4096)
    data = bytes(random.randint(0, 255) for _ in range(size))
    return [data]

# Create and run server
server = Server("sha")
server.run(provider)
```

## Examples

See the `examples/python/` directory for complete working examples:

- `client.py` - SHA256 hashing client implementation
- `server.py` - Fuzzing server with random data provider

### Running the Examples

Start the server:
```bash
./examples/python/server.py
```

In another terminal, start one or more clients:
```bash
./examples/python/client.py
./examples/python/client.py python2
./examples/golang/client/client golang
```

The server will detect any differences in the outputs from different clients.

## Architecture

The framework uses:
- **Unix domain sockets** for control messages and coordination
- **System V shared memory** for efficient data transfer
- **Multiple client support** for differential testing

### Protocol

1. Client connects to server via Unix socket at `/tmp/dff`
2. Client sends its name
3. Server responds with:
   - Input shared memory ID (4 bytes, big-endian)
   - Output shared memory ID (4 bytes, big-endian)
   - Method name (up to 64 bytes)
4. For each fuzzing iteration:
   - Server writes input data to shared memory
   - Server sends message with input count and sizes
   - Client processes data and writes result to output shared memory
   - Client sends result size back to server
   - Server compares results across clients

## Performance

The Python implementation is functional but slower than compiled language implementations (Go, Rust) due to:
- Python's Global Interpreter Lock (GIL)
- Interpreter overhead
- Dynamic typing

For better performance, consider:
- Using PyPy instead of CPython
- Implementing compute-heavy processing in C extensions
- Running multiple client instances

## Development

### Running Tests

```bash
cd python
pip install -e .[dev]
pytest
```

### Code Quality

```bash
# Format code
black dff/

# Lint
ruff dff/

# Type checking
mypy dff/
```

## License

MIT License - see the LICENSE file in the root directory.