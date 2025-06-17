# DFF Nim Client

Differential Fuzzing Framework client library for Nim.

## Installation

```bash
nimble install https://github.com/jtraglia/dff?subdir=nim
```

## Usage

```nim
import dff/client

proc processFunc(method: string, inputs: seq[string]): string =
  # Your processing logic here
  return "result"

let client = newClient("my-client", processFunc)
client.connect()
client.run()
client.close()
```

## API

### Types

- `ProcessFunc` - Function type for processing fuzzing inputs
- `Client` - Main client object

### Functions

- `newClient(name: string, processFunc: ProcessFunc): Client` - Create a new client
- `connect(client: Client)` - Connect to the DFF server
- `run(client: Client)` - Start the fuzzing loop
- `close(client: Client)` - Clean up resources

## Example

See `../examples/nim/client.nim` for a complete SHA256 example.

## Requirements

- Nim >= 1.6.0
- Unix/Linux system with System V shared memory support
