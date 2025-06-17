# dff

A simple DFF (differential fuzzing framework).

## System configuration

This fuzzer framework only supports Linux and macOS, not Windows. This is because it uses [Unix
Domain Sockets](https://en.wikipedia.org/wiki/Unix_domain_socket) and [Shared
Memory](https://en.wikipedia.org/wiki/Shared_memory) segments for interprocess communication.

There are two limits whcih must be increased to support 100 MiB segements.

* `shmmax` -- the max shared memory segment size.
* `shmall` -- total shared memory size in pages.

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

### Go

See the [examples](./examples/golang).

### Rust

See the [examples](./examples/rust).
