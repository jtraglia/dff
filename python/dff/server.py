"""DFF Server implementation."""

import ctypes
import hashlib
import os
import socket
import struct
import signal
import threading
import time
from typing import Callable, Dict, List, Optional
from collections import defaultdict

from .shm import SharedMemory, IPC_CREAT, IPC_EXCL, IPC_RMID

SOCKET_PATH = "/tmp/dff"
DEFAULT_INPUT_SHM_KEY = 1000
DEFAULT_SHM_MAX_SIZE = 100 * 1024 * 1024  # 100 MiB
DEFAULT_SHM_PERM = 0o666

ProviderFunc = Callable[[], List[bytes]]


class ClientEntry:
    """Represents a connected client."""

    def __init__(self, name: str, conn: socket.socket, shm_id: int, method: str):
        self.name = name
        self.conn = conn
        self.shm_id = shm_id
        self.shm_buffer = bytearray(DEFAULT_SHM_MAX_SIZE)
        self.method = method


class Server:
    """Server encapsulates the server-side behavior for the fuzzing framework."""

    def __init__(self, method: str):
        """Initialize a new Server.

        Args:
            method: The fuzzing method name to send to clients
        """
        self.method = method
        self.input_shm_key = DEFAULT_INPUT_SHM_KEY
        self.shm_max_size = DEFAULT_SHM_MAX_SIZE
        self.shm_perm = DEFAULT_SHM_PERM
        self.clients: Dict[str, ClientEntry] = {}
        self.clients_lock = threading.Lock()
        self.shutdown = False
        self.iteration_count = 0
        self.total_duration = 0.0
        self.input_shm: Optional[SharedMemory] = None
        self.input_shm_buffer: Optional[ctypes.Array] = None
        self.listener: Optional[socket.socket] = None

    def _cleanup_existing_shm(self) -> None:
        """Clean up any existing shared memory with our key."""
        try:
            existing_shm = SharedMemory.get(self.input_shm_key)
            existing_shm.remove()
            print(f"Removed existing input shared memory segment with key {self.input_shm_key}")
        except OSError:
            pass

    def _create_shared_memory(self) -> None:
        """Create the input shared memory segment."""
        self._cleanup_existing_shm()

        self.input_shm = SharedMemory.create(
            self.input_shm_key,
            self.shm_max_size,
            self.shm_perm
        )

        self.input_shm_buffer = self.input_shm.attach()

    def _handle_client(self, conn: socket.socket, addr: str) -> None:
        """Handle a new client connection."""
        try:
            # Receive client name
            name_bytes = conn.recv(256)
            if not name_bytes:
                conn.close()
                return

            client_name = name_bytes.decode().rstrip('\x00')
            # Create output shared memory for this client
            output_shm_key = self.input_shm_key + len(self.clients) + 1

            # Clean up if it exists
            try:
                existing = SharedMemory.get(output_shm_key)
                existing.remove()
            except OSError:
                pass

            output_shm = SharedMemory.create(
                output_shm_key,
                self.shm_max_size,
                self.shm_perm
            )

            # Send input shared memory ID
            conn.sendall(struct.pack(">I", self.input_shm.shmid))

            # Send output shared memory ID
            conn.sendall(struct.pack(">I", output_shm.shmid))

            # Send method name
            conn.sendall(self.method.encode())

            # Store client
            with self.clients_lock:
                if client_name not in self.clients:
                    self.clients[client_name] = ClientEntry(
                        client_name, conn, output_shm.shmid, self.method
                    )
                    print(f"Registered new client: {client_name}")

        except Exception as e:
            print(f"Error handling client: {e}")
            conn.close()

    def _status_updates(self) -> None:
        """Print status updates every 5 seconds."""
        while not self.shutdown:
            time.sleep(5)

            if self.iteration_count > 0:
                with self.clients_lock:
                    client_names = sorted(self.clients.keys())

                avg_duration = self.total_duration / self.iteration_count
                total_seconds = int(self.total_duration)
                avg_ms = int(avg_duration * 1000)

                print(f"Fuzzing Time: {total_seconds}s, Iterations: {self.iteration_count}, "
                      f"Average Iteration: {avg_ms}ms, Clients: {','.join(client_names)}")

    def _accept_clients(self) -> None:
        """Accept client connections in a separate thread."""
        while not self.shutdown:
            try:
                self.listener.settimeout(1.0)
                conn, addr = self.listener.accept()
                # Handle each client in a separate thread
                thread = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr)
                )
                thread.daemon = True
                thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if not self.shutdown:
                    print(f"Error accepting client: {e}")

    def run(self, provider: ProviderFunc) -> None:
        """Run the fuzzing server.

        Args:
            provider: Function that generates fuzzing inputs
        """
        # Setup signal handler
        def signal_handler(_signum: int, _frame: object) -> None:
            self.shutdown = True
            print("\nShutting down server...")

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Clean up any existing socket
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)

        # Create shared memory
        self._create_shared_memory()

        # Create and bind socket
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(SOCKET_PATH)
        self.listener.listen(10)

        # Start accepting clients in a separate thread
        accept_thread = threading.Thread(target=self._accept_clients)
        accept_thread.daemon = True
        accept_thread.start()

        # Start status updates thread
        status_thread = threading.Thread(target=self._status_updates)
        status_thread.daemon = True
        status_thread.start()

        # Main fuzzing loop
        try:
            while not self.shutdown:
                # Wait until at least one client is connected
                if len(self.clients) == 0:
                    print("Waiting for a client...")
                    time.sleep(1)
                    continue

                start_time = time.perf_counter()

                # Generate inputs
                inputs = provider()
                if not inputs:
                    continue

                # Prepare input data
                input_sizes = []
                offset = 0
                for input_data in inputs:
                    size = len(input_data)
                    if offset + size > self.shm_max_size:
                        print(f"Warning: Input data exceeds shared memory size")
                        break

                    # Write to shared memory using memmove for better performance
                    dest_ptr = ctypes.addressof(self.input_shm_buffer) + offset
                    if isinstance(input_data, bytes):
                        src = ctypes.c_char_p(input_data)
                        ctypes.memmove(dest_ptr, src, size)
                    else:
                        # Fallback for other types
                        self.input_shm_buffer[offset:offset + size] = input_data
                    input_sizes.append(size)
                    offset += size

                # Prepare message with number of inputs and their sizes
                msg = struct.pack(">I", len(input_sizes))
                for size in input_sizes:
                    msg += struct.pack(">I", size)

                # Send to all clients and collect results
                results = {}
                dead_clients = []

                with self.clients_lock:
                    for name, client in self.clients.items():
                        try:
                            # Send input sizes
                            client.conn.sendall(msg)

                            # Read result size
                            result_size_bytes = client.conn.recv(4)
                            if len(result_size_bytes) != 4:
                                dead_clients.append(name)
                                continue

                            result_size = struct.unpack(">I", result_size_bytes)[0]

                            # Read result from client's output shared memory
                            output_shm = SharedMemory(client.shm_id)
                            output_buffer = output_shm.attach()
                            result = bytes(output_buffer[0:result_size])
                            output_shm.detach()

                            results[name] = result

                        except Exception as e:
                            print(f"Error communicating with client {name}: {e}")
                            dead_clients.append(name)

                # Remove dead clients
                for name in dead_clients:
                    print(f"Disconnected client: {name}")
                    with self.clients_lock:
                        if name in self.clients:
                            try:
                                self.clients[name].conn.close()
                            except:
                                pass
                            del self.clients[name]

                # Check for differences
                if len(results) > 1:
                    first_result = None
                    all_same = True
                    for result in results.values():
                        if first_result is None:
                            first_result = result
                        elif result != first_result:
                            all_same = False
                            break

                    if not all_same:
                        print("Values are different:")
                        for name, result in results.items():
                            result_hash = hashlib.sha256(result).hexdigest()
                            print(f"Key: {name}, Value: {result_hash}")

                # Update statistics
                duration = time.perf_counter() - start_time
                self.iteration_count += 1
                self.total_duration += duration


        except Exception as e:
            if not self.shutdown:
                print(f"Server error: {e}")
                raise
        finally:
            self._cleanup()

    def _cleanup(self) -> None:
        """Clean up resources."""
        print("Cleaning up server resources...")

        # Close client connections
        with self.clients_lock:
            for client in self.clients.values():
                try:
                    client.conn.close()
                except:
                    pass
            self.clients.clear()

        # Close listener
        if self.listener:
            try:
                self.listener.close()
            except:
                pass

        # Clean up socket file
        if os.path.exists(SOCKET_PATH):
            try:
                os.unlink(SOCKET_PATH)
            except:
                pass

        # Clean up shared memory
        if self.input_shm:
            try:
                self.input_shm.detach()
                self.input_shm.remove()
            except:
                pass

        print("Server shutdown complete")
