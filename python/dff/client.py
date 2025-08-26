"""DFF Client implementation."""

import ctypes
import socket
import struct
import signal
import time
from typing import Callable, List, Optional

from .shm import SharedMemory

SOCKET_PATH = "/tmp/dff"
MAX_METHOD_LENGTH = 64


ProcessFunc = Callable[[str, List[bytes]], bytes]


class Client:
    """Client encapsulates the client-side behavior for connecting to the fuzzing server."""

    def __init__(self, name: str, process_func: ProcessFunc):
        """Initialize a new Client.

        Args:
            name: The client identifier sent to the server
            process_func: The callback function used to process fuzzing inputs
        """
        self.name = name
        self.process_func = process_func
        self.conn: Optional[socket.socket] = None
        self.input_shm: Optional[ctypes.Array] = None
        self.output_shm: Optional[ctypes.Array] = None
        self.input_shm_obj: Optional[SharedMemory] = None
        self.output_shm_obj: Optional[SharedMemory] = None
        self.method: str = ""
        self.shutdown = False

    def connect(self) -> None:
        """Establish a connection to the fuzzing server.

        Connects to the server, sends the client name, attaches to shared memory
        segments, and reads the fuzzing method from the server.

        Raises:
            ConnectionError: If connection fails
            OSError: If shared memory operations fail
        """
        max_retries = 10
        retry_delay = 0.1

        for attempt in range(max_retries):
            try:
                self.conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.conn.connect(SOCKET_PATH)
                break
            except (ConnectionError, FileNotFoundError) as e:
                if attempt == max_retries - 1:
                    raise ConnectionError(
                        f"Failed to connect to server after {max_retries} attempts: {e}"
                    )
                time.sleep(retry_delay)

        if not self.conn:
            raise ConnectionError("Failed to establish connection")

        self.conn.sendall(self.name.encode())

        input_shm_id_bytes = self.conn.recv(4)
        if len(input_shm_id_bytes) != 4:
            raise ConnectionError("Failed to read input shared memory ID")
        input_shm_id = struct.unpack(">I", input_shm_id_bytes)[0]

        self.input_shm_obj = SharedMemory(input_shm_id)
        self.input_shm = self.input_shm_obj.attach()

        output_shm_id_bytes = self.conn.recv(4)
        if len(output_shm_id_bytes) != 4:
            raise ConnectionError("Failed to read output shared memory ID")
        output_shm_id = struct.unpack(">I", output_shm_id_bytes)[0]

        self.output_shm_obj = SharedMemory(output_shm_id)
        self.output_shm = self.output_shm_obj.attach()

        method_bytes = self.conn.recv(MAX_METHOD_LENGTH)
        if not method_bytes:
            raise ConnectionError("Failed to read method name")
        self.method = method_bytes.decode().rstrip('\x00')

        print(f"Connected with fuzzing method: {self.method}")

    def run(self) -> None:
        """Run the client fuzzing loop.

        Waits for the server to send input sizes, extracts data from shared memory,
        processes it via the provided process_func, writes results to output shared
        memory, and sends back the result size.

        Raises:
            RuntimeError: If not connected
            Exception: Any exception from the process function
        """
        if not self.conn or not self.input_shm or not self.output_shm:
            raise RuntimeError("Client not connected")

        def signal_handler(_signum: int, _frame: object) -> None:
            self.shutdown = True
            print("\nShutting down gracefully...")

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        print("Client running... Press Ctrl+C to exit.")

        try:
            while not self.shutdown:
                # Read the message containing number of inputs and their sizes
                input_msg = self.conn.recv(1024)
                if not input_msg:
                    break

                if len(input_msg) < 4:
                    raise ValueError(f"Invalid input message length: {len(input_msg)}")

                # First 4 bytes: number of inputs
                num_inputs = struct.unpack(">I", input_msg[0:4])[0]

                # Following bytes: sizes of each input (4 bytes each)
                expected_length = 4 + (num_inputs * 4)
                if len(input_msg) < expected_length:
                    raise ValueError(f"Input message too short: expected {expected_length}, got {len(input_msg)}")

                # Parse all sizes at once
                input_sizes = struct.unpack(f">{num_inputs}I", input_msg[4:4 + num_inputs * 4])

                inputs: List[bytes] = []
                offset = 0
                for size in input_sizes:
                    if offset + size > len(self.input_shm):
                        raise ValueError(f"Input size {size} at offset {offset} exceeds buffer")
                    # Use string_at to read bytes directly from memory address
                    data_ptr = ctypes.addressof(self.input_shm) + offset
                    data = ctypes.string_at(data_ptr, size)
                    inputs.append(data)
                    offset += size

                try:
                    start_time = time.perf_counter()
                    result = self.process_func(self.method, inputs)
                    elapsed_time = (time.perf_counter() - start_time) * 1000
                    print(f"Processing time: {elapsed_time:.2f}ms")
                except Exception as e:
                    print(f"Process function error: {e}")
                    result = b""

                if not isinstance(result, bytes):
                    raise TypeError(f"Process function must return bytes, got {type(result)}")

                if len(result) > len(self.output_shm):
                    raise ValueError(f"Result size {len(result)} exceeds output buffer")

                # Write result bytes to output shared memory using memmove for performance
                if isinstance(result, bytes) and len(result) > 0:
                    dest_ptr = ctypes.addressof(self.output_shm)
                    src = ctypes.c_char_p(result)
                    ctypes.memmove(dest_ptr, src, len(result))
                else:
                    # Fallback for empty or non-bytes
                    self.output_shm[0:len(result)] = result

                self.conn.sendall(struct.pack(">I", len(result)))

        except Exception as e:
            if not self.shutdown:
                print(f"Client error: {e}")
                raise
        finally:
            self.close()

    def close(self) -> None:
        """Close the client connection and clean up resources."""
        if self.conn:
            try:
                self.conn.close()
            except:
                pass
            self.conn = None

        if self.input_shm_obj:
            try:
                self.input_shm_obj.detach()
            except:
                pass
            self.input_shm_obj = None
            self.input_shm = None

        if self.output_shm_obj:
            try:
                self.output_shm_obj.detach()
            except:
                pass
            self.output_shm_obj = None
            self.output_shm = None

    def __enter__(self) -> "Client":
        """Context manager entry."""
        return self

    def __exit__(self, *_args: object) -> None:
        """Context manager exit."""
        self.close()
