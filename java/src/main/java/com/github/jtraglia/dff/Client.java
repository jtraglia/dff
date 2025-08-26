package com.github.jtraglia.dff;

import com.sun.jna.Pointer;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Client encapsulates the client-side behavior for connecting to the fuzzing server.
 */
public class Client {
    private static final String SOCKET_PATH = "/tmp/dff";
    private static final int MAX_METHOD_LENGTH = 64;
    private static final int MAX_INPUT_SIZE_BUFFER = 1024;

    private final String name;
    private final ProcessFunc processFunc;
    private final AtomicBoolean shutdown = new AtomicBoolean(false);

    private SocketChannel channel;
    private Pointer inputShm;
    private Pointer outputShm;
    private String method;

    /**
     * Creates a new Client with the given name and processing function.
     *
     * @param name the client identifier sent to the server
     * @param processFunc the callback function used to process fuzzing inputs
     */
    public Client(String name, ProcessFunc processFunc) {
        this.name = name;
        this.processFunc = processFunc;
    }

    /**
     * Establishes a connection to the fuzzing server, sends the client name,
     * attaches to the shared memory segments, and reads the fuzzing method.
     *
     * @throws IOException if connection or setup fails
     */
    public void connect() throws IOException {
        // Connect to Unix domain socket
        UnixDomainSocketAddress address = UnixDomainSocketAddress.of(Path.of(SOCKET_PATH));
        channel = SocketChannel.open(StandardProtocolFamily.UNIX);
        channel.connect(address);

        // Send client name
        ByteBuffer nameBuffer = ByteBuffer.wrap(name.getBytes());
        channel.write(nameBuffer);

        // Read input shared memory ID (4 bytes, big-endian)
        ByteBuffer inputShmIdBuffer = ByteBuffer.allocate(4);
        readFully(inputShmIdBuffer);
        inputShmIdBuffer.flip();
        inputShmIdBuffer.order(ByteOrder.BIG_ENDIAN);
        int inputShmId = inputShmIdBuffer.getInt();

        // Attach to input shared memory
        inputShm = SharedMemory.attach(inputShmId);

        // Read output shared memory ID (4 bytes, big-endian)
        ByteBuffer outputShmIdBuffer = ByteBuffer.allocate(4);
        readFully(outputShmIdBuffer);
        outputShmIdBuffer.flip();
        outputShmIdBuffer.order(ByteOrder.BIG_ENDIAN);
        int outputShmId = outputShmIdBuffer.getInt();

        // Attach to output shared memory
        outputShm = SharedMemory.attach(outputShmId);

        // Read method name (up to 64 bytes)
        ByteBuffer methodBuffer = ByteBuffer.allocate(MAX_METHOD_LENGTH);
        int methodLength = channel.read(methodBuffer);
        if (methodLength <= 0) {
            throw new IOException("Failed to read method name");
        }
        // Find null terminator or use full length
        int actualLength = methodLength;
        for (int i = 0; i < methodLength; i++) {
            if (methodBuffer.get(i) == 0) {
                actualLength = i;
                break;
            }
        }
        method = new String(methodBuffer.array(), 0, actualLength).trim();

        System.out.printf("Connected with fuzzing method: %s%n", method);
    }

    /**
     * Runs the client fuzzing loop. Waits for the server to send input sizes,
     * extracts the corresponding data from shared memory, processes it via the
     * provided ProcessFunc, writes the result to output shared memory, and sends
     * back the size of the result.
     *
     * @throws IOException if communication fails
     * @throws Exception if processing fails
     */
    public void run() throws IOException, Exception {
        System.out.println("Client running... Press Ctrl+C to exit.");

        // Setup shutdown hook for graceful cleanup
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            shutdown.set(true);
            System.out.println("\nShutdown signal received. Exiting client.");
        }));

        while (!shutdown.get()) {
            try {
                // First read just the count (4 bytes)
                ByteBuffer countBuffer = ByteBuffer.allocate(4);
                countBuffer.order(ByteOrder.BIG_ENDIAN);
                readFully(countBuffer);
                countBuffer.flip();
                int numInputs = countBuffer.getInt();

                // Now read all the sizes (numInputs * 4 bytes)
                ByteBuffer sizesBuffer = ByteBuffer.allocate(numInputs * 4);
                sizesBuffer.order(ByteOrder.BIG_ENDIAN);
                readFully(sizesBuffer);
                sizesBuffer.flip();

                // Extract input sizes and create byte arrays from shared memory
                byte[][] inputs = new byte[numInputs][];
                long inputOffset = 0;

                for (int i = 0; i < numInputs; i++) {
                    int inputSize = sizesBuffer.getInt();

                    // Read data from shared memory
                    inputs[i] = new byte[inputSize];
                    inputShm.read(inputOffset, inputs[i], 0, inputSize);
                    inputOffset += inputSize;
                }

                // Process the inputs using the provided ProcessFunc
                long startTime = System.nanoTime();
                byte[] result = processFunc.process(method, inputs);
                long elapsedTime = System.nanoTime() - startTime;

                // Write the processed result to output shared memory
                outputShm.write(0, result, 0, result.length);

                System.out.printf("Processing time: %.2fms%n", elapsedTime / 1_000_000.0);

                // Send the size of the processed result back to server (4 bytes, big-endian)
                ByteBuffer responseSizeBuffer = ByteBuffer.allocate(4);
                responseSizeBuffer.order(ByteOrder.BIG_ENDIAN);
                responseSizeBuffer.putInt(result.length);
                responseSizeBuffer.flip();
                channel.write(responseSizeBuffer);

            } catch (Exception e) {
                System.err.printf("Error in client loop: %s%n", e.getMessage());
                break;
            }
        }
    }

    /**
     * Cleans up all resources held by the client.
     */
    public void close() {
        try {
            if (channel != null) {
                channel.close();
            }
        } catch (IOException e) {
            System.err.printf("Error closing socket: %s%n", e.getMessage());
        }

        try {
            if (inputShm != null) {
                SharedMemory.detach(inputShm);
            }
        } catch (RuntimeException e) {
            System.err.printf("Error detaching input shared memory: %s%n", e.getMessage());
        }

        try {
            if (outputShm != null) {
                SharedMemory.detach(outputShm);
            }
        } catch (RuntimeException e) {
            System.err.printf("Error detaching output shared memory: %s%n", e.getMessage());
        }
    }

    /**
     * Helper method to read fully into a ByteBuffer.
     */
    private void readFully(ByteBuffer buffer) throws IOException {
        while (buffer.hasRemaining()) {
            int bytesRead = channel.read(buffer);
            if (bytesRead == -1) {
                throw new IOException("Unexpected end of stream");
            }
        }
    }

    /**
     * Get the client name.
     *
     * @return the client name
     */
    public String getName() {
        return name;
    }
}