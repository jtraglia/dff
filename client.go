package dff

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gen2brain/shm"
)

// ProcessFunc defines the signature for functions that process fuzzing inputs.
// Users of the package must supply their own function.
type ProcessFunc func(method string, inputs [][]byte) ([]byte, error)

// Client encapsulates the client-side behavior for connecting to the fuzzing server.
type Client struct {
	// Name is the identifier sent to the server.
	Name string
	// Process is the callback function used to process fuzzing inputs.
	Process ProcessFunc

	conn      net.Conn
	inputShm  []byte
	outputShm []byte
	method    string
}

// NewClient creates a new Client with the given name and processing function.
func NewClient(name string, process ProcessFunc) *Client {
	return &Client{
		Name:    name,
		Process: process,
	}
}

// Connect establishes a connection to the fuzzing server,
// sends the client name, attaches to the shared memory segments,
// and reads the fuzzing method from the server.
func (c *Client) Connect() error {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %v", err)
	}
	c.conn = conn

	// Send client name.
	_, err = c.conn.Write([]byte(c.Name))
	if err != nil {
		return fmt.Errorf("failed to send client name: %v", err)
	}

	// Read the input shared memory ID (4 bytes).
	var inputShmIdBytes [4]byte
	_, err = c.conn.Read(inputShmIdBytes[:])
	if err != nil {
		return fmt.Errorf("failed to read input shared memory id: %v", err)
	}
	inputShmId := int(binary.BigEndian.Uint32(inputShmIdBytes[:]))
	inputShm, err := shm.At(inputShmId, 0, 0)
	if err != nil {
		return fmt.Errorf("failed to attach to input shared memory: %v", err)
	}
	c.inputShm = inputShm

	// Read the output shared memory ID (4 bytes).
	var outputShmIdBytes [4]byte
	_, err = c.conn.Read(outputShmIdBytes[:])
	if err != nil {
		return fmt.Errorf("failed to read output shared memory id: %v", err)
	}
	outputShmId := int(binary.BigEndian.Uint32(outputShmIdBytes[:]))
	outputShm, err := shm.At(outputShmId, 0, 0)
	if err != nil {
		return fmt.Errorf("failed to attach to output shared memory: %v", err)
	}
	c.outputShm = outputShm

	// Read the method name (up to 64 bytes).
	var methodBytes [64]byte
	methodLength, err := c.conn.Read(methodBytes[:])
	if err != nil {
		return fmt.Errorf("failed to read method name: %v", err)
	}
	c.method = string(methodBytes[:methodLength])
	fmt.Printf("Connected with fuzzing method: %s\n", c.method)

	return nil
}

// Run enters the client fuzzing loop. It waits for the server to send input sizes,
// extracts the corresponding slices from shared memory, processes the input via the
// provided Process callback, writes the result to the output shared memory, and sends
// back the size of the result.
func (c *Client) Run() error {
	// Setup signal handling for graceful shutdown.
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	fmt.Println("Client running... Press Ctrl+C to exit.")

	var iterationCount int64
	var totalProcessing time.Duration
	lastStatus := time.Now()
	const statusInterval = 5 * time.Second

	for {
		// Read input sizes from the server.
		var inputSizeBytes [1024]byte
		n, err := c.conn.Read(inputSizeBytes[:])
		if err != nil {
			return fmt.Errorf("failed to read input sizes: %v", err)
		}
		if n < 4 {
			return fmt.Errorf("invalid input sizes data received")
		}
		numInputs := binary.BigEndian.Uint32(inputSizeBytes[:4])
		inputs := make([][]byte, numInputs)
		var inputOffset uint32 = 0
		for i := 0; i < int(numInputs); i++ {
			start := 4 + i*4
			if start+4 > len(inputSizeBytes) {
				return fmt.Errorf("unexpected end of input sizes data")
			}
			inputSize := binary.BigEndian.Uint32(inputSizeBytes[start : start+4])
			if inputOffset+inputSize > uint32(len(c.inputShm)) {
				return fmt.Errorf("invalid input size or offset")
			}
			inputs[i] = c.inputShm[inputOffset : inputOffset+inputSize]
			inputOffset += inputSize
		}

		// Process the input using the supplied Process callback.
		startTime := time.Now()
		result, err := c.Process(c.method, inputs)
		if err != nil {
			fmt.Printf("Failed to process input: %v\n", err)
			continue
		}

		// Write the processed result into the output shared memory.
		copy(c.outputShm, result)
		elapsed := time.Since(startTime)
		iterationCount++
		totalProcessing += elapsed

		if time.Since(lastStatus) >= statusInterval {
			avgMs := float64(totalProcessing.Nanoseconds()) / float64(iterationCount) / 1e6
			totalSecs := int(totalProcessing.Seconds())
			fmt.Printf("Iterations: %d, Total Processing: %ds, Average: %.2fms\n",
				iterationCount, totalSecs, avgMs)
			lastStatus = time.Now()
		}

		// Send the size of the processed result back to the server (4 bytes).
		var responseSizeBuffer [4]byte
		binary.BigEndian.PutUint32(responseSizeBuffer[:], uint32(len(result)))
		_, err = c.conn.Write(responseSizeBuffer[:])
		if err != nil {
			return fmt.Errorf("failed to send response size: %v", err)
		}

		// Check for an interrupt signal before the next iteration.
		select {
		case <-signalChan:
			fmt.Println("\nCtrl+C detected. Exiting client.")
			return nil
		default:
			// Continue looping.
		}
	}
}

// Close cleans up all resources held by the client.
func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
	if c.inputShm != nil {
		shm.Dt(c.inputShm)
	}
	if c.outputShm != nil {
		shm.Dt(c.outputShm)
	}
}
