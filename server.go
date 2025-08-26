package dff

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gen2brain/shm"
)

// Default configuration values.
const (
	socketPath          = "/tmp/dff"
	defaultMaxClientNameLength = 32
	defaultInputShmKey         = 1000
	defaultShmMaxSize          = 100 * 1024 * 1024 // 100 MiB
	defaultShmPerm             = 0666
)

// clientEntry represents a connected fuzzing client.
type clientEntry struct {
	Name      string
	Conn      net.Conn
	ShmId     int
	ShmBuffer []byte
	Method    string
}

// Server encapsulates the state of the fuzzing server.
type Server struct {
	// Method is the name of the fuzzing method that will be sent to clients.
	Method string
	// InputProvider is a function that returns a slice of fuzzing inputs.
	InputProvider func() [][]byte

	socketPath  string
	inputShmKey int
	shmMaxSize  int
	shmPerm     int

	mu      *sync.Mutex
	clients map[string]*clientEntry
	quit    chan struct{}

	iterationCount int
	totalDuration  time.Duration
}

// NewServer returns a new Server instance with the given method name and input provider.
func NewServer(method string, inputProvider func() [][]byte) *Server {
	return &Server{
		Method:        method,
		InputProvider: inputProvider,
		socketPath:    socketPath,
		inputShmKey:   defaultInputShmKey,
		shmMaxSize:    defaultShmMaxSize,
		shmPerm:       defaultShmPerm,
		mu:            &sync.Mutex{},
		clients:       make(map[string]*clientEntry),
		quit:          make(chan struct{}),
	}
}

// detachAndDelete detaches and removes a shared memory segment.
func detachAndDelete(shmId int, shmBuffer []byte) {
	if err := shm.Dt(shmBuffer); err != nil {
		fmt.Printf("Failed to detach shared memory: %v\n", err)
	}
	if _, err := shm.Ctl(shmId, shm.IPC_RMID, nil); err != nil {
		fmt.Printf("Failed to remove shared memory: %v\n", err)
	}
}

// newSharedMemory creates and attaches to a new shared memory segment.
func newSharedMemory(shmKey, shmMaxSize, shmPerm int) (int, []byte, error) {
	shmId, err := shm.Get(shmKey, shmMaxSize, shmPerm|shm.IPC_CREAT|shm.IPC_EXCL)
	if err != nil {
		fmt.Printf("Error creating shared memory: %v\n", err)
		return 0, nil, err
	}
	shmBuffer, err := shm.At(shmId, 0, 0)
	if err != nil {
		fmt.Printf("Error attaching to shared memory: %v\n", err)
		return 0, nil, err
	}
	return shmId, shmBuffer, nil
}

// Start launches the fuzzing server. It sets up shared memory, a Unix domain socket for client
// registrations, and runs the main fuzzing loop. This call blocks until Shutdown is called or
// an interrupt signal is received.
func (s *Server) Start() error {
	// Setup signal handling.
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	// Create shared memory for input.
	inputShmId, inputShmBuffer, err := newSharedMemory(s.inputShmKey, s.shmMaxSize, s.shmPerm)
	if err != nil {
		return fmt.Errorf("error creating input shared memory: %v", err)
	}

	// Create Unix domain socket for client registration.
	os.Remove(s.socketPath)
	registrationListener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("error creating Unix domain socket: %v", err)
	}

	// Cleanup on interrupt or shutdown.
	go func() {
		select {
		case <-signalChan:
			fmt.Println("\nReceived interrupt signal")
			s.Stop(inputShmId, inputShmBuffer, registrationListener)
			os.Exit(0)
		case <-s.quit:
			s.Stop(inputShmId, inputShmBuffer, registrationListener)
			return
		}
	}()

	// Start goroutines for accepting clients and status updates.
	go s.acceptClients(registrationListener, inputShmId)
	go s.statusUpdates()

	// Main fuzzing loop.
	for {
		select {
		case <-s.quit:
			return nil
		default:
			start := time.Now()

			// Wait until at least one client is connected.
			s.mu.Lock()
			numClients := len(s.clients)
			s.mu.Unlock()
			if numClients == 0 {
				fmt.Println("Waiting for a client...")
				time.Sleep(1 * time.Second)
				continue
			}

			// Get inputs from the caller’s function.
			inputs := s.InputProvider()
			combinedInputs := []byte{}
			for _, input := range inputs {
				combinedInputs = append(combinedInputs, input...)
			}
			// Copy the combined inputs into shared memory.
			copy(inputShmBuffer, combinedInputs)

			// Copy the list of clients so we don't hold s.mu while communicating.
			s.mu.Lock()
			clients := make([]*clientEntry, 0, len(s.clients))
			for _, client := range s.clients {
				clients = append(clients, client)
			}
			s.mu.Unlock()

			var wg sync.WaitGroup
			var muResult sync.Mutex
			results := make(map[string][]byte)
			for _, client := range clients {
				wg.Add(1)
				go func(client *clientEntry) {
					defer wg.Done()

					// Send the number of inputs followed by each input's size.
					countAndSizesBytes := make([]byte, 4)
					binary.BigEndian.PutUint32(countAndSizesBytes, uint32(len(inputs)))
					for _, input := range inputs {
						sizesBytes := make([]byte, 4)
						binary.BigEndian.PutUint32(sizesBytes, uint32(len(input)))
						countAndSizesBytes = append(countAndSizesBytes, sizesBytes...)
					}
					_, err := client.Conn.Write(countAndSizesBytes)
					if err != nil {
						if strings.Contains(err.Error(), "broken pipe") {
							fmt.Printf("client disconnected: %v\n", client.Name)
						} else {
							fmt.Printf("Error writing to client %s: %v\n", client.Name, err)
						}
						detachAndDelete(client.ShmId, client.ShmBuffer)
						s.mu.Lock()
						delete(s.clients, client.Name)
						s.mu.Unlock()
						return
					}

					// Wait for the client to respond with the response size.
					responseSizeBytes := make([]byte, 4)
					_, err = client.Conn.Read(responseSizeBytes)
					if err != nil {
						if !strings.Contains(err.Error(), "EOF") {
							fmt.Printf("Error reading response from client %s: %v\n", client.Name, err)
						}
						detachAndDelete(client.ShmId, client.ShmBuffer)
						s.mu.Lock()
						delete(s.clients, client.Name)
						s.mu.Unlock()
						return
					}
					responseSize := binary.BigEndian.Uint32(responseSizeBytes)

					muResult.Lock()
					results[client.Name] = client.ShmBuffer[:responseSize]
					muResult.Unlock()
				}(client)
			}
			wg.Wait()

			// Compare client responses.
			same := true
			var first []byte
			firstResultSet := false
			for _, result := range results {
				if !firstResultSet {
					first = result
					firstResultSet = true
				} else if !bytes.Equal(result, first) {
					same = false
					break
				}
			}
			if !same {
				fmt.Println("Values are different:")
				for client, result := range results {
					fmt.Printf("Key: %v, Value: %x\n", client, result)
				}

				// Save finding to disk
				s.mu.Lock()
				iterationNum := s.iterationCount
				s.mu.Unlock()

				if err := s.saveFinding(iterationNum, inputs, results); err != nil {
					fmt.Printf("Failed to save finding: %v\n", err)
				}
			}

			duration := time.Since(start)
			s.mu.Lock()
			s.iterationCount++
			s.totalDuration += duration
			s.mu.Unlock()
		}
	}
}

// acceptClients listens for new client connections on the registration listener.
func (s *Server) acceptClients(registrationListener net.Listener, inputShmId int) {
	for {
		conn, err := registrationListener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			fmt.Printf("Error accepting connection: %v\n", err)
			continue
		}
		go s.handleClient(conn, inputShmId)
	}
}

// handleClient performs client registration by reading the client's name, sending the input shared
// memory ID, creating a client-specific output shared memory, and sending the method name.
func (s *Server) handleClient(conn net.Conn, inputShmId int) {
	// Read the client name.
	clientNameBytes := make([]byte, defaultMaxClientNameLength)
	n, err := conn.Read(clientNameBytes)
	if err != nil {
		fmt.Printf("Error reading client name: %v\n", err)
		conn.Close()
		return
	}
	clientName := string(clientNameBytes[:n])

	// Send the input shared memory ID.
	inputShmIdBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(inputShmIdBytes, uint32(inputShmId))
	_, err = conn.Write(inputShmIdBytes)
	if err != nil {
		fmt.Printf("Error writing to client %s: %v\n", clientName, err)
		conn.Close()
		return
	}

	// Create a new shared memory segment for client output.
	outputShmKey := s.inputShmKey + len(s.clients) + 1
	outputShmId, clientShmBuffer, err := newSharedMemory(outputShmKey, s.shmMaxSize, s.shmPerm)
	if err != nil {
		fmt.Printf("Error creating client output shared memory: %v\n", err)
		conn.Close()
		return
	}

	// Send the output shared memory ID.
	outputShmIdBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(outputShmIdBytes, uint32(outputShmId))
	_, err = conn.Write(outputShmIdBytes)
	if err != nil {
		fmt.Printf("Error writing to client %s: %v\n", clientName, err)
		detachAndDelete(outputShmId, clientShmBuffer)
		conn.Close()
		return
	}

	// Send the method name.
	_, err = conn.Write([]byte(s.Method))
	if err != nil {
		fmt.Printf("Error writing method to client %s: %v\n", clientName, err)
		detachAndDelete(outputShmId, clientShmBuffer)
		conn.Close()
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[clientName]; !exists {
		s.clients[clientName] = &clientEntry{
			Name:      clientName,
			Conn:      conn,
			ShmId:     outputShmId,
			ShmBuffer: clientShmBuffer,
			Method:    s.Method,
		}
		fmt.Printf("Registered new client: %s\n", clientName)
	}
}

// statusUpdates periodically prints server status such as total fuzzing time, iteration count,
// average iteration duration, and list of connected clients.
func (s *Server) statusUpdates() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		count := s.iterationCount
		total := s.totalDuration
		clientNames := make([]string, 0, len(s.clients))
		for name := range s.clients {
			clientNames = append(clientNames, name)
		}
		s.mu.Unlock()

		if count != 0 {
			average := total / time.Duration(count)
			sort.Strings(clientNames)
			joinedNames := strings.Join(clientNames, ",")
			fmt.Printf("Fuzzing Time: %s, Iterations: %v, Average Iteration: %s, Clients: %v\n",
				total.Round(time.Second), count, average.Round(time.Millisecond), joinedNames)
		}
	}
}

// Stop cleans up resources by detaching shared memory segments, closing client connections,
// closing the registration listener, and removing the Unix domain socket.
func (s *Server) Stop(inputShmId int, inputShmBuffer []byte, registrationListener net.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	detachAndDelete(inputShmId, inputShmBuffer)
	for _, client := range s.clients {
		client.Conn.Close()
		detachAndDelete(client.ShmId, client.ShmBuffer)
	}
	registrationListener.Close()
	os.Remove(s.socketPath)
	fmt.Println("Server stopped and cleaned up.")
}

// saveFinding saves a fuzzing finding (input and client outputs) to disk
func (s *Server) saveFinding(iteration int, inputs [][]byte, results map[string][]byte) error {
	findingsDir := fmt.Sprintf("findings/%d", iteration)
	if err := os.MkdirAll(findingsDir, 0755); err != nil {
		return fmt.Errorf("failed to create findings directory: %v", err)
	}

	// Save input data (concatenated)
	inputPath := fmt.Sprintf("%s/input", findingsDir)
	inputFile, err := os.Create(inputPath)
	if err != nil {
		return fmt.Errorf("failed to create input file: %v", err)
	}
	defer inputFile.Close()

	for _, input := range inputs {
		if _, err := inputFile.Write(input); err != nil {
			return fmt.Errorf("failed to write input data: %v", err)
		}
	}

	// Save each client's output
	for clientName, output := range results {
		outputPath := fmt.Sprintf("%s/%s", findingsDir, clientName)
		if err := os.WriteFile(outputPath, output, 0644); err != nil {
			return fmt.Errorf("failed to write %s output: %v", clientName, err)
		}
	}

	fmt.Printf("Finding saved to: %s\n", findingsDir)
	return nil
}

// Shutdown signals the server to stop. It is safe to call from another goroutine.
func (s *Server) Shutdown() {
	close(s.quit)
}
