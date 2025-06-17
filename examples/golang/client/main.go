package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"sync"

	"github.com/jtraglia/dff"
)

var (
	iterationCount int
	mu             sync.Mutex
)

// processFunc is an example processing function that supports the "sha" method.
func processFunc(method string, inputs [][]byte) ([]byte, error) {
	mu.Lock()
	iterationCount++
	currentIteration := iterationCount
	mu.Unlock()

	switch method {
	case "sha":
		if len(inputs) == 0 {
			return nil, fmt.Errorf("no inputs provided")
		}
		hash := sha256.Sum256(inputs[0])

		// Return wrong result on 100th iteration
		if currentIteration == 100 {
			fmt.Println("Golang client: Returning wrong result on iteration 100")
			// Flip the first byte to make it different
			hash[0] = ^hash[0]
		}

		return hash[:], nil
	default:
		return nil, fmt.Errorf("unknown method: '%s'", method)
	}
}

func main() {
	// Create a new fuzzing client.
	client := dff.NewClient("golang", processFunc)

	// Connect to the fuzzing server.
	if err := client.Connect(); err != nil {
		log.Fatalf("Connection error: %v", err)
	}
	defer client.Close()

	// Run the fuzzing client.
	if err := client.Run(); err != nil {
		log.Fatalf("Client error: %v", err)
	}
}
