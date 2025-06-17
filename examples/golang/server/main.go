package main

import (
	"fmt"
	"math/rand"
	"sync/atomic"

	"github.com/jtraglia/dff"
)

// Global seed counter for deterministic fuzzing
var seedCounter int64 = 1

// inputProvider returns some random bytes between 1 and 4 MB using a deterministic seed.
func inputProvider() [][]byte {
	const minSize = 1 * 1024 * 1024 // 1 MB
	const maxSize = 4 * 1024 * 1024 // 4 MB

	// Use atomic counter as seed for deterministic fuzzing
	seed := atomic.AddInt64(&seedCounter, 1)
	r := rand.New(rand.NewSource(seed))
	size := r.Intn(maxSize-minSize+1) + minSize

	input := make([]byte, size)
	if _, err := r.Read(input); err != nil {
		panic(err)
	}

	return [][]byte{input}
}

func main() {
	// Create a new fuzzing server.
	server := dff.NewServer("sha", inputProvider)

	// Start the server (this call blocks until shutdown).
	if err := server.Start(); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
