package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/jtraglia/dff"
)

// inputProvider returns some random bytes between 1 and 4 MB.
func inputProvider() [][]byte {
	const minSize = 1 * 1024 * 1024 // 1 MB
	const maxSize = 4 * 1024 * 1024 // 4 MB

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
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
