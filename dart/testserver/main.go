// Small server for Dart integration tests.
// Starts libwallet with a temp data dir and listens on a Unix socket.
// Prints the socket path to stdout, then blocks until killed.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/KarpelesLab/libwallet"
)

func main() {
	dataDir, err := os.MkdirTemp("", "libwallet-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dataDir)

	sockPath := filepath.Join(dataDir, "ipc.sock")

	if err := libwallet.MakeSocket(dataDir, sockPath); err != nil {
		fmt.Fprintf(os.Stderr, "MakeSocket failed: %v\n", err)
		os.Exit(1)
	}

	// Print socket path so the Dart test can connect
	fmt.Println(sockPath)

	// Block until SIGINT/SIGTERM
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}
