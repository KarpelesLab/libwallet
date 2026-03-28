package libwallet

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/KarpelesLab/libwallet/wltbase"
	"github.com/KarpelesLab/apirouter"
)

// Methods exposed to the application to setup an environment

// ShowDebug enables outputting debug output on the standard error output
func ShowDebug() {
	// set the default logger to one which has level set to debug
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
}

// MakeRPC generates and return a socket
func MakeRPC(dataDir string) (int, error) {
	e, err := wltbase.InitEnv(dataDir)
	if err != nil {
		return -1, fmt.Errorf("failed to init env: %w", err)
	}

	return apirouter.MakeJsonSocketFD(map[string]any{"@env": e})
}

// MakeSocket creates a socket
func MakeSocket(dataDir, socketName string) error {
	e, err := wltbase.InitEnv(dataDir)
	if err != nil {
		return fmt.Errorf("failed to init env: %w", err)
	}

	return apirouter.MakeJsonUnixListener(socketName, map[string]any{"@env": e})
}
