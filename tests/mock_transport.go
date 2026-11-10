// Offline test transport: records SSH/SCP arguments, never opens a socket.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	name := strings.ToLower(filepath.Base(os.Args[0]))
	f, err := os.OpenFile(os.Getenv("WG68_MOCK_TRACE"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		os.Exit(2)
	}
	json.NewEncoder(f).Encode(os.Args)
	f.Close()
	if strings.HasPrefix(name, "scp") && len(os.Args) >= 3 {
		data, err := os.ReadFile(os.Args[len(os.Args)-2])
		if err != nil {
			os.Exit(3)
		}
		if err := os.WriteFile(os.Getenv("WG68_MOCK_ARCHIVE"), data, 0600); err != nil {
			os.Exit(4)
		}
	}
	if strings.HasPrefix(name, os.Getenv("WG68_MOCK_FAIL")) && os.Getenv("WG68_MOCK_FAIL") != "" {
		os.Exit(1)
	}
}
