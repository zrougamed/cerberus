// Package tui is a terminal console for Cerberus. It reads the REST API,
// so it runs on the sensor, inside its container, or on a laptop pointed
// at a remote sensor, and needs no privileges.
package tui

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
)

// Main runs `cerberus tui` and returns the exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cerberus tui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", envOr("CERBERUS_HTTP_ADDR", "127.0.0.1:8080"), "Cerberus address: host:port or an http(s) URL")
	tokenFile := fs.String("token-file", "", "file holding an API token (default: $CERBERUS_API_TOKEN)")
	caFile := fs.String("ca-file", "", "CA certificate to trust for https")
	interval := fs.Duration("interval", 2*time.Second, "refresh interval (500ms to 1m)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: cerberus tui [flags]")
		fmt.Fprintln(stderr, "\nTerminal console for a running Cerberus. Without a token it is read-only.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *interval < 500*time.Millisecond || *interval > time.Minute {
		fmt.Fprintln(stderr, "cerberus tui: --interval must be between 500ms and 1m")
		return 2
	}
	token := os.Getenv("CERBERUS_API_TOKEN")
	if *tokenFile != "" {
		b, err := readFile(*tokenFile)
		if err != nil {
			fmt.Fprintf(stderr, "cerberus tui: read token file: %v\n", err)
			return 2
		}
		token = strings.TrimSpace(string(b))
	}
	c, err := NewClient(*addr, token, *caFile)
	if err != nil {
		fmt.Fprintf(stderr, "cerberus tui: %v\n", err)
		return 2
	}
	// 20 frames a second keeps keys responsive (50 ms) at a third of the
	// default redraw cost; the data only changes every few seconds.
	p := tea.NewProgram(newModel(c, *interval), tea.WithOutput(stdout), tea.WithFPS(20))
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(stderr, "cerberus tui: %v\n", err)
		return 1
	}
	return 0
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
