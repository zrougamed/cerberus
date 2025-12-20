package utils

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func CleanCards() {
	fmt.Println("TC cleanup...")

	// Delete ingress qdisc
	ifaces, err := getInterfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting interfaces: %v\n", err)
		return
	}

	for _, iface := range ifaces {
		fmt.Printf("Cleaning %s...\n", iface)
		exec.Command("tc", "qdisc", "del", "dev", iface, "clsact").Run()
		exec.Command("tc", "qdisc", "del", "dev", iface, "ingress").Run()
	}

	// Use bpftool to detach if available
	if _, err := exec.LookPath("bpftool"); err == nil {
		fmt.Println("Using bpftool to clean up...")
		exec.Command("bpftool", "net", "detach", "xdp", "dev", "all").Run()
	}

	fmt.Println("Cleanup complete!")
}

func getInterfaces() ([]string, error) {
	out, err := exec.Command("ip", "-o", "link", "show").Output()
	if err != nil {
		return nil, err
	}

	var ifaces []string
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ": ")
		if len(parts) >= 2 {
			ifaces = append(ifaces, parts[1])
		}
	}
	return ifaces, nil
}
