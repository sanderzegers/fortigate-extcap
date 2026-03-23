//go:build !windows

package main

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh/agent"
)

func getAgentAuthSigners() (agent.Agent, func(), error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, nil, fmt.Errorf("SSH_AUTH_SOCK not set")
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to SSH agent: %w", err)
	}
	return agent.NewClient(conn), func() { conn.Close() }, nil
}
