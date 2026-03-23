//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"
)

func getAgentAuthSigners() (agent.Agent, func(), error) {
	pipePath := `\\.\pipe\openssh-ssh-agent`
	handle, err := windows.CreateFile(
		windows.StringToUTF16Ptr(pipePath),
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to SSH agent pipe: %w", err)
	}
	f := os.NewFile(uintptr(handle), pipePath)
	return agent.NewClient(f), func() { f.Close() }, nil
}
