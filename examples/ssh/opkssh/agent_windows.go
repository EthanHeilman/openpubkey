package main

import (
	"context"
	"net"
	"os"

	"github.com/Microsoft/go-winio"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/agent"
)

// from: https://github.com/smallstep/cli/blob/bf32ddf9f2e2acabed0cfaa4ce2f03ca967bb38e/internal/sshutil/agent_windows.go

// dialAgent returns an ssh.Agent client. It uses the SSH_AUTH_SOCK to connect
// to the agent.
func dialAgent() (*Agent, error) {
	// Attempt unix sockets for environments like cygwin.
	if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" {
		if conn, err := net.Dial("unix", socket); err == nil {
			return &Agent{
				ExtendedAgent: agent.NewClient(conn),
				Conn:          conn,
			}, nil
		}
	}

	// Windows OpenSSH agent
	conn, err := winio.DialPipeContext(context.Background(), `\\.\\pipe\\openssh-ssh-agent`)
	if err != nil {
		return nil, errors.Wrap(err, "error connecting with ssh-agent")
	}
	return &Agent{
		ExtendedAgent: agent.NewClient(conn),
		Conn:          conn,
	}, nil
}
