//go:build !userspace

package main

import (
	"context"
	"errors"
)

// cmdExit is only available in the userspace build: go build -tags userspace.
func cmdExit(ctx context.Context, args []string) error {
	// main reports our error through the logger, which only the subcommands
	// initialize: without this the default build panicked instead of saying
	// why exit is missing.
	initLog(false)
	return errors.New("exit mode requires the userspace build: go build -tags userspace")
}
