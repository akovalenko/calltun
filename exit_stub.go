//go:build !userspace

package main

import (
	"context"
	"errors"
)

// cmdExit is only available in the userspace build: go build -tags userspace.
func cmdExit(ctx context.Context, args []string) error {
	return errors.New("exit mode requires the userspace build: go build -tags userspace")
}
