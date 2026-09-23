//go:build !darwin && !linux

package tls

import (
	"errors"
	"os"
)

func lockStore(root *os.Root) (func(), error) {
	return nil, errors.New("persistent certificate stores are supported on macOS and Linux; use --ephemeral-cert on this platform")
}
