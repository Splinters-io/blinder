//go:build darwin || linux

package tls

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

func lockStore(root *os.Root) (func(), error) {
	// Separate creation from reopening: concurrent O_CREATE opens can report
	// ENOENT on Darwin. Exclusive creation also refuses an existing symlink.
	f, err := root.OpenFile(".lock", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if errors.Is(err, os.ErrExist) {
		info, statErr := root.Lstat(".lock")
		if statErr != nil || !info.Mode().IsRegular() {
			return nil, errors.New("certificate store lock must be a regular file")
		}
		f, err = root.OpenFile(".lock", os.O_RDWR, 0)
	}
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("certificate store lock must be a regular file")
	}
	entry, err := root.Lstat(".lock")
	if err != nil || !entry.Mode().IsRegular() || !os.SameFile(info, entry) {
		f.Close()
		return nil, errors.New("certificate store lock changed while opening")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
		}
		if err != syscall.EWOULDBLOCK || time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("lock certificate store: %w", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}
