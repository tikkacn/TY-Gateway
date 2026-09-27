//go:build linux

package localadmin

import (
	"errors"
	"syscall"
)

func availableBytes(path string) (uint64, error) {
	var info syscall.Statfs_t
	if err := syscall.Statfs(path, &info); err != nil {
		return 0, err
	}
	if info.Bsize <= 0 {
		return 0, errors.New("filesystem block size is invalid")
	}
	return uint64(info.Bavail) * uint64(info.Bsize), nil
}
