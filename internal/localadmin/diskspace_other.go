//go:build !linux

package localadmin

func availableBytes(string) (uint64, error) {
	return ^uint64(0), nil
}
