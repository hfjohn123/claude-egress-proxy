package securefs

import "strings"

func validRootPolicy(policy RootPolicy) bool { return policy.Access.kind != permissionInvalid }

func validFilePolicy(policy FilePolicy) bool {
	return policy.Access.kind != permissionInvalid && policy.Presence <= MustBeAbsent && policy.Kind <= Directory && policy.MaxBytes >= 0
}

func validLeaf(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "\\/\x00:")
}

// boundedReadChunk keeps every syscall at or below the sole policy bound plus
// one overflow-probe byte; a zero maximum deliberately leaves the caller's
// fixed buffer unchanged.
func boundedReadChunk(maxBytes, used int64, bufferSize int) int {
	if maxBytes == 0 {
		return bufferSize
	}
	remaining := maxBytes + 1 - used
	if remaining <= 0 {
		return 0
	}
	if remaining < int64(bufferSize) {
		return int(remaining)
	}
	return bufferSize
}
