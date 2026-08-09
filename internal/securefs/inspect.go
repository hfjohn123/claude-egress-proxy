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
	if used < 0 || used > maxBytes {
		return 0
	}
	// maxBytes-used is the number of permitted bytes remaining. Compute the
	// one-byte overflow probe only after comparison so MaxInt64 cannot wrap.
	permitted := maxBytes - used
	if permitted >= int64(bufferSize) {
		return bufferSize
	}
	return int(permitted + 1)
}
