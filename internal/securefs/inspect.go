package securefs

import "strings"

func validRootPolicy(policy RootPolicy) bool { return policy.Access.kind != permissionInvalid }

func validFilePolicy(policy FilePolicy) bool {
	return policy.Access.kind != permissionInvalid && policy.Presence <= MustBeAbsent && policy.Kind <= Directory && policy.MaxBytes >= 0
}

func validLeaf(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "\\/\x00:")
}
