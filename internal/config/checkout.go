package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

func checkoutIdentity() (securefs.Identity, error) {
	_, source, _, sourceOK := runtime.Caller(0)
	if !sourceOK {
		source = ""
	}
	executable, _ := os.Executable()
	return checkoutIdentityFromPaths(source, executable)
}

func checkoutIdentityFromPaths(source, executable string) (securefs.Identity, error) {
	anchors := make([]string, 0, 2)
	if root, ok := sourceCheckoutRoot(source); ok {
		anchors = append(anchors, root)
	}
	if executable, ok := normalizeCleanAbsolutePath(executable); ok {
		dir := filepath.Dir(executable)
		if len(anchors) == 0 || !samePath(anchors[0], dir) {
			anchors = append(anchors, dir)
		}
	}
	for _, anchor := range anchors {
		root, err := securefs.OpenRoot(anchor, securefs.RootPolicy{Access: securefs.IdentityOnlyPermissions()})
		if err != nil {
			continue
		}
		id := root.Identity()
		_ = root.Close()
		return id, nil
	}
	return securefs.Identity{}, securefs.ErrUnsafePath
}

func sourceCheckoutRoot(source string) (string, bool) {
	source, ok := normalizeCleanAbsolutePath(source)
	if !ok {
		return "", false
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(source)))
	want := filepath.Join(root, "internal", "config", "checkout.go")
	if !samePath(source, want) {
		return "", false
	}
	return root, true
}

func normalizeCleanAbsolutePath(path string) (string, bool) {
	if path == "" || strings.ContainsRune(path, '\x00') {
		return "", false
	}
	if runtime.GOOS == "windows" {
		path = filepath.FromSlash(path)
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", false
	}
	return path, true
}

func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func CheckoutIdentity() (securefs.Identity, error) { return checkoutIdentity() }
