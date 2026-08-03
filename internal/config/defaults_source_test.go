package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPlatformDefaultsHaveNoAmbientFallbackCalls(t *testing.T) {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller unavailable")
	}
	dir := filepath.Dir(self)
	for _, name := range []string{"defaults_windows.go", "defaults_linux.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			forbidden := pkg.Name == "os" && (selector.Sel.Name == "Getenv" || selector.Sel.Name == "LookupEnv" || selector.Sel.Name == "UserConfigDir" || selector.Sel.Name == "UserHomeDir" || selector.Sel.Name == "Getwd") || pkg.Name == "user" && selector.Sel.Name == "Current" || pkg.Name == "filepath" && (selector.Sel.Name == "Abs" || selector.Sel.Name == "Rel") || pkg.Name == "registry"
			if forbidden {
				t.Errorf("%s uses ambient fallback %s.%s", name, pkg.Name, selector.Sel.Name)
			}
			return true
		})
	}
}
