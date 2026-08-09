package docs_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var markdownLink = regexp.MustCompile(`\[[^]]+\]\(([^)#]+)(?:#[^)]*)?\)`)

func TestLocalDocumentationLinksResolve(t *testing.T) {
	root := filepath.Join("..", "..")
	files, err := filepath.Glob(filepath.Join(root, "docs", "*.md")); if err != nil { t.Fatal(err) }
	files = append(files, filepath.Join(root, "README.md"))
	for _, file := range files {
		body, err := os.ReadFile(file); if err != nil { t.Fatal(err) }
		for _, match := range markdownLink.FindAllStringSubmatch(string(body), -1) {
			target := match[1]
			if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") { continue }
			if _, err := os.Stat(filepath.Join(filepath.Dir(file), filepath.FromSlash(target))); err != nil {
				t.Errorf("%s: link %q does not resolve: %v", file, target, err)
			}
		}
	}
}
