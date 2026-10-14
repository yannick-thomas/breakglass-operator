/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package architecture enforces the dependency rule of
// docs/adr-002-clean-architecture.md: source code dependencies point inward
// only. It checks the transitive dependencies of every inner package, so an
// indirect import through a helper package is caught as well.
package architecture

import (
	"bufio"
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

const module = "github.com/yannick-thomas/breakglass-operator"

// layers lists, from the inside out, which non-standard packages each inner
// layer may depend on, directly or transitively.
var layers = []struct {
	pattern string
	allowed []string
}{
	{
		pattern: module + "/internal/domain/...",
		allowed: []string{module + "/internal/domain/"},
	},
	{
		pattern: module + "/internal/usecase/...",
		allowed: []string{
			module + "/internal/domain/",
			module + "/internal/usecase/",
			"github.com/go-logr/logr",
		},
	},
}

func TestDependenciesPointInward(t *testing.T) {
	for _, layer := range layers {
		t.Run(layer.pattern, func(t *testing.T) {
			for pkg, deps := range dependencies(t, layer.pattern) {
				for _, dep := range deps {
					if !allowed(dep, layer.allowed) {
						t.Errorf("%s depends on %s, which is outside its layer", pkg, dep)
					}
				}
			}
		})
	}
}

func allowed(dep string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(dep, prefix) {
			return true
		}
	}
	return false
}

// dependencies returns the non-standard transitive dependencies of each
// package matching pattern, including test-only imports.
func dependencies(t *testing.T, pattern string) map[string][]string {
	t.Helper()
	pkgs := goList(t, "-f", "{{.ImportPath}}", pattern)
	result := make(map[string][]string, len(pkgs))
	for _, pkg := range pkgs {
		deps := goList(t, "-deps", "-test", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", pkg)
		for _, dep := range deps {
			// -test lists the package's own test variants; they are the
			// package itself.
			if dep == "" || strings.HasPrefix(dep, pkg) {
				continue
			}
			result[pkg] = append(result[pkg], dep)
		}
	}
	if len(result) == 0 && len(pkgs) == 0 {
		t.Fatalf("pattern %s matched no packages", pattern)
	}
	return result
}

func goList(t *testing.T, args ...string) []string {
	t.Helper()
	cmd := exec.Command("go", append([]string{"list"}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %v: %v\n%s", args, err, stderr.String())
	}
	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
