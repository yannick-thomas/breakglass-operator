// Package frontend embeds the WebUI single-page app built by Vite.
//
// The React/TypeScript sources live next to this file. `make webui-frontend`
// builds them into build/app, which is embedded into the WebUI binary. Without
// a build, build/ contains only a README and the WebUI refuses to start.
package frontend

import (
	"embed"
	"errors"
	"io/fs"
)

//go:embed all:build
var buildFS embed.FS

// ErrNotBuilt reports a binary that was compiled without the frontend build.
var ErrNotBuilt = errors.New("WebUI frontend is not built; run 'make webui-frontend' before building the WebUI")

// GetFS returns the built app.
func GetFS() (fs.FS, error) {
	app, err := fs.Sub(buildFS, "build/app")
	if err != nil {
		return nil, err
	}
	if _, err := fs.Stat(app, "index.html"); err != nil {
		return nil, ErrNotBuilt
	}
	return app, nil
}
