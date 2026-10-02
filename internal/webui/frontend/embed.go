package frontend

import (
	"embed"
	"io/fs"
)

//go:embed static/*
var staticFS embed.FS

// GetFS returns the sub-filesystem pointing to static assets.
func GetFS() (fs.FS, error) {
	return fs.Sub(staticFS, "static")
}
