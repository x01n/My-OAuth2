package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var staticFiles embed.FS

// GetFileSystem returns the embedded file system for static files
func GetFileSystem() http.FileSystem {
	sub, err := fs.Sub(staticFiles, "dist")
	if err != nil {
		panic(err)
	}
	return http.FS(sub)
}

// HasStaticFiles checks if static files are embedded
func HasStaticFiles() bool {
	_, err := staticFiles.Open("dist/index.html")
	return err == nil
}
