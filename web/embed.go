package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static/*
var assets embed.FS

func Handler() http.Handler {
	sub, _ := fs.Sub(assets, "static")
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Embedded asset paths are stable across releases. Revalidate them so
		// installed PWAs do not keep old authentication code after an update.
		w.Header().Set("Cache-Control", "no-cache")
		if r.URL.Path == "/sw.js" {
			w.Header().Set("Service-Worker-Allowed", "/")
		}
		files.ServeHTTP(w, r)
	})
}
