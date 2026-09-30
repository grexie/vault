package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed vault/*
var vaultAssets embed.FS

func VaultHandler() http.Handler {
	sub, _ := fs.Sub(vaultAssets, "vault")
	files := http.FileServer(http.FS(sub))
	legacy := Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		switch r.URL.Path {
		case "/":
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/home.html"
			files.ServeHTTP(w, r2)
		case "/app", "/app/":
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/app.html"
			files.ServeHTTP(w, r2)
		case "/wasm_exec.js", "/icon-192.png", "/icon-512.png", "/icon-180.png", "/favicon-32.png":
			legacy.ServeHTTP(w, r)
		case "/SKILL.md", "/skill.md":
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
			b, e := fs.ReadFile(sub, "SKILL.md")
			if e != nil {
				http.NotFound(w, r)
				return
			}
			w.Write(b)
		default:
			if strings.Contains(r.URL.Path, "/") && strings.Count(r.URL.Path, "/") > 1 {
				http.NotFound(w, r)
				return
			}
			files.ServeHTTP(w, r)
		}
	})
}
