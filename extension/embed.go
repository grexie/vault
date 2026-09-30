// Package extension embeds the built Chrome wallet so vault install is self contained.
package extension

import "embed"

//go:embed dist/*
var Assets embed.FS
