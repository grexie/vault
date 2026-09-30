//go:build unix

package main

import "github.com/grexie/vault/internal/command"

var version = "dev"

func main() { command.Main(version) }
