package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/grexie/vault/client"
	"github.com/grexie/vault/server"
)

type command struct {
	flagSet *flag.FlagSet
	run     func() error
}

func main() {
	commands := []command{
		{
			flagSet: server.NewFlagSet(),
			run:     server.Run,
		},
		{
			flagSet: client.NewFlagSet(),
			run:     client.Run,
		},
	}

	commandNames := []string{}
	for _, command := range commands {
		commandNames = append(commandNames, command.flagSet.Name())
	}

	if len(os.Args) < 2 {
		fmt.Println("usage:", os.Args[0], "(", strings.Join(commandNames, " | "), ")")
		os.Exit(1)
	}

	for _, command := range commands {
		if command.flagSet.Name() == os.Args[1] {
			command.flagSet.Parse(os.Args[2:])
			if err := command.run(); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
	}
}
