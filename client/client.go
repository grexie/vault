package client

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/websocket"
	"github.com/grexie/vault/hub"
)

var server *string

func NewFlagSet() *flag.FlagSet {
	flagSet := flag.NewFlagSet("client", flag.ExitOnError)
	server = flagSet.String("server", "ws://localhost:8080", "server url")
	return flagSet
}

func connect(interrupt chan os.Signal) {
	for {
		log.Println("reconnecting")
		reconnect := make(chan error, 1)
		var protocol *serverProtocol
		var err error
		var c *websocket.Conn

		if c, _, err = websocket.DefaultDialer.Dial(*server, nil); err != nil {
			reconnect <- err
		} else {
			h := hub.NewHub(c)

			if protocol, err = newServerProtocol(h); err != nil {
				reconnect <- err
			} else {
				defer func() {
					if protocol != nil {
						protocol.Done()
					}
				}()
				go protocol.Start()

				go func() {
					defer close(reconnect)
					for {
						if _, message, err := c.ReadMessage(); err != nil {
							reconnect <- err
							return
						} else if err := h.ProcessMessage(message); err != nil {
							reconnect <- err
							return
						}
					}
				}()

			}
		}

		select {
		case err := <-reconnect:
			log.Println(err)
			select {
			case <-time.After(time.Second):
			case <-interrupt:
				return
			}
		case <-interrupt:
			done := make(chan error)

			go func() {
				if err := c.WriteMessage(websocket.CloseMessage, nil); err == nil {
					done <- nil
				} else {
					done <- err
				}
			}()

			select {
			case <-time.After(time.Second):
				log.Println("timeout while aborting due to interrupt")
			case err := <-done:
				if err != nil {
					log.Println(err)
				} else {
					log.Println("exiting due to interrupt")
				}
			}
			return
		}
	}
}

func Run() error {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	connect(interrupt)
	return nil
}
