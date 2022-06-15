package server

import (
	"log"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/grexie/vault/hub"
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
)

func websocketHandler(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}

	defer c.Close()

	h := hub.NewHub(c)

	if protocol, err := newProtocol(h); err != nil {
		log.Println(err)
		return
	} else {
		defer protocol.Done()
	}

	for {
		_, message, err := c.ReadMessage()
		if err != nil {
			log.Println(err)
			return
		} else if err := h.ProcessMessage(message); err != nil {
			log.Println(err)
			return
		}
	}
}
