package server

import (
	"encoding/json"
	"errors"
	"log"
	"sync"

	"github.com/google/uuid"
	"github.com/grexie/vault/hub"
	proto "github.com/grexie/vault/protocol"
	"github.com/grexie/vault/webrtc"
)

var protocols = map[proto.ConnectType]map[string]*protocol{}
var peers = map[string]*peer{}
var mutex = sync.Mutex{}

type peer struct {
	service *protocol
	user    *protocol
}

type protocol struct {
	sync.Mutex
	hub            *hub.Hub
	connected      bool
	connectRequest proto.ConnectRequest
	peers          map[string]bool
}

func newProtocol(hub *hub.Hub) (*protocol, error) {
	p := &protocol{
		Mutex: sync.Mutex{},
		hub:   hub,
		peers: map[string]bool{},
	}
	hub.Handle("connect", p.onConnect)
	hub.Handle("delete-peer", p.onDeletePeer)
	hub.Handle("ice-candidate", p.onICECandidate)

	return p, nil
}

func (p *protocol) Done() {
	for peer := range p.peers {
		p.deletePeer(peer)
	}

	mutex.Lock()
	if protocolsOfType, ok := protocols[p.connectRequest.Type]; ok {
		delete(protocolsOfType, p.hub.ID)
		if len(protocolsOfType) == 0 {
			delete(protocols, p.connectRequest.Type)
		}
	}
	mutex.Unlock()

	log.Println("disconnected:", p.connectRequest.Type, p.hub.ID)

	log.Println("len of peers", len(peers), len(p.peers))
}

func (p *protocol) announce(user *protocol) error {
	var createPeerResponse proto.CreatePeerResponse

	if res, err := p.hub.RequestSync("create-peer", &proto.CreatePeerRequest{
		ID: uuid.NewString(),
	}); err != nil {
		log.Println(err)
		return err
	} else if bytes, err := json.Marshal(res); err != nil {
		log.Println(err)
		return err
	} else if err := json.Unmarshal(bytes, &createPeerResponse); err != nil {
		log.Println(err)
		return err
	} else {
		mutex.Lock()
		peers[createPeerResponse.ID] = &peer{
			service: p,
			user:    user,
		}
		mutex.Unlock()

		p.Lock()
		user.Lock()
		p.peers[createPeerResponse.ID] = true
		user.peers[createPeerResponse.ID] = true
		user.Unlock()
		p.Unlock()

		if res, err := user.hub.RequestSync("announce", createPeerResponse); err != nil {
			log.Println(err)
			return err
		} else if _, err := p.hub.RequestSync("answer", res); err != nil {
			return err
		} else {
			log.Println("answer responded")
			return nil
		}
	}
}

func (p *protocol) onICECandidate(res hub.ResponseWriter, req *hub.Request) error {
	var iceCandidate webrtc.ICECandidate

	if bytes, err := json.Marshal(req.Payload); err != nil {
		return err
	} else if err := json.Unmarshal(bytes, &iceCandidate); err != nil {
		return err
	} else {
		mutex.Lock()
		peer, ok := peers[iceCandidate.ID]
		mutex.Unlock()

		if !ok {
			return errors.New("peer not found")
		} else if p.connectRequest.Type == proto.CONNECT_TYPE_SERVICE {
			return peer.user.hub.RequestWithoutResponse("ice-candidate", req.Payload)
		} else if p.connectRequest.Type == proto.CONNECT_TYPE_USER {
			return peer.service.hub.RequestWithoutResponse("ice-candidate", req.Payload)
		} else {
			return errors.New("protocol error")
		}
	}
}

func (p *protocol) deletePeer(id string) error {
	mutex.Lock()
	if peer, ok := peers[id]; !ok {
		mutex.Unlock()
		return errors.New("peer not found")
	} else {
		peer.service.Lock()
		peer.user.Lock()
		delete(peer.service.peers, id)
		delete(peer.user.peers, id)
		delete(peers, id)
		peer.user.Unlock()
		peer.service.Unlock()
		mutex.Unlock()

		if p.connectRequest.Type == proto.CONNECT_TYPE_SERVICE {
			return peer.user.hub.RequestWithoutResponse("delete-peer", &proto.DeletePeerRequest{ID: id})
		} else if p.connectRequest.Type == proto.CONNECT_TYPE_USER {
			return peer.user.hub.RequestWithoutResponse("delete-peer", &proto.DeletePeerRequest{ID: id})
		} else {
			return nil
		}
	}
}

func (p *protocol) onDeletePeer(res hub.ResponseWriter, req *hub.Request) error {
	var deletePeerRequest proto.DeletePeerRequest
	if bytes, err := json.Marshal(req.Payload); err != nil {
		return err
	} else if err := json.Unmarshal(bytes, &deletePeerRequest); err != nil {
		return err
	} else {
		return p.deletePeer(deletePeerRequest.ID)
	}
}

func (p *protocol) onConnect(res hub.ResponseWriter, req *hub.Request) error {
	if p.connected {
		return errors.New("already connected")
	}

	if bytes, err := json.Marshal(req.Payload); err != nil {
		return err
	} else if err := json.Unmarshal(bytes, &p.connectRequest); err != nil {
		return err
	}

	p.connected = true

	mutex.Lock()
	protocolsOfType, ok := protocols[p.connectRequest.Type]
	if !ok {
		protocolsOfType = map[string]*protocol{}
		protocols[p.connectRequest.Type] = protocolsOfType
	}
	protocolsOfType[p.hub.ID] = p
	mutex.Unlock()

	log.Println("connected:", p.connectRequest.Type, p.hub.ID)
	res.Write(&proto.ConnectResponse{
		ICEServers: []string{},
	})

	if p.connectRequest.Type == proto.CONNECT_TYPE_USER {
		if services, ok := protocols[proto.CONNECT_TYPE_SERVICE]; ok {
			for _, service := range services {
				if err := service.announce(p); err != nil {
					return err
				}
			}
		}
	} else if p.connectRequest.Type == proto.CONNECT_TYPE_SERVICE {
		if users, ok := protocols[proto.CONNECT_TYPE_USER]; ok {
			for _, user := range users {
				if err := p.announce(user); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
