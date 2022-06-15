package client

import (
	"encoding/json"
	"errors"
	"log"
	"sync"

	"github.com/grexie/vault/hub"
	proto "github.com/grexie/vault/protocol"
	"github.com/grexie/vault/webrtc"
	webrtc2 "github.com/pion/webrtc/v3"
)

type serverProtocol struct {
	sync.Mutex
	hub        *hub.Hub
	ICEServers []string
	peers      map[string]*webrtc.PeerConnection
}

func newServerProtocol(hub *hub.Hub) (*serverProtocol, error) {
	p := &serverProtocol{
		hub:   hub,
		peers: map[string]*webrtc.PeerConnection{},
	}

	hub.Handle("create-peer", p.onCreatePeer)
	hub.Handle("delete-peer", p.onDeletePeer)

	return p, nil
}

func (p *serverProtocol) Done() {

}

func (p *serverProtocol) Start() {
	p.hub.Request("connect", &proto.ConnectRequest{
		Type: proto.CONNECT_TYPE_SERVICE,
	}, func(res interface{}, err error) {

		var connectResponse proto.ConnectResponse
		if bytes, err := json.Marshal(res); err != nil {
		} else if err := json.Unmarshal(bytes, &connectResponse); err != nil {
		} else {
			p.ICEServers = connectResponse.ICEServers
			log.Println("connected")
		}
	})
}

func (p *serverProtocol) onCreatePeer(res hub.ResponseWriter, req *hub.Request) error {
	var createPeerRequest proto.CreatePeerRequest
	if bytes, err := json.Marshal(req.Payload); err != nil {
		return err
	} else if err := json.Unmarshal(bytes, &createPeerRequest); err != nil {
		return err
	} else if peer, err := webrtc.NewPeerConnection(createPeerRequest.ID, p.ICEServers, p.hub); err != nil {
		return err
	} else {
		peer.OnConnectionStateChange(func(c webrtc2.PeerConnectionState) {
			if c == webrtc2.PeerConnectionStateClosed {
				if err := p.deletePeer(createPeerRequest.ID); err == nil {
					p.hub.RequestWithoutResponse("delete-peer", &proto.DeletePeerRequest{
						ID: createPeerRequest.ID,
					})
				}
			}
		})

		p.Lock()
		p.peers[createPeerRequest.ID] = peer
		p.Unlock()

		if err := startUserProtocol(peer.Hub); err != nil {
			return err
		} else if offer, err := peer.CreateOffer(); err != nil {
			return err
		} else {
			return res.Write(&proto.CreatePeerResponse{
				ID:                 peer.ID,
				SessionDescription: offer,
			})
		}
	}
}

func (p *serverProtocol) deletePeer(id string) error {
	p.Lock()
	defer p.Unlock()

	if peer, ok := p.peers[id]; !ok {
		return errors.New("peer not found")
	} else {
		delete(p.peers, id)
		return peer.Close()
	}
}

func (p *serverProtocol) onDeletePeer(res hub.ResponseWriter, req *hub.Request) error {
	var deletePeerRequest proto.DeletePeerRequest

	if bytes, err := json.Marshal(req.Payload); err != nil {
		return err
	} else if err := json.Unmarshal(bytes, &deletePeerRequest); err != nil {
		return err
	} else {
		return p.deletePeer(deletePeerRequest.ID)
	}
}
