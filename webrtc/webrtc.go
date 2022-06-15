package webrtc

import (
	"encoding/json"
	"log"
	"sync"

	"github.com/grexie/vault/hub"
	proto "github.com/grexie/vault/protocol"
	webrtc "github.com/pion/webrtc/v3"
)

type PeerConnection struct {
	sync.Mutex
	conn           *webrtc.PeerConnection
	channel        *webrtc.DataChannel
	queue          [][]byte
	Hub            *hub.Hub
	signalling     *hub.Hub
	iceCandidates  []webrtc.ICECandidateInit
	answerReceived bool
	onClose        func()
	ID             string
}

type ICECandidate struct {
	ID           string                  `json:"id"`
	ICECandidate webrtc.ICECandidateInit `json:"candidate"`
}

func NewPeerConnection(id string, urls []string, signalling *hub.Hub) (*PeerConnection, error) {
	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs: urls,
			},
		},
	}

	peerConnection, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return nil, err
	}

	peerConnection.OnConnectionStateChange(func(pcs webrtc.PeerConnectionState) {
		log.Println("peer connection state change", pcs)
	})

	c := &PeerConnection{
		Mutex:         sync.Mutex{},
		conn:          peerConnection,
		ID:            id,
		signalling:    signalling,
		iceCandidates: []webrtc.ICECandidateInit{},
	}

	hub := hub.NewHub(c)
	c.Hub = hub

	removeAnswerHandler := signalling.Handle("answer", c.onAnswer)
	removeICECandidateHandler := signalling.Handle("ice-candidate", c.onCandidate)

	c.onClose = func() {
		removeAnswerHandler()
		removeICECandidateHandler()
	}

	peerConnection.OnICECandidate(func(i *webrtc.ICECandidate) {
		if i == nil {
			return
		}

		c.sendICECandidate(i.ToJSON())
	})

	if d, err := peerConnection.CreateDataChannel("hub", nil); err != nil {
		peerConnection.Close()
		log.Println(err)
		return nil, err
	} else {
		c.channel = d

		d.OnOpen(func() {
			queue := c.queue
			c.queue = [][]byte{}
			for _, bytes := range queue {
				d.Send(bytes)
			}
		})

		d.OnClose(func() {
			c.Close()
		})

		d.OnMessage(func(msg webrtc.DataChannelMessage) {
			hub.ProcessMessage(msg.Data)
		})
	}

	return c, nil
}

func (c *PeerConnection) Close() error {
	return c.conn.Close()
}

func (c *PeerConnection) sendICECandidate(iceCandidate webrtc.ICECandidateInit) {
	c.Lock()
	if c.answerReceived {
		c.Unlock()

		candidate := &ICECandidate{
			ID:           c.ID,
			ICECandidate: iceCandidate,
		}

		c.signalling.RequestWithoutResponse("ice-candidate", candidate)
	} else {
		c.iceCandidates = append(c.iceCandidates, iceCandidate)
		c.Unlock()
	}
}

func (c *PeerConnection) OnConnectionStateChange(handler func(c webrtc.PeerConnectionState)) {
	c.conn.OnConnectionStateChange(handler)
}

func (c *PeerConnection) CreateOffer() (*webrtc.SessionDescription, error) {
	if offer, err := c.conn.CreateOffer(nil); err != nil {
		return nil, err
	} else if err := c.conn.SetLocalDescription(offer); err != nil {
		return nil, err
	} else {
		return &offer, err
	}
}

func (c *PeerConnection) onAnswer(res hub.ResponseWriter, req *hub.Request) error {
	var createPeerResponse proto.CreatePeerResponse

	if bytes, err := json.Marshal(req.Payload); err != nil {
		return err
	} else if err := json.Unmarshal(bytes, &createPeerResponse); err != nil {
		return err
	} else if createPeerResponse.ID != c.ID {
		return nil
	} else if err := c.conn.SetRemoteDescription(*createPeerResponse.SessionDescription); err != nil {
		return err
	}

	c.Lock()
	c.answerReceived = true
	c.Unlock()
	for _, iceCandidate := range c.iceCandidates {
		c.sendICECandidate(iceCandidate)
	}
	c.iceCandidates = []webrtc.ICECandidateInit{}

	return nil
}

func (c *PeerConnection) onCandidate(res hub.ResponseWriter, req *hub.Request) error {
	var candidate ICECandidate

	if bytes, err := json.Marshal(req.Payload); err != nil {
		return err
	} else if err := json.Unmarshal(bytes, &candidate); err != nil {
		return err
	} else if candidate.ID != c.ID {
		return nil
	} else if err := c.conn.AddICECandidate(candidate.ICECandidate); err != nil {
		return err
	}

	return nil
}

func (c *PeerConnection) WriteJSON(message interface{}) error {
	if bytes, err := json.Marshal(message); err != nil {
		return err
	} else if c.channel == nil {
		c.queue = append(c.queue, bytes)
		return nil
	} else {
		return c.channel.Send(bytes)
	}
}
