package protocol

import (
	webrtc "github.com/pion/webrtc/v3"
)

type CreatePeerRequest struct {
	ID string `json:"id"`
}

type CreatePeerResponse struct {
	ID                 string                     `json:"id"`
	SessionDescription *webrtc.SessionDescription `json:"sessionDescription"`
}

type DeletePeerRequest struct {
	ID string `json:"id"`
}
