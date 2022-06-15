package protocol

type ConnectType string

const (
	CONNECT_TYPE_SERVICE ConnectType = "service"
	CONNECT_TYPE_USER    ConnectType = "user"
)

type ConnectRequest struct {
	Type ConnectType `json:"type"`
}

type ConnectResponse struct {
	ICEServers []string `json:"iceServers"`
}
