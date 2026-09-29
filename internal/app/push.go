package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
)

// An allowlist prevents authenticated subscription endpoints becoming an SSRF
// primitive. Redirects are disabled as well.
func validPush(s webpush.Subscription) bool {
	u, e := url.Parse(s.Endpoint)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" {
		return false
	}
	h := u.Hostname()
	allowed := h == "fcm.googleapis.com" || h == "updates.push.services.mozilla.com" || strings.HasSuffix(h, ".push.apple.com")
	a, e1 := base64.RawURLEncoding.DecodeString(s.Keys.Auth)
	p, e2 := base64.RawURLEncoding.DecodeString(s.Keys.P256dh)
	return allowed && e1 == nil && e2 == nil && len(a) == 16 && len(p) == 65
}
func (s *Server) subscribe(w http.ResponseWriter, r *http.Request) {
	// Browser PushSubscription.toJSON() includes this nullable timestamp. The
	// delivery library only models endpoint/keys; decode the browser shape
	// explicitly without weakening unknown-field validation for other inputs.
	var in struct {
		webpush.Subscription
		ExpirationTime *uint64 `json:"expirationTime"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !validPush(in.Subscription) {
		fail(w, 400, "Unsupported push endpoint or invalid subscription")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, v := range s.state.Push {
		if v.Endpoint == in.Endpoint {
			s.state.Push = append(s.state.Push[:i], s.state.Push[i+1:]...)
			break
		}
	}
	if len(s.state.Push) >= 10 {
		fail(w, 409, "Too many notification devices")
		return
	}
	s.state.Push = append(s.state.Push, in.Subscription)
	if err := s.persistLocked(); err != nil {
		s.errorInternal(w, err)
		return
	}
	jsonReply(w, 200, map[string]bool{"ok": true})
}
func (s *Server) notify(id string) {
	s.mu.Lock()
	q := s.state.Requests[id]
	if q == nil || s.closed {
		s.mu.Unlock()
		return
	}
	subs := append([]webpush.Subscription{}, s.state.Push...)
	pub, priv := s.state.VAPIDPublic, s.state.VAPIDPrivate
	s.mu.Unlock()
	// Justifications stay off the lock screen. Open the authenticated app to see them.
	payload, _ := json.Marshal(map[string]string{"title": "SSH access requested", "body": "Open Remote SSH Agent to review and approve.", "requestId": id})
	delivered := 0
	expired := map[string]bool{}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, sub := range subs {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		res, err := webpush.SendNotificationWithContext(ctx, payload, &sub, &webpush.Options{HTTPClient: client, Subscriber: s.config.Origin, VAPIDPublicKey: pub, VAPIDPrivateKey: priv, TTL: 300, Urgency: webpush.UrgencyHigh})
		if err == nil {
			res.Body.Close()
			if res.StatusCode >= 200 && res.StatusCode < 300 {
				delivered++
			}
			if res.StatusCode == 404 || res.StatusCode == 410 {
				expired[sub.Endpoint] = true
			}
		}
		cancel()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if q = s.state.Requests[id]; q != nil {
		q.Notification = "failed"
		if len(subs) == 0 {
			q.Notification = "not configured"
		} else if delivered > 0 {
			q.Notification = "sent"
		}
	}
	kept := s.state.Push[:0]
	for _, sub := range s.state.Push {
		if !expired[sub.Endpoint] {
			kept = append(kept, sub)
		}
	}
	s.state.Push = kept
	_ = s.persistLocked()
}
