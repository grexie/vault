package cloud

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/grexie/vault/internal/cloudstore"
)

type pushConfig struct {
	Public  string `json:"public"`
	Private string `json:"private"`
}

func (s *Server) pushRoutes(ctx context.Context, mux *http.ServeMux) error {
	var config pushConfig
	_, err := s.store.Get(ctx, "configuration", "push", &config)
	if errors.Is(err, cloudstore.ErrNotFound) {
		config.Private, config.Public, err = webpush.GenerateVAPIDKeys()
		if err != nil {
			return err
		}
		err = s.store.Put(ctx, "configuration", "push", 0, config, nil)
		if errors.Is(err, cloudstore.ErrConflict) {
			_, err = s.store.Get(ctx, "configuration", "push", &config)
		}
	}
	if err != nil {
		return err
	}
	mux.HandleFunc("GET /api/v1/push/key", s.requireSession(func(w http.ResponseWriter, r *http.Request, session Session, user User) {
		reply(w, 200, map[string]string{"publicKey": config.Public})
	}))
	mux.HandleFunc("POST /api/v1/push/subscribe", s.requireSession(s.subscribePush))
	return nil
}
func (s *Server) subscribePush(w http.ResponseWriter, r *http.Request, session Session, user User) {
	var in struct {
		webpush.Subscription
		ExpirationTime *uint64 `json:"expirationTime"`
	}
	if !decode(w, r, &in) {
		return
	}
	u, e := url.Parse(in.Endpoint)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" {
		fail(w, 400, "Invalid push endpoint")
		return
	}
	h := u.Hostname()
	allowed := h == "fcm.googleapis.com" || h == "updates.push.services.mozilla.com" || strings.HasSuffix(h, ".push.apple.com")
	a, e1 := base64.RawURLEncoding.DecodeString(in.Keys.Auth)
	p, e2 := base64.RawURLEncoding.DecodeString(in.Keys.P256dh)
	if !allowed || e1 != nil || e2 != nil || len(a) != 16 || len(p) != 65 {
		fail(w, 400, "Unsupported push subscription")
		return
	}
	var old webpush.Subscription
	v, e := s.store.Get(r.Context(), "push:"+user.key(), hash(in.Endpoint), &old)
	if e != nil && !errors.Is(e, cloudstore.ErrNotFound) {
		fail(w, 503, "Push storage unavailable")
		return
	}
	if v == 0 {
		docs, e := s.store.List(r.Context(), "push:"+user.key())
		if e != nil || len(docs) >= 20 {
			fail(w, 409, "Notification device limit reached")
			return
		}
	}
	if s.store.Put(r.Context(), "push:"+user.key(), hash(in.Endpoint), v, in.Subscription, nil) != nil {
		fail(w, 409, "Subscription changed; retry")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
func (s *Server) notify(owner string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var config pushConfig
	if _, e := s.store.Get(ctx, "configuration", "push", &config); e != nil {
		return
	}
	docs, e := s.store.List(ctx, "push:"+owner)
	if e != nil {
		return
	}
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, doc := range docs {
		var sub webpush.Subscription
		if s.store.Open(doc, &sub) != nil {
			continue
		}
		res, e := webpush.SendNotificationWithContext(ctx, []byte(`{"title":"Vault approval requested","body":"Open Vault to review this request."}`), &sub, &webpush.Options{HTTPClient: client, Subscriber: s.cfg.Origin, VAPIDPublicKey: config.Public, VAPIDPrivateKey: config.Private, TTL: 300, Urgency: webpush.UrgencyHigh})
		if e == nil {
			res.Body.Close()
			if res.StatusCode == 404 || res.StatusCode == 410 {
				_ = s.store.Delete(ctx, "push:"+owner, hash(sub.Endpoint))
			}
		}
	}
}

// Coalesce bursts and bound background notification work across all accounts.
func (s *Server) notifyRequest(owner string) {
	s.mu.Lock()
	now := time.Now()
	last := s.notified[owner]
	if now.Sub(last) < 5*time.Second {
		s.mu.Unlock()
		return
	}
	for id, at := range s.notified {
		if now.Sub(at) > time.Minute {
			delete(s.notified, id)
		}
	}
	s.notified[owner] = now
	s.mu.Unlock()
	select {
	case s.notifications <- struct{}{}:
		go func() { defer func() { <-s.notifications }(); s.notify(owner) }()
	default:
	}
}
