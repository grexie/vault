package cloud

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Forwarded identity is accepted only from explicitly provisioned proxy peers.
// The proxy must remove untrusted forwarded headers before setting X-Real-IP.
func trustedProxies(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil || p.Bits() == 0 || p.Addr().Zone() != "" {
			return nil, errors.New("trusted proxies must be explicit, non-default CIDR ranges")
		}
		if p.Addr().Is4In6() {
			if p.Bits() <= 96 {
				return nil, errors.New("trusted proxy range is too broad")
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func (s *Server) clientIP(r *http.Request) (string, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || peer.Zone() != "" {
		return "", errors.New("invalid client address")
	}
	peer = peer.Unmap()
	for _, proxy := range s.proxies {
		if !proxy.Contains(peer) {
			continue
		}
		values := r.Header.Values("X-Real-IP")
		if len(values) != 1 || values[0] != strings.TrimSpace(values[0]) {
			return "", errors.New("trusted proxy must provide one client address")
		}
		address, e := netip.ParseAddr(values[0])
		if e != nil || address.Zone() != "" {
			return "", errors.New("trusted proxy must provide one literal client IP")
		}
		return address.Unmap().String(), nil
	}
	return peer.String(), nil
}

func (s *Server) allowIP(w http.ResponseWriter, r *http.Request, scope, message string) bool {
	ip, err := s.clientIP(r)
	if err != nil {
		fail(w, http.StatusBadRequest, "Invalid proxy client address")
		return false
	}
	if !s.allowKey(scope + "/" + ip) {
		fail(w, http.StatusTooManyRequests, message)
		return false
	}
	return true
}
