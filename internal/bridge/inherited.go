//go:build unix

package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/grexie/remote-ssh-agent/internal/access"
	"github.com/grexie/remote-ssh-agent/internal/app"
)

// InheritedSocket recognizes only this user's Remote SSH Agent sockets, then
// verifies the lease with its client proof. Ordinary SSH agents are ignored.
// Once a managed socket is recognized, any failure is terminal: it must not
// silently create a replacement request or select a different active lease.
// An explicit task lease may have a different pairing/job config on this server.
func InheritedSocket(ctx context.Context, c Config, socket string) (found bool, err error) {
	if socket == "" {
		return false, nil
	}
	d, e := RuntimeDir()
	if e != nil {
		return false, e
	}
	realDir, e := filepath.EvalSymlinks(d)
	if e != nil {
		return false, e
	}
	canonical := func(p string) string {
		p = filepath.Clean(p)
		if strings.HasPrefix(p, d+string(os.PathSeparator)) {
			p = realDir + strings.TrimPrefix(p, d)
		}
		return p
	}
	if !strings.HasPrefix(canonical(socket), realDir+string(os.PathSeparator)) {
		return false, nil
	}
	target, e := filepath.EvalSymlinks(socket)
	if e != nil {
		return true, errors.New("inherited Remote SSH Agent socket is unavailable; do not retry without a fresh request")
	}
	files, e := filepath.Glob(filepath.Join(d, "*.json"))
	if e != nil {
		return true, e
	}
	for _, path := range files {
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 128*1024 {
			continue
		}
		b, e := os.ReadFile(path)
		if e != nil {
			continue
		}
		var l Lease
		e = json.Unmarshal(b, &l)
		clear(b)
		if e != nil || canonical(l.Request.Socket) != target {
			continue
		}
		if l.Config.Server != c.Server {
			return true, errors.New("inherited socket belongs to a different Remote SSH Agent server")
		}
		expected, _, _, e := paths(l.Config, l.Request.Session)
		if e != nil || expected != path {
			return true, errors.New("inherited socket has invalid local request state")
		}
		var q app.Request
		if e := leaseClient(l).Call(ctx, "GET", "/v1/requests/"+l.Request.ID, l.Capability, nil, &q); e != nil {
			return true, fmt.Errorf("cannot verify inherited socket: %w", e)
		}
		if q.ID != l.Request.ID || canonical(q.Socket) != target || q.Status != "active" || !access.AllowsSSH(q.Access) || !time.Now().Before(q.ExpiresAt) {
			return true, errors.New("inherited socket does not have an active SSH lease")
		}
		conn, e := net.DialTimeout("unix", target, time.Second)
		if e != nil {
			return true, fmt.Errorf("inherited socket is not listening: %w", e)
		}
		conn.Close()
		return true, nil
	}
	return true, errors.New("inherited socket has no matching local request")
}
