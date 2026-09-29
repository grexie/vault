// An isolated loopback SSH/SFTP server for the browser approval smoke test.
// It accepts only the generated fixture public key and writes no private keys.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) != 3 {
		panic("expected fixture public key and scratch directory")
	}
	b, err := os.ReadFile(os.Args[1])
	check(err)
	allowed, _, _, _, err := ssh.ParseAuthorizedKey(b)
	check(err)
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	check(err)
	host, err := ssh.NewSignerFromKey(hostKey)
	check(err)
	c := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(key.Marshal(), allowed.Marshal()) {
			return nil, fmt.Errorf("not the fixture key")
		}
		return nil, nil
	}}
	c.AddHostKey(host)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	check(err)
	port := listener.Addr().(*net.TCPAddr).Port
	sftp := ""
	for _, path := range []string{"/usr/lib/openssh/sftp-server", "/usr/lib/ssh/sftp-server", "/usr/libexec/sftp-server"} {
		if _, err := os.Stat(path); err == nil {
			sftp = path
			break
		}
	}
	if sftp == "" {
		panic("install openssh-sftp-server for the native scp test")
	}
	check(json.NewEncoder(os.Stdout).Encode(map[string]any{"port": port, "hostKey": string(ssh.MarshalAuthorizedKey(host.PublicKey()))}))
	for {
		conn, err := listener.Accept()
		check(err)
		go func() {
			defer conn.Close()
			_, channels, requests, err := ssh.NewServerConn(conn, c)
			if err != nil {
				return
			}
			go ssh.DiscardRequests(requests)
			for request := range channels {
				if request.ChannelType() == "direct-tcpip" {
					var dest struct {
						Host       string
						Port       uint32
						Origin     string
						OriginPort uint32
					}
					if ssh.Unmarshal(request.ExtraData(), &dest) != nil || dest.Host != "127.0.0.1" || dest.Port != uint32(port) {
						request.Reject(ssh.Prohibited, "only fixture forwarding is permitted")
						continue
					}
					go func() {
						ch, reqs, err := request.Accept()
						if err != nil {
							return
						}
						defer ch.Close()
						go ssh.DiscardRequests(reqs)
						upstream, err := net.Dial("tcp", net.JoinHostPort(dest.Host, strconv.Itoa(int(dest.Port))))
						if err != nil {
							return
						}
						defer upstream.Close()
						go func() { io.Copy(upstream, ch); upstream.(*net.TCPConn).CloseWrite() }()
						io.Copy(ch, upstream)
					}()
					continue
				}
				if request.ChannelType() != "session" {
					request.Reject(ssh.UnknownChannelType, "unsupported")
					continue
				}
				go func() {
					ch, reqs, err := request.Accept()
					if err != nil {
						return
					}
					defer ch.Close()
					for req := range reqs {
						var arg struct{ Value string }
						if ssh.Unmarshal(req.Payload, &arg) != nil {
							req.Reply(false, nil)
							continue
						}
						var cmd *exec.Cmd
						switch req.Type {
						case "exec":
							cmd = exec.Command("/bin/sh", "-c", arg.Value)
						case "subsystem":
							if arg.Value == "sftp" {
								cmd = exec.Command(sftp, "-d", os.Args[2])
							}
						}
						if cmd == nil {
							req.Reply(false, nil)
							continue
						}
						cmd.Dir = filepath.Clean(os.Args[2])
						// Legacy scp waits for the exit status before closing input.
						// Own this pump so exec.Wait doesn't wait for that same EOF.
						input, err := cmd.StdinPipe()
						if err != nil {
							req.Reply(false, nil)
							return
						}
						cmd.Stdout, cmd.Stderr = ch, ch.Stderr()
						go func() { io.Copy(input, ch); input.Close() }()
						req.Reply(true, nil)
						err = cmd.Run()
						code := uint32(0)
						if err != nil {
							code = 1
							if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() >= 0 {
								code = uint32(cmd.ProcessState.ExitCode())
							}
						}
						ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
						return
					}
				}()
			}
		}()
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
