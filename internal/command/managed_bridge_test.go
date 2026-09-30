//go:build unix

package command

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestManagedBridgeRefusesExtensionsAndMutationsWithoutLosingSigning(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	ring := agent.NewKeyring()
	if err = ring.Add(agent.AddedKey{PrivateKey: key}); err != nil {
		t.Fatal(err)
	}
	clientConn, bridgeConn := net.Pipe()
	defer clientConn.Close()
	clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveManagedSSHConn(context.Background(), bridgeConn, func(packet []byte) ([]byte, error) {
			if packet[4] != 11 && packet[4] != 13 {
				t.Errorf("forbidden operation reached signing device: %d", packet[4])
			}
			left, right := net.Pipe()
			defer left.Close()
			go func() { defer right.Close(); agent.ServeAgent(ring, right) }()
			if _, err := left.Write(packet); err != nil {
				return nil, err
			}
			header := make([]byte, 4)
			if _, err := io.ReadFull(left, header); err != nil {
				return nil, err
			}
			reply := make([]byte, 4+int(binary.BigEndian.Uint32(header)))
			copy(reply, header)
			_, err := io.ReadFull(left, reply[4:])
			return reply, err
		})
	}()
	// Adding/removing/locking keys, constraints, and unknown operations must
	// fail locally, with a valid reply and without breaking later signatures.
	packets := [][]byte{ssh.Marshal(struct {
		Type byte
		Name string
	}{27, "session-bind@openssh.com"})}
	for _, op := range []byte{7, 9, 17, 18, 19, 20, 21, 22, 23, 25, 26, 255} {
		packets = append(packets, []byte{op})
	}
	for _, packet := range packets {
		message := make([]byte, 4+len(packet))
		binary.BigEndian.PutUint32(message, uint32(len(packet)))
		copy(message[4:], packet)
		if _, err = clientConn.Write(message); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 5)
		if _, err = io.ReadFull(clientConn, reply); err != nil || !bytes.Equal(reply, []byte{0, 0, 0, 1, 5}) {
			t.Fatalf("operation %d response = %v, %v", packet[0], reply, err)
		}
	}
	client := agent.NewClient(clientConn)
	keys, err := client.List()
	if err != nil || len(keys) != 1 || !bytes.Equal(keys[0].Blob, public.Marshal()) {
		t.Fatalf("key list after refusals = %v, %v", keys, err)
	}
	data := []byte("approved SSH authentication fixture")
	signature, err := client.Sign(public, data)
	if err != nil {
		t.Fatal(err)
	}
	if err = public.Verify(data, signature); err != nil {
		t.Fatal(err)
	}
	clientConn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bridge did not exit after client disconnected")
	}
}

func TestManagedBridgeClosesOnCancellation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveManagedSSHConn(ctx, server, func([]byte) ([]byte, error) {
			t.Error("idle connection unexpectedly invoked signing device")
			return nil, errors.New("unexpected operation")
		})
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled bridge left a connection open")
	}
}
