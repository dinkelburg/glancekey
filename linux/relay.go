package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	pingInterval = 20 * time.Second
	readTimeout  = 45 * time.Second
)

// runRelay keeps the outgoing WebSocket to the relay open, reconnecting with backoff.
func (a *Agent) runRelay(ctx context.Context) {
	backoff := []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second}
	attempt := 0
	for ctx.Err() == nil {
		connected, err := a.serveRelay(ctx)
		if connected {
			attempt = 0
		}
		if ctx.Err() != nil {
			return
		}
		delay := backoff[minInt(attempt, len(backoff)-1)]
		attempt++
		a.setRelayStatus(fmt.Sprintf("offline (%v), retrying", err))
		log.Printf("Relay connection lost: %v; retrying in %v", err, delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func agentURL(relay, machineID string) string {
	relay = strings.TrimRight(relay, "/")
	relay = strings.Replace(relay, "https://", "wss://", 1)
	relay = strings.Replace(relay, "http://", "ws://", 1)
	return relay + "/v1/agent/" + machineID
}

// serveRelay handles one connection until it drops. It reports whether the connection was established.
func (a *Agent) serveRelay(ctx context.Context) (bool, error) {
	a.mu.Lock()
	url := agentURL(a.state.relayURL(), a.state.MachineID)
	header := http.Header{"Authorization": {"Bearer " + a.state.AgentSecret}}
	a.mu.Unlock()

	dialer := websocket.Dialer{HandshakeTimeout: 15 * time.Second, Proxy: http.ProxyFromEnvironment}
	conn, response, err := dialer.DialContext(ctx, url, header)
	if err != nil {
		if response != nil {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
			var message ErrorResponse
			if json.Unmarshal(body, &message) == nil && message.Error != "" {
				return false, fmt.Errorf("%s (HTTP %d)", message.Error, response.StatusCode)
			}
			return false, fmt.Errorf("HTTP %d", response.StatusCode)
		}
		return false, err
	}
	defer conn.Close()
	// The relay isn't trusted, so it doesn't get to make this agent buffer or run without bounds either.
	conn.SetReadLimit(maxRelayMessage)
	a.setRelayStatus("connected")
	log.Printf("Connected to %s", url)

	var writeMu sync.Mutex
	write := func(data []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return conn.WriteMessage(websocket.TextMessage, data)
	}
	a.setRelaySender(write)
	defer a.setRelaySender(nil)

	done := make(chan struct{})
	defer close(done)
	go func() {
		// Ping to keep NAT mappings alive. Go timers pause during suspend, so also watch the wall clock:
		// a jump means the machine slept and the connection is probably dead, so reconnect right away.
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		lastTick, lastPing := time.Now().Round(0), time.Now()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				conn.Close()
				return
			case <-ticker.C:
				now := time.Now().Round(0)
				if now.Sub(lastTick) > 30*time.Second {
					log.Print("Woke from sleep; reconnecting")
					conn.Close()
					return
				}
				lastTick = now
				if time.Since(lastPing) >= pingInterval {
					lastPing = time.Now()
					if err := write([]byte("ping")); err != nil {
						conn.Close()
						return
					}
				}
			}
		}
	}()

	busy := make(chan struct{}, maxRelayRequests)
	for {
		conn.SetReadDeadline(time.Now().Add(readTimeout))
		kind, data, err := conn.ReadMessage()
		if err != nil {
			return true, err
		}
		if kind != websocket.TextMessage || string(data) == "pong" {
			continue
		}
		var request RelayRequest
		if err := json.Unmarshal(data, &request); err != nil {
			continue
		}
		select {
		case busy <- struct{}{}:
		default:
			reply, _ := json.Marshal(RelayResponse{ID: request.ID, Status: 503, Body: `{"error":"Your computer is busy. Try again."}`})
			write(reply)
			continue
		}
		go func() {
			defer func() { <-busy }()
			status, result := a.handle(request.Path, []byte(request.Body))
			body, _ := json.Marshal(result)
			reply, _ := json.Marshal(RelayResponse{ID: request.ID, Status: status, Body: string(body)})
			if err := write(reply); err != nil {
				log.Printf("Couldn't answer the relay: %v", err)
			}
		}()
	}
}

const (
	// Requests are at most 16 KB at the relay (relay/src/index.ts); JSON escaping can double that.
	maxRelayMessage  = 64 << 10
	maxRelayRequests = 16
)

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
