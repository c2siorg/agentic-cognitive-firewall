// listener.go — IPC accept loop.
// Accepts connections from the platform Connector (UDS on Linux/macOS,
// named pipe on Windows). Spawns one goroutine per connection.
// Each connection: read frame → verify HMAC → check nonce → run pipeline → write response.
// Invalid HMAC or reused nonce drops the connection immediately with no response.
package transport

import (
	"encoding/json"
	"log"
	"net"
	"time"

	"github.com/acf-sdk/sidecar/internal/clock"
	"github.com/acf-sdk/sidecar/internal/crypto"
	"github.com/acf-sdk/sidecar/internal/pipeline"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// Config holds listener configuration.
type Config struct {
	// Address is the UDS socket path (Linux/macOS) or named pipe name (Windows).
	// If empty, Connector.DefaultAddress() is used.
	Address    string
	Connector  Connector
	Signer     *crypto.Signer
	NonceStore *crypto.NonceStore
	// Pipeline is the enforcement pipeline. If nil, a hardcoded ALLOW is returned
	// (Phase 1 fallback — should not be nil in Phase 2+).
	Pipeline *pipeline.Pipeline
	// OnTiming, if set, receives the step durations of each request that ran
	// the pipeline and got a response. It is called after the response is
	// written, on the connection goroutine, so it must not block. Nil in
	// production, where no clock is read.
	OnTiming func(Timing)
}

// Timing is how long each step of one request took inside the sidecar.
type Timing struct {
	HookType     string
	Decision     byte
	BlockedAt    string
	RiskScore    float64
	Signals      []string
	PayloadBytes int
	// Read covers reading the frame off the connection, including any wait
	// for the client to finish sending it.
	Read      time.Duration
	Verify    time.Duration // HMAC over the signed message
	Nonce     time.Duration // replay check
	Unmarshal time.Duration // JSON payload into a RiskContext
	Pipeline  pipeline.Trace
	Log       time.Duration // per-request decision log line
	Write     time.Duration // encode and write the response
	// Total runs from the start of handleConn to the response being written.
	Total time.Duration
}

// stopwatch times consecutive steps. When off it never reads the clock.
type stopwatch struct {
	on          bool
	start, last time.Duration
}

func newStopwatch(on bool) stopwatch {
	if !on {
		return stopwatch{}
	}
	now := clock.Now()
	return stopwatch{on: true, start: now, last: now}
}

// lap returns the time since the previous lap and starts the next one.
func (s *stopwatch) lap() time.Duration {
	if !s.on {
		return 0
	}
	now := clock.Now()
	d := now - s.last
	s.last = now
	return d
}

func (s *stopwatch) total() time.Duration {
	if !s.on {
		return 0
	}
	return clock.Since(s.start)
}

// Listener wraps a platform net.Listener and handles incoming connections.
type Listener struct {
	cfg    Config
	ln     net.Listener
	stopCh chan struct{}
}

// NewListener creates a Listener bound to cfg.Address using cfg.Connector.
// Any platform-specific cleanup (e.g. stale UDS socket file) is performed
// before binding.
func NewListener(cfg Config) (*Listener, error) {
	if cfg.Address == "" {
		cfg.Address = cfg.Connector.DefaultAddress()
	}

	if err := cfg.Connector.Cleanup(cfg.Address); err != nil {
		return nil, err
	}

	ln, err := cfg.Connector.Listen(cfg.Address)
	if err != nil {
		return nil, err
	}

	return &Listener{
		cfg:    cfg,
		ln:     ln,
		stopCh: make(chan struct{}),
	}, nil
}

// Serve enters the accept loop. Blocks until Stop is called.
// Returns nil after a clean shutdown, or a non-nil error on unexpected failure.
func (l *Listener) Serve() error {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			select {
			case <-l.stopCh:
				return nil // clean shutdown
			default:
				return err
			}
		}
		go l.handleConn(conn)
	}
}

// Stop closes the underlying listener, causing Serve to return.
func (l *Listener) Stop() {
	select {
	case <-l.stopCh:
		// already stopped
	default:
		close(l.stopCh)
	}
	l.ln.Close()
}

// handleConn processes a single client connection.
func (l *Listener) handleConn(conn net.Conn) {
	defer conn.Close()

	sw := newStopwatch(l.cfg.OnTiming != nil)
	var tm Timing

	// 1. Decode the frame header and payload.
	rf, err := DecodeRequest(conn)
	if err != nil {
		log.Printf("transport: decode error: %v", err)
		return
	}
	tm.Read = sw.lap()

	// 2. Verify HMAC.
	length := uint32(len(rf.Payload))
	signedMsg := SignedMessage(rf.Version, length, rf.Nonce, rf.Payload)
	if !l.cfg.Signer.Verify(signedMsg, rf.HMAC[:]) {
		log.Printf("transport: %v", ErrBadHMAC)
		return
	}
	tm.Verify = sw.lap()

	// 3. Check nonce replay.
	if l.cfg.NonceStore.Seen(rf.Nonce[:]) {
		log.Printf("transport: %v", ErrReplayNonce)
		return
	}
	tm.Nonce = sw.lap()

	// 4. Run pipeline if configured; fall back to ALLOW if not (Phase 1 compat).
	decision := DecisionAllow
	if l.cfg.Pipeline != nil {
		var rc riskcontext.RiskContext
		if err := json.Unmarshal(rf.Payload, &rc); err != nil {
			log.Printf("transport: JSON unmarshal error: %v", err)
			resp := EncodeResponse(&ResponseFrame{Decision: DecisionBlock})
			conn.Write(resp) //nolint:errcheck
			return
		}
		tm.Unmarshal = sw.lap()

		var trace *pipeline.Trace
		if sw.on {
			trace = &tm.Pipeline
		}
		result := l.cfg.Pipeline.RunTraced(&rc, trace)
		sw.lap() // the pipeline's own steps are in tm.Pipeline
		decision = result.Decision
		log.Printf("transport: session=%s hook=%s score=%.2f signals=%v decision=%d blocked_at=%s",
			rc.SessionID, rc.HookType, result.Score, result.Signals, decision, result.BlockedAt)
		tm.Log = sw.lap()

		// 5. Write response (include sanitised payload if decision == SANITISE).
		resp := EncodeResponse(&ResponseFrame{
			Decision:         decision,
			SanitisedPayload: result.SanitisedPayload,
		})
		if _, err := conn.Write(resp); err != nil {
			log.Printf("transport: write error: %v", err)
			return
		}
		tm.Write = sw.lap()

		if sw.on {
			tm.HookType = rc.HookType
			tm.Decision = decision
			tm.BlockedAt = result.BlockedAt
			tm.RiskScore = result.Score

			tm.Signals = make([]string, 0, len(result.Signals))
			for _, signal := range result.Signals {
				tm.Signals = append(tm.Signals, signal.Category)
			}

			tm.PayloadBytes = len(rf.Payload)
			tm.Total = sw.total()
			l.cfg.OnTiming(tm)
		}
		return
	}

	// Phase 1 fallback (no pipeline configured): write ALLOW.
	resp := EncodeResponse(&ResponseFrame{Decision: decision})
	if _, err := conn.Write(resp); err != nil {
		log.Printf("transport: write error: %v", err)
	}
}
