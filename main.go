package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/sethvargo/go-envconfig"
	"github.com/simon-engledew/kafkaproto"
	"golang.org/x/sync/errgroup"
)

const (
	apiKeyFetch            = 1
	apiKeyMetadata         = 3
	apiKeyFindCoordinator  = 10
	apiKeySaslHandshake    = 17
	apiKeyApiVersions      = 18
	apiKeySaslAuthenticate = 36
	apiKeyDescribeCluster  = 60

	errTopicAuthorizationFailed int16 = 29
	errUnsupportedSaslMechanism int16 = 33
	errSaslAuthenticationFailed int16 = 58
)

type pending struct {
	apiKey, apiVersion int16
}

type connState struct {
	admin   bool
	mu      sync.Mutex
	pending *lru.Cache[int32, pending]
}

func (s *connState) put(corrID int32, apiKey, apiVersion int16) {
	s.mu.Lock()
	s.pending.Add(corrID, pending{apiKey: apiKey, apiVersion: apiVersion})
	s.mu.Unlock()
}

var errNoCorrelation = errors.New("correlation id not found")

func (s *connState) take(corrID int32) (apiKey, apiVersion int16, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending.Get(corrID)
	if !ok {
		return apiKey, apiVersion, errNoCorrelation
	}
	s.pending.Remove(corrID)
	return p.apiKey, p.apiVersion, nil
}

type Addr struct {
	Host string
	Port int32
}

func (a Addr) MarshalText() (text []byte, err error) {
	return []byte(a.String()), nil
}

func (a *Addr) UnmarshalText(text []byte) error {
	return a.Set(string(text))
}

func (a Addr) String() string {
	return fmt.Sprintf("%s:%d", a.Host, a.Port)
}

func (a *Addr) Set(s string) error {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}
	a.Host = host
	a.Port = int32(port)
	return nil
}

var cfg = struct {
	Listen        string `env:"LISTEN,overwrite"`
	UpstreamAddr  string `env:"UPSTREAM,overwrite"`
	AdvertiseAddr Addr   `env:"ADVERTISE,overwrite"`
	Auth          struct {
		Username string `env:"USERNAME,overwrite"`
		Password string `env:"PASSWORD,overwrite"`
	} `env:", prefix=AUTH_"`
	Admin struct {
		Username string `env:"USERNAME,overwrite"`
		Password string `env:"PASSWORD,overwrite"`
	} `env:", prefix=ADMIN_"`
}{}

func (c *connState) isAllowed(apiKey int16) bool {
	if c.admin {
		return true
	}
	switch apiKey {
	case 0, // Produce
		1,  // Fetch
		2,  // ListOffsets
		3,  // Metadata
		8,  // OffsetCommit
		9,  // OffsetFetch
		10, // FindCoordinator
		11, // JoinGroup
		12, // Heartbeat
		13, // LeaveGroup
		14, // SyncGroup
		15, // DescribeGroups
		16, // ListGroups
		18, // Versions
		22, // InitProducerId (idempotent producers)
		32, // DescribeConfigs
		60, // DescribeCluster
		68, // ConsumerGroupHeartbeat (KIP-848)
		69, // ConsumerGroupDescribe  (KIP-848)
		71, // GetTelemetrySubscriptions (KIP-714)
		72, // PushTelemetry            (KIP-714)
		75, // DescribeTopicPartitions
		apiKeySaslAuthenticate,
		apiKeySaslHandshake:
		return true
	}
	return false
}

func main() {
	ctx, cancelFunc := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancelFunc()

	flag.StringVar(&cfg.Listen, "listen", ":9093", "address to listen on")
	flag.StringVar(&cfg.UpstreamAddr, "upstream", "127.0.0.1:9092", "kafka broker to forward to")
	flag.TextVar(&cfg.AdvertiseAddr, "advertise", Addr{Host: "127.0.0.1", Port: 9093}, "host:port to advertise to clients in Metadata responses")
	flag.StringVar(&cfg.Auth.Username, "auth-username", "", "required SASL/PLAIN username")
	flag.StringVar(&cfg.Auth.Password, "auth-password", "", "required SASL/PLAIN password")
	flag.StringVar(&cfg.Admin.Username, "admin-username", "", "SASL/PLAIN admin username")
	flag.StringVar(&cfg.Admin.Password, "admin-password", "", "SASL/PLAIN admin password")
	flag.Parse()

	if err := envconfig.Process(ctx, &cfg); err != nil {
		log.Fatal(err)
	}

	if cfg.Auth.Username == "" || cfg.Auth.Password == "" {
		log.Fatal("both -auth-username and -auth-password are required")
	}

	if err := listen(ctx); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Fatal(err)
	}
}

func listen(ctx context.Context) error {
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { err = errors.Join(ln.Close()) })
	defer stop()

	log.Printf("listening on %s, forwarding to %s, advertising %s (SASL/PLAIN user=%q)",
		cfg.Listen, cfg.UpstreamAddr, cfg.AdvertiseAddr, cfg.Auth.Username)

	wg, gCtx := errgroup.WithContext(ctx)
	for ctx.Err() == nil {
		client, err := ln.Accept()
		if err != nil {
			return err
		}
		wg.Go(func() error {
			if err := handle(gCtx, client, cfg.UpstreamAddr); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Print(err)
			}
			return nil
		})
	}

	log.Print("shutting down...")
	return wg.Wait()
}

func handle(ctx context.Context, client net.Conn, upstreamAddr string) (err error) {
	stopClient := context.AfterFunc(ctx, func() {
		err = errors.Join(err, client.Close())
	})
	defer stopClient()

	var d net.Dialer
	upstream, err := d.DialContext(ctx, "tcp", upstreamAddr)
	if err != nil {
		return fmt.Errorf("dial upstream: %w", err)
	}

	stopUpstream := context.AfterFunc(ctx, func() {
		err = errors.Join(err, upstream.Close())
	})
	defer stopUpstream()

	src := &kafkaConn{Conn: client}
	dst := &kafkaConn{Conn: upstream}

	username, authErr := authenticate(ctx, src, dst)
	if authErr != nil {
		return errors.Join(authErr, src.Close(), dst.Close())
	}

	log.Printf("%s authenticated as %s, switching to transparent proxy", client.RemoteAddr(), username)

	cache, err := lru.New[int32, pending](64)
	if err != nil {
		return err
	}

	st := &connState{admin: username == cfg.Admin.Username, pending: cache}
	wg, gCtx := errgroup.WithContext(ctx)
	wg.Go(func() error {
		return errors.Join(requests(gCtx, src, dst, st), dst.Close())
	})
	wg.Go(func() error {
		return errors.Join(responses(gCtx, dst, src, st), src.Close())
	})
	return wg.Wait()
}

func rewriteApiVersions(payload []byte, msg *kafkaproto.ApiVersionsResponse, corrID int32, apiVersion int16) error {
	r := kafkaproto.NewReader(payload)

	respID, err := r.ReadInt32()
	if err != nil {
		return err
	}
	if corrID != respID {
		return errors.New("incorrect response ID")
	}

	if err := msg.Decode(r, apiVersion); err != nil {
		return err
	}

	apiKeys := make([]kafkaproto.ApiVersionsResponseApiVersion, 0, len(msg.ApiKeys)+2)

	for _, k := range msg.ApiKeys {
		if k.ApiKey == apiKeySaslAuthenticate || k.ApiKey == apiKeySaslHandshake {
			continue
		}
		apiKeys = append(apiKeys, k)
	}

	apiKeys = append(apiKeys,
		kafkaproto.ApiVersionsResponseApiVersion{ApiKey: apiKeySaslHandshake, MinVersion: 0, MaxVersion: 1},
		kafkaproto.ApiVersionsResponseApiVersion{ApiKey: apiKeySaslAuthenticate, MinVersion: 0, MaxVersion: 2},
	)

	msg.ApiKeys = apiKeys

	return nil
}

// authenticate runs the pre-SASL state machine. We only forward ApiVersions
// (so the broker can advertise versions); SaslHandshake and SaslAuthenticate
// are answered locally and the credentials are checked here. Anything else
// is rejected — no client requests reach the upstream until auth succeeds.
func authenticate(ctx context.Context, src, dst *kafkaConn) (string, error) {
	for ctx.Err() == nil {
		buf, err := src.ReadPacket(ctx)
		if err != nil {
			return "", err
		}

		if len(buf) < 8 {
			return "", errors.New("short request header")
		}

		r := kafkaproto.NewReader(buf)
		apiKey, apiVersion, corrID, clientID, err := kafkaproto.ReadRequestHeader(r)
		if err != nil {
			return "", err
		}

		_ = clientID

		switch apiKey {
		case apiKeyApiVersions:
			if err := dst.WritePacket(ctx, buf); err != nil {
				return "", err
			}
			buf, err := dst.ReadPacket(ctx)
			if err != nil {
				return "", err
			}

			var msg kafkaproto.ApiVersionsResponse
			if err := rewriteApiVersions(buf, &msg, corrID, apiVersion); err != nil {
				return "", err
			}

			w := kafkaproto.NewWriter()
			kafkaproto.WriteResponseHeader(w, corrID, apiKey, apiVersion)
			if err := msg.Encode(w, apiVersion); err != nil {
				return "", err
			}

			if err := src.WritePacket(ctx, w.Bytes()); err != nil {
				return "", err
			}

		case apiKeySaslHandshake:
			var req kafkaproto.SaslHandshakeRequest
			if err := req.Decode(r, apiVersion); err != nil {
				return "", err
			}
			var resp kafkaproto.SaslHandshakeResponse

			resp.Mechanisms = []string{"PLAIN"}

			if !strings.EqualFold(req.Mechanism, "PLAIN") {
				resp.ErrorCode = errUnsupportedSaslMechanism
			}

			w := kafkaproto.NewWriter()
			kafkaproto.WriteResponseHeader(w, corrID, apiKey, apiVersion)
			if err := resp.Encode(w, apiVersion); err != nil {
				return "", err
			}

			if err := src.WritePacket(ctx, w.Bytes()); err != nil {
				return "", err
			}

			if resp.ErrorCode != 0 {
				return "", fmt.Errorf("client requested unsupported mechanism %q", req.Mechanism)
			}

		case apiKeySaslAuthenticate:
			var req kafkaproto.SaslAuthenticateRequest

			if err := req.Decode(r, apiVersion); err != nil {
				return "", err
			}
			var resp kafkaproto.SaslAuthenticateResponse

			resp.AuthBytes = []byte{}

			auth := cfg.Auth
			if cfg.Admin.Username != "" && cfg.Admin.Password != "" && usernameFromAuthBytes(req.AuthBytes) == cfg.Admin.Username {
				auth = cfg.Admin
			}

			username, ok := checkPlainAuth(req.AuthBytes, auth.Username, auth.Password)

			w := kafkaproto.NewWriter()
			kafkaproto.WriteResponseHeader(w, corrID, apiKey, apiVersion)

			if !ok {
				resp.ErrorCode = errSaslAuthenticationFailed
				resp.ErrorMessage = new("Authentication failed")
			}

			if err := resp.Encode(w, apiVersion); err != nil {
				return "", err
			}
			if err := src.WritePacket(ctx, w.Bytes()); err != nil {
				return "", err
			}

			if !ok {
				return "", fmt.Errorf("authentication failed for user %q", cfg.Auth.Username)
			}
			return username, nil
		default:
			return "", fmt.Errorf("access denied for %s (%d)", src.RemoteAddr(), apiKey)
		}
	}

	return "", ctx.Err()
}

func usernameFromAuthBytes(authBytes []byte) string {
	i := bytes.IndexByte(authBytes, 0) + 1
	if i > 0 {
		j := bytes.IndexByte(authBytes[i:], 0) + 1
		if j > 0 {
			return string(authBytes[i:j])
		}
	}
	return ""
}

// checkPlainAuth parses RFC 4616 PLAIN auth bytes ("[authzid]\0authcid\0passwd")
// and constant-time-compares against the configured credentials.
func checkPlainAuth(actual []byte, username, password string) (string, bool) {
	expected := []byte("\x00" + username + "\x00" + password)
	return username, subtle.ConstantTimeCompare(actual, expected) == 1
}

func requests(ctx context.Context, src, dst *kafkaConn, st *connState) error {
	for ctx.Err() == nil {
		buf, err := src.ReadPacket(ctx)
		if err != nil {
			return err
		}

		if len(buf) >= 8 {
			r := kafkaproto.NewReader(buf)
			apiKey, apiVersion, corrID, clientID, err := kafkaproto.ReadRequestHeader(r)
			if err != nil {
				return err
			}

			_ = clientID

			if !st.isAllowed(apiKey) {
				req, err := kafkaproto.UnmarshalRequest(r, apiKey, apiVersion)
				if err != nil {
					return err
				}

				res, err := kafkaproto.ErrorResponse(req, apiVersion, errTopicAuthorizationFailed, new("Access Denied"))
				if err != nil {
					return fmt.Errorf("access denied for %s (%d): %w", src.RemoteAddr(), apiKey, err)
				}

				log.Printf("access denied for (%d) %d", src.RemoteAddr(), apiKey)

				w := kafkaproto.NewWriter()
				kafkaproto.WriteResponseHeader(w, corrID, apiKey, apiVersion)
				if err := res.Encode(w, apiVersion); err != nil {
					return err
				}
				if err := src.WritePacket(ctx, w.Bytes()); err != nil {
					return err
				}
				continue
			}

			st.put(corrID, apiKey, apiVersion)
		}

		if err := dst.WritePacket(ctx, buf); err != nil {
			return err
		}
	}

	return ctx.Err()
}

// writeResponse encodes msg with the given response header and forwards it.
func writeResponse(ctx context.Context, dst *kafkaConn, corrID int32, apiKey, apiVersion int16, msg interface {
	Encode(*kafkaproto.Writer, int16) error
}) error {
	w := kafkaproto.NewWriter()
	kafkaproto.WriteResponseHeader(w, corrID, apiKey, apiVersion)
	if err := msg.Encode(w, apiVersion); err != nil {
		return err
	}
	return dst.WritePacket(ctx, w.Bytes())
}

func responses(ctx context.Context, src, dst *kafkaConn, st *connState) error {
	for ctx.Err() == nil {
		buf, err := src.ReadPacket(ctx)
		if err != nil {
			return err
		}

		if len(buf) >= 4 {
			r := kafkaproto.NewReader(buf)
			corrID, apiKey, apiVersion, err := kafkaproto.ReadResponseHeader(r, st.take)
			if err != nil {
				return err
			}

			// Several APIs hand back a broker's real host:port. Metadata is
			// the obvious one, but FindCoordinator and DescribeCluster leak it
			// too, so rewrite all of them to advertise only AdvertiseAddr.
			switch apiKey {
			case apiKeyMetadata:
				var resp kafkaproto.MetadataResponse
				if err := resp.Decode(r, apiVersion); err != nil {
					return err
				}

				if len(resp.Brokers) > 1 {
					resp.Brokers = resp.Brokers[:1]
				}
				for i := range resp.Brokers {
					resp.Brokers[i].Host = cfg.AdvertiseAddr.Host
					resp.Brokers[i].Port = cfg.AdvertiseAddr.Port
					resp.Brokers[i].Rack = nil
				}

				if err := writeResponse(ctx, dst, corrID, apiKey, apiVersion, &resp); err != nil {
					return err
				}
				continue

			case apiKeyFindCoordinator:
				var resp kafkaproto.FindCoordinatorResponse
				if err := resp.Decode(r, apiVersion); err != nil {
					return err
				}

				// v0-v3 carry a single top-level coordinator; v4+ a list.
				resp.Host = cfg.AdvertiseAddr.Host
				resp.Port = cfg.AdvertiseAddr.Port
				if len(resp.Coordinators) > 1 {
					resp.Coordinators = resp.Coordinators[:1]
				}
				for i := range resp.Coordinators {
					resp.Coordinators[i].Host = cfg.AdvertiseAddr.Host
					resp.Coordinators[i].Port = cfg.AdvertiseAddr.Port
				}

				if err := writeResponse(ctx, dst, corrID, apiKey, apiVersion, &resp); err != nil {
					return err
				}
				continue

			case apiKeyDescribeCluster:
				var resp kafkaproto.DescribeClusterResponse
				if err := resp.Decode(r, apiVersion); err != nil {
					return err
				}

				if len(resp.Brokers) > 1 {
					resp.Brokers = resp.Brokers[:1]
				}
				for i := range resp.Brokers {
					resp.Brokers[i].Host = cfg.AdvertiseAddr.Host
					resp.Brokers[i].Port = cfg.AdvertiseAddr.Port
					resp.Brokers[i].Rack = nil
				}

				if err := writeResponse(ctx, dst, corrID, apiKey, apiVersion, &resp); err != nil {
					return err
				}
				continue
			}
		}

		if err := dst.WritePacket(ctx, buf); err != nil {
			return err
		}
	}

	return ctx.Err()
}

type kafkaConn struct {
	net.Conn
	buf [256]byte
}

func (c *kafkaConn) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		var tmp [4]byte
		if _, err := io.ReadFull(c.Conn, tmp[:]); err != nil {
			return nil, err
		}
		size := int(binary.BigEndian.Uint32(tmp[:]))
		var buf []byte
		if size > 256 {
			buf = make([]byte, size)
		} else {
			buf = c.buf[:size]
		}
		if _, err := io.ReadFull(c.Conn, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}
}

func (c *kafkaConn) WritePacket(ctx context.Context, payload []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		var tmp [4]byte
		binary.BigEndian.PutUint32(tmp[:], uint32(len(payload)))
		if _, err := c.Conn.Write(tmp[:]); err != nil {
			return err
		}
		_, err := c.Conn.Write(payload)
		return err
	}
}
