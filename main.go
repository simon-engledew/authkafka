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
	"sync"
	"syscall"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/sethvargo/go-envconfig"
	"github.com/simon-engledew/kafkaproto"
	"golang.org/x/sync/errgroup"
)

const (
	apiKeyMetadata         = 3
	apiKeySaslHandshake    = 17
	apiKeyApiVersions      = 18
	apiKeySaslAuthenticate = 36

	errUnsupportedSaslMechanism int16 = 33
	errSaslAuthenticationFailed int16 = 58
)

var allowedApiKeys = map[int16]struct{}{
	0:  {}, // Produce
	1:  {}, // Fetch
	2:  {}, // ListOffsets
	3:  {}, // Metadata
	8:  {}, // OffsetCommit
	9:  {}, // OffsetFetch
	10: {}, // FindCoordinator
	11: {}, // JoinGroup
	12: {}, // Heartbeat
	13: {}, // LeaveGroup
	14: {}, // SyncGroup
	15: {}, // DescribeGroups
	16: {}, // ListGroups
	17: {}, // SaslHandshake
	18: {}, // Versions
	22: {}, // InitProducerId (idempotent producers)
	36: {}, // SaslAuthenticate
	68: {}, // ConsumerGroupHeartbeat (KIP-848)
	69: {}, // ConsumerGroupDescribe  (KIP-848)
	71: {}, // GetTelemetrySubscriptions (KIP-714)
	72: {}, // PushTelemetry            (KIP-714)
}

type pending struct {
	apiKey, apiVersion int16
	clientID           *string
}

type connState struct {
	mu      sync.Mutex
	pending *lru.Cache[int32, pending]
}

func (s *connState) put(corrID int32, p pending) {
	s.mu.Lock()
	s.pending.Add(corrID, p)
	s.mu.Unlock()
}

func (s *connState) take(corrID int32) (pending, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending.Get(corrID)
	s.pending.Remove(corrID)
	return p, ok
}

type Addr struct {
	Host string
	Port int32
}

func (a Addr) MarshalText() (text []byte, err error) {
	return []byte(fmt.Sprintf("%s:%d", a.Host, a.Port)), nil
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
}{}

func IsErrGoneAway(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}

func main() {
	ctx, cancelFunc := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancelFunc()

	flag.StringVar(&cfg.Listen, "listen", ":9093", "address to listen on")
	flag.StringVar(&cfg.UpstreamAddr, "upstream", "127.0.0.1:9092", "kafka broker to forward to")
	flag.TextVar(&cfg.AdvertiseAddr, "advertise", Addr{Host: "127.0.0.1", Port: 9093}, "host:port to advertise to clients in Metadata responses")
	flag.StringVar(&cfg.Auth.Username, "auth-username", "", "required SASL/PLAIN username")
	flag.StringVar(&cfg.Auth.Password, "auth-password", "", "required SASL/PLAIN password")
	flag.Parse()

	if err := envconfig.Process(ctx, &cfg); err != nil {
		log.Fatal(err)
	}

	if cfg.Auth.Username == "" || cfg.Auth.Password == "" {
		log.Fatal("both -auth-username and -auth-password are required")
	}

	if err := listen(ctx); err != nil {
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
			if err := handle(gCtx, client, cfg.UpstreamAddr); err != nil && !IsErrGoneAway(err) {
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

	if authErr := authenticate(ctx, client, upstream); authErr != nil {
		return errors.Join(authErr, upstream.Close(), client.Close())
	}

	log.Printf("%s authenticated, switching to transparent proxy", client.RemoteAddr())

	cache, err := lru.New[int32, pending](64)
	if err != nil {
		return err
	}

	st := &connState{pending: cache}
	wg, gCtx := errgroup.WithContext(ctx)
	wg.Go(func() error {
		return errors.Join(requests(gCtx, client, upstream, st), upstream.Close())
	})
	wg.Go(func() error {
		return errors.Join(responses(gCtx, upstream, client, st), client.Close())
	})
	return wg.Wait()
}

func ReadHeader(r *kafkaproto.Reader) (apiKey int16, apiVersion int16, corrID int32, clientID *string, err error) {
	apiKey, err = r.ReadInt16()
	if err != nil {
		return
	}
	apiVersion, err = r.ReadInt16()
	if err != nil {
		return
	}
	corrID, err = r.ReadInt32()
	if err != nil {
		return
	}
	clientID, err = r.ReadNullableString()
	return
}

// authenticate runs the pre-SASL state machine. We only forward ApiVersions
// (so the broker can advertise versions); SaslHandshake and SaslAuthenticate
// are answered locally and the credentials are checked here. Anything else
// is rejected — no client requests reach the upstream until auth succeeds.
func authenticate(ctx context.Context, client, upstream net.Conn) error {
	for ctx.Err() == nil {
		payload, err := readPacket(ctx, client)
		if err != nil {
			return fmt.Errorf("read client: %w", err)
		}
		if len(payload) < 8 {
			return errors.New("short request header")
		}

		r := kafkaproto.NewReader(payload)
		apiKey, apiVersion, corrID, clientID, err := ReadHeader(r)
		if err != nil {
			return err
		}

		_ = clientID

		switch apiKey {
		case apiKeyApiVersions:
			if err := writePacket(ctx, upstream, payload); err != nil {
				return err
			}

			resp, err := readPacket(ctx, upstream)
			if err != nil {
				return err
			}

			r := kafkaproto.NewReader(resp)

			respID, err := r.ReadInt32()
			if err != nil {
				return err
			}
			if corrID != respID {
				return errors.New("incorrect response ID")
			}

			var msg kafkaproto.ApiVersionsResponse
			if err := msg.Decode(r, apiVersion); err != nil {
				return err
			}

			apiKeys := make([]kafkaproto.ApiVersionsResponseApiVersion, 0, len(allowedApiKeys))

			for _, k := range msg.ApiKeys {
				if k.ApiKey == apiKeySaslAuthenticate || k.ApiKey == apiKeySaslHandshake {
					continue
				}
				if _, ok := allowedApiKeys[k.ApiKey]; ok {
					apiKeys = append(apiKeys, k)
				}
			}

			apiKeys = append(apiKeys,
				kafkaproto.ApiVersionsResponseApiVersion{ApiKey: apiKeySaslHandshake, MinVersion: 1, MaxVersion: 1},
				kafkaproto.ApiVersionsResponseApiVersion{ApiKey: apiKeySaslAuthenticate, MinVersion: 0, MaxVersion: 2},
			)

			msg.ApiKeys = apiKeys

			w := kafkaproto.NewWriter()
			w.WriteInt32(respID)
			if err := msg.Encode(w, apiVersion); err != nil {
				return err
			}
			if err := writePacket(ctx, client, w.Bytes()); err != nil {
				return fmt.Errorf("write ApiVersions response: %w", err)
			}

		case apiKeySaslHandshake:
			var req kafkaproto.SaslHandshakeRequest
			if err := req.Decode(r, apiVersion); err != nil {
				return err
			}
			var resp kafkaproto.SaslHandshakeResponse

			if req.Mechanism != "PLAIN" {
				resp.ErrorCode = errUnsupportedSaslMechanism
			}

			w := kafkaproto.NewWriter()
			w.WriteInt32(corrID)
			if err := resp.Encode(w, apiVersion); err != nil {
				return err
			}

			if err := writePacket(ctx, client, w.Bytes()); err != nil {
				return err
			}

			if resp.ErrorCode != 0 {
				return fmt.Errorf("client requested unsupported mechanism %q", req.Mechanism)
			}

		case apiKeySaslAuthenticate:
			var req kafkaproto.SaslAuthenticateRequest

			if apiVersion >= 2 {
				if _, err := r.ReadUvarint(); err != nil {
					return err
				}
			}

			if err := req.Decode(r, apiVersion); err != nil {
				return err
			}
			var resp kafkaproto.SaslAuthenticateResponse

			ok := checkPlainAuth(req.AuthBytes, cfg.Auth.Username, cfg.Auth.Password)

			w := kafkaproto.NewWriter()
			w.WriteInt32(corrID)
			if apiVersion >= 2 {
				w.WriteUvarint(0)
			}

			if !ok {
				resp.ErrorCode = errSaslAuthenticationFailed
				resp.ErrorMessage = new("Authentication failed")
			}

			if err := resp.Encode(w, apiVersion); err != nil {
				return err
			}
			if err := writePacket(ctx, client, w.Bytes()); err != nil {
				return err
			}

			if !ok {
				return fmt.Errorf("authentication failed for user %q", cfg.Auth.Username)
			}
			log.Printf("auth succeeded for user %q", cfg.Auth.Username)
			return nil
		default:
			return fmt.Errorf("access denied for %d", apiKey)
		}
	}

	return ctx.Err()
}

// checkPlainAuth parses RFC 4616 PLAIN auth bytes ("[authzid]\0authcid\0passwd")
// and constant-time-compares against the configured credentials.
func checkPlainAuth(actual []byte, username, password string) bool {
	idx := bytes.IndexByte(actual, byte(0))
	expected := []byte(username + "\x00" + password)
	return subtle.ConstantTimeCompare(actual[idx+1:], expected) == 1
}

func requests(ctx context.Context, src, dst net.Conn, st *connState) error {
	for ctx.Err() == nil {
		payload, err := readPacket(ctx, src)
		if err != nil {
			return err
		}

		if len(payload) >= 8 {
			r := kafkaproto.NewReader(payload)
			apiKey, apiVersion, corrID, clientID, err := ReadHeader(r)
			if err != nil {
				return err
			}

			if _, allowed := allowedApiKeys[apiKey]; !allowed {
				return fmt.Errorf("access denied for %d", apiKey)
			}

			st.put(corrID, pending{apiKey: apiKey, apiVersion: apiVersion, clientID: clientID})
		}

		if err := writePacket(ctx, dst, payload); err != nil {
			return err
		}
	}

	return ctx.Err()
}

func responses(ctx context.Context, src, dst net.Conn, st *connState) error {
	for ctx.Err() == nil {
		payload, err := readPacket(ctx, src)
		if err != nil {
			return err
		}

		if len(payload) >= 4 {
			r := kafkaproto.NewReader(payload)
			corrID, err := r.ReadInt32()
			if err != nil {
				return err
			}

			if p, ok := st.take(corrID); ok {
				if p.apiKey == apiKeyMetadata {
					if p.apiVersion >= 9 {
						if _, err := r.ReadUvarint(); err != nil {
							return err
						}
					}

					var resp kafkaproto.MetadataResponse

					if err := resp.Decode(r, p.apiVersion); err != nil {
						return err
					}

					resp.Brokers = resp.Brokers[:1]

					for i := range resp.Brokers {
						resp.Brokers[i].Host = cfg.AdvertiseAddr.Host
						resp.Brokers[i].Port = cfg.AdvertiseAddr.Port
					}

					w := kafkaproto.NewWriter()
					w.WriteInt32(corrID)

					if p.apiVersion >= 9 {
						w.WriteUvarint(0)
					}

					if err := resp.Encode(w, p.apiVersion); err != nil {
						return err
					}

					if err := writePacket(ctx, dst, w.Bytes()); err != nil {
						return err
					}

					continue
				}
			}
		}

		if err := writePacket(ctx, dst, payload); err != nil {
			return err
		}
	}

	return ctx.Err()
}

func readPacket(ctx context.Context, r io.Reader) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		var size int32
		if err := binary.Read(r, binary.BigEndian, &size); err != nil {
			return nil, err
		}
		if size < 0 {
			return nil, fmt.Errorf("negative size %d", size)
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
		return payload, nil
	}
}

func writePacket(ctx context.Context, rw io.Writer, payload []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		if err := binary.Write(rw, binary.BigEndian, uint32(len(payload))); err != nil {
			return err
		}
		_, err := rw.Write(payload)
		return err
	}
}
