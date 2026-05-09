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
	"golang.org/x/exp/constraints"
	"golang.org/x/sync/errgroup"
)

const (
	apiKeyMetadata         = 3
	apiKeySaslHandshake    = 17
	apiKeyApiVersions      = 18
	apiKeySaslAuthenticate = 36

	errNoError                  int16 = 0
	errUnsupportedSaslMechanism int16 = 33
	errSaslAuthenticationFailed int16 = 58
)

type pending struct {
	apiKey, apiVersion int16
	clientID           string
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

	fmt.Println("waiting for shutdown")
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

	if err := authenticate(ctx, client, upstream); err != nil {
		return err
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

// authenticate runs the pre-SASL state machine. We only forward ApiVersions
// (so the broker can advertise versions); SaslHandshake and SaslAuthenticate
// are answered locally and the credentials are checked here. Anything else
// is rejected — no client requests reach the upstream until auth succeeds.
func authenticate(ctx context.Context, client, upstream net.Conn) error {
	for ctx.Err() == nil {
		payload, err := readPacket(client)
		if err != nil {
			return fmt.Errorf("read client: %w", err)
		}
		if len(payload) < 8 {
			return errors.New("short request header")
		}
		apiKey := int16(binary.BigEndian.Uint16(payload[0:2]))
		apiVersion := int16(binary.BigEndian.Uint16(payload[2:4]))
		corrID := int32(binary.BigEndian.Uint32(payload[4:8]))

		switch apiKey {
		case apiKeyApiVersions:
			if err := writePacket(upstream, payload); err != nil {
				return fmt.Errorf("forward ApiVersions: %w", err)
			}
			resp, err := readPacket(upstream)
			if err != nil {
				return fmt.Errorf("read ApiVersions response: %w", err)
			}
			// Brokers on non-SASL listeners don't advertise SaslHandshake/SaslAuthenticate.
			// Inject them so the client believes the (proxy) broker supports SASL/PLAIN.
			rewritten, rerr := rewriteApiVersionsResponse(resp, apiVersion, saslApiVersions)
			if rerr != nil {
				return rerr
			}
			log.Printf("auth ApiVersions rewritten %d -> %d bytes (injected SaslHandshake, SaslAuthenticate)",
				len(resp), len(rewritten))
			if err := writePacket(client, rewritten); err != nil {
				return fmt.Errorf("write ApiVersions response: %w", err)
			}

		case apiKeySaslHandshake:
			mechanism, err := parseSaslHandshakeRequest(payload)
			if err != nil {
				return fmt.Errorf("parse SaslHandshake: %w", err)
			}
			log.Printf("auth SaslHandshake mechanism=%q", mechanism)
			code := errNoError
			if mechanism != "PLAIN" {
				code = errUnsupportedSaslMechanism
			}
			resp := buildSaslHandshakeResponse(corrID, code, []string{"PLAIN"})
			if err := writePacket(client, resp); err != nil {
				return fmt.Errorf("write SaslHandshake response: %w", err)
			}
			if code != errNoError {
				return fmt.Errorf("client requested unsupported mechanism %q", mechanism)
			}

		case apiKeySaslAuthenticate:
			authBytes, err := parseSaslAuthenticateRequest(payload, apiVersion)
			if err != nil {
				return fmt.Errorf("parse SaslAuthenticate: %w", err)
			}
			ok := checkPlainAuth(authBytes, cfg.Auth.Username, cfg.Auth.Password)
			code := errNoError
			msg := ""
			if !ok {
				code = errSaslAuthenticationFailed
				msg = "Authentication failed"
			}
			resp := buildSaslAuthenticateResponse(corrID, apiVersion, code, msg)
			if err := writePacket(client, resp); err != nil {
				return fmt.Errorf("write SaslAuthenticate response: %w", err)
			}
			if !ok {
				return fmt.Errorf("authentication failed for user %q", cfg.Auth.Username)
			}
			log.Printf("auth succeeded for user %q", cfg.Auth.Username)
			return nil

		default:
			return fmt.Errorf("unexpected api_key %d before SASL authentication", apiKey)
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
		payload, err := readPacket(src)
		if err != nil {
			return err
		}

		if len(payload) >= 8 {
			apiKey := int16(binary.BigEndian.Uint16(payload[0:2]))
			apiVersion := int16(binary.BigEndian.Uint16(payload[2:4]))
			corrID := int32(binary.BigEndian.Uint32(payload[4:8]))
			var clientID string
			if len(payload) >= 10 {
				clen := int16(binary.BigEndian.Uint16(payload[8:10]))
				if clen > 0 && 10+int(clen) <= len(payload) {
					clientID = string(payload[10 : 10+clen])
				}
			}
			st.put(corrID, pending{apiKey: apiKey, apiVersion: apiVersion, clientID: clientID})
		}

		if err := writePacket(dst, payload); err != nil {
			return err
		}
	}

	return ctx.Err()
}

func responses(ctx context.Context, src, dst net.Conn, st *connState) error {
	for ctx.Err() == nil {
		payload, err := readPacket(src)
		if err != nil {
			return err
		}

		if len(payload) >= 4 {
			corrID := int32(binary.BigEndian.Uint32(payload[0:4]))
			if p, ok := st.take(corrID); ok {
				if p.apiKey == apiKeyMetadata {
					rewritten, err := rewriteMetadataResponse(payload, p.apiVersion, cfg.AdvertiseAddr)
					if err != nil {
						return err
					}

					log.Printf("<< metadata rewritten %d -> %d bytes (addr=%s)",
						len(payload), len(rewritten), cfg.AdvertiseAddr)

					payload = rewritten
				}
			}
		}

		if err := writePacket(dst, payload); err != nil {
			return err
		}
	}

	return ctx.Err()
}

type apiVersionEntry struct {
	apiKey, minVersion, maxVersion int16
}

// saslApiVersions are the (key, min, max) ranges we advertise locally because we
// terminate SASL ourselves. Range maxes match the versions our parsers/builders
// implement; clients pick the highest mutually supported version.
var saslApiVersions = []apiVersionEntry{
	{apiKey: apiKeySaslHandshake, minVersion: 1, maxVersion: 1},
	{apiKey: apiKeySaslAuthenticate, minVersion: 0, maxVersion: 2},
}

// rewriteApiVersionsResponse injects (or replaces) entries in the api_keys array of
// an ApiVersionsResponse. Note: ApiVersions uses a non-flexible response header at
// every version — only the body becomes flexible at v3+.
func rewriteApiVersionsResponse(payload []byte, apiVersion int16, inject []apiVersionEntry) ([]byte, error) {
	flexibleBody := apiVersion >= 3
	r := bytes.NewReader(payload)

	var out bytes.Buffer

	if _, err := io.CopyN(&out, r, 4); err != nil { // correlation_id
		return nil, fmt.Errorf("corr_id: %w", err)
	}
	if _, err := io.CopyN(&out, r, 2); err != nil { // error_code
		return nil, fmt.Errorf("error_code: %w", err)
	}

	var existingCount int
	if flexibleBody {
		n, err := binary.ReadUvarint(r)
		if err != nil {
			return nil, fmt.Errorf("api_keys count: %w", err)
		}
		if n > 0 {
			existingCount = int(n) - 1
		}
	} else {
		var n int32
		if err := binary.Read(r, binary.BigEndian, &n); err != nil {
			return nil, fmt.Errorf("api_keys count: %w", err)
		}
		if n > 0 {
			existingCount = int(n)
		}
	}

	dropKey := make(map[int16]struct{}, len(inject))
	for _, e := range inject {
		dropKey[e.apiKey] = struct{}{}
	}

	var entriesBuf bytes.Buffer
	keptCount := 0
	for i := 0; i < existingCount; i++ {
		var ak, minV, maxV int16
		if err := binary.Read(r, binary.BigEndian, &ak); err != nil {
			return nil, fmt.Errorf("entry[%d] api_key: %w", i, err)
		}
		if err := binary.Read(r, binary.BigEndian, &minV); err != nil {
			return nil, fmt.Errorf("entry[%d] min: %w", i, err)
		}
		if err := binary.Read(r, binary.BigEndian, &maxV); err != nil {
			return nil, fmt.Errorf("entry[%d] max: %w", i, err)
		}
		var tagBuf bytes.Buffer
		if flexibleBody {
			if err := readTaggedFields(&byteReader{io.TeeReader(r, &tagBuf)}); err != nil {
				return nil, fmt.Errorf("entry[%d] tags: %w", i, err)
			}
		}
		if _, drop := dropKey[ak]; drop {
			continue
		}
		keptCount++
		_ = binary.Write(&entriesBuf, binary.BigEndian, ak)
		_ = binary.Write(&entriesBuf, binary.BigEndian, minV)
		_ = binary.Write(&entriesBuf, binary.BigEndian, maxV)
		if flexibleBody {
			if _, err := tagBuf.WriteTo(&entriesBuf); err != nil {
				return nil, fmt.Errorf("write[%d] tags: %w", i, err)
			}
		}
	}

	for _, e := range inject {
		_ = binary.Write(&entriesBuf, binary.BigEndian, e.apiKey)
		_ = binary.Write(&entriesBuf, binary.BigEndian, e.minVersion)
		_ = binary.Write(&entriesBuf, binary.BigEndian, e.maxVersion)
		if flexibleBody {
			entriesBuf.WriteByte(0) // empty per-entry tag_buffer
		}
	}

	newCount := keptCount + len(inject)
	if flexibleBody {
		_, _ = writeUvarint(&out, uint64(newCount+1))
	} else {
		_ = binary.Write(&out, binary.BigEndian, int32(newCount))
	}
	out.Write(entriesBuf.Bytes())

	// throttle_time_ms (v1+) and the response-level tag_buffer (v3+) follow the
	// array; copy whatever's left through verbatim.
	_, err := io.Copy(&out, r)
	return out.Bytes(), err
}

// rewriteMetadataResponse parses the brokers array out of a Metadata response and
// replaces every (host, port) pair with the proxy's advertised address. The rest
// of the payload (controller_id, topics, ...) is copied through verbatim.
func rewriteMetadataResponse(payload []byte, apiVersion int16, addr Addr) ([]byte, error) {
	flexible := apiVersion >= 9
	r := bytes.NewReader(payload)
	var out bytes.Buffer

	if _, err := io.CopyN(&out, r, 4); err != nil {
		return nil, fmt.Errorf("corr_id: %w", err)
	}
	if flexible {
		if err := readTaggedFields(&byteReader{io.TeeReader(r, &out)}); err != nil {
			return nil, fmt.Errorf("header tags: %w", err)
		}
	}
	if apiVersion >= 3 {
		if _, err := io.CopyN(&out, r, 4); err != nil {
			return nil, fmt.Errorf("throttle: %w", err)
		}
	}

	var brokerCount int
	if flexible {
		n, err := binary.ReadUvarint(r)
		if err != nil {
			return nil, fmt.Errorf("brokers count: %w", err)
		}
		_, _ = writeUvarint(&out, n)
		if n > 0 {
			brokerCount = int(n) - 1
		}
	} else {
		var n int32
		if err := binary.Read(r, binary.BigEndian, &n); err != nil {
			return nil, fmt.Errorf("brokers count: %w", err)
		}
		_ = binary.Write(&out, binary.BigEndian, n)
		if n > 0 {
			brokerCount = int(n)
		}
	}

	for i := 0; i < brokerCount; i++ {
		if _, err := io.CopyN(&out, r, 4); err != nil {
			return nil, fmt.Errorf("broker[%d] node_id: %w", i, err)
		}
		if flexible {
			n, err := binary.ReadUvarint(r)
			if err != nil {
				return nil, fmt.Errorf("broker[%d] host len: %w", i, err)
			}
			if n == 0 {
				return nil, fmt.Errorf("broker[%d] null host", i)
			}
			if _, err := r.Seek(int64(n-1), io.SeekCurrent); err != nil {
				return nil, fmt.Errorf("broker[%d] host body: %w", i, err)
			}
			_, _ = writeUvarint(&out, uint64(len(addr.Host)+1))
			out.WriteString(addr.Host)
		} else {
			var n int16
			if err := binary.Read(r, binary.BigEndian, &n); err != nil {
				return nil, fmt.Errorf("broker[%d] host len: %w", i, err)
			}
			if n < 0 {
				return nil, fmt.Errorf("broker[%d] null host", i)
			}
			if _, err := r.Seek(int64(n), io.SeekCurrent); err != nil {
				return nil, fmt.Errorf("broker[%d] host body: %w", i, err)
			}
			_ = binary.Write(&out, binary.BigEndian, int16(len(addr.Host)))
			out.WriteString(addr.Host)
		}
		var n int32
		if err := binary.Read(r, binary.BigEndian, &n); err != nil {
			return nil, fmt.Errorf("broker[%d] port: %w", i, err)
		}
		_ = binary.Write(&out, binary.BigEndian, addr.Port)
		if apiVersion >= 1 {
			if flexible {
				n, err := binary.ReadUvarint(r)
				if err != nil {
					return nil, fmt.Errorf("broker[%d] rack len: %w", i, err)
				}
				_, _ = writeUvarint(&out, n)
				if n > 1 {
					if _, err := io.CopyN(&out, r, int64(n-1)); err != nil {
						return nil, fmt.Errorf("broker[%d] rack body: %w", i, err)
					}
				}
			} else {
				var n int16
				if err := binary.Read(r, binary.BigEndian, &n); err != nil {
					return nil, fmt.Errorf("broker[%d] rack len: %w", i, err)
				}
				_ = binary.Write(&out, binary.BigEndian, n)
				if n > 0 {
					if _, err := io.CopyN(&out, r, int64(n)); err != nil {
						return nil, fmt.Errorf("broker[%d] rack body: %w", i, err)
					}
				}
			}
		}
		if flexible {
			if err := readTaggedFields(&byteReader{io.TeeReader(r, &out)}); err != nil {
				return nil, fmt.Errorf("broker[%d] tags: %w", i, err)
			}
		}
	}

	_, err := io.Copy(&out, r)
	return out.Bytes(), err
}

func parseSaslHandshakeRequest(payload []byte) (string, error) {
	// SaslHandshake is non-flexible at all versions; request header v1.
	r := bytes.NewReader(payload)
	if _, err := r.Seek(8, io.SeekCurrent); err != nil {
		return "", err
	}
	if err := skipNullableString(r); err != nil { // client_id
		return "", err
	}
	var mlen int16
	if err := binary.Read(r, binary.BigEndian, &mlen); err != nil {
		return "", err
	}
	if mlen < 0 {
		return "", errors.New("null mechanism")
	}
	out, err := readN(r, mlen)
	return string(out), err
}

func parseSaslAuthenticateRequest(payload []byte, apiVersion int16) ([]byte, error) {
	flexible := apiVersion >= 2
	r := bytes.NewReader(payload)

	if _, err := r.Seek(8, io.SeekCurrent); err != nil {
		return nil, err
	}
	if err := skipNullableString(r); err != nil { // client_id (still int16-prefixed)
		return nil, err
	}
	if flexible {
		if err := readTaggedFields(r); err != nil {
			return nil, err
		}
	}
	if flexible {
		n, err := binary.ReadUvarint(r)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, errors.New("null auth_bytes")
		}
		sz := int(n - 1)
		return readN(r, sz)
	}
	var sz int32
	if err := binary.Read(r, binary.BigEndian, &sz); err != nil {
		return nil, err
	}
	if sz < 0 {
		return nil, errors.New("null auth_bytes")
	}
	return readN(r, sz)
}

func buildSaslHandshakeResponse(corrID int32, errorCode int16, mechanisms []string) []byte {
	var out bytes.Buffer
	_ = binary.Write(&out, binary.BigEndian, corrID)
	_ = binary.Write(&out, binary.BigEndian, errorCode)
	_ = binary.Write(&out, binary.BigEndian, int32(len(mechanisms)))
	for _, m := range mechanisms {
		_ = binary.Write(&out, binary.BigEndian, int16(len(m)))
		out.WriteString(m)
	}
	return out.Bytes()
}

func buildSaslAuthenticateResponse(corrID int32, apiVersion int16, errorCode int16, errorMsg string) []byte {
	flexible := apiVersion >= 2
	var out bytes.Buffer
	_ = binary.Write(&out, binary.BigEndian, corrID)
	if flexible {
		out.WriteByte(0) // header tagged_fields (count=0)
	}
	_ = binary.Write(&out, binary.BigEndian, errorCode)
	if flexible {
		if errorMsg == "" {
			out.WriteByte(0) // null compact_nullable_string
		} else {
			_, _ = writeUvarint(&out, uint64(len(errorMsg)+1))
			out.WriteString(errorMsg)
		}
		out.WriteByte(1) // empty compact_bytes (length 0+1)
	} else {
		if errorMsg == "" {
			_ = binary.Write(&out, binary.BigEndian, int16(-1))
		} else {
			_ = binary.Write(&out, binary.BigEndian, int16(len(errorMsg)))
			out.WriteString(errorMsg)
		}
		_ = binary.Write(&out, binary.BigEndian, int32(0)) // empty auth_bytes
	}
	if apiVersion >= 1 {
		_ = binary.Write(&out, binary.BigEndian, int64(0)) // session_lifetime_ms
	}
	if flexible {
		out.WriteByte(0) // body tagged_fields
	}
	return out.Bytes()
}

func skipNullableString(r *bytes.Reader) error {
	var n int16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return err
	}
	if n > 0 {
		_, err := r.Seek(int64(n), io.SeekCurrent)
		return err
	}
	return nil
}

func readPacket(c net.Conn) ([]byte, error) {
	var size int32
	if err := binary.Read(c, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	if size < 0 {
		return nil, fmt.Errorf("negative size %d", size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(c, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func readN[T constraints.Integer](r io.Reader, size T) ([]byte, error) {
	out := make([]byte, size)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func writePacket(c net.Conn, payload []byte) error {
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(payload)))
	if _, err := c.Write(prefix[:]); err != nil {
		return err
	}
	_, err := c.Write(payload)
	return err
}

func writeUvarint(out io.Writer, v uint64) (int, error) {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], v)
	return out.Write(buf[:n])
}

type byteReader struct {
	io.Reader
}

func (t *byteReader) ReadByte() (byte, error) {
	var b [1]byte
	_, err := io.ReadFull(t.Reader, b[:])
	return b[0], err
}

func readTaggedFields(r interface {
	io.Reader
	io.ByteReader
}) error {
	count, err := binary.ReadUvarint(r)
	if err != nil {
		return err
	}
	for i := uint64(0); i < count; i++ {
		_, err := binary.ReadUvarint(r)
		if err != nil {
			return err
		}
		sz, err := binary.ReadUvarint(r)
		if err != nil {
			return err
		}
		if _, err := io.ReadAll(io.LimitReader(r, int64(sz))); err != nil {
			return err
		}
	}
	return nil
}
