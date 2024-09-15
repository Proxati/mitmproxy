package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// client connection
type ClientConn struct {
	ID   uuid.UUID       `json:"id"`
	Conn *wrapClientConn `json:"-"`
	TLS  bool            `json:"tls"`
}

func newClientConn(c *wrapClientConn) *ClientConn {
	return &ClientConn{
		ID:   uuid.New(),
		Conn: c,
		TLS:  false,
	}
}

func (c *ClientConn) MarshalJSON() ([]byte, error) {
	m := struct {
		ID      uuid.UUID `json:"id"`
		Address string    `json:"address"`
		TLS     bool      `json:"tls"`
	}{
		ID:      c.ID,
		Address: c.Conn.RemoteAddr().String(),
		TLS:     c.TLS,
	}
	return json.Marshal(m)
}

// server connection
type ServerConn struct {
	ID      uuid.UUID `json:"id"`
	Address string    `json:"address"`
	Conn    net.Conn  `json:"-"`

	tlsHandshaked   chan struct{}
	tlsHandshakeErr error
	tlsConn         *tls.Conn
	tlsState        *tls.ConnectionState
	client          *http.Client
}

func newServerConn() *ServerConn {
	return &ServerConn{
		ID:            uuid.New(),
		tlsHandshaked: make(chan struct{}),
	}
}

func (c *ServerConn) MarshalJSON() ([]byte, error) {
	m := struct {
		ID       uuid.UUID `json:"id"`
		Address  string    `json:"address"`
		PeerName string    `json:"peername"`
	}{
		ID:       c.ID,
		Address:  c.Address,
		PeerName: c.Conn.LocalAddr().String(),
	}
	return json.Marshal(m)
}

func (c *ServerConn) TLSState() *tls.ConnectionState {
	<-c.tlsHandshaked
	return c.tlsState
}

// connection context ctx key
var connContextKey = new(struct{})

// connection context
type ConnContext struct {
	ClientConn *ClientConn `json:"clientConn"`
	ServerConn *ServerConn `json:"serverConn"`

	proxy              *Proxy
	pipeConn           *pipeConn
	closeAfterResponse bool // after http response, http server will close the connection
}

func newConnContext(c *wrapClientConn, proxy *Proxy) *ConnContext {
	clientConn := newClientConn(c)
	return &ConnContext{
		ClientConn: clientConn,
		proxy:      proxy,
	}
}

func (connCtx *ConnContext) ID() uuid.UUID {
	return connCtx.ClientConn.ID
}

func (connCtx *ConnContext) initHttpServerConn() {
	if connCtx.ServerConn != nil {
		return
	}
	if connCtx.ClientConn.TLS {
		return
	}

	serverConn := newServerConn()
	serverConn.client = &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				cw := &wrapServerConn{
					Conn:    c,
					proxy:   connCtx.proxy,
					connCtx: connCtx,
				}
				serverConn.Conn = cw
				serverConn.Address = addr
				defer func() {
					for _, addon := range connCtx.proxy.Addons {
						addon.ServerConnected(connCtx)
					}
				}()
				return cw, nil
			},
			ForceAttemptHTTP2:  false, // disable http2
			DisableCompression: true,  // To get the original response from the server, set Transport.DisableCompression to true.
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: connCtx.proxy.Opts.InsecureSkipVerifyTLS,
				KeyLogWriter:       getTLSKeyLogWriter(),
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Disable automatic redirects.
			return http.ErrUseLastResponse
		},
	}
	connCtx.ServerConn = serverConn
}

func (connCtx *ConnContext) initServerTcpConn(_ *http.Request) error {
	sLogger.Debug("in initServerTcpConn")
	ServerConn := newServerConn()
	connCtx.ServerConn = ServerConn
	ServerConn.Address = connCtx.pipeConn.host

	// test is use proxy
	clientReq := &http.Request{URL: &url.URL{Scheme: "https", Host: ServerConn.Address}}
	proxyUrl, err := http.ProxyFromEnvironment(clientReq)
	if err != nil {
		return err
	}
	var plainConn net.Conn
	if proxyUrl != nil {
		plainConn, err = getProxyConn(proxyUrl, ServerConn.Address)
	} else {
		plainConn, err = (&net.Dialer{}).DialContext(context.Background(), "tcp", ServerConn.Address)
	}
	if err != nil {
		return err
	}
	ServerConn.Conn = &wrapServerConn{
		Conn:    plainConn,
		proxy:   connCtx.proxy,
		connCtx: connCtx,
	}

	for _, addon := range connCtx.proxy.Addons {
		addon.ServerConnected(connCtx)
	}

	return nil
}

// connect proxy when set https_proxy env
// ref: http/transport.go dialConn func
func getProxyConn(proxyUrl *url.URL, address string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", proxyUrl.Host)
	if err != nil {
		return nil, err
	}
	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: address},
		Host:   address,
	}
	connectCtx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	didReadResponse := make(chan struct{}) // closed after CONNECT write+read is done or fails
	var resp *http.Response
	// Write the CONNECT request & read the response.
	go func() {
		defer close(didReadResponse)
		err = connectReq.Write(conn)
		if err != nil {
			return
		}
		// Okay to use and discard buffered reader here, because
		// TLS server will not speak until spoken to.
		br := bufio.NewReader(conn)
		resp, err = http.ReadResponse(br, connectReq)
	}()
	select {
	case <-connectCtx.Done():
		conn.Close()
		<-didReadResponse
		return nil, connectCtx.Err()
	case <-didReadResponse:
		// resp or err now set
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != 200 {
		_, text, ok := strings.Cut(resp.Status, " ")
		conn.Close()
		if !ok {
			return nil, errors.New("unknown status code")
		}
		return nil, errors.New(text)
	}
	return conn, nil
}

func (connCtx *ConnContext) initHttpsServerConn() {
	if !connCtx.ClientConn.TLS {
		return
	}
	connCtx.ServerConn.client = &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				<-connCtx.ServerConn.tlsHandshaked
				return connCtx.ServerConn.tlsConn, connCtx.ServerConn.tlsHandshakeErr
			},
			ForceAttemptHTTP2:  false, // disable http2
			DisableCompression: true,  // To get the original response from the server, set Transport.DisableCompression to true.
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Disable automatic redirects.
			return http.ErrUseLastResponse
		},
	}
}

func (connCtx *ConnContext) tlsHandshake(clientHello *tls.ClientHelloInfo) error {
	cfg := &tls.Config{
		InsecureSkipVerify: connCtx.proxy.Opts.InsecureSkipVerifyTLS,
		KeyLogWriter:       getTLSKeyLogWriter(),
		ServerName:         clientHello.ServerName,
		NextProtos:         []string{"http/1.1"}, // todo: h2
		// CurvePreferences:   clientHello.SupportedCurves, // todo: 如果打开会出错
		CipherSuites: clientHello.CipherSuites,
	}
	if len(clientHello.SupportedVersions) > 0 {
		minVersion := clientHello.SupportedVersions[0]
		maxVersion := clientHello.SupportedVersions[0]
		for _, version := range clientHello.SupportedVersions {
			if version < minVersion {
				minVersion = version
			}
			if version > maxVersion {
				maxVersion = version
			}
		}
		cfg.MinVersion = minVersion
		cfg.MaxVersion = maxVersion
	}

	tlsConn := tls.Client(connCtx.ServerConn.Conn, cfg)
	err := tlsConn.HandshakeContext(context.Background())
	if err != nil {
		connCtx.ServerConn.tlsHandshakeErr = err
		close(connCtx.ServerConn.tlsHandshaked)
		return err
	}

	connCtx.ServerConn.tlsConn = tlsConn
	tlsState := tlsConn.ConnectionState()
	connCtx.ServerConn.tlsState = &tlsState
	close(connCtx.ServerConn.tlsHandshaked)

	return nil
}

// wrapClientConn is a wrapper around net.Conn for a client connection.
type wrapClientConn struct {
	net.Conn
	proxy    *Proxy
	connCtx  *ConnContext
	once     sync.Once
	closeErr error
}

// Close closes the wrapped client connection and performs necessary cleanup.
func (c *wrapClientConn) Close() error {
	c.once.Do(func() {
		// Log the close operation with the client's remote address.
		sLogger.Debug("in wrapClientConn close", "clientAddress", c.connCtx.ClientConn.Conn.RemoteAddr())

		// Close the underlying connection and store any error that occurs.
		c.closeErr = c.Conn.Close()

		// Notify all addons that the client has disconnected.
		for _, addon := range c.proxy.Addons {
			addon.ClientDisconnected(c.connCtx.ClientConn)
		}

		// If there is an active server connection, close it.
		if c.connCtx.ServerConn != nil && c.connCtx.ServerConn.Conn != nil {
			c.connCtx.ServerConn.Conn.Close()
		}
	})
	return c.closeErr
}

// wrap tcpListener for remote client
type wrapListener struct {
	net.Listener
	proxy *Proxy
}

func (l *wrapListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &wrapClientConn{
		Conn:  c,
		proxy: l.proxy,
	}, nil
}

// wrapServerConn is a wrapper around net.Conn for a remote server connection.
type wrapServerConn struct {
	net.Conn
	proxy    *Proxy
	connCtx  *ConnContext
	once     sync.Once
	closeErr error
}

// Close closes the wrapped server connection and performs necessary cleanup.
func (c *wrapServerConn) Close() error {
	c.once.Do(func() {
		sLogger.Debug("in wrapServerConn close", "clientAddress", c.connCtx.ClientConn.Conn.RemoteAddr())

		// Close the underlying connection and store any error that occurs.
		c.closeErr = c.Conn.Close()

		// Notify all addons that the server has disconnected.
		for _, addon := range c.proxy.Addons {
			addon.ServerDisconnected(c.connCtx)
		}

		// If the client connection is not using TLS, close the read side of the TCP connection.
		if !c.connCtx.ClientConn.TLS {
			if tcpConn, ok := c.connCtx.ClientConn.Conn.Conn.(*net.TCPConn); ok {
				tcpConn.CloseRead()
			}
			return
		}

		// If the connection should not be closed after the response and there is a pipe connection, close it.
		if !c.connCtx.closeAfterResponse && c.connCtx.pipeConn != nil {
			c.connCtx.pipeConn.Close()
		}
	})
	return c.closeErr
}
