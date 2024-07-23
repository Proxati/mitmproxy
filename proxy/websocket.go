package proxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
)

// Currently only forwarding websocket flow.

type webSocket struct{}

var defaultWebSocket webSocket

func (s *webSocket) ws(conn net.Conn, host string) {
	logger := sLogger.With(
		"in", "webSocket.ws",
		"host", host,
	)

	defer conn.Close()
	remoteConn, err := net.Dial("tcp", host)
	if err != nil {
		logErr(logger, "websocket dial", err)
		return
	}
	defer remoteConn.Close()
	transfer(logger, conn, remoteConn)
}

func (s *webSocket) wss(res http.ResponseWriter, req *http.Request) {
	logger := sLogger.With(
		"in", "webSocket.wss",
		"host", req.Host,
	)

	upgradeBuf, err := httputil.DumpRequest(req, false)
	if err != nil {
		logger.Error("DumpRequest", "error", err)
		res.WriteHeader(502)
		return
	}

	cConn, _, err := res.(http.Hijacker).Hijack()
	if err != nil {
		logger.Error("Hijack", "error", err)
		res.WriteHeader(502)
		return
	}
	defer cConn.Close()

	host := req.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}
	conn, err := tls.Dial("tcp", host, nil)
	if err != nil {
		logger.Error("tls.Dial", "error", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(upgradeBuf)
	if err != nil {
		logger.Error("wss upgrade", "error", err)
		return
	}
	transfer(logger, conn, cConn)
}
