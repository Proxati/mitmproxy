package addon

import (
	"log/slog"
	"time"

	"github.com/proxati/mitmproxy/proxy"
)

// LogAddon log connection and flow
type LogAddon struct {
	proxy.BaseAddon
	logger *slog.Logger
}

// NewLogAddon create a new LogAddon
func NewLogAddon() *LogAddon {
	return &LogAddon{
		logger: sLogger.With("addonName", "LogAddon"),
	}
}

func (a *LogAddon) ClientConnected(client *proxy.ClientConn) {
	a.logger.Info("client connect", "clientAddress", client.Conn.RemoteAddr())
}

func (a *LogAddon) ClientDisconnected(client *proxy.ClientConn) {
	a.logger.Info("client disconnect", "clientAddress", client.Conn.RemoteAddr())
}

func (a *LogAddon) ServerConnected(connCtx *proxy.ConnContext) {
	a.logger.Info(
		"server connect",
		"clientAddress", connCtx.ClientConn.Conn.RemoteAddr(),
		"serverAddress", connCtx.ServerConn.Address,
		"serverLocalAddress", connCtx.ServerConn.Conn.LocalAddr(),
		"serverRemoteAddress", connCtx.ServerConn.Conn.RemoteAddr(),
	)
}

func (a *LogAddon) ServerDisconnected(connCtx *proxy.ConnContext) {
	a.logger.Info(
		"server disconnect",
		"clientAddress", connCtx.ClientConn.Conn.RemoteAddr(),
		"serverAddress", connCtx.ServerConn.Address,
		"serverLocalAddress", connCtx.ServerConn.Conn.LocalAddr(),
		"serverRemoteAddress", connCtx.ServerConn.Conn.RemoteAddr(),
	)
}

func (a *LogAddon) Requestheaders(f *proxy.Flow) {
	start := time.Now()
	go func() {
		<-f.Done()
		var StatusCode int
		if f.Response != nil {
			StatusCode = f.Response.StatusCode
		}
		var contentLen int
		if f.Response != nil && f.Response.Body != nil {
			contentLen = len(f.Response.Body)
		}
		a.logger.Info(
			"request completed",
			"clientAddress", f.ConnContext.ClientConn.Conn.RemoteAddr(),
			"method", f.Request.Method,
			"URL", f.Request.URL.String(),
			"StatusCode", StatusCode,
			"contentLen", contentLen,
			"length", time.Since(start).Milliseconds(),
		)
	}()
}
