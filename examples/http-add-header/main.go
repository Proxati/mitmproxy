package main

import (
	"log/slog"
	"net/http"
	"os"
	"strconv"

	"github.com/proxati/mitmproxy/proxy"
)

type AddHeader struct {
	proxy.BaseAddon
	count int
}

func (a *AddHeader) Responseheaders(f *proxy.Flow) {
	a.count += 1
	f.Response.Header.Add("x-count", strconv.Itoa(a.count))
}

func main() {
	opts := &proxy.Options{
		Addr:              ":9080",
		StreamLargeBodies: 1024 * 1024 * 5,
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		slog.Error("could not start proxy", "error", err)
	}

	p.AddAddon(&AddHeader{})

	if err := p.Start(); err != http.ErrServerClosed {
		slog.Error("failed to start proxy", "error", err)
		os.Exit(1)
	}
}
