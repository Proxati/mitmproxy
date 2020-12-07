package proxy

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

type Options struct {
	Addr string
}

type Proxy struct {
	Server *http.Server
	Client *http.Client
	Mitm   Mitm
}

func (proxy *Proxy) Start() error {
	go func() {
		err := proxy.Mitm.Start()
		if err != nil {
			// TODO
			log.Fatal(err)
		}
	}()

	log.Printf("Proxy start listen at %v\n", proxy.Server.Addr)
	return proxy.Server.ListenAndServe()
}

func (proxy *Proxy) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	if req.Method == "CONNECT" {
		proxy.handleConnect(res, req)
		return
	}

	if !req.URL.IsAbs() || req.URL.Host == "" {
		res.WriteHeader(400)
		_, err := io.WriteString(res, "此为代理服务器，不能直接发起请求")
		if err != nil {
			log.Printf("error: %v, url: %v\n", err, req.URL.String())
		}
		return
	}

	start := time.Now()

	proxyReq, err := http.NewRequest(req.Method, req.URL.String(), req.Body)
	if err != nil {
		log.Printf("error: %v, url: %v\n", err, req.URL.String())
		res.WriteHeader(502)
		return
	}

	for key, value := range req.Header {
		for _, v := range value {
			proxyReq.Header.Add(key, v)
		}
	}
	proxyRes, err := proxy.Client.Do(proxyReq)
	if err != nil {
		log.Printf("error: %v, url: %v\n", err, req.URL.String())
		res.WriteHeader(502)
		return
	}
	defer proxyRes.Body.Close()

	for key, value := range proxyRes.Header {
		for _, v := range value {
			res.Header().Add(key, v)
		}
	}
	res.WriteHeader(proxyRes.StatusCode)
	_, err = io.Copy(res, proxyRes.Body)
	if err != nil {
		log.Printf("error: %v, url: %v\n", err, req.URL.String())
		return
	}

	log.Printf("%v %v %v - %v ms", req.Method, req.URL.String(), proxyRes.StatusCode, time.Since(start).Milliseconds())
}

func (proxy *Proxy) handleConnect(res http.ResponseWriter, req *http.Request) {
	// log.Printf("CONNECT: %v\n", req.Host)

	conn, err := proxy.Mitm.Dial(req.Host)

	if err != nil {
		log.Printf("error: %v, host: %v\n", err, req.Host)
		res.WriteHeader(502)
		return
	}
	defer conn.Close()

	cconn, _, err := res.(http.Hijacker).Hijack()
	if err != nil {
		log.Printf("error: %v, host: %v\n", err, req.Host)
		res.WriteHeader(502)
		return
	}
	defer cconn.Close()

	_, err = io.WriteString(cconn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if err != nil {
		log.Printf("error: %v, host: %v\n", err, req.Host)
		return
	}

	ch := make(chan bool)
	go func() {
		_, err := io.Copy(conn, cconn)
		if err != nil {
			log.Printf("error: %v, host: %v\n", err, req.Host)
		}
		ch <- true
	}()

	_, err = io.Copy(cconn, conn)
	if err != nil {
		log.Printf("error: %v, host: %v\n", err, req.Host)
	}

	<-ch
}

func NewProxy(opts *Options) (*Proxy, error) {
	proxy := new(Proxy)
	proxy.Server = &http.Server{
		Addr:    opts.Addr,
		Handler: proxy,
	}

	proxy.Client = &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,

			ForceAttemptHTTP2:  false, // disable http2
			DisableCompression: true,
			TLSClientConfig: &tls.Config{
				KeyLogWriter: GetTlsKeyLogWriter(),
			},
		},
	}

	mitm, err := NewMitmServer(proxy)
	if err != nil {
		return nil, err
	}

	proxy.Mitm = mitm

	return proxy, nil
}

var tlsKeyLogWriter io.Writer
var tlsKeyLogOnce sync.Once

// Wireshark 解析 https 设置
func GetTlsKeyLogWriter() io.Writer {
	tlsKeyLogOnce.Do(func() {
		logfile := os.Getenv("SSLKEYLOGFILE")
		if logfile == "" {
			return
		}

		writer, err := os.OpenFile(logfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Printf("GetTlsKeyLogWriter error: %v\n", err)
			return
		}

		tlsKeyLogWriter = writer
	})
	return tlsKeyLogWriter
}