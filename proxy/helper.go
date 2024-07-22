package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
)

var normalErrMsgs []string = []string{
	"read: connection reset by peer",
	"write: broken pipe",
	"i/o timeout",
	"net/http: TLS handshake timeout",
	"io: read/write on closed pipe",
	"connect: connection refused",
	"connect: connection reset by peer",
	"use of closed network connection",
}

// logErr will only print unexpected error messages.
// It will return true if the error is unexpected.
func logErr(logger *slog.Logger, err error) bool {
	msg := err.Error()

	for _, str := range normalErrMsgs {
		if strings.Contains(msg, str) {
			logger.Debug("ignoring network error", "error", err)
			return false
		}
	}

	logger.Error("network error", "error", err)
	return true
}

// Forward traffic.
func transfer(logger *slog.Logger, server, client io.ReadWriteCloser) {
	done := make(chan struct{})
	defer close(done)

	errChan := make(chan error)
	go func() {
		_, err := io.Copy(server, client)
		logger.Debug("client copy end", "error", err)
		client.Close()
		select {
		case <-done:
			return
		case errChan <- err:
			return
		}
	}()
	go func() {
		_, err := io.Copy(client, server)
		logger.Debug("server copy end", "error", err)
		server.Close()

		if clientConn, ok := client.(*wrapClientConn); ok {
			err := clientConn.Conn.(*net.TCPConn).CloseRead()
			logger.Debug("clientConn.Conn.(*net.TCPConn).CloseRead()", "error", err)
		}

		select {
		case <-done:
			return
		case errChan <- err:
			return
		}
	}()

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			logErr(logger, err)
			return
		}
	}
}

// Try to read Reader into the buffer.
// If the buffer limit size is reached then read from buffered data and rest of connection.
// Otherwise just return buffer.
func readerToBuffer(r io.Reader, limit int64) ([]byte, io.Reader, error) {
	buf := bytes.NewBuffer(make([]byte, 0))
	lr := io.LimitReader(r, limit)

	_, err := io.Copy(buf, lr)
	if err != nil {
		return nil, nil, err
	}

	// If limit is reached.
	if int64(buf.Len()) == limit {
		// Return new Reader.
		return nil, io.MultiReader(bytes.NewBuffer(buf.Bytes()), r), nil
	}

	// Return buffer.
	return buf.Bytes(), nil, nil
}

// Wireshark parse https setup.
var tlsKeyLogWriter io.Writer
var tlsKeyLogOnce sync.Once

func getTLSKeyLogWriter() io.Writer {
	tlsKeyLogOnce.Do(func() {
		logfile := os.Getenv("SSLKEYLOGFILE")
		if logfile == "" {
			return
		}

		writer, err := os.OpenFile(logfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			sLogger.Warn("could not open getTlsKeyLogWriter file", "error", err)
			return
		}

		tlsKeyLogWriter = writer
	})
	return tlsKeyLogWriter
}
