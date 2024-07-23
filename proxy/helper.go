package proxy

import (
	"bytes"
	"fmt"
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
func logErr(logger *slog.Logger, loggerMsg string, err error) bool {
	if loggerMsg == "" {
		loggerMsg = "Network error"
	}

	msg := err.Error()

	for _, str := range normalErrMsgs {
		if strings.Contains(msg, str) {
			logger.Debug(loggerMsg, "error", err)
			return false
		}
	}

	logger.Error(loggerMsg, "error", err)
	return true
}

// Forward traffic.
func transfer(logger *slog.Logger, server, client io.ReadWriteCloser) {
	var wg sync.WaitGroup
	errChan := make(chan error, 2) // Buffer to avoid goroutine leak

	// Function to copy and handle closing of connections
	copyAndClose := func(dst, src io.ReadWriteCloser, direction string) {
		defer wg.Done()
		defer src.Close()
		written, err := io.Copy(dst, src)
		logger.Debug("transfer copy", "direction", direction, "written", written)
		if err != nil {
			err = fmt.Errorf("%s copy: %w", direction, err)
			errChan <- err
		}
	}

	wg.Add(2)
	go copyAndClose(server, client, "client->server")
	go copyAndClose(client, server, "server->client")

	// Wait for both copy operations to finish
	wg.Wait()
	close(errChan)

	// Close the client connection if it's a TCP connection
	if clientConn, ok := client.(*wrapClientConn); ok {
		err := closeTCPConnection(clientConn)
		if err != nil {
			go logErr(logger, "close TCP connection error", err)
		}
	}

	for err := range errChan {
		if err != nil {
			go logErr(logger, "transfer copy error", err)
		}
	}
}

// closeTCPConnection closes the read side of a TCP connection.
func closeTCPConnection(clientConn *wrapClientConn) error {
	if tcpConn, ok := clientConn.Conn.(*net.TCPConn); ok {
		return tcpConn.CloseRead()
	}
	return nil
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
