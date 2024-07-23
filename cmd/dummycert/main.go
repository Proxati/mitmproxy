package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/proxati/mitmproxy/cert"
)

// Generate fake/test server certificates

type Config struct {
	commonName string
}

func loadConfig() *Config {
	config := new(Config)
	flag.StringVar(&config.commonName, "commonName", "", "server commonName")
	flag.Parse()
	return config
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	config := loadConfig()
	if config.commonName == "" {
		logger.Error("commonName required")
		os.Exit(1)
	}

	l := &cert.MemoryLoader{}
	ca, err := cert.New(l)
	if err != nil {
		panic(err)
	}

	cert, err := ca.GenerateCert(config.commonName)
	if err != nil {
		panic(err)
	}

	os.Stdout.WriteString(fmt.Sprintf("%v-cert.pem\n", config.commonName))
	err = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	if err != nil {
		panic(err)
	}
	os.Stdout.WriteString(fmt.Sprintf("\n%v-key.pem\n", config.commonName))

	keyBytes, err := x509.MarshalPKCS8PrivateKey(&ca.PrivateKey)
	if err != nil {
		panic(err)
	}
	err = pem.Encode(os.Stdout, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err != nil {
		panic(err)
	}
}
