package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/proxati/mitmproxy/addon"
	"github.com/proxati/mitmproxy/cert"
	"github.com/proxati/mitmproxy/proxy"
	"github.com/proxati/mitmproxy/web"
)

type Config struct {
	debug    int
	version  bool
	certPath string

	addr         string
	webAddr      string
	ssl_insecure bool

	dump      string // dump filename
	dumpLevel int    // dump level

	mapperDir string
}

func loadConfig() *Config {
	config := new(Config)

	flag.BoolVar(&config.version, "version", false, "show version")
	flag.StringVar(&config.addr, "addr", ":9080", "proxy listen addr")
	flag.StringVar(&config.webAddr, "web_addr", ":9081", "web interface listen addr")
	flag.BoolVar(&config.ssl_insecure, "ssl_insecure", false, "not verify upstream server SSL/TLS certificates.")
	flag.StringVar(&config.dump, "dump", "", "dump filename")
	flag.IntVar(&config.dumpLevel, "dump_level", 0, "dump level: 0 - header, 1 - header + body")
	flag.StringVar(&config.mapperDir, "mapper_dir", "", "mapper files dirpath")
	flag.StringVar(&config.certPath, "cert_path", "", "path of generate cert files")
	flag.Parse()

	return config
}

func main() {
	config := loadConfig()

	logHandler := &slog.HandlerOptions{}
	if config.debug > 0 {
		logHandler.Level = slog.LevelDebug
	} else {
		logHandler.Level = slog.LevelInfo
	}
	if config.debug == 2 {
		logHandler.AddSource = true
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, logHandler))
	slog.SetDefault(logger)

	l, err := cert.NewPathLoader(config.certPath)
	if err != nil {
		logger.Error("could not load certs", "error", err)
		os.Exit(1)
	}
	ca, err := cert.New(l)
	if err != nil {
		logger.Error("could not create certs", "error", err)
		os.Exit(1)
	}

	opts := &proxy.Options{
		Addr:                  config.addr,
		StreamLargeBodies:     1024 * 1024 * 5,
		InsecureSkipVerifyTLS: config.ssl_insecure,
		CA:                    ca,
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		logger.Error("could not create new proxy", "error", err)
		os.Exit(1)
	}

	if config.version {
		fmt.Println("go-mitmproxy: " + p.Version)
		os.Exit(0)
	}

	logger.Debug("go-mitmproxy", "version", p.Version)

	p.AddAddon(&addon.LogAddon{})
	p.AddAddon(web.NewWebAddon(config.webAddr))

	if config.dump != "" {
		dumper := addon.NewDumperWithFilename(config.dump, config.dumpLevel)
		p.AddAddon(dumper)
	}

	if config.mapperDir != "" {
		mapper := addon.NewMapper(config.mapperDir)
		p.AddAddon(mapper)
	}

	log.Fatal(p.Start())
}
