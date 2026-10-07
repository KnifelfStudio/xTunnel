package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"server/internal/relay"
)

func main() {
	listen := flag.String("listen", ":8443", "HTTPS/WSS listen address")
	cert := flag.String("tls-cert", "", "TLS certificate PEM path")
	key := flag.String("tls-key", "", "TLS private key PEM path")
	flag.Parse()
	if *cert == "" || *key == "" {
		log.Fatal("-tls-cert and -tls-key are required")
	}
	service := relay.New()
	server := &http.Server{Addr: *listen, Handler: service.Handler(), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	failed := make(chan error, 1)
	go func() { failed <- server.ListenAndServeTLS(*cert, *key) }()
	log.Printf("xTunnel relay listening on %s (TLS)", *listen)
	select {
	case <-ctx.Done():
	case err := <-failed:
		if !errors.Is(err, http.ErrServerClosed) {
			service.Close()
			log.Fatal(err)
		}
	}
	service.Close()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		_ = server.Close()
		log.Printf("HTTP shutdown timed out")
	}
}
