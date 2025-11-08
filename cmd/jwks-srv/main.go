package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"csce-3550_jwks-srv/internal/httpserver"
	"csce-3550_jwks-srv/internal/keys"
)

func main() {
	// intitialize logger
	logger := log.New(os.Stdout, "jwsk-srv: ", log.LstdFlags)

	// load config from env vars
	config, err := httpserver.NewConfig()
	if err != nil {
		logger.Fatalf("Config error: %v", err)
	}

	// key manager initialization
	manager, err := keys.NewManager(config.KeyLifetime, config.KeyRetainPeriod, config.EncryptionKey)
	if err != nil {
		logger.Fatalf("Key manager initialization error: %v", err)
	}

	// start manager
	if err := manager.Start(); err != nil {
		logger.Fatalf("Key manager start error: %v", err)
	}

	// http server creation
	server := httpserver.NewSrv(manager, config)

	// channel for OS sig
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// spin up http srv in a goroutine
	go func() {
		logger.Println("Server starting on :8080")
		if err := server.Waiter(":8080"); err != nil {
			logger.Printf("HTTP server error: %v", err)
		}
	}()

	// hold off until signal is recieved
	<-sigCh
	logger.Println("Termination signal recieved")

	// graceful death
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// stop manager first
	manager.Stop()

	if err := server.Death(ctx); err != nil {
		logger.Printf("Issue during death: %v", err)
	}
	logger.Println("SRV halted safely")
}
