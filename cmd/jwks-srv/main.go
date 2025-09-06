package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"csce-3550_jwks-srv/internal/httpserver"
	// "csce-3550_jwks-srv/internal/keys" // TODO: add when keys package is ready
)

func main() {
	// intitialize logger
	logger := log.New(os.Stdout, "jwsk-srv: ", log.LstdFlags)

	// load config from env vars
	config, err := httpserver.NewConfig()
	if err != nil {
		logger.Fatalf("Config error: %v", err)
	}

	// key manager initialization - TODO: implement keys package
	// manager := keys.NewManager(config.KeyLifetime, config.KeyRetainPeriod)

	// start manager - TODO: uncomment when keys package ready
	// manager.Start()

	// http server creation
	server := httpserver.NewSrv(nil, config) // TODO: pass actual manager

	// channel for OS sig
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// spin up http srv in a goroutine
	go func() {
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
	if err := server.Death(ctx); err != nil {
		logger.Printf("Issue during death: %v", err)
	}
	logger.Println("SRV halted safely")
}
