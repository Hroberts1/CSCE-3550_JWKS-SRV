package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main(){
	// intitialize logger
	logger := log.New(os.Stdout, "jwsk-srv: ", log.LstdFlags)

	// load config from env vars
	config := http.server.NewConfig()

	// key manager initialization
	manager := keys.NewManager(config.KeyRotationDuration, config.KeyCleanupDuration)

	// start manager
	manager.Start()

	// http server creation
	server := httpserver,NewServer(manager, config)

	// channel for OS sig
	sigCh := make(chan os.Signal,1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// spin up http srv in a goroutine
	go func ()  {
		if err := server.ListenAndServe("::8080"); err != nil {
			logger.Printf("HTTP server error: %v, err")
		}
	}()

	// hold off until signal is recieved
	<-sigCh
	logger.Println("Termination signal recieved")

	// graceful death
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err :=server.Shutdown(ctx); err != nil {
		logger.
	}
}
