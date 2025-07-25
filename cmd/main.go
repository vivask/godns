package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"godns/internal/config"
	"godns/internal/log"
	"godns/internal/server"
)

func main() {
	// Флаг -c для пути к конфигу
	configPath := flag.String("c", "godns.yaml", "Path to configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("cannot load config %s: %v", *configPath, err)
	}

	log.SetLogger("DNS", cfg.LogLevel)

	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("cannot create server: %v", err)
	}

	go func() {
		if err := srv.Run(); err != nil {
			log.Fatalf("run: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	if err := srv.Stop(); err != nil {
		log.Fatalf("stop: %v", err)
	}
}
