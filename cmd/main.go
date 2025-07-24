package main

import (
	"flag"

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
	if err := srv.Run(); err != nil {
		log.Fatalf("cannot run server: %v", err)
	}
}
