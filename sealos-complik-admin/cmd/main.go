package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"sealos-complik-admin/internal/infra/config"
	"sealos-complik-admin/internal/infra/database"
	"sealos-complik-admin/internal/infra/migration"
	"sealos-complik-admin/internal/router"
)

const (
	defaultConfigFile  = "/config/config.yaml"
	fallbackConfigFile = "configs/config.yaml"
)

func resolveConfigFile() string {
	if value := strings.TrimSpace(os.Getenv("CONFIG_FILE")); value != "" {
		return value
	}

	if _, err := os.Stat(defaultConfigFile); err == nil {
		return defaultConfigFile
	}

	return fallbackConfigFile
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg := config.LoadConfig(resolveConfigFile())

	if _, err := database.Init(cfg.Database); err != nil {
		return fmt.Errorf("initialize database: %w", err)
	}

	defer database.CloseWithReport(log.Printf)

	if err := migration.AutoMigrate(database.Get()); err != nil {
		return fmt.Errorf("auto migrate tables: %w", err)
	}

	srv, err := router.InitRouter(cfg)
	if err != nil {
		return fmt.Errorf("initialize router: %w", err)
	}

	addr := fmt.Sprintf(":%d", cfg.Port)

	log.Printf("server listening on %s", addr)

	if err := srv.Run(addr); err != nil {
		return fmt.Errorf("run server: %w", err)
	}

	return nil
}
