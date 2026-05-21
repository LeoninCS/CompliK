package database

import (
	"strings"
	"testing"

	"sealos-complik-admin/internal/infra/config"
)

func TestValidateConfigAcceptsDatabaseNames(t *testing.T) {
	tests := []string{
		"sealos-complik-admin",
		"sealos_complik_admin",
		"CompliK2026",
		strings.Repeat("a", maxDatabaseNameLength),
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := validDatabaseConfig()
			cfg.Name = name

			if err := validateConfig(cfg); err != nil {
				t.Fatalf("validateConfig() error = %v", err)
			}
		})
	}
}

func TestValidateConfigRejectsDatabaseNames(t *testing.T) {
	tests := []string{
		"sealos complik",
		"sealos`complik",
		"sealos.complik",
		"sealos/complik",
		strings.Repeat("a", maxDatabaseNameLength+1),
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := validDatabaseConfig()
			cfg.Name = name

			if err := validateConfig(cfg); err == nil {
				t.Fatal("validateConfig() error = nil")
			}
		})
	}
}

func validDatabaseConfig() config.DatabaseConfig {
	return config.DatabaseConfig{
		Host:     "localhost",
		Port:     3306,
		Username: "root",
		Name:     "sealos-complik-admin",
	}
}
