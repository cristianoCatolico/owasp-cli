package config

import (
	"github.com/joho/godotenv"
	"log/slog"
	"os"
	"sync"
)

type Config struct {
	Timeout string
	Server  struct {
		URL string
	}
}

var (
	configInstance *Config
	loadConfigOnce sync.Once
)

func LoadConfig() *Config {
	loadConfigOnce.Do(func() {
		configInstance = load() // Call the actual loading logic once
	})
	return configInstance
}

func load() *Config {
	if os.Getenv("GO_ENV") != "production" {
		err := godotenv.Load()
		if err != nil {
			slog.Warn("No .env file found, using system environment variables")
		}
	}
	cfg := &Config{
		Timeout: fetchEnv("TIMEOUT", "5"),
	}

	cfg.Server = struct {
		URL string
	}{
		URL: fetchEnv("ZAP_CLIENT_URL", "http://127.0.0.1:8080"),
	}
	return cfg
}

func fetchEnv(varString string, fallbackString string) string {
	value, found := os.LookupEnv(varString)

	if !found {
		return fallbackString
	}

	return value
}
