package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const defaultDatabaseURL = "postgres://postgres:postgres@localhost:5432/sec-api?sslmode=disable"

// Config holds runtime configuration for the API and worker processes.
type Config struct {
	AppEnv       string
	HTTPAddr     string
	DatabaseURL  string
	CronSchedule string
	HIBPAPIKey   string
	NVDAPIKey    string
}

// Load reads config from environment variables and validates the required values.
func Load() (Config, error) {
	cfg := Config{
		AppEnv:       getEnv("APP_ENV", "local"),
		HTTPAddr:     getEnv("HTTP_ADDR", ":8080"),
		DatabaseURL:  getEnv("DATABASE_URL", defaultDatabaseURL),
		CronSchedule: getEnv("CRON_SCHEDULE", "@hourly"),
		HIBPAPIKey:   strings.TrimSpace(os.Getenv("HIBP_API_KEY")),
		NVDAPIKey:    strings.TrimSpace(os.Getenv("NVD_API_KEY")),
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// Validate checks the minimum settings the app needs in order to start.
func (c Config) Validate() error {
	var errs []error

	if strings.TrimSpace(c.AppEnv) == "" {
		errs = append(errs, errors.New("APP_ENV must not be empty"))
	}
	if strings.TrimSpace(c.HTTPAddr) == "" {
		errs = append(errs, errors.New("HTTP_ADDR must not be empty"))
	}
	if strings.TrimSpace(c.DatabaseURL) == "" {
		errs = append(errs, errors.New("DATABASE_URL must not be empty"))
	}
	if strings.TrimSpace(c.CronSchedule) == "" {
		errs = append(errs, errors.New("CRON_SCHEDULE must not be empty"))
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid config: %w", errors.Join(errs...))
	}

	return nil
}

func getEnv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
