package main

import (
	"context"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/kuberhealthy/kuberhealthy/v2/pkg/checks/external/checkclient"

	"github.com/zrks/sec-api/internal/khcheck/apicheck"
)

func main() {
	cfg := apicheck.Config{
		BaseURL:           os.Getenv("API_BASE_URL"),
		CheckRootHeaders:  envBool("CHECK_ROOT_HEADERS", true),
		RequireHTTPS:      envBool("REQUIRE_HTTPS", false),
		AllowedCORSOrigin: envString("ALLOWED_CORS_ORIGIN", "http://localhost:5173"),
		BlockedCORSOrigin: envString("BLOCKED_CORS_ORIGIN", "https://example.com"),
		Timeout:           envDuration("REQUEST_TIMEOUT", 5*time.Second),
	}

	failures := apicheck.Run(context.Background(), cfg)
	if len(failures) == 0 {
		checkclient.ReportSuccess()
		return
	}

	log.Printf("Kuberhealthy API check failed: %v", failures)
	checkclient.ReportFailure(failures)
}

func envString(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func envBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}
