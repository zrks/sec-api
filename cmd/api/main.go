package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net"
    "net/http"
    "os"
    "strings"
    "time"

    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"
    
    dbpkg "github.com/zrks/sec-api/internal/db"
    "github.com/zrks/sec-api/internal/scanner"
    dnsScanner "github.com/zrks/sec-api/internal/scanner/dns"
    httpScanner "github.com/zrks/sec-api/internal/scanner/httpheaders"
    tlsScanner "github.com/zrks/sec-api/internal/scanner/tls"
)

// responseJSON writes the given data as JSON to the ResponseWriter.
func responseJSON(w http.ResponseWriter, status int, v any) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    enc := json.NewEncoder(w)
    enc.SetIndent("", "  ")
    _ = enc.Encode(v)
}

func main() {
    addr := getEnv("HTTP_ADDR", ":8080")
    dsn := getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/sec-api?sslmode=disable")
    ctx := context.Background()
    db, err := dbpkg.New(ctx, dsn)
    if err != nil {
        log.Fatalf("failed to connect database: %v", err)
    }
    defer db.Close()

    r := chi.NewRouter()

    // health check
    r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        _, _ = w.Write([]byte("ok"))
    })

    // version endpoint
    r.Get("/api/v1/version", func(w http.ResponseWriter, r *http.Request) {
        responseJSON(w, http.StatusOK, map[string]string{"version": "mvp"})
    })

    // domains endpoints
    r.Route("/api/v1/domains", func(r chi.Router) {
        // create domain
        r.Post("/", func(w http.ResponseWriter, r *http.Request) {
            var req struct {
                Domain string `json:"domain"`
            }
            if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                responseJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
                return
            }
            domain := strings.TrimSpace(req.Domain)
            if domain == "" {
                responseJSON(w, http.StatusBadRequest, map[string]string{"error": "domain required"})
                return
            }
            // generate verification token
            token := uuid.NewString()
            id, err := db.CreateDomain(r.Context(), domain, token)
            if err != nil {
                log.Printf("create domain error: %v", err)
                responseJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create domain"})
                return
            }
            responseJSON(w, http.StatusCreated, map[string]any{
                "id":                id.String(),
                "domain":            domain,
                "verification_token": token,
            })
        })

        // verify domain
        r.Post("/{id}/verify", func(w http.ResponseWriter, r *http.Request) {
            idParam := chi.URLParam(r, "id")
            id, err := uuid.Parse(idParam)
            if err != nil {
                responseJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
                return
            }
            dom, err := db.GetDomain(r.Context(), id)
            if err != nil {
                responseJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
                return
            }
            if dom.Verified {
                responseJSON(w, http.StatusOK, map[string]any{"verified": true})
                return
            }
            if dom.VerificationToken == nil {
                responseJSON(w, http.StatusInternalServerError, map[string]string{"error": "missing verification token"})
                return
            }
            // lookup TXT record
            txtName := fmt.Sprintf("_domainriskdigest.%s", dom.Name)
            txts, err := net.LookupTXT(txtName)
            if err != nil {
                // not found: treat as not verified
                responseJSON(w, http.StatusOK, map[string]any{"verified": false, "detail": "txt lookup failed"})
                return
            }
            found := false
            for _, rec := range txts {
                if rec == *dom.VerificationToken {
                    found = true
                    break
                }
            }
            if found {
                if err := db.SetDomainVerified(r.Context(), id, true); err != nil {
                    log.Printf("failed to set verified: %v", err)
                    responseJSON(w, http.StatusInternalServerError, map[string]string{"error": "update failed"})
                    return
                }
            }
            responseJSON(w, http.StatusOK, map[string]any{"verified": found})
        })

        // trigger manual scan
        r.Post("/{id}/scan-now", func(w http.ResponseWriter, r *http.Request) {
            idParam := chi.URLParam(r, "id")
            id, err := uuid.Parse(idParam)
            if err != nil {
                responseJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
                return
            }
            dom, err := db.GetDomain(r.Context(), id)
            if err != nil {
                responseJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
                return
            }
            if !dom.Verified {
                responseJSON(w, http.StatusForbidden, map[string]string{"error": "domain not verified"})
                return
            }
            // create scan run
            scanID, err := db.CreateScanRun(r.Context(), id)
            if err != nil {
                log.Printf("create scan run error: %v", err)
                responseJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create scan run"})
                return
            }
            // run scanners synchronously for MVP
            scs := []scanner.Scanner{
                dnsScanner.New(),
                tlsScanner.New(),
                httpScanner.New(),
            }
            obs, err := scanner.Run(r.Context(), scs, scanner.Target{Domain: dom.Name})
            if err != nil {
                // finish scan run with error message
                msg := err.Error()
                _ = db.FinishScanRun(r.Context(), scanID, &msg)
                responseJSON(w, http.StatusInternalServerError, map[string]string{"error": "scan error"})
                return
            }
            // store observations
            for _, o := range obs {
                if err := db.InsertObservation(r.Context(), scanID, id, o); err != nil {
                    log.Printf("insert observation error: %v", err)
                }
            }
            // finish scan run
            if err := db.FinishScanRun(r.Context(), scanID, nil); err != nil {
                log.Printf("finish scan run error: %v", err)
            }
            responseJSON(w, http.StatusOK, map[string]any{"scan_id": scanID.String(), "observations": obs})
        })

        // get latest report (observations)
        r.Get("/{id}/latest-report", func(w http.ResponseWriter, r *http.Request) {
            idParam := chi.URLParam(r, "id")
            id, err := uuid.Parse(idParam)
            if err != nil {
                responseJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
                return
            }
            dom, err := db.GetDomain(r.Context(), id)
            if err != nil {
                responseJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
                return
            }
            obs, err := db.GetLatestObservations(r.Context(), id)
            if err != nil {
                responseJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch observations"})
                return
            }
            // compute simple risk score: start from 100 and subtract per missing header or upcoming expiry
            score := computeRiskScore(obs)
            responseJSON(w, http.StatusOK, map[string]any{
                "domain": dom.Name,
                "score":  score,
                "observations": obs,
            })
        })
    })

    srv := &http.Server{
        Addr:         addr,
        Handler:      r,
        ReadTimeout:  15 * time.Second,
        WriteTimeout: 15 * time.Second,
        IdleTimeout:  60 * time.Second,
    }
    log.Printf("DomainRiskDigest API listening on %s", addr)
    if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
        log.Fatalf("listen: %v", err)
    }
}

// computeRiskScore is a naive risk scoring function. It starts at 100 and
// subtracts points for missing DMARC, close TLS expiry, missing HSTS, and missing CSP.
func computeRiskScore(obs []scanner.Observation) int {
    score := 100
    // flags to track presence
    hasDMARC := false
    tlsDaysRemaining := -1
    hstsMissing := false
    cspMissing := false
	for _, o := range obs {
		key := strings.ToLower(o.Key)
		value, _ := o.Value.(map[string]any)
		switch o.Category {
		case "dns":
			if key == "dmarc" {
				hasDMARC = true
			}
		case "tls":
			if key == "expiry" {
				if days, ok := value["days_remaining"].(float64); ok {
					tlsDaysRemaining = int(days)
				}
			}
		case "http":
			switch key {
			case "hsts":
				present, _ := value["present"].(bool)
				if !present {
					hstsMissing = true
				}
			case "csp":
				present, _ := value["present"].(bool)
				if !present {
					cspMissing = true
				}
            }
        }
    }
    if !hasDMARC {
        score -= 15
    }
    if tlsDaysRemaining >= 0 && tlsDaysRemaining < 14 {
        score -= 25
    }
    if hstsMissing {
        score -= 10
    }
    if cspMissing {
        score -= 5
    }
    if score < 0 {
        score = 0
    }
    return score
}

// getEnv returns the environment variable value or fallback if empty.
func getEnv(key, fallback string) string {
    if val := os.Getenv(key); val != "" {
        return val
    }
    return fallback
}
