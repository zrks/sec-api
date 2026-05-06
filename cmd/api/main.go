package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zrks/sec-api/internal/config"
	dbpkg "github.com/zrks/sec-api/internal/db"
	domainpkg "github.com/zrks/sec-api/internal/domain"
	"github.com/zrks/sec-api/internal/scanjob"
	"github.com/zrks/sec-api/internal/scanner"
	dnsScanner "github.com/zrks/sec-api/internal/scanner/dns"
	httpScanner "github.com/zrks/sec-api/internal/scanner/httpheaders"
	rdapScanner "github.com/zrks/sec-api/internal/scanner/rdap"
	subdomainScanner "github.com/zrks/sec-api/internal/scanner/subdomains"
	tlsScanner "github.com/zrks/sec-api/internal/scanner/tls"
	"github.com/zrks/sec-api/internal/ui"
)

// responseJSON writes the given data as JSON to the ResponseWriter.
func responseJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func responseError(w http.ResponseWriter, status int, message string) {
	responseJSON(w, status, map[string]string{"error": message})
}

func serializeDomain(dom dbpkg.Domain, summary dbpkg.DomainSummary) map[string]any {
	verificationToken := ""
	verificationRecordValue := ""
	if dom.VerificationToken != nil {
		verificationToken = *dom.VerificationToken
		verificationRecordValue = domainpkg.VerificationRecordValue(*dom.VerificationToken)
	}

	payload := map[string]any{
		"id":                        dom.ID.String(),
		"domain":                    dom.Name,
		"normalized_domain":         dom.NormalizedDomain,
		"status":                    dom.Status,
		"ownership_verified":        dom.OwnershipVerified,
		"verification_token":        verificationToken,
		"verification_record_name":  domainpkg.VerificationRecordName(dom.Name),
		"verification_record_value": verificationRecordValue,
		"created_at":                dom.CreatedAt,
		"updated_at":                dom.UpdatedAt,
	}
	if dom.LastScanAt != nil {
		payload["last_scan_at"] = *dom.LastScanAt
	}
	if dom.LastError != nil && *dom.LastError != "" {
		payload["last_error"] = *dom.LastError
	}
	if summary.LatestScore != nil {
		payload["latest_score"] = *summary.LatestScore
	}
	if summary.LatestReportGeneratedAt != nil {
		payload["latest_report_generated_at"] = *summary.LatestReportGeneratedAt
	}
	if summary.LatestScanStatus != nil {
		payload["latest_scan_status"] = *summary.LatestScanStatus
	}
	if summary.LatestScanError != nil && *summary.LatestScanError != "" {
		payload["latest_scan_error"] = *summary.LatestScanError
	}
	return payload
}

func serializeDomainWithSummary(ctx context.Context, db *dbpkg.DB, dom dbpkg.Domain) (map[string]any, error) {
	summary, err := db.GetDomainSummary(ctx, dom.ID)
	if err != nil {
		return nil, err
	}
	return serializeDomain(dom, summary), nil
}

func allowCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && (strings.HasPrefix(origin, "http://localhost:") || strings.HasPrefix(origin, "http://127.0.0.1:")) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func defaultScanners() []scanner.Scanner {
	return []scanner.Scanner{dnsScanner.New(), subdomainScanner.New(), rdapScanner.New(), tlsScanner.New(), httpScanner.New()}
}

func writeStoredReport(w http.ResponseWriter, report dbpkg.LatestReport) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(report.Data)
}

func newRouter(db *dbpkg.DB) http.Handler {
	r := chi.NewRouter()
	r.Use(securityHeaders)
	r.Use(allowCORS)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(ui.Page))
	})

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
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			domains, err := db.ListDomains(r.Context())
			if err != nil {
				responseError(w, http.StatusInternalServerError, "failed to list domains")
				return
			}
			payload := make([]map[string]any, 0, len(domains))
			for _, dom := range domains {
				item, err := serializeDomainWithSummary(r.Context(), db, dom)
				if err != nil {
					responseError(w, http.StatusInternalServerError, "failed to load domain summary")
					return
				}
				payload = append(payload, item)
			}
			responseJSON(w, http.StatusOK, payload)
		})

		// create domain
		r.Post("/", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Domain string `json:"domain"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				responseJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			domainName := strings.TrimSpace(req.Domain)
			if domainName == "" {
				responseError(w, http.StatusBadRequest, "domain required")
				return
			}
			normalizedDomain, err := domainpkg.NormalizePublicDomain(domainName)
			if err != nil {
				responseError(w, http.StatusBadRequest, err.Error())
				return
			}
			id, err := db.CreateDomain(r.Context(), normalizedDomain, normalizedDomain)
			if err != nil {
				var pgErr *pgconn.PgError
				if errors.As(err, &pgErr) && pgErr.Code == "23505" {
					responseError(w, http.StatusConflict, "domain already exists")
					return
				}
				log.Printf("create domain error: %v", err)
				responseError(w, http.StatusInternalServerError, "failed to create domain")
				return
			}
			created, err := db.GetDomain(r.Context(), id)
			if err != nil {
				responseError(w, http.StatusInternalServerError, "failed to fetch created domain")
				return
			}
			payload, err := serializeDomainWithSummary(r.Context(), db, created)
			if err != nil {
				responseError(w, http.StatusInternalServerError, "failed to load domain summary")
				return
			}
			result, scanErr := scanjob.Run(r.Context(), db, created, defaultScanners(), "initial")
			response := map[string]any{"domain": payload}
			if scanErr == nil {
				response["latest_report"] = result.Report
				if refreshed, getErr := db.GetDomain(r.Context(), id); getErr == nil {
					if refreshedPayload, serializeErr := serializeDomainWithSummary(r.Context(), db, refreshed); serializeErr == nil {
						response["domain"] = refreshedPayload
					}
				}
			} else {
				response["scan_error"] = scanErr.Error()
			}
			responseJSON(w, http.StatusCreated, response)
		})

		r.Get("/{id}", func(w http.ResponseWriter, r *http.Request) {
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				responseError(w, http.StatusBadRequest, "invalid id")
				return
			}
			dom, err := db.GetDomain(r.Context(), id)
			if err != nil {
				if errors.Is(err, dbpkg.ErrNotFound) {
					responseError(w, http.StatusNotFound, "domain not found")
					return
				}
				responseError(w, http.StatusInternalServerError, "failed to fetch domain")
				return
			}
			payload, err := serializeDomainWithSummary(r.Context(), db, dom)
			if err != nil {
				responseError(w, http.StatusInternalServerError, "failed to load domain summary")
				return
			}
			responseJSON(w, http.StatusOK, payload)
		})

		// optional future ownership verification
		r.Post("/{id}/verify-ownership", func(w http.ResponseWriter, r *http.Request) {
			idParam := chi.URLParam(r, "id")
			id, err := uuid.Parse(idParam)
			if err != nil {
				responseJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
				return
			}
			dom, err := db.GetDomain(r.Context(), id)
			if err != nil {
				responseError(w, http.StatusNotFound, "domain not found")
				return
			}
			if dom.OwnershipVerified {
				payload, err := serializeDomainWithSummary(r.Context(), db, dom)
				if err != nil {
					responseError(w, http.StatusInternalServerError, "failed to load domain summary")
					return
				}
				responseJSON(w, http.StatusOK, map[string]any{"verified": true, "domain": payload})
				return
			}
			if dom.VerificationToken == nil {
				token := domainpkg.GenerateVerificationToken()
				if err := db.SetVerificationToken(r.Context(), id, token); err != nil {
					responseError(w, http.StatusInternalServerError, "failed to create verification token")
					return
				}
				dom.VerificationToken = &token
			}
			if dom.VerificationToken == nil {
				responseError(w, http.StatusInternalServerError, "missing verification token")
				return
			}
			// lookup TXT record
			txtName := domainpkg.VerificationRecordName(dom.Name)
			txts, err := net.DefaultResolver.LookupTXT(r.Context(), txtName)
			if err != nil {
				// not found: treat as not verified
				responseJSON(w, http.StatusOK, map[string]any{"verified": false, "detail": "txt lookup failed", "verification_record_name": txtName, "verification_record_value": domainpkg.VerificationRecordValue(*dom.VerificationToken)})
				return
			}
			found := domainpkg.HasVerificationTXT(txts, *dom.VerificationToken)
			if found {
				if err := db.MarkDomainOwnershipVerified(r.Context(), id, true); err != nil {
					log.Printf("failed to set verified: %v", err)
					responseError(w, http.StatusInternalServerError, "update failed")
					return
				}
				dom.OwnershipVerified = true
			}
			payload, err := serializeDomainWithSummary(r.Context(), db, dom)
			if err != nil {
				responseError(w, http.StatusInternalServerError, "failed to load domain summary")
				return
			}
			responseJSON(w, http.StatusOK, map[string]any{"verified": found, "domain": payload, "verification_record_name": txtName, "verification_record_value": domainpkg.VerificationRecordValue(*dom.VerificationToken), "txt_records": txts})
		})
		// backward-compatible alias
		r.Post("/{id}/verify", func(w http.ResponseWriter, r *http.Request) {
			r.URL.Path = strings.Replace(r.URL.Path, "/verify", "/verify-ownership", 1)
			rctx := chi.RouteContext(r.Context())
			_ = rctx
			responseError(w, http.StatusGone, "use verify-ownership for optional future ownership checks")
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
				responseError(w, http.StatusNotFound, "domain not found")
				return
			}
			if dom.Status != "active" {
				responseError(w, http.StatusForbidden, "domain is not active")
				return
			}
			result, err := scanjob.Run(r.Context(), db, dom, defaultScanners(), "manual")
			if err != nil {
				log.Printf("scan error: %v", err)
				responseError(w, http.StatusInternalServerError, "scan error")
				return
			}
			responseJSON(w, http.StatusOK, map[string]any{"scan_id": result.ScanRunID.String(), "report": result.Report, "findings": result.Findings})
		})

		// get latest report
		r.Get("/{id}/latest-report", func(w http.ResponseWriter, r *http.Request) {
			idParam := chi.URLParam(r, "id")
			id, err := uuid.Parse(idParam)
			if err != nil {
				responseJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
				return
			}
			dom, err := db.GetDomain(r.Context(), id)
			if err != nil {
				responseError(w, http.StatusNotFound, "domain not found")
				return
			}
			report, err := db.GetLatestReport(r.Context(), id)
			if err != nil {
				if errors.Is(err, dbpkg.ErrNotFound) {
					responseError(w, http.StatusNotFound, "no report available")
					return
				}
				responseError(w, http.StatusInternalServerError, "failed to fetch latest report")
				return
			}
			writeStoredReport(w, report)
			_ = dom
		})

		r.Get("/{id}/reports", func(w http.ResponseWriter, r *http.Request) {
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				responseError(w, http.StatusBadRequest, "invalid id")
				return
			}
			if _, err := db.GetDomain(r.Context(), id); err != nil {
				responseError(w, http.StatusNotFound, "domain not found")
				return
			}
			reports, err := db.ListReportsForDomain(r.Context(), id)
			if err != nil {
				responseError(w, http.StatusInternalServerError, "failed to list reports")
				return
			}
			payload := make([]map[string]any, 0, len(reports))
			for _, report := range reports {
				payload = append(payload, map[string]any{
					"id":          report.ID.String(),
					"scan_run_id": report.ScanRunID.String(),
					"score":       report.Score,
					"created_at":  report.CreatedAt,
				})
			}
			responseJSON(w, http.StatusOK, payload)
		})
	})

	r.Get("/api/v1/reports/{id}", func(w http.ResponseWriter, r *http.Request) {
		reportID, err := uuid.Parse(chi.URLParam(r, "id"))
		if err != nil {
			responseError(w, http.StatusBadRequest, "invalid id")
			return
		}
		report, err := db.GetReportByID(r.Context(), reportID)
		if err != nil {
			if errors.Is(err, dbpkg.ErrNotFound) {
				responseError(w, http.StatusNotFound, "report not found")
				return
			}
			responseError(w, http.StatusInternalServerError, "failed to fetch report")
			return
		}
		writeStoredReport(w, report)
	})

	return r
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	addr := cfg.HTTPAddr
	dsn := cfg.DatabaseURL
	ctx := context.Background()
	db, err := dbpkg.New(ctx, dsn)
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}
	defer db.Close()

	r := newRouter(db)

	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Printf("DomainRiskDigest API listening on %s (%s)", addr, cfg.AppEnv)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
}
