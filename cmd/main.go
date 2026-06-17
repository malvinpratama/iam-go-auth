package main

import (
	"context"
	"io/fs"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	auth "github.com/malvinpratama/iam-go-auth"
	"github.com/malvinpratama/iam-go-auth/internal/cache"
	authdb "github.com/malvinpratama/iam-go-auth/internal/db"
	"github.com/malvinpratama/iam-go-auth/internal/email"
	"github.com/malvinpratama/iam-go-auth/internal/handler"
	"github.com/malvinpratama/iam-go-auth/internal/jwt"
	"github.com/malvinpratama/iam-go-auth/internal/outbox"
	"github.com/malvinpratama/iam-go-auth/internal/saga"
	"github.com/malvinpratama/iam-go-auth/internal/totpsecret"
	authv1 "github.com/malvinpratama/iam-go-contracts/gen/auth/v1"
	"github.com/malvinpratama/iam-go-libs/config"
	"github.com/malvinpratama/iam-go-libs/db"
	"github.com/malvinpratama/iam-go-libs/events"
	"github.com/malvinpratama/iam-go-libs/logger"
	"github.com/malvinpratama/iam-go-libs/migrate"
	"github.com/malvinpratama/iam-go-libs/obs"
)

func main() {
	log := logger.New("auth")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The `migrate` subcommand runs the embedded migrations as the privileged DB
	// owner and exits — used by the PreSync Job so the long-running server need not
	// migrate on startup. This matters for Phase 3c: once the server connects as the
	// least-privilege iam_app it can no longer run DDL, so migrations move to the Job.
	migrateOnly := len(os.Args) > 1 && os.Args[1] == "migrate"

	if !migrateOnly {
		if err := config.ValidateSecurity(); err != nil {
			log.Error("insecure configuration", "err", err)
			os.Exit(1)
		}

		// Tracing (optional) + Prometheus /metrics.
		shutdownTracer, err := obs.InitTracer(ctx, "auth", config.OTLPEndpoint())
		if err != nil {
			log.Error("init tracer", "err", err)
			os.Exit(1)
		}
		defer func() { _ = shutdownTracer(context.Background()) }()
		obs.ServeMetrics(config.MetricsAddr(), log)
	}

	dbURL := config.MustEnv("AUTH_DATABASE_URL")
	port := config.Getenv("AUTH_GRPC_PORT", "50051")

	// Run embedded migrations for the `migrate` subcommand, or on startup unless
	// AUTO_MIGRATE=false (set at cutover, once the Job owns migrations and the
	// server connects as iam_app, which cannot run DDL).
	if migrateOnly || config.Getenv("AUTO_MIGRATE", "true") != "false" {
		sub, err := fs.Sub(auth.MigrationsFS, "db/migrations")
		if err != nil {
			log.Error("embed migrations", "err", err)
			os.Exit(1)
		}
		// migrate.Run connects once with no retry of its own. A freshly-scheduled
		// migrate-Job pod can briefly precede its NetworkPolicy programming (the
		// kube-router ipset that permits app=auth-migrate→postgres), so the first
		// connect fails "connection refused". Retry the connect/apply a few times —
		// the run is idempotent (applied versions are tracked + skipped).
		var migErr error
		for attempt := 1; attempt <= 12; attempt++ {
			if migErr = migrate.Run(ctx, dbURL, sub); migErr == nil {
				break
			}
			log.Warn("run migrations failed; retrying", "attempt", attempt, "err", migErr)
			select {
			case <-ctx.Done():
				log.Error("run migrations", "err", ctx.Err())
				os.Exit(1)
			case <-time.After(3 * time.Second):
			}
		}
		if migErr != nil {
			log.Error("run migrations", "err", migErr)
			os.Exit(1)
		}
		log.Info("migrations applied")
	} else {
		log.Info("auto-migrate disabled (AUTO_MIGRATE=false) — migrations run by the Job")
	}
	if migrateOnly {
		return
	}

	pool, err := db.NewPool(ctx, dbURL)
	if err != nil {
		log.Error("connect db", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := handler.BootstrapAdmin(ctx, pool,
		config.Getenv("BOOTSTRAP_ADMIN_EMAIL", ""),
		config.Getenv("BOOTSTRAP_ADMIN_PASSWORD", ""),
	); err != nil {
		log.Error("bootstrap admin", "err", err)
		os.Exit(1)
	}
	if err := handler.BootstrapOIDCClient(ctx, pool); err != nil {
		log.Error("bootstrap oidc client", "err", err)
		os.Exit(1)
	}
	// Read-only demo account for the public demo (default demo@iam.local). Set
	// DEMO_EMAIL="" to disable.
	if err := handler.BootstrapDemo(ctx, pool,
		config.Getenv("DEMO_EMAIL", "demo@iam.local"),
		config.Getenv("DEMO_PASSWORD", "demo1234"),
	); err != nil {
		log.Error("bootstrap demo", "err", err)
		os.Exit(1)
	}

	jwtCfg := config.LoadJWT()
	keys, err := jwt.LoadKeys(ctx, pool)
	if err != nil {
		log.Error("load signing keys", "err", err)
		os.Exit(1)
	}
	// Optional Redis: shared access-token denylist + permission cache across
	// replicas. Falls back to Postgres (denylist) / no cache when REDIS_URL is
	// unset or unreachable.
	authCache := cache.New(config.Getenv("REDIS_URL", ""))
	if authCache.Enabled() {
		log.Info("auth cache: redis-backed (shared denylist + permission cache)")
	} else {
		log.Info("auth cache: disabled (postgres denylist, no permission cache)")
	}
	// TS3: encrypt TOTP shared secrets at rest. Without TOTP_ENC_KEY this is a
	// passthrough (plaintext, as before) so dev keeps working; production should
	// set the key.
	totpEnc, err := totpsecret.New(config.Getenv("TOTP_ENC_KEY", ""))
	if err != nil {
		log.Error("init totp encryptor", "err", err)
		os.Exit(1)
	}
	if totpEnc.Enabled() {
		log.Info("totp secrets: encrypted at rest (AES-256-GCM)")
	} else {
		log.Warn("totp secrets: plaintext at rest — set TOTP_ENC_KEY to encrypt")
	}
	h := handler.New(pool, jwt.NewManager(keys, jwtCfg.Issuer, jwtCfg.AccessTTL), jwtCfg.RefreshTTL, email.NewLogSender(log), authCache, totpEnc)

	// Outbox relay: drain pending domain events to NATS JetStream. Optional —
	// without NATS_URL the events are still recorded; the gateway's lazy profile
	// healing keeps the system working.
	if url := config.NatsURL(); url != "" {
		nc, js, err := events.Connect(url)
		if err != nil {
			log.Error("connect nats", "err", err)
			os.Exit(1)
		}
		defer nc.Close()
		if err := events.EnsureStream(js); err != nil {
			log.Error("ensure stream", "err", err)
			os.Exit(1)
		}
		go outbox.NewRelay(authdb.New(pool), js, log).Run(ctx)
		log.Info("outbox relay started", "nats", url)
		// Saga: roll back identities whose profile creation failed permanently.
		saga.NewCompensator(authdb.New(pool), js, log).Start(ctx)
	} else {
		log.Warn("NATS_URL not set — event publishing disabled")
	}

	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}

	srv := grpc.NewServer(obs.ServerOptions(config.InternalToken(), log)...)
	authv1.RegisterAuthServiceServer(srv, h)

	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(srv, hs)
	if !config.IsProduction() {
		reflection.Register(srv) // dev only — avoid schema disclosure in prod
	}
	obs.RegisterServerMetrics(srv) // per-method metrics at zero

	go func() {
		<-ctx.Done()
		log.Info("shutting down")
		srv.GracefulStop()
	}()

	log.Info("auth service listening", "port", port)
	if err := srv.Serve(lis); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}
