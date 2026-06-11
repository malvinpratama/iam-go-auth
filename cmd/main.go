package main

import (
	"context"
	"io/fs"
	"net"
	"os"
	"os/signal"
	"syscall"

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

	dbURL := config.MustEnv("AUTH_DATABASE_URL")
	port := config.Getenv("AUTH_GRPC_PORT", "50051")

	sub, err := fs.Sub(auth.MigrationsFS, "db/migrations")
	if err != nil {
		log.Error("embed migrations", "err", err)
		os.Exit(1)
	}
	if err := migrate.Run(ctx, dbURL, sub); err != nil {
		log.Error("run migrations", "err", err)
		os.Exit(1)
	}
	log.Info("migrations applied")

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
	h := handler.New(pool, jwt.NewManager(keys, jwtCfg.Issuer, jwtCfg.AccessTTL), jwtCfg.RefreshTTL, email.NewLogSender(log), authCache)

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
