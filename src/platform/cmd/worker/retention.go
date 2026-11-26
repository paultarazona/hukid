package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"hukid.local/platform/internal/adapters/postgres"
	"hukid.local/platform/internal/issuance"
)

const (
	defaultRetentionTTL       = 7 * 24 * time.Hour
	defaultRetentionBatchSize = 500
	retentionLockNamespace    = "hukid/retention-worker/v1"
	defaultRetentionActorID   = "system:retention-worker"
)

var errRetentionWorkerConfig = errors.New("complete isolated retention worker configuration is required")

type retentionWorkerOptions struct {
	tenantID     string
	retentionTTL time.Duration
	limit        int
	interval     time.Duration
	actorID      string
}

func consumeFlagValue(args []string, i *int, flag string) (string, bool) {
	arg := args[*i]
	if strings.HasPrefix(arg, flag+"=") {
		return strings.TrimPrefix(arg, flag+"="), true
	}
	if arg == flag && *i+1 < len(args) {
		*i++
		return args[*i], true
	}
	return "", false
}

func parseRetentionWorkerOptions(args []string) (retentionWorkerOptions, error) {
	opts := retentionWorkerOptions{
		retentionTTL: defaultRetentionTTL,
		limit:        defaultRetentionBatchSize,
		actorID:      defaultRetentionActorID,
	}
	positional := make([]string, 0, len(args))
	var seenTTL, seenLimit, seenInterval, seenActor bool
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--retention-ttl" || strings.HasPrefix(arg, "--retention-ttl="):
			raw, ok := consumeFlagValue(args, &i, "--retention-ttl")
			if !ok || seenTTL {
				return retentionWorkerOptions{}, errRetentionWorkerConfig
			}
			parsed, err := time.ParseDuration(strings.TrimSpace(raw))
			if err != nil || parsed < 0 {
				return retentionWorkerOptions{}, errRetentionWorkerConfig
			}
			opts.retentionTTL = parsed
			seenTTL = true
		case arg == "--limit" || strings.HasPrefix(arg, "--limit="):
			raw, ok := consumeFlagValue(args, &i, "--limit")
			if !ok || seenLimit {
				return retentionWorkerOptions{}, errRetentionWorkerConfig
			}
			parsed, err := strconv.Atoi(strings.TrimSpace(raw))
			if err != nil || parsed < 1 || parsed > 5000 {
				return retentionWorkerOptions{}, errRetentionWorkerConfig
			}
			opts.limit = parsed
			seenLimit = true
		case arg == "--interval" || strings.HasPrefix(arg, "--interval="):
			raw, ok := consumeFlagValue(args, &i, "--interval")
			if !ok || seenInterval {
				return retentionWorkerOptions{}, errRetentionWorkerConfig
			}
			parsed, err := time.ParseDuration(strings.TrimSpace(raw))
			if err != nil || parsed < minDeferredInterval || parsed > maxDeferredInterval {
				return retentionWorkerOptions{}, errRetentionWorkerConfig
			}
			opts.interval = parsed
			seenInterval = true
		case arg == "--actor" || strings.HasPrefix(arg, "--actor="):
			raw, ok := consumeFlagValue(args, &i, "--actor")
			if !ok || seenActor || strings.TrimSpace(raw) == "" {
				return retentionWorkerOptions{}, errRetentionWorkerConfig
			}
			opts.actorID = strings.TrimSpace(raw)
			seenActor = true
		case strings.HasPrefix(arg, "-"):
			return retentionWorkerOptions{}, errRetentionWorkerConfig
		default:
			positional = append(positional, arg)
		}
	}
	if len(positional) != 1 || strings.TrimSpace(positional[0]) == "" {
		return retentionWorkerOptions{}, errRetentionWorkerConfig
	}
	opts.tenantID = strings.TrimSpace(positional[0])
	return opts, nil
}

// runRetentionWorker executes bounded tenant-scoped offer expiration and crypto-shredding (HK-053).
// Invoke once with `worker retention <tenant-id> [--retention-ttl=168h] [--limit=500]`
// or periodically with `--interval=<dur>`.
func runRetentionWorker(args []string) error {
	opts, err := parseRetentionWorkerOptions(args)
	if err != nil || !isDeferredRuntimeEnv(os.Getenv("HUKID_ENV")) {
		return errRetentionWorkerConfig
	}
	if opts.interval == 0 {
		if envInterval := strings.TrimSpace(os.Getenv("HUKID_WORKER_INTERVAL")); envInterval != "" {
			parsed, parseErr := time.ParseDuration(envInterval)
			if parseErr != nil || parsed < minDeferredInterval || parsed > maxDeferredInterval {
				return errRetentionWorkerConfig
			}
			opts.interval = parsed
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, service, err := openIssuanceWorkerRuntime(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()

	return runDeferredScheduler(ctx, opts.interval, func(tickCtx context.Context) error {
		batchCtx, batchCancel := context.WithTimeout(tickCtx, 2*time.Minute)
		defer batchCancel()
		var summary issuance.RetentionSummary
		acquired, lockErr := postgres.TryWithTenantAdvisoryLock(batchCtx, pool, retentionLockNamespace, opts.tenantID, func() error {
			var purgeErr error
			summary, purgeErr = service.PurgeExpiredMaterial(
				opts.tenantID, opts.retentionTTL, opts.limit, opts.actorID, "retention-"+opts.tenantID,
			)
			return purgeErr
		})
		if lockErr != nil {
			return fmt.Errorf("retention batch failed: %w", lockErr)
		}
		if !acquired {
			fmt.Printf("retention batch: tenant=%s skipped=lock_held\n", opts.tenantID)
			return nil
		}
		fmt.Printf("retention batch: tenant=%s expiredOffers=%d shreddedRequests=%d shreddedDeferredVcs=%d\n",
			opts.tenantID, summary.ExpiredOffers, summary.ShreddedRequests, summary.ShreddedDeferredVCs)
		return nil
	})
}
