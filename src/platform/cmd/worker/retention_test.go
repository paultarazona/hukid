package main

import (
	"testing"
	"time"
)

func TestParseRetentionWorkerOptions(t *testing.T) {
	opts, err := parseRetentionWorkerOptions([]string{"tenant-1"})
	if err != nil {
		t.Fatalf("default parse failed: %v", err)
	}
	if opts.tenantID != "tenant-1" || opts.retentionTTL != defaultRetentionTTL || opts.limit != defaultRetentionBatchSize || opts.actorID != defaultRetentionActorID {
		t.Fatalf("unexpected defaults: %+v", opts)
	}

	opts, err = parseRetentionWorkerOptions([]string{
		"--retention-ttl=72h", "--limit", "250", "--interval=30s", "--actor=ops-cron", "tenant-2",
	})
	if err != nil {
		t.Fatalf("custom parse failed: %v", err)
	}
	if opts.tenantID != "tenant-2" || opts.retentionTTL != 72*time.Hour || opts.limit != 250 || opts.interval != 30*time.Second || opts.actorID != "ops-cron" {
		t.Fatalf("unexpected custom options: %+v", opts)
	}

	for _, bad := range [][]string{
		{},
		{" "},
		{"tenant-1", "extra"},
		{"tenant-1", "--limit=0"},
		{"tenant-1", "--limit=5001"},
		{"tenant-1", "--retention-ttl=-1s"},
		{"tenant-1", "--interval=500ms"},
		{"tenant-1", "--interval=2h"},
		{"tenant-1", "--actor= "},
		{"tenant-1", "--unknown=1"},
	} {
		if _, err := parseRetentionWorkerOptions(bad); err == nil {
			t.Fatalf("expected error for %v", bad)
		}
	}
}
