package tlog

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func setupLowRateTest(t *testing.T, level slog.Level) <-chan LogEvent {
	t.Helper()
	ResetRateLimit()
	ClearAllCallbacks()
	ch := make(chan LogEvent, 128)
	RegisterCallback(level, func(e LogEvent) { ch <- e })
	t.Cleanup(func() {
		ResetRateLimit()
		ClearAllCallbacks()
	})
	return ch
}

func requireEvent(t *testing.T, ch <-chan LogEvent) LogEvent {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for log event")
		return LogEvent{}
	}
}

func requireNoEvent(t *testing.T, ch <-chan LogEvent, d time.Duration) {
	t.Helper()
	select {
	case e := <-ch:
		t.Fatalf("unexpected log event: %q", e.Record.Message)
	case <-time.After(d):
	}
}

func recordAttr(record slog.Record, key string) (slog.Value, bool) {
	var found slog.Value
	ok := false
	record.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			found, ok = a.Value, true
			return false
		}
		return true
	})
	return found, ok
}

func TestLowRateFirstEmitAndFabricatedSummary(t *testing.T) {
	ch := setupLowRateTest(t, LevelWarn)
	cfg := RateLimitConfig{Window: 120 * time.Millisecond}

	WarnLowRate(cfg, "disk failure", "disk", "sda")

	first := requireEvent(t, ch)
	require.Equal(t, "disk failure", first.Record.Message)
	require.NotZero(t, first.Record.PC, "original caller PC must be preserved")
	_, hasCount := recordAttr(first.Record, "silenced")
	require.False(t, hasCount, "first emit must not carry a silenced attribute")

	WarnLowRate(cfg, "disk failure", "disk", "sda")
	WarnLowRate(cfg, "disk failure", "disk", "sda")

	summary := requireEvent(t, ch)
	require.Equal(t, "[2 silenced] disk failure", summary.Record.Message)
	v, hasCount := recordAttr(summary.Record, "silenced")
	require.True(t, hasCount, "summary must carry the structured silenced attribute")
	require.Equal(t, int64(2), v.Int64())
	require.NotZero(t, summary.Record.PC, "fabricated summary must reuse the original caller PC")

	// After the summary, no more lines arrive, so the next deadline emits nothing.
	requireNoEvent(t, ch, 2*cfg.Window+80*time.Millisecond)
}

func TestLowRateNoSummaryWhenNothingSilenced(t *testing.T) {
	ch := setupLowRateTest(t, LevelWarn)
	cfg := RateLimitConfig{Window: 100 * time.Millisecond}

	WarnLowRate(cfg, "heartbeat", "id", 1)
	require.Equal(t, "heartbeat", requireEvent(t, ch).Record.Message)

	requireNoEvent(t, ch, 3*cfg.Window)
}

func TestLowRateIgnoresTimeAndConfiguredKeys(t *testing.T) {
	ch := setupLowRateTest(t, LevelWarn)
	cfg := RateLimitConfig{
		Window:     120 * time.Millisecond,
		IgnoreKeys: []string{"duration"},
	}

	for i := 0; i < 3; i++ {
		WarnLowRate(cfg, "refresh failed", "time", time.Now().UnixNano(), "duration", i)
	}

	first := requireEvent(t, ch)
	require.Equal(t, "refresh failed", first.Record.Message)

	summary := requireEvent(t, ch)
	require.Equal(t, "[2 silenced] refresh failed", summary.Record.Message)
	v, ok := recordAttr(summary.Record, "silenced")
	require.True(t, ok)
	require.Equal(t, int64(2), v.Int64())
}

func TestLowRateDistinctMessagesAndWindowsAreIndependent(t *testing.T) {
	ch := setupLowRateTest(t, LevelWarn)

	// Distinct messages produce separate windows.
	WarnLowRate(RateLimitConfig{Window: time.Second}, "alpha")
	WarnLowRate(RateLimitConfig{Window: time.Second}, "beta")

	msgs := []string{
		requireEvent(t, ch).Record.Message,
		requireEvent(t, ch).Record.Message,
	}
	require.ElementsMatch(t, []string{"alpha", "beta"}, msgs)

	// The same message under a different window is a different key.
	WarnLowRate(RateLimitConfig{Window: 2 * time.Second}, "alpha")
	require.Equal(t, "alpha", requireEvent(t, ch).Record.Message)
}

func TestLowRateWindowDisabled(t *testing.T) {
	ch := setupLowRateTest(t, LevelWarn)
	cfg := RateLimitConfig{Window: 0}

	for i := 0; i < 3; i++ {
		WarnLowRate(cfg, "always", "n", i)
	}
	for i := 0; i < 3; i++ {
		require.Equal(t, "always", requireEvent(t, ch).Record.Message)
	}
	requireNoEvent(t, ch, 150*time.Millisecond)
}

func TestLowRateContextVariant(t *testing.T) {
	ch := setupLowRateTest(t, LevelWarn)
	cfg := RateLimitConfig{Window: 100 * time.Millisecond}
	ctx := context.WithValue(context.Background(), "request_id", "req-1")

	WarnLowRateContext(ctx, cfg, "context failure", "disk", "sda")
	WarnLowRateContext(ctx, cfg, "context failure", "disk", "sda")

	first := requireEvent(t, ch)
	v, ok := recordAttr(first.Record, "request_id")
	require.True(t, ok, "context values must be present on the emitted record")
	require.Equal(t, "req-1", v.String())

	summary := requireEvent(t, ch)
	require.Equal(t, "[1 silenced] context failure", summary.Record.Message)
	v, ok = recordAttr(summary.Record, "request_id")
	require.True(t, ok, "fabricated summary must retain context attributes")
	require.Equal(t, "req-1", v.String())
}

func TestLowRateAllLevels(t *testing.T) {
	ResetRateLimit()
	ClearAllCallbacks()
	original := GetLevel()
	SetLevel(LevelTrace)
	t.Cleanup(func() {
		SetLevel(original)
		ResetRateLimit()
		ClearAllCallbacks()
	})

	ch := make(chan LogEvent, 32)
	for _, level := range []slog.Level{LevelTrace, LevelDebug, LevelInfo, LevelNotice, LevelWarn, LevelError} {
		RegisterCallback(level, func(e LogEvent) { ch <- e })
	}

	cfg := RateLimitConfig{Window: time.Second}
	TraceLowRate(cfg, "l-trace")
	DebugLowRate(cfg, "l-debug")
	InfoLowRate(cfg, "l-info")
	NoticeLowRate(cfg, "l-notice")
	WarnLowRate(cfg, "l-warn")
	ErrorLowRate(cfg, "l-error")
	TraceLowRateContext(context.Background(), cfg, "l-trace-ctx")
	DebugLowRateContext(context.Background(), cfg, "l-debug-ctx")
	InfoLowRateContext(context.Background(), cfg, "l-info-ctx")
	NoticeLowRateContext(context.Background(), cfg, "l-notice-ctx")
	WarnLowRateContext(context.Background(), cfg, "l-warn-ctx")
	ErrorLowRateContext(context.Background(), cfg, "l-error-ctx")

	for i := 0; i < 12; i++ {
		requireEvent(t, ch)
	}
	requireNoEvent(t, ch, 100*time.Millisecond)
}

func TestLowRateConcurrentSameKey(t *testing.T) {
	ch := setupLowRateTest(t, LevelWarn)
	cfg := RateLimitConfig{Window: 400 * time.Millisecond}

	const calls = 50
	var wg sync.WaitGroup
	wg.Add(calls)
	for i := 0; i < calls; i++ {
		go func() {
			defer wg.Done()
			WarnLowRate(cfg, "concurrent", "id", 7)
		}()
	}
	wg.Wait()

	first := requireEvent(t, ch)
	require.Equal(t, "concurrent", first.Record.Message)
	summary := requireEvent(t, ch)
	v, ok := recordAttr(summary.Record, "silenced")
	require.True(t, ok)
	require.Equal(t, int64(calls-1), v.Int64())
	requireNoEvent(t, ch, 2*cfg.Window)
}

func TestLowRateReset(t *testing.T) {
	ch := setupLowRateTest(t, LevelWarn)
	cfg := RateLimitConfig{Window: 150 * time.Millisecond}

	WarnLowRate(cfg, "resettable", "id", 1)
	require.Equal(t, "resettable", requireEvent(t, ch).Record.Message)

	WarnLowRate(cfg, "resettable", "id", 1) // silenced
	ResetRateLimit()

	WarnLowRate(cfg, "resettable", "id", 1)
	require.Equal(t, "resettable", requireEvent(t, ch).Record.Message, "post-reset call is a first occurrence")

	requireNoEvent(t, ch, 3*cfg.Window)
}

func TestRateLimitFingerprintExcludesTimeAndSource(t *testing.T) {
	cfg := normalizeRateLimitConfig(RateLimitConfig{Window: time.Second})
	a := rateLimitFingerprint("msg", []any{"time", int64(1), "id", 42}, cfg)
	b := rateLimitFingerprint("msg", []any{"time", int64(999999), "id", 42}, cfg)
	require.Equal(t, a, b, "timestamp must not affect the fingerprint")

	c := rateLimitFingerprint("msg", []any{"id", 43}, cfg)
	require.NotEqual(t, a, c, "different attribute values must produce different keys")

	other := normalizeRateLimitConfig(RateLimitConfig{Window: 2 * time.Second})
	d := rateLimitFingerprint("msg", []any{"id", 42}, other)
	require.NotEqual(t, a, d, "different windows must produce different keys")
}

func TestRateLimitDefaults(t *testing.T) {
	cfg := normalizeRateLimitConfig(RateLimitConfig{Window: time.Second})
	require.Equal(t, defaultSuppressedFormat, cfg.SuppressedFormat)
	require.Equal(t, defaultSilencedKey, cfg.SilencedKey)
	require.Contains(t, cfg.IgnoreKeys, slog.TimeKey)

	msg, args := withSuppressed(cfg, "boom", []any{"k", "v"}, 3)
	require.Equal(t, "[3 silenced] boom", msg)
	require.Equal(t, fmt.Sprintf("%s=%d", defaultSilencedKey, 3), fmt.Sprint(args[len(args)-2])+"="+fmt.Sprint(args[len(args)-1]))
	require.True(t, strings.HasPrefix(msg, "[3 silenced] "))
}
