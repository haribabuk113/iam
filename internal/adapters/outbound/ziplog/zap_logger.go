// Package ziplog is the zap implementation of outbound.Logger — the only
// package that imports go.uber.org/zap. Swapping to a different backend
// later means adding a sibling package here and changing one line in
// cmd/server/main.go; nothing in application/ or adapters/inbound/ knows
// zap exists.
//
// zap over zerolog: zap's production config ships with built-in log
// sampling (after the first N identical entries per second it drops the
// rest and just counts them), which matters specifically for an IAM under
// credential-stuffing/brute-force load — every failed login is a log
// line, and sampling caps that volume without an app-level rate limiter.
package ziplog

import (
	"go.uber.org/zap"

	"github.com/haribabuk113/iam/internal/application/ports/outbound"
)

// Logger wraps zap's SugaredLogger, whose Infow/Warnw/... methods already
// take a msg plus alternating key-value pairs — the exact shape of
// outbound.Logger, so no per-call conversion is needed.
type Logger struct {
	z *zap.SugaredLogger
}

var _ outbound.Logger = (*Logger)(nil)

// New builds a Logger. env "production" gets JSON output + sampling
// (zap.NewProduction); anything else gets human-readable console output
// with debug level enabled (zap.NewDevelopment), matching how the service
// is run per CLAUDE.md ("go run ./cmd/server" locally vs. deployed).
func New(env string) (*Logger, error) {
	var z *zap.Logger
	var err error
	if env == "production" {
		z, err = zap.NewProduction()
	} else {
		z, err = zap.NewDevelopment()
	}
	if err != nil {
		return nil, err
	}
	return &Logger{z: z.Sugar()}, nil
}

func (l *Logger) Debug(msg string, kv ...any) { l.z.Debugw(msg, kv...) }
func (l *Logger) Info(msg string, kv ...any)  { l.z.Infow(msg, kv...) }
func (l *Logger) Warn(msg string, kv ...any)  { l.z.Warnw(msg, kv...) }
func (l *Logger) Error(msg string, kv ...any) { l.z.Errorw(msg, kv...) }

func (l *Logger) With(kv ...any) outbound.Logger {
	return &Logger{z: l.z.With(kv...)}
}

// Sync flushes any buffered log entries. Not part of outbound.Logger —
// only cmd/server needs it, and only cmd/server is allowed to know it's
// holding a *ziplog.Logger rather than the port interface.
func (l *Logger) Sync() error {
	return l.z.Sync()
}
