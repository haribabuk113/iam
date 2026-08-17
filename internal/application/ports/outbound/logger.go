package outbound

// Logger is the seam every use case and adapter logs through. Signature
// mirrors log/slog's key-value style on purpose — swapping the concrete
// backend (adapters/outbound/ziplog today, zerolog or anything else
// later) never touches a call site.
type Logger interface {
	Debug(msg string, kv ...any)
	Info(msg string, kv ...any)
	Warn(msg string, kv ...any)
	Error(msg string, kv ...any)

	// With returns a child Logger that prepends kv to every subsequent
	// call — for attaching request-scoped fields (request_id, app_id)
	// without threading them through every log call by hand.
	With(kv ...any) Logger
}
