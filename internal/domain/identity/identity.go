package identity

import (
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

// ClientEcosystemID is the permanent, immutable identity of a user across
// the whole ecosystem (PRD §9). ULID: sortable, collision-resistant,
// generated with no coordination across replicas.
type ClientEcosystemID string

func NewClientEcosystemID() ClientEcosystemID {
	return ClientEcosystemID(ulid.Make().String())
}

type AccountStatus string

const (
	StatusActive    AccountStatus = "active"
	StatusSuspended AccountStatus = "suspended"
)

// Identity holds only what PRD §8 allows — no application data, ever.
type Identity struct {
	ID              ClientEcosystemID
	FullName        string
	Email           string
	PrimaryProvider string
	Status          AccountStatus
	CreatedAt       time.Time
}

func NormalizeEmail(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}
