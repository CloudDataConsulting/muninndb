package engine

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/scrypster/muninndb/internal/storage"
	"github.com/scrypster/muninndb/internal/transport/mbp"
)

const externalIdentityPayloadDomain = "muninndb/external-identity-payload/v1\x00"

var (
	// ErrExternalIdentityConflict is returned when a caller reuses an external
	// identity with a changed canonical payload.
	ErrExternalIdentityConflict = storage.ErrExternalIdentityConflict
	// ErrExternalIdentityClusterUnsupported prevents non-replicated 0x27 state
	// from being accepted while MuninnDB is running in cluster mode.
	ErrExternalIdentityClusterUnsupported = errors.New("durable external identities are not supported in cluster mode")
	// ErrExternalIdentityClusterDataPresent prevents cluster activation when
	// standalone 0x27 bindings already exist.
	ErrExternalIdentityClusterDataPresent = errors.New("cluster mode cannot be enabled while durable external identities exist")
	// ErrExternalIdentityUnsupportedPayload prevents caller-owned enrichment
	// fields from entering a contract that cannot yet commit those auxiliary
	// indexes atomically with the canonical engram.
	ErrExternalIdentityUnsupportedPayload = errors.New("durable external identities do not yet support inline entities or relationships")
)

// EnableClusterMode atomically closes the external-identity write gate and
// verifies that no standalone 0x27 bindings exist. The write-side read lock is
// held through each 0x27 commit, so activation cannot pass its scan while a
// request that already observed standalone mode is still in flight.
func (e *Engine) EnableClusterMode(ctx context.Context) error {
	e.identityModeMu.Lock()
	defer e.identityModeMu.Unlock()
	hasExternalIdentities, err := e.store.HasAnyExternalIdentities(ctx)
	if err != nil {
		return fmt.Errorf("check durable external identities: %w", err)
	}
	if hasExternalIdentities {
		return ErrExternalIdentityClusterDataPresent
	}
	e.clusterMode.Store(true)
	return nil
}

// setClusterModeForTest resets the gate in same-package tests. Production
// cluster activation must use EnableClusterMode.
func (e *Engine) setClusterModeForTest(enabled bool) {
	e.identityModeMu.Lock()
	e.clusterMode.Store(enabled)
	e.identityModeMu.Unlock()
}

func canonicalVaultName(vault string) string {
	if vault == "" {
		return "default"
	}
	return vault
}

// externalIdentityPayloadHash computes the canonical caller-visible write
// payload digest. Vault is excluded because the 0x27 key is vault-scoped;
// IdempotentID is excluded because it is the identity being bound. CreatedAt is
// normalized to UTC. Slice order remains significant and nil/empty slices are
// equivalent through their omitempty JSON representation.
func externalIdentityPayloadHash(req *mbp.WriteRequest) ([32]byte, error) {
	if req == nil {
		return [32]byte{}, fmt.Errorf("write request must not be nil")
	}
	if len(req.Entities) > 0 || len(req.Relationships) > 0 || len(req.EntityRelationships) > 0 {
		return [32]byte{}, ErrExternalIdentityUnsupportedPayload
	}
	canonical := *req
	canonical.Vault = ""
	canonical.IdempotentID = ""
	if canonical.Confidence == 0 {
		canonical.Confidence = 1
	}
	if canonical.Stability == 0 {
		canonical.Stability = 30
	}
	if req.CreatedAt != nil && !req.CreatedAt.IsZero() {
		createdAt := req.CreatedAt.UTC()
		canonical.CreatedAt = &createdAt
	} else {
		canonical.CreatedAt = nil
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return [32]byte{}, fmt.Errorf("canonicalize external identity payload: %w", err)
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(externalIdentityPayloadDomain))
	_, _ = hasher.Write(payload)
	var digest [32]byte
	copy(digest[:], hasher.Sum(nil))
	return digest, nil
}
