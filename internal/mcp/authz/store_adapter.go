package authz

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"

	"github.com/scrypster/muninndb/internal/auth"
)

const (
	apiKeyReferencePrefix      = "api-key:v1:"
	publicVaultReferencePrefix = "public-vault:v1:"
	apiKeyStorageHashSize      = 16
	apiKeyDisplayIDSize        = 8
)

// ErrUnauthorized is the deliberately uniform result for an invalid
// credential reference or unavailable current authorization state. It does
// not reveal whether a credential was missing, revoked, locked, or corrupt.
var ErrUnauthorized = errors.New("mcp authz: unauthorized")

type authMetadataStore interface {
	LookupAPIKeyByStorageHash(storageHash []byte) (auth.APIKey, error)
	LookupPublicVaultConfig(vault string) (auth.VaultConfig, error)
}

// AuthStoreAdapter revalidates non-secret credential references against the
// current auth.Store state. It is intentionally unwired from MCPServer while
// MCP authentication and legacy-token product policies remain undecided.
type AuthStoreAdapter struct {
	store authMetadataStore
	now   func() time.Time
}

// NewAuthStoreAdapter adapts auth.Store to PrincipalStore. The adapter retains
// no bearer token or credential reference and performs a fresh point lookup on
// every Revalidate call. Revalidation is not authentication: callers may use
// it only with a principal established by an earlier proof-of-possession or
// explicit public-vault authentication step.
func NewAuthStoreAdapter(store *auth.Store) *AuthStoreAdapter {
	return newAuthStoreAdapter(store, time.Now)
}

func newAuthStoreAdapter(store authMetadataStore, now func() time.Time) *AuthStoreAdapter {
	return &AuthStoreAdapter{store: store, now: now}
}

// APIKeyCredentialRef creates the stable internal reference for API-key
// metadata returned by successful authentication. It never accepts a raw
// bearer token. The reference is internal authorization state and must not be
// logged or returned through an API.
func APIKeyCredentialRef(key auth.APIKey) (string, error) {
	if !validAPIKeyIdentity(key) {
		return "", ErrInvalidPrincipal
	}
	return apiKeyReferencePrefix + base64.RawURLEncoding.EncodeToString(key.StorageHash), nil
}

// PublicVaultCredentialRef creates the stable internal reference for an
// explicitly authenticated public-vault principal.
func PublicVaultCredentialRef(vault string) (string, error) {
	if !auth.ValidVaultName(vault) {
		return "", ErrInvalidPrincipal
	}
	return publicVaultReferencePrefix + vault, nil
}

// Revalidate implements PrincipalStore. All persistence and reference failures
// collapse to ErrUnauthorized; request cancellation remains observable so a
// caller can stop work promptly.
func (a *AuthStoreAdapter) Revalidate(ctx context.Context, credentialRef string) (Principal, error) {
	if ctx == nil || a == nil || a.store == nil || a.now == nil {
		return Principal{}, ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return Principal{}, err
	}

	var (
		principal Principal
		err       error
	)
	switch {
	case len(credentialRef) > len(apiKeyReferencePrefix) &&
		credentialRef[:len(apiKeyReferencePrefix)] == apiKeyReferencePrefix:
		principal, err = a.revalidateAPIKey(ctx, credentialRef[len(apiKeyReferencePrefix):])
	case len(credentialRef) > len(publicVaultReferencePrefix) &&
		credentialRef[:len(publicVaultReferencePrefix)] == publicVaultReferencePrefix:
		principal, err = a.revalidatePublicVault(ctx, credentialRef[len(publicVaultReferencePrefix):])
	default:
		return Principal{}, ErrUnauthorized
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return Principal{}, contextErr
	}
	if err != nil {
		return Principal{}, ErrUnauthorized
	}
	return principal, nil
}

func (a *AuthStoreAdapter) revalidateAPIKey(ctx context.Context, encodedHash string) (Principal, error) {
	storageHash, ok := parseStorageHash(encodedHash)
	if !ok {
		return Principal{}, ErrUnauthorized
	}
	now := a.now().UTC().Round(0)
	key, err := a.store.LookupAPIKeyByStorageHash(storageHash)
	if contextErr := ctx.Err(); contextErr != nil {
		return Principal{}, contextErr
	}
	if err != nil || !validAPIKeyIdentity(key) ||
		subtle.ConstantTimeCompare(key.StorageHash, storageHash) != 1 {
		return Principal{}, ErrUnauthorized
	}
	if key.ExpiresAt != nil && !now.Before(*key.ExpiresAt) {
		return Principal{}, ErrUnauthorized
	}
	ref, err := APIKeyCredentialRef(key)
	if err != nil {
		return Principal{}, ErrUnauthorized
	}
	principal, err := NewPrincipal(PrincipalClaims{
		Kind:          auth.PrincipalAPIKey,
		Vault:         key.Vault,
		Mode:          key.Mode,
		CredentialRef: ref,
		KeyID:         key.ID,
		ExpiresAt:     key.ExpiresAt,
	})
	if err != nil {
		return Principal{}, ErrUnauthorized
	}
	return principal, nil
}

func (a *AuthStoreAdapter) revalidatePublicVault(ctx context.Context, vault string) (Principal, error) {
	if !auth.ValidVaultName(vault) {
		return Principal{}, ErrUnauthorized
	}
	cfg, err := a.store.LookupPublicVaultConfig(vault)
	if contextErr := ctx.Err(); contextErr != nil {
		return Principal{}, contextErr
	}
	if err != nil || cfg.Name != vault || !cfg.Public {
		return Principal{}, ErrUnauthorized
	}
	ref, err := PublicVaultCredentialRef(vault)
	if err != nil {
		return Principal{}, ErrUnauthorized
	}
	principal, err := NewPrincipal(PrincipalClaims{
		Kind:          auth.PrincipalPublic,
		Vault:         vault,
		Mode:          auth.ModeFull,
		CredentialRef: ref,
	})
	if err != nil {
		return Principal{}, ErrUnauthorized
	}
	return principal, nil
}

func parseStorageHash(encoded string) ([]byte, bool) {
	if len(encoded) != base64.RawURLEncoding.EncodedLen(apiKeyStorageHashSize) {
		return nil, false
	}
	hash, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(hash) != apiKeyStorageHashSize ||
		base64.RawURLEncoding.EncodeToString(hash) != encoded {
		return nil, false
	}
	return hash, true
}

func validAPIKeyIdentity(key auth.APIKey) bool {
	if len(key.StorageHash) != apiKeyStorageHashSize || !auth.ValidVaultName(key.Vault) || !validMode(key.Mode) {
		return false
	}
	id, err := base64.RawURLEncoding.DecodeString(key.ID)
	return err == nil && len(id) == apiKeyDisplayIDSize &&
		base64.RawURLEncoding.EncodeToString(id) == key.ID &&
		subtle.ConstantTimeCompare(id, key.StorageHash[:apiKeyDisplayIDSize]) == 1
}

var _ PrincipalStore = (*AuthStoreAdapter)(nil)
