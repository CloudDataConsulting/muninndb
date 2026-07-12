package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cockroachdb/pebble"
)

// ErrKeyNotFound is returned by RevokeAPIKey when the key does not exist.
var ErrKeyNotFound = errors.New("api key not found")

// GenerateAPIKey creates a new API key for the given vault.
// Returns the raw token (shown once) and the key metadata.
// expiresAt is optional; pass nil for a key that never expires.
func (s *Store) GenerateAPIKey(vault, label, mode string, expiresAt *time.Time) (token string, key APIKey, err error) {
	if !ValidVaultName(vault) {
		err = fmt.Errorf("invalid vault name")
		return
	}
	if mode != ModeFull && mode != ModeObserve && mode != ModeWrite {
		err = fmt.Errorf("mode must be %q, %q, or %q", ModeFull, ModeObserve, ModeWrite)
		return
	}

	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		err = fmt.Errorf("generate random bytes: %w", err)
		return
	}
	token = "mk_" + base64.RawURLEncoding.EncodeToString(raw)

	h := sha256.Sum256(raw)
	storageHash := h[:16]
	keyID := h[:8]

	key = APIKey{
		ID:          base64.RawURLEncoding.EncodeToString(keyID),
		Vault:       vault,
		Label:       label,
		Mode:        mode,
		CreatedAt:   time.Now(),
		StorageHash: storageHash,
		ExpiresAt:   expiresAt,
	}

	data, marshalErr := json.Marshal(key)
	if marshalErr != nil {
		err = fmt.Errorf("marshal key: %w", marshalErr)
		return
	}

	batch := s.db.NewBatch()
	if setErr := batch.Set(apiKeyStorageKey(storageHash), data, nil); setErr != nil {
		batch.Close()
		err = setErr
		return
	}
	if setErr := batch.Set(apiKeyVaultIdxKey(vault, keyID), storageHash, nil); setErr != nil {
		batch.Close()
		err = setErr
		return
	}
	err = batch.Commit(pebble.Sync)
	return
}

// ValidateAPIKey parses the token and returns the associated key metadata.
func (s *Store) ValidateAPIKey(token string) (APIKey, error) {
	const pfx = "mk_"
	if len(token) <= len(pfx) || token[:len(pfx)] != pfx {
		return APIKey{}, fmt.Errorf("invalid token format")
	}
	raw, err := base64.RawURLEncoding.DecodeString(token[len(pfx):])
	if err != nil || len(raw) != 32 {
		return APIKey{}, fmt.Errorf("invalid token encoding")
	}
	h := sha256.Sum256(raw)
	return s.LookupAPIKeyByStorageHash(h[:16])
}

// LookupAPIKeyByStorageHash performs a direct, collision-resistant metadata
// lookup using the full 128-bit storage hash persisted for an API key. It is
// intended for revalidating a key that has already been authenticated; callers
// must not substitute the shorter display ID or scan ListAPIKeys.
//
// Expiration is inclusive: a key is invalid at its exact expiration instant.
func (s *Store) LookupAPIKeyByStorageHash(storageHash []byte) (APIKey, error) {
	return s.lookupAPIKeyByStorageHashAt(storageHash, time.Now())
}

func (s *Store) lookupAPIKeyByStorageHashAt(storageHash []byte, now time.Time) (APIKey, error) {
	if s == nil || s.db == nil || len(storageHash) != 16 {
		return APIKey{}, fmt.Errorf("invalid key reference")
	}

	data, closer, err := s.db.Get(apiKeyStorageKey(storageHash))
	if err != nil {
		return APIKey{}, fmt.Errorf("invalid key")
	}
	defer closer.Close()

	var key APIKey
	if err := json.Unmarshal(data, &key); err != nil {
		return APIKey{}, fmt.Errorf("corrupt key record: %w", err)
	}
	if len(key.StorageHash) != 16 || subtle.ConstantTimeCompare(key.StorageHash, storageHash) != 1 {
		return APIKey{}, fmt.Errorf("corrupt api key storage hash")
	}
	id, err := base64.RawURLEncoding.DecodeString(key.ID)
	if err != nil || len(id) != 8 || base64.RawURLEncoding.EncodeToString(id) != key.ID ||
		subtle.ConstantTimeCompare(id, storageHash[:8]) != 1 {
		return APIKey{}, fmt.Errorf("corrupt api key ID")
	}
	if !ValidVaultName(key.Vault) {
		return APIKey{}, fmt.Errorf("corrupt api key vault scope")
	}
	if key.Mode != ModeFull && key.Mode != ModeObserve && key.Mode != ModeWrite {
		return APIKey{}, fmt.Errorf("corrupt api key mode")
	}
	if key.ExpiresAt != nil && !now.Before(*key.ExpiresAt) {
		return APIKey{}, fmt.Errorf("api key has expired")
	}
	return key, nil
}

// ListAPIKeys returns all API key metadata for a vault (tokens not included).
func (s *Store) ListAPIKeys(vault string) ([]APIKey, error) {
	prefix := apiKeyVaultIdxPrefix(vault)
	upper := make([]byte, len(prefix))
	copy(upper, prefix)
	upper[len(upper)-1]++

	iter, err := s.db.NewIter(&pebble.IterOptions{
		LowerBound: prefix,
		UpperBound: upper,
	})
	if err != nil {
		return nil, fmt.Errorf("new iter: %w", err)
	}
	defer iter.Close()

	var keys []APIKey
	for iter.First(); iter.Valid(); iter.Next() {
		storageHash := make([]byte, 16)
		copy(storageHash, iter.Value())

		data, closer, err := s.db.Get(apiKeyStorageKey(storageHash))
		if err != nil {
			continue
		}
		var key APIKey
		if jsonErr := json.Unmarshal(data, &key); jsonErr == nil {
			keys = append(keys, key)
		}
		closer.Close()
	}
	return keys, iter.Error()
}

// RevokeAPIKey removes the key with the given display ID from the given vault.
// Returns ErrKeyNotFound if the key does not exist or the ID is invalid.
func (s *Store) RevokeAPIKey(vault, keyID string) error {
	idBytes, err := base64.RawURLEncoding.DecodeString(keyID)
	if err != nil || len(idBytes) != 8 {
		return ErrKeyNotFound
	}

	idxKey := apiKeyVaultIdxKey(vault, idBytes)
	storageHash, closer, err := s.db.Get(idxKey)
	if err != nil {
		return ErrKeyNotFound
	}
	hash := make([]byte, 16)
	copy(hash, storageHash)
	closer.Close()

	batch := s.db.NewBatch()
	if err := batch.Delete(apiKeyStorageKey(hash), nil); err != nil {
		batch.Close()
		return err
	}
	if err := batch.Delete(idxKey, nil); err != nil {
		batch.Close()
		return err
	}
	return batch.Commit(pebble.Sync)
}
