package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cockroachdb/pebble"
)

// RevokeVaultAPIKeys atomically revokes every well-formed API-key record and
// index bound to vault. It reconciles both directions so a valid unindexed
// 0x12 record cannot survive and authorize a later same-name lifecycle.
//
// This is name-bound containment, not a durable lifecycle identity or a
// process-independent write fence. Namespace migration remains separate work.
func (s *Store) RevokeVaultAPIKeys(vault string) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	batch := s.db.NewBatch()
	defer batch.Close()
	if err := s.stageVaultAPIKeyRevocations(batch, vault); err != nil {
		return err
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return fmt.Errorf("revoke vault API keys: commit: %w", err)
	}
	return nil
}

// DeleteVaultLifecycle atomically revokes the vault's API-key records and
// indexes and deletes its auth config. Corrupt or mismatched auth records abort
// before the Sync batch commits.
func (s *Store) DeleteVaultLifecycle(vault string) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	batch := s.db.NewBatch()
	defer batch.Close()
	if err := s.stageVaultAPIKeyRevocations(batch, vault); err != nil {
		return err
	}
	if err := batch.Delete(vaultConfigKey(vault), nil); err != nil {
		return fmt.Errorf("delete vault lifecycle: stage config delete: %w", err)
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return fmt.Errorf("delete vault lifecycle: commit: %w", err)
	}
	return nil
}

type lifecycleAPIKeyRecord struct {
	key  APIKey
	hash [16]byte
}

func (s *Store) stageVaultAPIKeyRevocations(batch *pebble.Batch, vault string) error {
	targetRecords := make(map[[16]byte]lifecycleAPIKeyRecord)

	recordIter, err := s.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte{prefixAPIKey},
		UpperBound: []byte{prefixAPIKey + 1},
	})
	if err != nil {
		return fmt.Errorf("delete vault lifecycle: scan API-key records: %w", err)
	}
	for valid := recordIter.First(); valid; valid = recordIter.Next() {
		keyBytes := recordIter.Key()
		// Storage coherence records share 0x12 and are exactly nine bytes.
		if len(keyBytes) == 9 {
			continue
		}
		if len(keyBytes) != 17 {
			recordIter.Close()
			return fmt.Errorf("delete vault lifecycle: malformed API-key storage key length %d", len(keyBytes))
		}
		var hash [16]byte
		copy(hash[:], keyBytes[1:])
		record, err := decodeLifecycleAPIKeyRecord(hash, recordIter.Value())
		if err != nil {
			recordIter.Close()
			return fmt.Errorf("delete vault lifecycle: %w", err)
		}
		if record.key.Vault == vault {
			targetRecords[hash] = record
		}
	}
	if err := recordIter.Error(); err != nil {
		recordIter.Close()
		return fmt.Errorf("delete vault lifecycle: scan API-key records: %w", err)
	}
	recordIter.Close()

	indexIter, err := s.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte{prefixAPIKeyVIdx},
		UpperBound: []byte{prefixAPIKeyVIdx + 1},
	})
	if err != nil {
		return fmt.Errorf("delete vault lifecycle: scan API-key indexes: %w", err)
	}
	for valid := indexIter.First(); valid; valid = indexIter.Next() {
		indexKey := indexIter.Key()
		// Storage vault-weight records share 0x13 and are exactly nine bytes.
		if len(indexKey) == 9 {
			continue
		}
		indexVault, indexID, err := decodeVaultAPIKeyIndex(indexKey, indexIter.Value())
		if err != nil {
			indexIter.Close()
			return fmt.Errorf("delete vault lifecycle: %w", err)
		}

		var hash [16]byte
		copy(hash[:], indexIter.Value())
		data, closer, err := s.db.Get(apiKeyStorageKey(hash[:]))
		if err != nil {
			indexIter.Close()
			if errors.Is(err, pebble.ErrNotFound) {
				return fmt.Errorf("delete vault lifecycle: API-key index for vault %q references a missing record", indexVault)
			}
			return fmt.Errorf("delete vault lifecycle: read indexed API-key record: %w", err)
		}
		record, decodeErr := decodeLifecycleAPIKeyRecord(hash, data)
		closer.Close()
		if decodeErr != nil {
			indexIter.Close()
			return fmt.Errorf("delete vault lifecycle: %w", decodeErr)
		}
		if record.key.Vault != indexVault {
			indexIter.Close()
			return fmt.Errorf("delete vault lifecycle: API-key index vault %q mismatches record vault %q", indexVault, record.key.Vault)
		}
		if !bytes.Equal(indexID, hash[:8]) {
			indexIter.Close()
			return fmt.Errorf("delete vault lifecycle: API-key index ID does not match record hash for vault %q", indexVault)
		}

		if indexVault == vault {
			indexKeyCopy := append([]byte(nil), indexKey...)
			if err := batch.Delete(indexKeyCopy, nil); err != nil {
				indexIter.Close()
				return fmt.Errorf("delete vault lifecycle: stage index delete: %w", err)
			}
			targetRecords[hash] = record
		}
	}
	if err := indexIter.Error(); err != nil {
		indexIter.Close()
		return fmt.Errorf("delete vault lifecycle: scan API-key indexes: %w", err)
	}
	indexIter.Close()

	for hash := range targetRecords {
		if err := batch.Delete(apiKeyStorageKey(hash[:]), nil); err != nil {
			return fmt.Errorf("delete vault lifecycle: stage API-key record delete: %w", err)
		}
	}
	return nil
}

func decodeLifecycleAPIKeyRecord(hash [16]byte, data []byte) (lifecycleAPIKeyRecord, error) {
	var key APIKey
	if err := json.Unmarshal(data, &key); err != nil {
		return lifecycleAPIKeyRecord{}, fmt.Errorf("corrupt API-key record: %w", err)
	}
	if len(key.StorageHash) != len(hash) || !bytes.Equal(key.StorageHash, hash[:]) {
		return lifecycleAPIKeyRecord{}, fmt.Errorf("API-key record storage hash mismatch")
	}
	id, err := base64.RawURLEncoding.DecodeString(key.ID)
	if err != nil || len(id) != 8 || !bytes.Equal(id, hash[:8]) {
		return lifecycleAPIKeyRecord{}, fmt.Errorf("API-key record display ID mismatch")
	}
	return lifecycleAPIKeyRecord{key: key, hash: hash}, nil
}

func decodeVaultAPIKeyIndex(key, value []byte) (string, []byte, error) {
	if len(key) < 10 {
		return "", nil, fmt.Errorf("malformed API-key vault index key length %d", len(key))
	}
	separator := len(key) - 9
	if key[0] != prefixAPIKeyVIdx || key[separator] != 0x00 {
		return "", nil, fmt.Errorf("malformed API-key vault index layout")
	}
	if len(value) != 16 {
		return "", nil, fmt.Errorf("malformed API-key vault index value length %d", len(value))
	}
	indexID := append([]byte(nil), key[separator+1:]...)
	return string(key[1:separator]), indexID, nil
}
