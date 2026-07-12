package trigger

import (
	"sync"
	"time"
)

// SubscriptionRegistry holds all active subscriptions.
type SubscriptionRegistry struct {
	mu         sync.RWMutex
	byID       map[string]*Subscription
	byVault    map[[8]byte][]*Subscription
	vaultCount map[[8]byte]int // O(1) per-vault counter (T3)
	totalCount int             // O(1) global counter (T3)
}

func newRegistry() *SubscriptionRegistry {
	return &SubscriptionRegistry{
		byID:       make(map[string]*Subscription),
		byVault:    make(map[[8]byte][]*Subscription),
		vaultCount: make(map[[8]byte]int),
	}
}

// CountForVault returns the number of active subscriptions for workspace (O(1), T3).
func (r *SubscriptionRegistry) CountForVault(workspace [8]byte) int {
	r.mu.RLock()
	n := r.vaultCount[workspace]
	r.mu.RUnlock()
	return n
}

// CountTotal returns the total number of active subscriptions across all vaults (O(1), T3).
func (r *SubscriptionRegistry) CountTotal() int {
	r.mu.RLock()
	n := r.totalCount
	r.mu.RUnlock()
	return n
}

func (r *SubscriptionRegistry) Add(sub *Subscription, limits ...int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byID[sub.ID]; exists {
		return ErrDuplicateSubscriptionID
	}
	var maxPerVault, maxTotal int
	if len(limits) > 0 {
		maxPerVault = limits[0]
	}
	if len(limits) > 1 {
		maxTotal = limits[1]
	}
	if maxTotal > 0 && r.totalCount >= maxTotal {
		return ErrGlobalSubscriptionLimitReached
	}
	workspace := sub.Workspace
	if maxPerVault > 0 && r.vaultCount[workspace] >= maxPerVault {
		return ErrVaultSubscriptionLimitReached
	}
	r.byID[sub.ID] = sub
	r.byVault[workspace] = append(r.byVault[workspace], sub)
	r.vaultCount[workspace]++
	r.totalCount++
	return nil
}

func (r *SubscriptionRegistry) Remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	sub, ok := r.byID[id]
	if !ok {
		return
	}
	r.removeLocked(sub)
}

func (r *SubscriptionRegistry) removeLocked(sub *Subscription) {
	id := sub.ID
	delete(r.byID, id)
	workspace := sub.Workspace
	subs := r.byVault[workspace]
	for i, s := range subs {
		if s == sub {
			subs[i] = subs[len(subs)-1]
			subs[len(subs)-1] = nil
			subs = subs[:len(subs)-1]
			break
		}
	}
	if len(subs) == 0 {
		delete(r.byVault, workspace)
	} else {
		r.byVault[workspace] = subs
	}
	r.vaultCount[workspace]--
	if r.vaultCount[workspace] == 0 {
		delete(r.vaultCount, workspace)
	}
	r.totalCount--
}

func (r *SubscriptionRegistry) Get(id string) (*Subscription, bool) {
	r.mu.RLock()
	sub, ok := r.byID[id]
	r.mu.RUnlock()
	return sub, ok
}

func (r *SubscriptionRegistry) ForVault(workspace [8]byte) []*Subscription {
	r.mu.RLock()
	subs := r.byVault[workspace]
	if len(subs) == 0 {
		r.mu.RUnlock()
		return nil
	}
	snapshot := make([]*Subscription, len(subs))
	copy(snapshot, subs)
	r.mu.RUnlock()
	return snapshot
}

func (r *SubscriptionRegistry) ActiveVaults() [][8]byte {
	r.mu.RLock()
	vaults := make([][8]byte, 0, len(r.byVault))
	for workspace := range r.byVault {
		vaults = append(vaults, workspace)
	}
	r.mu.RUnlock()
	return vaults
}

func (r *SubscriptionRegistry) PruneExpired() int {
	now := time.Now()
	pruned := 0
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, sub := range r.byID {
		if !sub.expiresAt.IsZero() && now.After(sub.expiresAt) {
			r.removeLocked(sub)
			pruned++
		}
	}
	return pruned
}
