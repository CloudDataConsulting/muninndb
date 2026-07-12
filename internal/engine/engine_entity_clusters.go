package engine

import (
	"context"
	"sort"
)

// EntityCluster represents a pair of entities that frequently appear together
// in the same engrams within a vault.
type EntityCluster struct {
	EntityA string
	EntityB string
	Count   int
}

// GetEntityClusters returns entity pairs that co-occur in the same engrams,
// sorted by count descending. Only pairs with count >= minCount are included.
// Results are capped at topN entries.
func (e *Engine) GetEntityClusters(ctx context.Context, vault string, minCount, topN int) ([]EntityCluster, error) {
	ws := e.resolveVaultPrefix(vault)

	var clusters []EntityCluster
	err := e.store.ScanEntityClusters(ctx, ws, minCount, func(nameA, nameB string, count int) error {
		clusters = append(clusters, EntityCluster{
			EntityA: nameA,
			EntityB: nameB,
			Count:   count,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Sort by count descending.
	sort.Slice(clusters, func(i, j int) bool {
		return clusters[i].Count > clusters[j].Count
	})

	// Cap at topN.
	if topN > 0 && len(clusters) > topN {
		clusters = clusters[:topN]
	}

	return clusters, nil
}
