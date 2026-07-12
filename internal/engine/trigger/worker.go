package trigger

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/scrypster/muninndb/internal/storage"
)

// DeliveryRouter sends pushes to client connections.
type DeliveryRouter struct {
	registry *SubscriptionRegistry
}

// Send delivers a push to a subscription's connection.
func (d *DeliveryRouter) Send(sub *Subscription, push *ActivationPush) {
	sub.mu.Lock()
	push.PushNumber = sub.pushCount + 1
	deliverFn := sub.Deliver
	sub.mu.Unlock()

	if deliverFn == nil {
		return
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Warn("trigger: delivery panic recovered", "panic", r)
				d.registry.Remove(sub.ID)
			}
		}()
		baseCtx := sub.RequestContext
		if baseCtx == nil {
			baseCtx = context.Background()
		}
		ctx, cancel := context.WithTimeout(baseCtx, deliverTimeout)
		defer cancel()
		err := deliverFn(ctx, push)
		if err != nil {
			d.registry.Remove(sub.ID)
		}
	}()
}

type subscriptionReadContext struct {
	context.Context
	values context.Context
}

func (c subscriptionReadContext) Value(key any) any {
	if c.values != nil {
		if value := c.values.Value(key); value != nil {
			return value
		}
	}
	return c.Context.Value(key)
}

func readContextForSubscription(workerCtx context.Context, sub *Subscription) context.Context {
	if sub == nil {
		return workerCtx
	}
	ctx := context.Context(workerCtx)
	if sub.RequestContext != nil {
		ctx = subscriptionReadContext{Context: workerCtx, values: sub.RequestContext}
	}
	if sub.PassiveReads {
		ctx = storage.ContextWithPassiveReads(ctx)
	}
	return ctx
}

func subscriptionsWithPassiveMode(subs []*Subscription, passive bool) []*Subscription {
	filtered := make([]*Subscription, 0, len(subs))
	for _, sub := range subs {
		if sub != nil && sub.PassiveReads == passive {
			filtered = append(filtered, sub)
		}
	}
	return filtered
}

// TriggerWorker is the shared event loop for all subscriptions.
type TriggerWorker struct {
	registry   *SubscriptionRegistry
	embedCache *EmbedCache
	store      TriggerStore
	fts        FTSIndex
	hnsw       HNSWIndex
	embedder   Embedder
	deliver    *DeliveryRouter

	writeEvents  <-chan *EngramEvent
	cogEvents    <-chan CognitiveEvent
	contraEvents <-chan ContradictEvent
}

// Run starts the trigger event loop.
func (w *TriggerWorker) Run(ctx context.Context) error {
	sweep := time.NewTicker(sweepInterval)
	defer sweep.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case event, ok := <-w.contraEvents:
			if !ok {
				return nil
			}
			w.handleContradiction(ctx, event)

		case event, ok := <-w.writeEvents:
			if !ok {
				return nil
			}
			w.handleWrite(ctx, event)

		case event, ok := <-w.cogEvents:
			if !ok {
				return nil
			}
			w.handleCognitive(ctx, event)

		case <-sweep.C:
			w.handleSweep(ctx)
			w.registry.PruneExpired()
		}
	}
}

func (w *TriggerWorker) handleWrite(ctx context.Context, event *EngramEvent) {
	if !event.IsNew {
		return
	}
	subs := w.registry.ForVault(event.Workspace)
	if len(subs) == 0 {
		return
	}

	engramVec := event.Engram.Embedding

	for _, sub := range subs {
		if !sub.PushOnWrite {
			continue
		}
		sub.mu.Lock()
		subVec := sub.embedding
		sub.mu.Unlock()

		// When either the engram or the subscription has no embedding, fall back
		// to vectorScore=0. TriggerScore will still fire for Threshold=0 subs
		// using decay, recency, and confidence components. This ensures
		// PushOnWrite delivers even for engrams that have not yet been embedded.
		var vectorScore float64
		if len(subVec) > 0 && len(engramVec) > 0 {
			vectorScore = cosineSimilarity(subVec, engramVec)
		}

		meta := engramToMeta(event.Engram)
		score, above := TriggerScore(sub, meta, vectorScore, 0)
		if !above {
			continue
		}

		// T4: rate-limit write pushes before delivery.
		if !sub.rateLimiter.TryConsume() {
			continue
		}

		w.deliver.Send(sub, &ActivationPush{
			SubscriptionID: sub.ID,
			Engram:         event.Engram,
			Score:          score,
			Trigger:        TriggerNewWrite,
			At:             time.Now(),
		})

		sub.mu.Lock()
		sub.pushedScores[event.Engram.ID] = score
		sub.pushCount++
		sub.mu.Unlock()
	}
}

func (w *TriggerWorker) handleCognitive(ctx context.Context, event CognitiveEvent) {
	workspace := event.Workspace
	subs := w.registry.ForVault(workspace)
	if len(subs) == 0 {
		return
	}

	ws := workspace
	for _, passive := range []bool{false, true} {
		modeSubs := subscriptionsWithPassiveMode(subs, passive)
		if len(modeSubs) == 0 {
			continue
		}
		metas, err := w.store.GetMetadata(readContextForSubscription(ctx, modeSubs[0]), ws, []storage.ULID{event.EngramID})
		if err != nil || len(metas) == 0 || metas[0] == nil {
			continue
		}
		meta := metas[0]

		for _, sub := range modeSubs {
			sub.mu.Lock()
			subVec := sub.embedding
			lastScore := sub.pushedScores[event.EngramID]
			sub.mu.Unlock()

			score, above := TriggerScore(sub, meta, cosineSimilarity(subVec, nil), 0)
			if !above {
				if lastScore > 0 {
					sub.mu.Lock()
					delete(sub.pushedScores, event.EngramID)
					sub.mu.Unlock()
				}
				continue
			}

			delta := math.Abs(score - lastScore)
			if lastScore > 0 && delta < sub.DeltaThreshold {
				continue
			}

			if !sub.rateLimiter.TryConsume() {
				continue
			}

			w.deliver.Send(sub, &ActivationPush{
				SubscriptionID: sub.ID,
				Score:          score,
				Trigger:        TriggerThresholdCrossed,
				At:             time.Now(),
			})

			sub.mu.Lock()
			sub.pushedScores[event.EngramID] = score
			sub.pushCount++
			sub.mu.Unlock()
		}
	}
}

func (w *TriggerWorker) handleContradiction(ctx context.Context, event ContradictEvent) {
	workspace := event.Workspace
	subs := w.registry.ForVault(workspace)
	if len(subs) == 0 {
		return
	}

	ws := workspace
	for _, passive := range []bool{false, true} {
		modeSubs := subscriptionsWithPassiveMode(subs, passive)
		if len(modeSubs) == 0 {
			continue
		}
		engrams, err := w.store.GetEngrams(readContextForSubscription(ctx, modeSubs[0]), ws, []storage.ULID{event.EngramA, event.EngramB})
		if err != nil || len(engrams) == 0 {
			continue
		}
		byID := make(map[storage.ULID]*storage.Engram, 2)
		for _, eng := range engrams {
			if eng != nil {
				byID[eng.ID] = eng
			}
		}

		for _, sub := range modeSubs {
			sub.mu.Lock()
			_, aWasPushed := sub.pushedScores[event.EngramA]
			_, bWasPushed := sub.pushedScores[event.EngramB]
			sub.mu.Unlock()

			if !aWasPushed && !bWasPushed {
				continue
			}

			// T5: contradiction events use burst-aware rate limiting (overdraft 3).
			if !sub.rateLimiter.TryConsumeOrBurst(3) {
				continue
			}

			for _, id := range []storage.ULID{event.EngramA, event.EngramB} {
				eng := byID[id]
				if eng == nil || eng.State == storage.StateSoftDeleted {
					continue
				}
				w.deliver.Send(sub, &ActivationPush{
					SubscriptionID: sub.ID,
					Engram:         eng,
					Score:          1.0,
					Trigger:        TriggerContradiction,
					Why:            fmt.Sprintf("contradiction detected (severity %.0f%%, type: %s)", event.Severity*100, event.Type),
					At:             time.Now(),
				})
			}
		}
	}
}

func (w *TriggerWorker) handleSweep(ctx context.Context) {
	workspaces := w.registry.ActiveVaults()
	for _, workspace := range workspaces {
		subs := w.registry.ForVault(workspace)
		if len(subs) == 0 {
			continue
		}
		w.sweepWorkspace(ctx, workspace, subs)
	}
}

func (w *TriggerWorker) sweepWorkspace(ctx context.Context, ws [8]byte, subs []*Subscription) {
	if w.hnsw == nil {
		return
	}

	type vecGroup struct {
		vec  []float32
		subs []*Subscription
	}
	type vecGroupKey struct {
		fingerprint [32]byte
		passive     bool
	}
	groups := make(map[vecGroupKey]*vecGroup)

	for _, sub := range subs {
		sub.mu.Lock()
		vec := sub.embedding
		subCtx := sub.Context
		sub.mu.Unlock()

		if len(vec) == 0 {
			if w.embedder != nil {
				computed, err := w.embedder.Embed(ctx, subCtx)
				if err != nil {
					continue
				}
				sub.mu.Lock()
				sub.embedding = computed
				vec = computed
				sub.mu.Unlock()
			}
		}

		if len(vec) == 0 {
			continue
		}

		key := vecGroupKey{fingerprint: contextFingerprint(subCtx), passive: sub.PassiveReads}
		if g, ok := groups[key]; ok {
			g.subs = append(g.subs, sub)
		} else {
			groups[key] = &vecGroup{vec: vec, subs: []*Subscription{sub}}
		}
	}

	for _, group := range groups {
		readCtx := readContextForSubscription(ctx, group.subs[0])
		candidates, err := w.hnsw.Search(readCtx, ws, group.vec, sweepTopK)
		if err != nil {
			slog.Warn("trigger: hnsw search failed in sweep", "workspace", ws, "err", err)
			continue
		}
		if len(candidates) == 0 {
			continue
		}

		ids := make([]storage.ULID, len(candidates))
		for i, c := range candidates {
			ids[i] = c.ID
		}
		metas, err := w.store.GetMetadata(readCtx, ws, ids)
		if err != nil {
			slog.Warn("trigger: GetMetadata failed in sweep", "workspace", ws, "err", err)
			continue
		}
		metaByID := make(map[storage.ULID]*storage.EngramMeta, len(metas))
		for _, m := range metas {
			if m != nil {
				metaByID[m.ID] = m
			}
		}

		vecScores := make(map[storage.ULID]float64, len(candidates))
		for _, c := range candidates {
			vecScores[c.ID] = c.Score
		}

		// Batch-load all candidate engrams in a single call before entering the
		// subscription loop — avoids N×M individual store calls (N subs × M candidates).
		allEngrams, err := w.store.GetEngrams(readCtx, ws, ids)
		if err != nil {
			slog.Warn("trigger: GetEngrams failed in sweep", "workspace", ws, "err", err)
			allEngrams = nil
		}
		engramByID := make(map[storage.ULID]*storage.Engram, len(allEngrams))
		for _, eng := range allEngrams {
			if eng != nil {
				engramByID[eng.ID] = eng
			}
		}

		for _, sub := range group.subs {
			for _, c := range candidates {
				meta := metaByID[c.ID]
				if meta == nil || meta.State == storage.StateSoftDeleted {
					continue
				}

				score, above := TriggerScore(sub, meta, vecScores[c.ID], 0)
				if !above {
					continue
				}

				sub.mu.Lock()
				lastScore := sub.pushedScores[c.ID]
				delta := math.Abs(score - lastScore)
				rateLimitOK := sub.rateLimiter.TryConsume()
				sub.mu.Unlock()

				if lastScore > 0 && delta < sub.DeltaThreshold {
					continue
				}
				if !rateLimitOK {
					continue
				}

				eng := engramByID[c.ID]
				if eng == nil || eng.State == storage.StateSoftDeleted {
					continue
				}

				w.deliver.Send(sub, &ActivationPush{
					SubscriptionID: sub.ID,
					Engram:         eng,
					Score:          score,
					Trigger:        TriggerThresholdCrossed,
					At:             time.Now(),
				})

				sub.mu.Lock()
				sub.pushedScores[c.ID] = score
				sub.pushCount++
				sub.mu.Unlock()
			}
		}
	}
}
