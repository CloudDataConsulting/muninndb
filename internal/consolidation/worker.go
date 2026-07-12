package consolidation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/storage"
)

// ErrVaultNotFound identifies a consolidation request for a vault with no
// persisted lifecycle mapping. Corrupt or one-sided mappings are not treated
// as not-found so callers can surface them as storage failures.
var ErrVaultNotFound = errors.New("consolidation vault not found")

// EngineInterface is the minimal engine surface needed by the consolidation worker.
// It avoids circular imports while providing all necessary operations.
type EngineInterface interface {
	// Store returns the underlying PebbleStore for direct storage access
	Store() *storage.PebbleStore
	// ListVaults returns all vault names
	ListVaults(ctx context.Context) ([]string, error)
	// UpdateLifecycleState transitions an engram to a named lifecycle state
	UpdateLifecycleState(ctx context.Context, vault, id, state string) error
}

// Worker is the main consolidation worker that periodically runs a 5-phase
// consolidation pipeline to reduce redundancy and strengthen associations.
type Worker struct {
	Engine        EngineInterface
	Schedule      time.Duration // frequency of consolidation runs (default 6h)
	MaxDedup      int            // max pairs to merge per run (default 100)
	MaxTransitive int            // max inferred edges per run (default 1000)
	DryRun        bool            // if true, no mutations occur
}

// NewWorker creates a new consolidation worker with sensible defaults.
func NewWorker(engine EngineInterface) *Worker {
	return &Worker{
		Engine:        engine,
		Schedule:      6 * time.Hour,
		MaxDedup:      100,
		MaxTransitive: 1000,
		DryRun:        false,
	}
}

// RunOnce executes a single consolidation pass on the specified vault.
// It orchestrates all five phases and returns a report.
func (w *Worker) RunOnce(ctx context.Context, vault string) (*ConsolidationReport, error) {
	report := &ConsolidationReport{
		Vault:     vault,
		StartedAt: time.Now(),
		DryRun:    w.DryRun,
	}

	store := w.Engine.Store()
	wsPrefix, err := store.ResolveExistingVaultPrefix(vault)
	if err != nil {
		if !errors.Is(err, pebble.ErrNotFound) {
			return nil, fmt.Errorf("consolidation: resolve persisted workspace: %w", err)
		}
		// A surviving name index or metadata record means the lifecycle mapping
		// is corrupt, not absent. Preserve that distinction so REST callers only
		// return 404 for a genuinely unknown vault.
		indexExists, indexErr := store.VaultNameIndexExists(vault)
		if indexErr != nil {
			return nil, fmt.Errorf("consolidation: resolve persisted workspace: %w (inspect name index evidence: %v)", err, indexErr)
		}
		if !indexExists {
			// Consult storage directly. Engine-facing ListVaults wrappers may
			// synthesize a default vault when storage is empty or unavailable,
			// which must not change absence-versus-corruption classification.
			vaults, listErr := store.ListVaultNames()
			if listErr != nil {
				return nil, fmt.Errorf("consolidation: resolve persisted workspace: %w (list vaults: %v)", err, listErr)
			}
			listed := false
			for _, name := range vaults {
				if name == vault {
					listed = true
					break
				}
			}
			if !listed {
				return nil, fmt.Errorf("consolidation: vault %q: %w", vault, ErrVaultNotFound)
			}
		}
		return nil, fmt.Errorf("consolidation: resolve persisted workspace: %w", err)
	}

	// Phase 1: Activation Replay
	if err := w.runPhase1Replay(ctx, store, wsPrefix, report); err != nil {
		slog.Warn("consolidation: phase 1 (replay) failed", "vault", vault, "error", err)
		report.Errors = append(report.Errors, "phase1_replay: "+err.Error())
	}

	// Phase 2: Semantic Deduplication
	if err := w.runPhase2Dedup(ctx, store, wsPrefix, report, vault); err != nil {
		slog.Warn("consolidation: phase 2 (dedup) failed", "vault", vault, "error", err)
		report.Errors = append(report.Errors, "phase2_dedup: "+err.Error())
	}

	// Phase 3: Schema Node Promotion
	if err := w.runPhase3SchemaPromotion(ctx, store, wsPrefix, report); err != nil {
		slog.Warn("consolidation: phase 3 (schema promotion) failed", "vault", vault, "error", err)
		report.Errors = append(report.Errors, "phase3_schema_promotion: "+err.Error())
	}

	// Phase 4: Decay Acceleration — disabled. ACT-R computes temporal priority
	// at query time from AccessCount + LastAccess. Background mutation of stored
	// Relevance contradicts the total-recall promise and is no longer needed.

	// Phase 5: Transitive Association Inference
	if err := w.runPhase5TransitiveInference(ctx, store, wsPrefix, report); err != nil {
		slog.Warn("consolidation: phase 5 (transitive inference) failed", "vault", vault, "error", err)
		report.Errors = append(report.Errors, "phase5_transitive_inference: "+err.Error())
	}

	report.Duration = time.Since(report.StartedAt)
	slog.Info("consolidation completed", "vault", vault, "duration", report.Duration,
		"merged", report.MergedEngrams, "promoted", report.PromotedNodes,
		"decayed", report.DecayedEngrams, "inferred", report.InferredEdges)

	return report, nil
}

// safeRunOnce executes RunOnce with panic recovery.
func safeRunOnce(w *Worker, ctx context.Context, vault string) (r *ConsolidationReport, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("consolidation panic: %v", rec)
			slog.Error("consolidation: panic recovered", "vault", vault, "panic", rec)
		}
	}()
	return w.RunOnce(ctx, vault)
}

// Start begins the background scheduler loop.
// It runs consolidation passes on all vaults at the configured Schedule frequency.
// The scheduler stops when ctx is cancelled.
func (w *Worker) Start(ctx context.Context) {
	ticker := time.NewTicker(w.Schedule)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("consolidation scheduler stopped")
			return
		case <-ticker.C:
			vaults, err := w.Engine.ListVaults(ctx)
			if err != nil {
				slog.Warn("consolidation: failed to list vaults", "error", err)
				continue
			}
			for _, vault := range vaults {
				// Run with a timeout to prevent hanging
				runCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
				_, runErr := safeRunOnce(w, runCtx, vault)
				cancel()
				if runErr != nil && ctx.Err() == nil {
					slog.Warn("consolidation: scheduled run failed", "vault", vault, "error", runErr)
				}
			}
		}
	}
}
