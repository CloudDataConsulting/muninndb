package vaultjob

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestJobManager_Create_ReturnsJob(t *testing.T) {
	m := NewManager()
	j, err := m.Create("clone", "src", "dst")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if j == nil {
		t.Fatal("expected non-nil job")
	}
	if j.ID == "" {
		t.Error("job ID should not be empty")
	}
	if j.GetStatus() != StatusRunning {
		t.Errorf("expected status Running, got %q", j.GetStatus())
	}
	if j.GetPhase() != PhaseCopying {
		t.Errorf("expected phase Copying, got %q", j.GetPhase())
	}
}

func TestJobManager_Get_Found(t *testing.T) {
	m := NewManager()
	j, _ := m.Create("merge", "a", "b")
	got, ok := m.Get(j.ID)
	if !ok {
		t.Fatal("expected to find job by ID")
	}
	if got.ID != j.ID {
		t.Errorf("wrong job returned")
	}
}

func TestJobManager_Get_NotFound(t *testing.T) {
	m := NewManager()
	_, ok := m.Get("nonexistent-job-id")
	if ok {
		t.Error("expected not found for unknown job ID")
	}
}

func TestJobManager_MaxConcurrent_Rejects(t *testing.T) {
	m := NewManager()
	// Fill up to the limit
	for i := 0; i < maxConcurrentJobs; i++ {
		_, err := m.Create("clone", "src", fmt.Sprintf("dst-%d", i))
		if err != nil {
			t.Fatalf("unexpected error at job %d: %v", i, err)
		}
	}
	// Next create should fail
	_, err := m.Create("clone", "src", "overflow")
	if err == nil {
		t.Error("expected error when exceeding maxConcurrentJobs")
	}
}

func TestJobManager_Complete_SetsStatusDone(t *testing.T) {
	m := NewManager()
	j, _ := m.Create("clone", "src", "dst")
	m.Complete(j)
	if j.GetStatus() != StatusDone {
		t.Errorf("expected StatusDone, got %q", j.GetStatus())
	}
	if j.GetPhase() != PhaseDone {
		t.Errorf("expected PhaseDone, got %q", j.GetPhase())
	}
	if j.GetCompletedAt().IsZero() {
		t.Error("expected CompletedAt to be set")
	}
}

func TestJobManager_Fail_SetsStatusError(t *testing.T) {
	m := NewManager()
	j, _ := m.Create("merge", "a", "b")
	m.Fail(j, errors.New("something went wrong"))
	if j.GetStatus() != StatusError {
		t.Errorf("expected StatusError, got %q", j.GetStatus())
	}
	if j.GetErr() == "" {
		t.Error("expected error message to be set")
	}
}

func TestJob_Pct_BothPhases(t *testing.T) {
	j := &Job{CopyTotal: 100, IndexTotal: 100}
	j.CopyCurrent.Store(50)
	j.IndexCurrent.Store(25)
	pct := j.Pct()
	expected := 37.5
	if pct != expected {
		t.Errorf("expected %.1f%%, got %.1f%%", expected, pct)
	}
}

func TestJob_Pct_ZeroTotal(t *testing.T) {
	j := &Job{}
	if pct := j.Pct(); pct != 0 {
		t.Errorf("expected 0%% for zero total, got %.1f%%", pct)
	}
}

func TestJob_Snapshot_ReflectsCurrentState(t *testing.T) {
	m := NewManager()
	j, _ := m.Create("clone", "src", "dst")
	j.CopyTotal = 100
	j.CopyCurrent.Store(30)

	snap := j.Snapshot()
	if snap.JobID != j.ID {
		t.Errorf("snapshot job ID mismatch")
	}
	if snap.CopyCurrent != 30 {
		t.Errorf("expected CopyCurrent=30, got %d", snap.CopyCurrent)
	}
	if snap.Status != "running" {
		t.Errorf("expected status=running, got %q", snap.Status)
	}
	if snap.ElapsedMs < 0 {
		t.Error("elapsed should be non-negative")
	}
}

func TestJobManager_RunningCountDecrement(t *testing.T) {
	m := NewManager()
	j1, _ := m.Create("clone", "src", "dst1")
	j2, _ := m.Create("clone", "src", "dst2")
	m.mu.Lock()
	before := m.running
	m.mu.Unlock()

	m.Complete(j1)
	m.Fail(j2, errors.New("err"))

	m.mu.Lock()
	after := m.running
	m.mu.Unlock()

	if before != 2 {
		t.Errorf("expected 2 running before, got %d", before)
	}
	if after != 0 {
		t.Errorf("expected 0 running after, got %d", after)
	}
}

func TestJobManager_HasActiveJobInvolvingChecksSourceAndTarget(t *testing.T) {
	m := NewManager()
	defer m.Close()
	job, err := m.Create("merge", "source-vault", "target-vault")
	if err != nil {
		t.Fatal(err)
	}

	if !m.HasActiveJobInvolving("source-vault") {
		t.Fatal("running job source was not reported as involved")
	}
	if !m.HasActiveJobInvolving("target-vault") {
		t.Fatal("running job target was not reported as involved")
	}
	if m.HasActiveJobInvolving("unrelated-vault") {
		t.Fatal("unrelated vault was reported as involved")
	}

	m.Complete(job)
	if m.HasActiveJobInvolving("source-vault") || m.HasActiveJobInvolving("target-vault") {
		t.Fatal("completed job still blocks vault rename")
	}
}

func TestJobManager_Close_Idempotent(t *testing.T) {
	m := NewManager()
	// First Close must not panic.
	m.Close()
	// Second Close must also not panic (sync.Once guard).
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Close() panicked on second call: %v", r)
		}
	}()
	m.Close()
}

// Ensure the unused time import doesn't cause issues — used in Snapshot test implicitly.
var _ = time.Now
