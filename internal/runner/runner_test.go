package runner

import (
	"context"
	"testing"

	"github.com/kolisko/domain-score/internal/audit"
)

type fakeCheck struct {
	meta audit.CheckMeta
}

func (f fakeCheck) Meta() audit.CheckMeta { return f.meta }
func (f fakeCheck) Run(context.Context, audit.Target, audit.SharedEvidence) audit.Result {
	return audit.Result{CheckID: f.meta.ID, Category: f.meta.Category, Status: audit.StatusPass, Weight: f.meta.Weight}
}

func TestSelectSkipsAggressiveByDefault(t *testing.T) {
	checks := []audit.Check{
		fakeCheck{meta: audit.CheckMeta{ID: "safe.one", Mode: audit.ModeSafe, Weight: 1}},
		fakeCheck{meta: audit.CheckMeta{ID: "aggressive.one", Mode: audit.ModeAggressive, Weight: 1}},
	}
	got, err := Select(checks, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Meta().ID != "safe.one" {
		t.Fatalf("selected %#v", got)
	}
}

func TestSelectEnablesAggressiveExplicitly(t *testing.T) {
	checks := []audit.Check{
		fakeCheck{meta: audit.CheckMeta{ID: "safe.one", Mode: audit.ModeSafe, Weight: 1}},
		fakeCheck{meta: audit.CheckMeta{ID: "aggressive.one", Mode: audit.ModeAggressive, Weight: 1}},
	}
	got, err := Select(checks, Options{Enable: []string{"aggressive.one"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("selected %d checks, want 2", len(got))
	}
}

func TestSelectWeightOverrides(t *testing.T) {
	checks := []audit.Check{fakeCheck{meta: audit.CheckMeta{ID: "safe.one", Mode: audit.ModeSafe, Weight: 1}}}
	got, err := Select(checks, Options{WeightsYAML: []byte("weights:\n  safe.one: 7\n")})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Meta().Weight != 7 {
		t.Fatalf("weight = %d, want 7", got[0].Meta().Weight)
	}
}
