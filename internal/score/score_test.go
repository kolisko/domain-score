package score

import (
	"testing"

	"github.com/kolisko/domain-score/internal/audit"
)

func TestCalculateScoresWarnAndFailImpact(t *testing.T) {
	got := Calculate([]audit.Result{
		{Category: "dns", Status: audit.StatusPass, Weight: 5},
		{Category: "dns", Status: audit.StatusWarn, Weight: 5, ScoreImpact: 2},
		{Category: "tls", Status: audit.StatusFail, Weight: 10, ScoreImpact: 10},
		{Category: "tls", Status: audit.StatusError, Weight: 10},
	})
	if got.Categories["dns"].Score != 80 {
		t.Fatalf("dns score = %d, want 80", got.Categories["dns"].Score)
	}
	if got.Categories["tls"].Score != 0 {
		t.Fatalf("tls score = %d, want 0", got.Categories["tls"].Score)
	}
	if got.Overall != 40 {
		t.Fatalf("overall = %d, want 40", got.Overall)
	}
	if got.Grade != "F" {
		t.Fatalf("grade = %s, want F", got.Grade)
	}
}
