package report

import (
	"sort"
	"strings"

	"github.com/kolisko/domain-score/internal/audit"
)

const (
	SortWeight   = "weight"
	SortStatus   = "status"
	SortCategory = "category"
	SortID       = "id"
	SortNone     = "none"
)

func sortedResults(results []audit.Result, mode string) []audit.Result {
	out := append([]audit.Result(nil), results...)
	switch normalizeSort(mode) {
	case SortNone:
		return out
	case SortStatus:
		sort.SliceStable(out, func(i, j int) bool {
			left, right := statusRank(out[i].Status), statusRank(out[j].Status)
			if left != right {
				return left < right
			}
			return fallbackLess(out[i], out[j])
		})
	case SortCategory:
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].Category != out[j].Category {
				return out[i].Category < out[j].Category
			}
			return fallbackLess(out[i], out[j])
		})
	case SortID:
		sort.SliceStable(out, func(i, j int) bool {
			return out[i].CheckID < out[j].CheckID
		})
	default:
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].Weight != out[j].Weight {
				return out[i].Weight > out[j].Weight
			}
			if out[i].ScoreImpact != out[j].ScoreImpact {
				return out[i].ScoreImpact > out[j].ScoreImpact
			}
			return fallbackLess(out[i], out[j])
		})
	}
	return out
}

func normalizeSort(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", SortWeight, "weight_desc", "weight-desc":
		return SortWeight
	case SortStatus, "severity":
		return SortStatus
	case SortCategory:
		return SortCategory
	case SortID, "check", "check_id", "check-id":
		return SortID
	case SortNone, "original":
		return SortNone
	default:
		return SortWeight
	}
}

func IsSortMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", SortWeight, "weight_desc", "weight-desc", SortStatus, "severity", SortCategory, SortID, "check", "check_id", "check-id", SortNone, "original":
		return true
	default:
		return false
	}
}

func statusRank(status audit.Status) int {
	switch status {
	case audit.StatusFail:
		return 0
	case audit.StatusError:
		return 1
	case audit.StatusWarn:
		return 2
	case audit.StatusPass:
		return 3
	case audit.StatusNotApplicable:
		return 4
	default:
		return 5
	}
}

func fallbackLess(left audit.Result, right audit.Result) bool {
	if left.Category != right.Category {
		return left.Category < right.Category
	}
	return left.CheckID < right.CheckID
}
