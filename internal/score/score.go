package score

import "github.com/kolisko/domain-score/internal/audit"

func Calculate(results []audit.Result) audit.ScoreSummary {
	cats := map[string]audit.CategoryScore{}
	for _, r := range results {
		if r.Status == audit.StatusNotApplicable || r.Status == audit.StatusError {
			continue
		}
		cs := cats[r.Category]
		cs.Checks++
		cs.TotalWeight += r.Weight
		switch r.Status {
		case audit.StatusPass:
			cs.PassedWeight += r.Weight
		case audit.StatusWarn:
			cs.PassedWeight += max(0, r.Weight-r.ScoreImpact)
		case audit.StatusFail:
			cs.PassedWeight += max(0, r.Weight-r.ScoreImpact)
		}
		cats[r.Category] = cs
	}
	total := 0
	passed := 0
	for category, cs := range cats {
		if cs.TotalWeight == 0 {
			cs.Score = 100
		} else {
			cs.Score = clamp((cs.PassedWeight * 100) / cs.TotalWeight)
		}
		cats[category] = cs
		total += cs.TotalWeight
		passed += cs.PassedWeight
	}
	overall := 100
	if total > 0 {
		overall = clamp((passed * 100) / total)
	} else if len(results) > 0 {
		return audit.ScoreSummary{Overall: 0, Grade: "N/A", Categories: cats}
	}
	return audit.ScoreSummary{Overall: overall, Grade: grade(overall), Categories: cats}
}

func grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func clamp(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
