package checks

import "github.com/kolisko/domain-score/internal/audit"

func pass(meta audit.CheckMeta, evidence map[string]any, recommendation string) audit.Result {
	return result(meta, audit.StatusPass, evidence, recommendation, 0, "")
}

func warn(meta audit.CheckMeta, evidence map[string]any, recommendation string, impact int) audit.Result {
	return result(meta, audit.StatusWarn, evidence, recommendation, impact, "")
}

func fail(meta audit.CheckMeta, evidence map[string]any, recommendation string, impact int) audit.Result {
	return result(meta, audit.StatusFail, evidence, recommendation, impact, "")
}

func notApplicable(meta audit.CheckMeta, evidence map[string]any, recommendation string) audit.Result {
	return result(meta, audit.StatusNotApplicable, evidence, recommendation, 0, "")
}

func checkError(meta audit.CheckMeta, err error, evidence map[string]any) audit.Result {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return result(meta, audit.StatusError, evidence, "Zkontrolujte dostupnost cíle a spusťte audit znovu.", 0, msg)
}

func result(meta audit.CheckMeta, status audit.Status, evidence map[string]any, recommendation string, impact int, err string) audit.Result {
	return audit.Result{
		CheckID:        meta.ID,
		Title:          meta.Title,
		Category:       meta.Category,
		Mode:           meta.Mode,
		Status:         status,
		Severity:       meta.Severity,
		Weight:         meta.Weight,
		ScoreImpact:    impact,
		Evidence:       evidence,
		Recommendation: recommendation,
		Error:          err,
	}
}

func hasHeader(headers map[string][]string, name string) bool {
	if headers == nil {
		return false
	}
	_, ok := headers[name]
	if ok {
		return true
	}
	for k := range headers {
		if equalFold(k, name) {
			return true
		}
	}
	return false
}

func headerValue(headers map[string][]string, name string) string {
	for k, vals := range headers {
		if equalFold(k, name) && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
