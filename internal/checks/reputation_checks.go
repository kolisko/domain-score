package checks

import (
	"context"

	"github.com/kolisko/domain-score/internal/audit"
)

type ReputationSpamhausDBL struct{}
type ReputationSURBL struct{}
type ReputationURLHaus struct{}
type ReputationVirusTotal struct{}

func (ReputationSpamhausDBL) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "reputation.spamhaus_dbl", Title: "Spamhaus DBL reputace", Category: "reputation", Mode: audit.ModeSafe, Weight: 4, Severity: audit.SeverityHigh, Tags: []string{"reputation", "spamhaus"}}
}

func (c ReputationSpamhausDBL) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	r := ev.Reputation.SpamhausDBL
	if r.Listed {
		return fail(c.Meta(), map[string]any{"status": r.Status, "categories": r.Categories}, "Doména je uvedená ve Spamhaus DBL; prověřte kompromitaci, phishing/spam abuse a požádejte o delisting po nápravě.", c.Meta().Weight)
	}
	return pass(c.Meta(), map[string]any{"status": r.Status}, "")
}

func (ReputationSURBL) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "reputation.surbl", Title: "SURBL reputace", Category: "reputation", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityHigh, Tags: []string{"reputation", "surbl"}}
}

func (c ReputationSURBL) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	r := ev.Reputation.SURBL
	if r.Listed {
		return fail(c.Meta(), map[string]any{"status": r.Status, "categories": r.Categories}, "Doména je uvedená v SURBL; prověřte spam/malware/phishing reputaci.", c.Meta().Weight)
	}
	return pass(c.Meta(), map[string]any{"status": r.Status}, "")
}

func (ReputationURLHaus) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "reputation.urlhaus", Title: "URLhaus malware/phishing reputace", Category: "reputation", Mode: audit.ModeSafe, Weight: 4, Severity: audit.SeverityHigh, Tags: []string{"reputation", "malware", "phishing"}}
}

func (c ReputationURLHaus) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	r := ev.Reputation.URLHaus
	if r.Error != "" {
		return warn(c.Meta(), map[string]any{"error": r.Error}, "URLhaus public API nebylo možné ověřit; audit zopakujte později.", 1)
	}
	if r.Listed {
		return fail(c.Meta(), map[string]any{"status": r.Status, "categories": r.Categories}, "URLhaus eviduje host jako škodlivý nebo kompromitovaný; prověřte incident a reputační delisting.", c.Meta().Weight)
	}
	return pass(c.Meta(), map[string]any{"status": r.Status}, "")
}

func (ReputationVirusTotal) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "reputation.virustotal", Title: "VirusTotal reputace", Category: "reputation", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityMedium, Tags: []string{"reputation", "virustotal"}}
}

func (c ReputationVirusTotal) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	r := ev.Reputation.VirusTotal
	if !r.Checked {
		return notApplicable(c.Meta(), map[string]any{"status": r.Status, "note": r.Error}, "VirusTotal nemá veřejné no-key API pro lokální CLI; konkurence ho může volat přes vlastní backendový účet.")
	}
	if r.Listed {
		return fail(c.Meta(), map[string]any{"malicious": r.Score}, "VirusTotal hlásí malicious detekce; prověřte reputaci a kompromitaci.", c.Meta().Weight)
	}
	return pass(c.Meta(), map[string]any{"malicious": r.Score, "status": r.Status}, "")
}
