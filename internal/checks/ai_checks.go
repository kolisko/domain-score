package checks

import (
	"context"
	"strings"

	"github.com/kolisko/domain-score/internal/audit"
)

type AILLMsTxt struct{}
type AIRobotsAI struct{}
type AIStructuredData struct{}
type AIExtractableText struct{}
type AICanonicalContent struct{}
type AIDocsFAQSignals struct{}

func (AILLMsTxt) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "ai.llms_txt", Title: "llms.txt", Category: "ai_optimization", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityLow, Tags: []string{"ai", "llms"}}
}
func (c AILLMsTxt) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if ev.LLMs.StatusCode != 200 {
		return warn(c.Meta(), map[string]any{"status": ev.LLMs.StatusCode}, "Publikujte `/llms.txt` se stručným popisem a odkazy na důležité zdroje pro AI asistenty.", 2)
	}
	return pass(c.Meta(), map[string]any{"url": ev.LLMs.URL}, "")
}

func (AIRobotsAI) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "ai.robots_ai_crawlers", Title: "AI crawleři v robots.txt", Category: "ai_optimization", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityInfo, Tags: []string{"ai", "robots"}}
}
func (c AIRobotsAI) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	body := strings.ToLower(ev.Robots.Body)
	for _, agent := range []string{"gptbot", "chatgpt-user", "claudebot", "perplexitybot", "google-extended"} {
		if strings.Contains(body, agent) {
			return pass(c.Meta(), map[string]any{"matched_agent": agent}, "")
		}
	}
	return warn(c.Meta(), nil, "Zvažte explicitní robots politiku pro AI crawlery podle obchodního cíle webu.", 1)
}

func (AIStructuredData) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "ai.structured_data", Title: "Strukturovaná data pro modely", Category: "ai_optimization", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityMedium, Tags: []string{"ai", "schema.org"}}
}
func (c AIStructuredData) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if ev.HTTP.JSONLDCount == 0 {
		return warn(c.Meta(), nil, "Přidejte schema.org JSON-LD pro jednoznačné pochopení obsahu.", 2)
	}
	return pass(c.Meta(), map[string]any{"json_ld_count": ev.HTTP.JSONLDCount}, "")
}

func (AIExtractableText) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "ai.extractable_text", Title: "Extrahovatelný text", Category: "ai_optimization", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityMedium, Tags: []string{"ai", "content"}}
}
func (c AIExtractableText) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	textLen := len(strings.TrimSpace(stripTagsApprox(ev.HTTP.Body)))
	if textLen < 500 {
		return warn(c.Meta(), map[string]any{"text_length": textLen}, "Zajistěte, aby klíčový obsah existoval v serverem doručeném HTML, ne pouze po JS renderingu.", 2)
	}
	return pass(c.Meta(), map[string]any{"text_length": textLen}, "")
}

func (AICanonicalContent) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "ai.canonical_content", Title: "Kanonický obsah", Category: "ai_optimization", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityLow, Tags: []string{"ai", "seo"}}
}
func (c AICanonicalContent) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.HTTP.Links["canonical"]) == 0 {
		return warn(c.Meta(), nil, "AI modelům i vyhledávačům pomáhá jednoznačný canonical signál.", 1)
	}
	return pass(c.Meta(), map[string]any{"canonical": ev.HTTP.Links["canonical"]}, "")
}

func (AIDocsFAQSignals) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "ai.docs_faq_signals", Title: "Docs/FAQ signály", Category: "ai_optimization", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityInfo, Tags: []string{"ai", "content"}}
}
func (c AIDocsFAQSignals) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	body := strings.ToLower(ev.HTTP.Body)
	if strings.Contains(body, "faq") || strings.Contains(body, "documentation") || strings.Contains(body, "docs") || strings.Contains(body, "otázky") {
		return pass(c.Meta(), nil, "")
	}
	return warn(c.Meta(), nil, "Zvažte veřejnou dokumentaci, FAQ nebo znalostní bázi pro lepší citovatelnost a odpovědi modelů.", 1)
}

func stripTagsApprox(in string) string {
	var out strings.Builder
	inTag := false
	for _, r := range in {
		switch r {
		case '<':
			inTag = true
		case '>':
			inTag = false
			out.WriteRune(' ')
		default:
			if !inTag {
				out.WriteRune(r)
			}
		}
	}
	return out.String()
}
