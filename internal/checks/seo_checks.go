package checks

import (
	"context"
	"strings"

	"github.com/kolisko/domain-score/internal/audit"
)

type SEOStatus struct{}
type SEOTitle struct{}
type SEODescription struct{}
type SEOCanonical struct{}
type SEORobots struct{}
type SEOSitemap struct{}
type SEOHreflang struct{}
type SEOHeadings struct{}
type SEOMetaRobots struct{}
type SEOOpenGraph struct{}
type SEOJSONLD struct{}

func (SEOStatus) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "seo.status", Title: "Hlavní stránka vrací úspěšný status", Category: "seo", Mode: audit.ModeSafe, Weight: 5, Severity: audit.SeverityHigh, Tags: []string{"seo"}}
}
func (c SEOStatus) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if ev.HTTP.StatusCode < 200 || ev.HTTP.StatusCode >= 400 {
		return fail(c.Meta(), map[string]any{"status": ev.HTTP.StatusCode}, "Hlavní URL musí vracet 2xx/3xx bez chyb.", c.Meta().Weight)
	}
	return pass(c.Meta(), map[string]any{"status": ev.HTTP.StatusCode, "url": ev.HTTP.FinalURL}, "")
}

func (SEOTitle) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "seo.title", Title: "HTML title", Category: "seo", Mode: audit.ModeSafe, Weight: 4, Severity: audit.SeverityMedium, Tags: []string{"seo"}}
}
func (c SEOTitle) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	l := len(strings.TrimSpace(ev.HTTP.Title))
	if l == 0 {
		return fail(c.Meta(), nil, "Doplňte unikátní `<title>`.", c.Meta().Weight)
	}
	if l < 10 || l > 70 {
		return warn(c.Meta(), map[string]any{"title": ev.HTTP.Title, "length": l}, "Udržujte title přibližně v rozsahu 10-70 znaků.", 2)
	}
	return pass(c.Meta(), map[string]any{"title": ev.HTTP.Title}, "")
}

func (SEODescription) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "seo.description", Title: "Meta description", Category: "seo", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityMedium, Tags: []string{"seo"}}
}
func (c SEODescription) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	desc := ev.HTTP.Meta["description"]
	if strings.TrimSpace(desc) == "" {
		return warn(c.Meta(), nil, "Doplňte popis stránky přes `meta name=\"description\"`.", 2)
	}
	return pass(c.Meta(), map[string]any{"description": desc}, "")
}

func (SEOCanonical) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "seo.canonical", Title: "Canonical URL", Category: "seo", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityMedium, Tags: []string{"seo"}}
}
func (c SEOCanonical) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	canon := ev.HTTP.Links["canonical"]
	if len(canon) == 0 {
		return warn(c.Meta(), nil, "Přidejte `rel=canonical` pro jasný kanonický obsah.", 2)
	}
	return pass(c.Meta(), map[string]any{"canonical": canon}, "")
}

func (SEORobots) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "seo.robots_txt", Title: "robots.txt", Category: "seo", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityLow, Tags: []string{"seo", "crawler"}}
}
func (c SEORobots) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if ev.Robots.StatusCode != 200 {
		return warn(c.Meta(), map[string]any{"status": ev.Robots.StatusCode}, "Publikujte robots.txt i když jen s minimální politikou.", 1)
	}
	return pass(c.Meta(), map[string]any{"url": ev.Robots.URL}, "")
}

func (SEOSitemap) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "seo.sitemap", Title: "Sitemap", Category: "seo", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityMedium, Tags: []string{"seo", "crawler"}}
}
func (c SEOSitemap) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if ev.Sitemap.StatusCode != 200 {
		return warn(c.Meta(), map[string]any{"status": ev.Sitemap.StatusCode}, "Publikujte `sitemap.xml` nebo ji odkažte v robots.txt.", 2)
	}
	return pass(c.Meta(), map[string]any{"url": ev.Sitemap.URL}, "")
}

func (SEOHreflang) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "seo.hreflang", Title: "Hreflang signály", Category: "seo", Mode: audit.ModeSafe, Weight: 1, Severity: audit.SeverityInfo, Tags: []string{"seo", "i18n"}}
}
func (c SEOHreflang) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.HTTP.Links["alternate"]) == 0 {
		return warn(c.Meta(), nil, "U vícejazyčného webu doplňte `hreflang`; pro jednojazyčný web je to informativní upozornění.", 1)
	}
	return pass(c.Meta(), map[string]any{"alternate": ev.HTTP.Links["alternate"]}, "")
}

func (SEOHeadings) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "seo.headings", Title: "Struktura nadpisů", Category: "seo", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityMedium, Tags: []string{"seo", "accessibility"}}
}
func (c SEOHeadings) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if len(ev.HTTP.Headings["h1"]) == 0 {
		return warn(c.Meta(), nil, "Doplňte jeden jasný H1 nadpis.", 2)
	}
	return pass(c.Meta(), map[string]any{"h1": ev.HTTP.Headings["h1"]}, "")
}

func (SEOMetaRobots) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "seo.meta_robots", Title: "Meta robots neblokuje indexaci", Category: "seo", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityMedium, Tags: []string{"seo"}}
}
func (c SEOMetaRobots) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	robots := strings.ToLower(ev.HTTP.Meta["robots"])
	if strings.Contains(robots, "noindex") {
		return fail(c.Meta(), map[string]any{"robots": robots}, "Odstraňte `noindex`, pokud má být stránka indexovatelná.", c.Meta().Weight)
	}
	return pass(c.Meta(), map[string]any{"robots": robots}, "")
}

func (SEOOpenGraph) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "seo.open_graph", Title: "OpenGraph/Twitter metadata", Category: "seo", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityLow, Tags: []string{"seo", "social"}}
}
func (c SEOOpenGraph) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if ev.HTTP.Meta["og:title"] == "" && ev.HTTP.Meta["twitter:title"] == "" {
		return warn(c.Meta(), nil, "Doplňte OpenGraph nebo Twitter metadata pro sdílení.", 1)
	}
	return pass(c.Meta(), map[string]any{"og_title": ev.HTTP.Meta["og:title"], "twitter_title": ev.HTTP.Meta["twitter:title"]}, "")
}

func (SEOJSONLD) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "seo.json_ld", Title: "JSON-LD strukturovaná data", Category: "seo", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityMedium, Tags: []string{"seo", "structured-data"}}
}
func (c SEOJSONLD) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if ev.HTTP.JSONLDCount == 0 {
		return warn(c.Meta(), nil, "Přidejte JSON-LD strukturovaná data podle typu webu.", 2)
	}
	return pass(c.Meta(), map[string]any{"json_ld_count": ev.HTTP.JSONLDCount}, "")
}
