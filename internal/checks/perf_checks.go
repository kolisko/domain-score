package checks

import (
	"context"
	"strings"
	"time"

	"github.com/kolisko/domain-score/internal/audit"
)

type PerfTTFB struct{}
type PerfHTMLSize struct{}
type PerfCompression struct{}
type PerfCacheHeaders struct{}
type PerfViewport struct{}
type PerfLanguage struct{}
type PerfImageAlt struct{}
type PerfLandmarks struct{}

func (PerfTTFB) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "performance.ttfb", Title: "TTFB", Category: "performance", Mode: audit.ModeSafe, Weight: 4, Severity: audit.SeverityMedium, Tags: []string{"performance"}}
}
func (c PerfTTFB) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if ev.HTTP.TTFB > 1500*time.Millisecond {
		return warn(c.Meta(), map[string]any{"ttfb_ms": ev.HTTP.TTFBMillis}, "Zkraťte TTFB optimalizací backendu, cache nebo CDN.", 3)
	}
	return pass(c.Meta(), map[string]any{"ttfb_ms": ev.HTTP.TTFBMillis}, "")
}

func (PerfHTMLSize) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "performance.html_size", Title: "Velikost HTML", Category: "performance", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityLow, Tags: []string{"performance"}}
}
func (c PerfHTMLSize) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if ev.HTTP.BodySize > 500_000 {
		return warn(c.Meta(), map[string]any{"body_size": ev.HTTP.BodySize}, "Zmenšete počáteční HTML payload.", 2)
	}
	return pass(c.Meta(), map[string]any{"body_size": ev.HTTP.BodySize}, "")
}

func (PerfCompression) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "performance.compression", Title: "HTTP compression", Category: "performance", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityLow, Tags: []string{"performance", "headers"}}
}
func (c PerfCompression) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	encoding := strings.ToLower(headerValue(ev.HTTP.Headers, "Content-Encoding"))
	if encoding == "" {
		return warn(c.Meta(), nil, "Zapněte gzip, br nebo zstd kompresi pro textové odpovědi.", 2)
	}
	return pass(c.Meta(), map[string]any{"content_encoding": encoding}, "")
}

func (PerfCacheHeaders) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "performance.cache_headers", Title: "Cache headers", Category: "performance", Mode: audit.ModeSafe, Weight: 3, Severity: audit.SeverityLow, Tags: []string{"performance", "headers"}}
}
func (c PerfCacheHeaders) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if !hasHeader(ev.HTTP.Headers, "Cache-Control") && !hasHeader(ev.HTTP.Headers, "ETag") {
		return warn(c.Meta(), nil, "Nastavte `Cache-Control` a/nebo `ETag` podle typu obsahu.", 2)
	}
	return pass(c.Meta(), map[string]any{"cache_control": headerValue(ev.HTTP.Headers, "Cache-Control"), "etag": headerValue(ev.HTTP.Headers, "ETag")}, "")
}

func (PerfViewport) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "performance.viewport", Title: "Mobile viewport", Category: "performance", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityLow, Tags: []string{"ux", "mobile"}}
}
func (c PerfViewport) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if ev.HTTP.Meta["viewport"] == "" {
		return warn(c.Meta(), nil, "Doplňte responsive viewport meta tag.", 1)
	}
	return pass(c.Meta(), map[string]any{"viewport": ev.HTTP.Meta["viewport"]}, "")
}

func (PerfLanguage) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "performance.language", Title: "HTML lang", Category: "performance", Mode: audit.ModeSafe, Weight: 1, Severity: audit.SeverityInfo, Tags: []string{"accessibility", "seo"}}
}
func (c PerfLanguage) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if ev.HTTP.Language == "" {
		return warn(c.Meta(), nil, "Nastavte `lang` atribut na elementu `<html>`.", 1)
	}
	return pass(c.Meta(), map[string]any{"language": ev.HTTP.Language}, "")
}

func (PerfImageAlt) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "performance.image_alt", Title: "Alt texty obrázků", Category: "performance", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityLow, Tags: []string{"accessibility"}}
}
func (c PerfImageAlt) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if ev.HTTP.ImagesMissingAlt > 0 {
		return warn(c.Meta(), map[string]any{"images_total": ev.HTTP.ImagesTotal, "missing_alt": ev.HTTP.ImagesMissingAlt}, "Doplňte `alt` texty u významových obrázků.", 1)
	}
	return pass(c.Meta(), map[string]any{"images_total": ev.HTTP.ImagesTotal}, "")
}

func (PerfLandmarks) Meta() audit.CheckMeta {
	return audit.CheckMeta{ID: "performance.landmarks", Title: "HTML landmarks", Category: "performance", Mode: audit.ModeSafe, Weight: 2, Severity: audit.SeverityLow, Tags: []string{"accessibility"}}
}
func (c PerfLandmarks) Run(_ context.Context, _ audit.Target, ev audit.SharedEvidence) audit.Result {
	if ev.HTTP.LandmarkCount == 0 {
		return warn(c.Meta(), nil, "Použijte sémantické landmark elementy jako `main`, `nav`, `header`, `footer`.", 1)
	}
	return pass(c.Meta(), map[string]any{"landmarks": ev.HTTP.LandmarkCount}, "")
}
