package catalog

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed data/*.yaml
var embedded embed.FS

type Catalog struct {
	Checks       []Check
	Mappings     []Mapping
	SourceCounts []SourceCount
	Access       []SourceAccess
	Evidence     []SourceEvidence
	Resolver     *Resolver
}

type Check struct {
	ID                 string `yaml:"id"`
	Title              string `yaml:"title"`
	Category           string `yaml:"category"`
	Mode               string `yaml:"mode"`
	Severity           string `yaml:"severity"`
	Weight             int    `yaml:"weight"`
	CoverageStatus     string `yaml:"coverage_status"`
	ImplementedBy      any    `yaml:"implemented_by"`
	FindingCardinality string `yaml:"finding_cardinality"`
	Rationale          string `yaml:"rationale"`
	Remediation        string `yaml:"remediation"`
}

type Mapping struct {
	Source      string `yaml:"source"`
	MatchType   string `yaml:"match_type"`
	SourceID    string `yaml:"source_id"`
	CanonicalID string `yaml:"canonical_id"`
	Confidence  string `yaml:"confidence"`
}

type SourceCount struct {
	Source          string `yaml:"source"`
	Path            string `yaml:"path"`
	IndexType       string `yaml:"index_type"`
	Count           int    `yaml:"count"`
	AtomicIDPattern string `yaml:"atomic_id_pattern"`
}

type SourceAccess struct {
	ID                string   `yaml:"id"`
	Title             string   `yaml:"title"`
	Access            string   `yaml:"access"`
	LocalRunnable     any      `yaml:"local_runnable"`
	APIKeyRequired    bool     `yaml:"api_key_required"`
	PaidRequired      bool     `yaml:"paid_required"`
	GeneratedCatalogs []string `yaml:"generated_catalogs"`
	IncludedByDefault bool     `yaml:"included_by_default"`
	Notes             []string `yaml:"notes"`
}

type SourceEvidence struct {
	ID                  string   `yaml:"id"`
	Title               string   `yaml:"title"`
	AccessClass         string   `yaml:"access_class"`
	ResearchStatus      string   `yaml:"research_status"`
	EvidenceTypes       []string `yaml:"evidence_types"`
	SourceURLs          []string `yaml:"source_urls"`
	GeneratedCatalogs   []string `yaml:"generated_catalogs"`
	DerivedCheckSurface []string `yaml:"derived_check_surface"`
	Exclusions          []string `yaml:"exclusions"`
}

type Match struct {
	CanonicalID string
	Confidence  string
	SourceID    string
	MatchType   string
}

type Resolver struct {
	bySource map[string][]Mapping
}

func LoadEmbedded() (*Catalog, error) {
	return load(embedded)
}

func load(files fs.FS) (*Catalog, error) {
	checks, err := loadChecks(files)
	if err != nil {
		return nil, err
	}
	mappings, err := loadMappings(files)
	if err != nil {
		return nil, err
	}
	sourceCounts, err := loadManifest(files)
	if err != nil {
		return nil, err
	}
	access, err := loadAccess(files)
	if err != nil {
		return nil, err
	}
	evidence, err := loadEvidence(files)
	if err != nil {
		return nil, err
	}
	sort.Slice(checks, func(i, j int) bool { return checks[i].ID < checks[j].ID })
	sort.Slice(sourceCounts, func(i, j int) bool {
		if sourceCounts[i].Source == sourceCounts[j].Source {
			return sourceCounts[i].Path < sourceCounts[j].Path
		}
		return sourceCounts[i].Source < sourceCounts[j].Source
	})
	return &Catalog{
		Checks:       checks,
		Mappings:     mappings,
		SourceCounts: sourceCounts,
		Access:       access,
		Evidence:     evidence,
		Resolver:     NewResolver(mappings),
	}, nil
}

func (c *Catalog) FindCheck(id string) (Check, bool) {
	for _, check := range c.Checks {
		if check.ID == id {
			return check, true
		}
	}
	return Check{}, false
}

func (c *Catalog) ChecksForTools(tools []string) []Check {
	want := map[string]bool{}
	for _, tool := range tools {
		tool = strings.TrimSpace(tool)
		if tool != "" {
			want[tool] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	out := []Check{}
	for _, check := range c.Checks {
		for _, tool := range check.ToolNames() {
			if want[tool] {
				out = append(out, check)
				break
			}
		}
	}
	return out
}

func (c *Catalog) SourceAccessByID(id string) (SourceAccess, bool) {
	for _, source := range c.Access {
		if source.ID == id {
			return source, true
		}
	}
	return SourceAccess{}, false
}

func (c Check) InternalCheckIDs() []string {
	return implementedStringList(c.ImplementedBy, "internal_check_ids")
}

func (c Check) InternalResultIDs() []string {
	return implementedStringList(c.ImplementedBy, "internal_results")
}

func (c Check) ToolNames() []string {
	return implementedStringList(c.ImplementedBy, "tools")
}

func (c Check) SourceLabels() []string {
	labels := []string{}
	for _, id := range c.InternalCheckIDs() {
		labels = append(labels, "internal:"+id)
	}
	for _, id := range c.InternalResultIDs() {
		labels = append(labels, "internal:"+id)
	}
	for _, tool := range c.ToolNames() {
		labels = append(labels, "tool:"+tool)
	}
	return labels
}

func implementedStringList(value any, key string) []string {
	m, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	raw, ok := m[key]
	if !ok {
		return nil
	}
	out := []string{}
	switch vals := raw.(type) {
	case []any:
		for _, val := range vals {
			if s := strings.TrimSpace(fmt.Sprint(val)); s != "" {
				out = append(out, s)
			}
		}
	case []string:
		for _, val := range vals {
			if s := strings.TrimSpace(val); s != "" {
				out = append(out, s)
			}
		}
	case string:
		if s := strings.TrimSpace(vals); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func NewResolver(mappings []Mapping) *Resolver {
	bySource := map[string][]Mapping{}
	for _, mapping := range mappings {
		bySource[mapping.Source] = append(bySource[mapping.Source], mapping)
	}
	for source := range bySource {
		sort.SliceStable(bySource[source], func(i, j int) bool {
			return mappingRank(bySource[source][i]) < mappingRank(bySource[source][j])
		})
	}
	return &Resolver{bySource: bySource}
}

func (r *Resolver) Resolve(source string, sourceRuleID string, groups ...string) (Match, bool) {
	if r == nil {
		return Match{}, false
	}
	source = strings.TrimSpace(source)
	sourceRuleID = strings.TrimSpace(sourceRuleID)
	for _, mapping := range r.bySource[source] {
		switch mapping.MatchType {
		case "exact":
			if sourceRuleID == mapping.SourceID {
				return mapping.toMatch(), true
			}
		case "prefix":
			if strings.HasPrefix(sourceRuleID, mapping.SourceID) {
				return mapping.toMatch(), true
			}
		case "group", "stream":
			for _, group := range groups {
				group = strings.Trim(strings.TrimSpace(group), "/")
				if group == mapping.SourceID || strings.HasPrefix(group, strings.Trim(mapping.SourceID, "/")+"/") {
					return mapping.toMatch(), true
				}
			}
		}
	}
	return Match{}, false
}

func (m Mapping) toMatch() Match {
	return Match{
		CanonicalID: m.CanonicalID,
		Confidence:  m.Confidence,
		SourceID:    m.SourceID,
		MatchType:   m.MatchType,
	}
}

func mappingRank(mapping Mapping) int {
	switch mapping.MatchType {
	case "exact":
		return 0
	case "group", "stream":
		return 1
	case "prefix":
		return 2
	default:
		return 3
	}
}

func loadChecks(files fs.FS) ([]Check, error) {
	var doc struct {
		Checks []Check `yaml:"checks"`
	}
	if err := readYAML(files, "data/atomic-checks.yaml", &doc); err != nil {
		return nil, err
	}
	return doc.Checks, nil
}

func loadMappings(files fs.FS) ([]Mapping, error) {
	var doc struct {
		Mappings []Mapping `yaml:"mappings"`
	}
	if err := readYAML(files, "data/source-to-canonical-map.yaml", &doc); err != nil {
		return nil, err
	}
	return doc.Mappings, nil
}

func loadManifest(files fs.FS) ([]SourceCount, error) {
	var doc struct {
		Sources []SourceCount `yaml:"sources"`
	}
	if err := readYAML(files, "data/source-catalog-manifest.yaml", &doc); err != nil {
		return nil, err
	}
	return doc.Sources, nil
}

func loadAccess(files fs.FS) ([]SourceAccess, error) {
	var doc struct {
		Sources []SourceAccess `yaml:"sources"`
	}
	if err := readYAML(files, "data/source-access-policy.yaml", &doc); err != nil {
		return nil, err
	}
	return doc.Sources, nil
}

func loadEvidence(files fs.FS) ([]SourceEvidence, error) {
	var doc struct {
		Sources []SourceEvidence `yaml:"sources"`
	}
	if err := readYAML(files, "data/source-research-evidence.yaml", &doc); err != nil {
		return nil, err
	}
	return doc.Sources, nil
}

func readYAML(files fs.FS, path string, out any) error {
	data, err := fs.ReadFile(files, path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, out); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func FindRepoCatalogDir(start string) (string, bool) {
	if start == "" {
		start, _ = os.Getwd()
	}
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", false
	}
	for {
		candidate := filepath.Join(dir, "catalog")
		if _, err := os.Stat(filepath.Join(candidate, "atomic-checks.yaml")); err == nil {
			return candidate, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}
