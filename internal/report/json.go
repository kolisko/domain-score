package report

import (
	"encoding/json"

	"github.com/kolisko/domain-score/internal/audit"
)

func JSON(r audit.Report) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
