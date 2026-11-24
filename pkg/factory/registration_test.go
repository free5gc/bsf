package factory_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/free5gc/bsf/pkg/factory"
	"github.com/free5gc/openapi/models"
)

func TestReadConfigPlmnList(t *testing.T) {
	saved := factory.BsfConfig
	t.Cleanup(func() { factory.BsfConfig = saved })
	defaults := []models.PlmnId{{Mcc: "208", Mnc: "93"}}
	tests := []struct {
		name, value string
		want        []models.PlmnId
		wantErr     bool
	}{
		{"custom multiple PLMNs", "[{mcc: '001', mnc: '01'}, {mcc: '001', mnc: '001'}]",
			[]models.PlmnId{{Mcc: "001", Mnc: "01"}, {Mcc: "001", Mnc: "001"}}, false},
		{"omitted after custom config restores default", "", defaults, false},
		{"null keeps default", "null", defaults, false},
		{"empty list", "[]", nil, true},
		{"short MCC", "[{mcc: '01', mnc: '01'}]", nil, true},
		{"long MCC", "[{mcc: '0001', mnc: '01'}]", nil, true},
		{"non-digit MCC", "[{mcc: '0a1', mnc: '01'}]", nil, true},
		{"short MNC", "[{mcc: '001', mnc: '1'}]", nil, true},
		{"long MNC", "[{mcc: '001', mnc: '0001'}]", nil, true},
		{"non-digit MNC", "[{mcc: '001', mnc: '0a'}]", nil, true},
		{"missing MNC", "[{mcc: '001'}]", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := "configuration:\n"
			if tt.value != "" {
				input += "  plmnList: " + tt.value + "\n"
			} else {
				input += "  bsfName: bsf\n"
			}
			path := filepath.Join(t.TempDir(), "bsfcfg.yaml")
			if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
				t.Fatal(err)
			}
			previous := factory.BsfConfig
			cfg, err := factory.ReadConfig(path)
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "plmnList") {
					t.Fatalf("expected plmnList error, got %v", err)
				}
				if factory.BsfConfig != previous {
					t.Fatal("invalid config replaced the active config")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := cfg.GetPlmnList()
			if !slices.Equal(got, tt.want) {
				t.Fatalf("PLMNs = %v, want %v", got, tt.want)
			}
			got[0].Mcc = "999"
			if !slices.Equal(cfg.GetPlmnList(), tt.want) {
				t.Fatal("caller mutated configured or default PLMNs")
			}
		})
	}
}
