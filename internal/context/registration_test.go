package context_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	bsf_context "github.com/free5gc/bsf/internal/context"
	"github.com/free5gc/bsf/pkg/factory"
	"github.com/free5gc/openapi/models"
)

func TestConfiguredPlmnsReachNFProfile(t *testing.T) {
	savedConfig, savedSelf := factory.BsfConfig, bsf_context.BsfSelf
	t.Cleanup(func() { factory.BsfConfig, bsf_context.BsfSelf = savedConfig, savedSelf })
	for _, custom := range []bool{false, true} {
		name := "legacy default"
		plmns := ""
		want := []models.PlmnId{{Mcc: "208", Mnc: "93"}}
		if custom {
			name = "configured PLMNs"
			plmns = "  plmnList: [{mcc: '001', mnc: '01'}, {mcc: '001', mnc: '001'}]\n"
			want = []models.PlmnId{{Mcc: "001", Mnc: "01"}, {Mcc: "001", Mnc: "001"}}
		}
		t.Run(name, func(t *testing.T) {
			input := "info: {version: '1.0.0'}\nconfiguration:\n" + plmns +
				"  sbi: {scheme: http, registerIPv4: 127.0.0.8, bindingIPv4: 127.0.0.8, port: 8000}\n"
			path := filepath.Join(t.TempDir(), "bsfcfg.yaml")
			if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := factory.ReadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			bsf_context.BsfSelf = &bsf_context.BSFContext{}
			bsf_context.InitBsfContext()
			// Changing the source config after initialization must not mutate the context.
			if custom {
				cfg.Configuration.PlmnList[0].Mcc = "999"
			}
			profile := bsf_context.BsfSelf.GetBsfProfile()
			wire, err := json.Marshal(profile)
			if err != nil {
				t.Fatal(err)
			}
			var registered models.Nrf_NFMgmt_NFProfile
			if err = json.Unmarshal(wire, &registered); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(registered.PlmnList, want) {
				t.Fatalf("registration PLMNs = %v, want %v", registered.PlmnList, want)
			}
			profile.PlmnList[0].Mcc = "888"
			if !slices.Equal(bsf_context.BsfSelf.GetBsfProfile().PlmnList, want) {
				t.Fatal("profile aliases context PLMNs")
			}
		})
	}
}
