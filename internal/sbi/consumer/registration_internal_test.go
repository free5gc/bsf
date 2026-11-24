package consumer

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/h2non/gock"

	"github.com/free5gc/bsf/pkg/factory"
	"github.com/free5gc/openapi/models"
)

func TestRegisterConfiguredPlmns(t *testing.T) {
	saved := factory.BsfConfig
	t.Cleanup(func() { factory.BsfConfig = saved })
	for _, custom := range []bool{false, true} {
		name, input := "legacy default", "configuration: {}\n"
		want := []models.PlmnId{{Mcc: "208", Mnc: "93"}}
		if custom {
			name = "configured PLMNs"
			input = "configuration:\n  plmnList: [{mcc: '001', mnc: '01'}, {mcc: '001', mnc: '001'}]\n"
			want = []models.PlmnId{{Mcc: "001", Mnc: "01"}, {Mcc: "001", Mnc: "001"}}
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bsfcfg.yaml")
			if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := factory.ReadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			c := newNrfTestConsumer(t)
			c.Context().PlmnList = cfg.GetPlmnList()
			gock.New(testNrfUri).Put(testNfIdPath).
				AddMatcher(func(req *http.Request, _ *gock.Request) (bool, error) {
					var profile models.Nrf_NFMgmt_NFProfile
					if decodeErr := json.NewDecoder(req.Body).Decode(&profile); decodeErr != nil {
						return false, decodeErr
					}
					return slices.Equal(profile.PlmnList, want), nil
				}).Reply(http.StatusCreated).JSON(nfProfileJSON(15))
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			if _, err = c.SendRegisterNFInstance(ctx); err != nil {
				t.Fatal(err)
			}
			if !gock.IsDone() {
				t.Fatal("NRF did not receive the configured registration PLMNs")
			}
		})
	}
}
