package consumer_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	bsfContext "github.com/free5gc/bsf/internal/context"
	"github.com/free5gc/bsf/internal/sbi/consumer"
	"github.com/free5gc/bsf/pkg/factory"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/nrf/NFDisc"
)

type testConsumerBsf struct {
	ctx *bsfContext.BSFContext
}

func (b *testConsumerBsf) Config() *factory.Config         { return nil }
func (b *testConsumerBsf) Context() *bsfContext.BSFContext { return b.ctx }
func (b *testConsumerBsf) CancelContext() context.Context  { return context.Background() }

func newTestConsumer(t *testing.T, uri string) (*consumer.Consumer, *bsfContext.BSFContext) {
	t.Helper()
	ctx := &bsfContext.BSFContext{NfId: "bsf-id", NrfUri: uri, UriScheme: "http"}
	original := bsfContext.BsfSelf
	bsfContext.BsfSelf = ctx
	t.Cleanup(func() { bsfContext.BsfSelf = original })
	c, err := consumer.NewConsumer(&testConsumerBsf{ctx: ctx})
	if err != nil {
		t.Fatal(err)
	}
	return c, ctx
}

func newNRFServer(handler http.HandlerFunc) *httptest.Server {
	server := httptest.NewUnstartedServer(handler)
	server.Config.Protocols = &http.Protocols{}
	server.Config.Protocols.SetHTTP1(true)
	server.Config.Protocols.SetUnencryptedHTTP2(true)
	server.Start()
	return server
}

func TestSendRegisterNFInstance(t *testing.T) {
	tests := []struct {
		name         string
		customInfo   interface{}
		location     bool
		initialOAuth bool
		wantOAuth    bool
	}{
		{"enabled", map[string]interface{}{"oauth2": true}, true, false, true},
		{"disabled", map[string]interface{}{"oauth2": false}, true, true, false},
		{"absent", nil, true, true, false},
		{"invalid custom info", "unexpected", true, false, false},
		{"invalid flag", map[string]interface{}{"oauth2": "true"}, true, false, false},
		{"update preserves setting", nil, false, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newNRFServer(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPut || r.URL.Path != "/nnrf-nfm/v1/nf-instances/bsf-id" {
					t.Errorf("unexpected registration: %s %s", r.Method, r.URL.Path)
				}
				var request models.Nrf_NFMgmt_NFProfile
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Errorf("decode registration: %v", err)
				}
				if request.NfInstanceId != "bsf-id" || request.NfType != models.Nrf_NFMgmt_NFType_BSF {
					t.Errorf("unexpected registration profile: %+v", request)
				}
				w.Header().Set("Content-Type", "application/json")
				status := http.StatusOK
				if tt.location {
					w.Header().Set("Location", "/nnrf-nfm/v1/nf-instances/assigned-id")
					status = http.StatusCreated
				}
				w.WriteHeader(status)
				profile := models.Nrf_NFMgmt_NFProfile{NfInstanceId: "assigned-id", CustomInfo: tt.customInfo}
				if err := json.NewEncoder(w).Encode(profile); err != nil {
					t.Errorf("encode registration: %v", err)
				}
			})
			defer server.Close()
			c, ctx := newTestConsumer(t, server.URL)
			ctx.OAuth2Required = tt.initialOAuth
			ctx.NrfCertPem = "nrf.pem"
			requestCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			profile, nfID, err := c.SendRegisterNFInstance(requestCtx)
			if err != nil {
				t.Fatal(err)
			}
			if profile == nil || profile.NfInstanceId != "assigned-id" {
				t.Fatalf("unexpected response profile: %+v", profile)
			}
			wantID := ""
			if tt.location {
				wantID = "assigned-id"
			}
			if nfID != wantID || ctx.OAuth2Required != tt.wantOAuth {
				t.Errorf("NF ID = %q, OAuth2 = %v; want %q, %v", nfID, ctx.OAuth2Required, wantID, tt.wantOAuth)
			}
		})
	}
}

func TestNRFOAuthRequests(t *testing.T) {
	var tokenScopes []string
	var discoveryCalled, deregisterCalled bool
	server := newNRFServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == "/oauth2/token" {
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse token request: %v", err)
			}
			if r.Form.Get("nfType") != "BSF" || r.Form.Get("targetNfType") != "NRF" ||
				r.Form.Get("nfInstanceId") != "bsf-id" || r.Form.Get("grant_type") != "client_credentials" {
				t.Errorf("unexpected token request: %v", r.Form)
			}
			tokenScopes = append(tokenScopes, r.Form.Get("scope"))
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-token", "token_type": "Bearer", "expires_in": 60,
			}); err != nil {
				t.Errorf("encode token: %v", err)
			}
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected Authorization: %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/nnrf-disc/v1/nf-instances":
			discoveryCalled = true
			if r.URL.Query().Get("target-nf-type") != "PCF" || r.URL.Query().Get("requester-nf-type") != "BSF" {
				t.Errorf("unexpected discovery parameters: %s", r.URL.RawQuery)
			}
			result := models.Nrf_NFDisc_SearchResult{
				NfInstances: []models.Nrf_NFDisc_NFProfile{{NfInstanceId: "pcf-id"}},
			}
			if err := json.NewEncoder(w).Encode(result); err != nil {
				t.Errorf("encode discovery: %v", err)
			}
		case r.Method == http.MethodDelete && r.URL.Path == "/nnrf-nfm/v1/nf-instances/bsf-id":
			deregisterCalled = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected NRF request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer server.Close()
	c, ctx := newTestConsumer(t, server.URL)
	ctx.OAuth2Required = true
	result, err := c.SendSearchNFInstances(server.URL, models.Nrf_NFMgmt_NFType_PCF,
		models.Nrf_NFMgmt_NFType_BSF, &NFDisc.SearchNFInstancesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || len(result.NfInstances) != 1 || result.NfInstances[0].NfInstanceId != "pcf-id" {
		t.Fatalf("unexpected discovery result: %+v", result)
	}
	if _, deregisterErr := c.SendDeregisterNFInstance(); deregisterErr != nil {
		t.Fatal(deregisterErr)
	}
	if !discoveryCalled || !deregisterCalled || len(tokenScopes) != 2 ||
		tokenScopes[0] != "nnrf-disc" || tokenScopes[1] != "nnrf-nfm" {
		t.Errorf("discovery = %v, deregister = %v, scopes = %v", discoveryCalled, deregisterCalled, tokenScopes)
	}
}
