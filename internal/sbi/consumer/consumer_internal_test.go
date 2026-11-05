package consumer

import (
	"context"
	"testing"

	"github.com/h2non/gock"

	bsfContext "github.com/free5gc/bsf/internal/context"
	"github.com/free5gc/bsf/pkg/factory"
	"github.com/free5gc/openapi"
)

const (
	testNrfUri   = "http://127.0.0.10:8000"
	testNfId     = "6ba7b810-9dad-41d1-80b4-00c04fd430c8"
	testNfIdPath = "/nnrf-nfm/v1/nf-instances/" + testNfId
)

type testBsf struct {
	cfg *factory.Config
	ctx *bsfContext.BSFContext
}

func (b *testBsf) Config() *factory.Config         { return b.cfg }
func (b *testBsf) Context() *bsfContext.BSFContext { return b.ctx }
func (b *testBsf) CancelContext() context.Context  { return context.Background() }

// newNrfTestConsumer builds a Consumer over a private BSF context pointed at the test NRF and intercepts the
// openapi cleartext HTTP/2 client with gock.
func newNrfTestConsumer(t *testing.T) *Consumer {
	t.Helper()

	c, err := NewConsumer(&testBsf{
		cfg: &factory.Config{Configuration: &factory.Configuration{}},
		ctx: &bsfContext.BSFContext{NfId: testNfId, NrfUri: testNrfUri},
	})
	if err != nil {
		t.Fatalf("NewConsumer: %v", err)
	}

	openapi.InterceptInnerHttp2Client(t, false)
	t.Cleanup(gock.OffAll)
	return c
}

// nfProfileJSON is an NRF NF profile reply body. It omits heartBeatTimer when timer is 0.
func nfProfileJSON(timer int32) map[string]any {
	body := map[string]any{
		"nfInstanceId": testNfId,
		"nfType":       "BSF",
		"nfStatus":     "REGISTERED",
	}
	if timer > 0 {
		body["heartBeatTimer"] = timer
	}
	return body
}

func problemJSON(status int, cause string) map[string]any {
	return map[string]any{"status": status, "cause": cause}
}
