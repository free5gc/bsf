package util_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	"github.com/free5gc/bsf/internal/util"
	"github.com/free5gc/openapi/models"
)

const (
	Valid   = "valid"
	Invalid = "invalid"
)

type mockBSFContext struct {
	called      bool
	token       string
	serviceName models.Nrf_NFMgmt_ServiceName
}

func newMockBSFContext() *mockBSFContext {
	return &mockBSFContext{}
}

func (m *mockBSFContext) AuthorizationCheck(token string, serviceName models.Nrf_NFMgmt_ServiceName) error {
	m.called = true
	m.token = token
	m.serviceName = serviceName
	if token == Valid {
		return nil
	}

	return errors.New("invalid token")
}

func TestRouterAuthorizationCheck_Check(t *testing.T) {
	type Args struct {
		token string
	}
	type Want struct {
		statusCode int
		aborted    bool
	}

	tests := []struct {
		name string
		args Args
		want Want
	}{
		{
			name: "Valid Token",
			args: Args{token: Valid},
			want: Want{statusCode: http.StatusOK, aborted: false},
		},
		{
			name: "Invalid Token",
			args: Args{token: Invalid},
			want: Want{statusCode: http.StatusUnauthorized, aborted: true},
		},
		{
			name: "Missing Token",
			args: Args{token: ""},
			want: Want{statusCode: http.StatusUnauthorized, aborted: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
			if err != nil {
				t.Fatalf("error on http request: %+v", err)
			}
			c.Request = req
			if tt.args.token != "" {
				c.Request.Header.Set("Authorization", tt.args.token)
			}

			serviceName := models.Nrf_NFMgmt_ServiceName("testService")
			rac := util.NewRouterAuthorizationCheck(serviceName)
			bsfContext := newMockBSFContext()
			rac.Check(c, bsfContext)

			if !bsfContext.called {
				t.Fatal("AuthorizationCheck was not called")
			}
			if bsfContext.token != tt.args.token || bsfContext.serviceName != serviceName {
				t.Errorf("AuthorizationCheck received token %q and service %q; want %q and %q",
					bsfContext.token, bsfContext.serviceName, tt.args.token, serviceName)
			}
			if w.Code != tt.want.statusCode {
				t.Errorf("StatusCode should be %d, but got %d", tt.want.statusCode, w.Code)
			}
			if c.IsAborted() != tt.want.aborted {
				t.Errorf("IsAborted should be %v, but got %v", tt.want.aborted, c.IsAborted())
			}
			if tt.want.statusCode == http.StatusUnauthorized {
				var body struct {
					Error string `json:"error"`
				}
				if decodeErr := json.Unmarshal(w.Body.Bytes(), &body); decodeErr != nil {
					t.Fatalf("invalid JSON error response: %v", decodeErr)
				}
				if body.Error != "invalid token" {
					t.Errorf("error body = %q, want %q", body.Error, "invalid token")
				}
			}
		})
	}
}

// Verify that the middleware permits or stops the protected handler.
func TestRouterAuthorizationCheck_Middleware(t *testing.T) {
	tests := []struct {
		name          string
		token         string
		statusCode    int
		handlerCalled bool
	}{
		{"Valid Token", Valid, http.StatusNoContent, true},
		{"Invalid Token", Invalid, http.StatusUnauthorized, false},
		{"Missing Token", "", http.StatusUnauthorized, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			rac := util.NewRouterAuthorizationCheck(models.Nrf_NFMgmt_ServiceName_NBSF_MANAGEMENT)
			bsfContext := newMockBSFContext()
			handlerCalled := false
			router.Use(func(c *gin.Context) { rac.Check(c, bsfContext) })
			router.GET("/protected", func(c *gin.Context) {
				handlerCalled = true
				c.Status(http.StatusNoContent)
			})

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", tt.token)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tt.statusCode {
				t.Errorf("StatusCode should be %d, but got %d", tt.statusCode, w.Code)
			}
			if handlerCalled != tt.handlerCalled {
				t.Errorf("handler called = %v, want %v", handlerCalled, tt.handlerCalled)
			}
		})
	}
}
