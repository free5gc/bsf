package factory

import (
	"testing"
	"time"

	"gopkg.in/yaml.v2"
)

func TestIdleTimeoutYAML(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  time.Duration
	}{
		{"omitted", "configuration: {}", time.Millisecond},
		{"disabled", "configuration: {idleTimeout: 0s}", 0},
		{"duration", "configuration: {idleTimeout: 30s}", 30 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg Config
			if err := yaml.Unmarshal([]byte(tc.input), &cfg); err != nil {
				t.Fatal(err)
			}
			if got := cfg.GetIdleTimeout(); got != tc.want {
				t.Fatalf("timeout = %v, want %v", got, tc.want)
			}
		})
	}
	var cfg Config
	if err := yaml.Unmarshal([]byte("configuration: {idleTimeout: invalid}"), &cfg); err == nil {
		t.Fatal("invalid duration was accepted")
	}
}
