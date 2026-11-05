package factory_test

import (
	"testing"

	"github.com/free5gc/bsf/pkg/factory"
	"github.com/free5gc/util/nfheartbeat"
)

func TestGetNfHeartBeatTimer(t *testing.T) {
	tests := []struct {
		name string
		cfg  *factory.Config
		want int32
	}{
		{
			name: "no configuration section",
			cfg:  &factory.Config{},
			want: nfheartbeat.DefaultTimer,
		},
		{
			name: "option absent",
			cfg:  &factory.Config{Configuration: &factory.Configuration{}},
			want: nfheartbeat.DefaultTimer,
		},
		{
			name: "option set",
			cfg:  &factory.Config{Configuration: &factory.Configuration{NfHeartBeatTimer: 45}},
			want: 45,
		},
		{
			name: "negative falls back to the default",
			cfg:  &factory.Config{Configuration: &factory.Configuration{NfHeartBeatTimer: -1}},
			want: nfheartbeat.DefaultTimer,
		},
		{
			name: "above the NRF maximum is capped",
			cfg:  &factory.Config{Configuration: &factory.Configuration{NfHeartBeatTimer: nfheartbeat.MaxTimer + 1}},
			want: nfheartbeat.MaxTimer,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.GetNfHeartBeatTimer(); got != tt.want {
				t.Errorf("GetNfHeartBeatTimer() = %d, want %d", got, tt.want)
			}
		})
	}
}
