package consumer

import (
	"context"

	bsfContext "github.com/free5gc/bsf/internal/context"
	"github.com/free5gc/bsf/internal/logger"
	"github.com/free5gc/bsf/pkg/factory"
	"github.com/free5gc/util/nfheartbeat"
)

var consumer *Consumer

type ConsumerBsf interface {
	Config() *factory.Config
	Context() *bsfContext.BSFContext
	CancelContext() context.Context
}

type Consumer struct {
	ConsumerBsf

	// consumer services
	*nnrfService
}

type nnrfService struct {
	consumer *Consumer

	heartbeat *nfheartbeat.Runner

	// Interval in seconds from the last registration response. Written before the heartbeat starts, then only on
	// the heartbeat goroutine.
	heartbeatTimer int32
}

func GetConsumer() *Consumer {
	return consumer
}

func NewConsumer(bsf ConsumerBsf) (*Consumer, error) {
	c := &Consumer{
		ConsumerBsf: bsf,
	}

	c.nnrfService = &nnrfService{
		consumer: c,
	}
	heartbeat, err := nfheartbeat.NewRunner(
		nrfRegistrar{c.nnrfService},
		func() int32 { return c.Config().GetNfHeartBeatTimer() },
		logger.ConsLog,
	)
	if err != nil {
		return nil, err
	}
	c.nnrfService.heartbeat = heartbeat

	consumer = c
	return c, nil
}

// RegisterWithNRF calls the existing NRF service registration function
func (c *Consumer) RegisterWithNRF(ctx context.Context) error {
	_, err := c.SendRegisterNFInstance(ctx)
	return err
}

// DeregisterWithNRF calls the existing NRF service deregistration function
func (c *Consumer) DeregisterWithNRF() error {
	_, err := c.SendDeregisterNFInstance()
	return err
}
