package consumer

import (
	"context"

	bsfContext "github.com/free5gc/bsf/internal/context"
	"github.com/free5gc/bsf/pkg/factory"
	Nnrf_NFDiscovery "github.com/free5gc/openapi/nrf/NFDiscovery"
	Nnrf_NFManagement "github.com/free5gc/openapi/nrf/NFManagement"
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

func GetConsumer() *Consumer {
	return consumer
}

func NewConsumer(bsf ConsumerBsf) (*Consumer, error) {
	c := &Consumer{
		ConsumerBsf: bsf,
	}

	c.nnrfService = &nnrfService{
		consumer:        c,
		nfMngmntClients: make(map[string]*Nnrf_NFManagement.APIClient),
		nfDiscClients:   make(map[string]*Nnrf_NFDiscovery.APIClient),
	}

	consumer = c
	return c, nil
}
