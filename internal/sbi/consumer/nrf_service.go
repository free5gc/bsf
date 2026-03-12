/*
 * BSF NRF Consumer
 */

package consumer

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	bsfContext "github.com/free5gc/bsf/internal/context"
	"github.com/free5gc/bsf/internal/logger"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	Nnrf_NFDiscovery "github.com/free5gc/openapi/nrf/NFDiscovery"
	Nnrf_NFManagement "github.com/free5gc/openapi/nrf/NFManagement"
)

type nnrfService struct {
	consumer *Consumer

	nfMngmntMu sync.RWMutex
	nfDiscMu   sync.RWMutex

	nfMngmntClients map[string]*Nnrf_NFManagement.APIClient
	nfDiscClients   map[string]*Nnrf_NFDiscovery.APIClient
}

func (s *nnrfService) getNFManagementClient(uri string) *Nnrf_NFManagement.APIClient {
	if uri == "" {
		return nil
	}
	s.nfMngmntMu.RLock()
	client, ok := s.nfMngmntClients[uri]
	if ok {
		s.nfMngmntMu.RUnlock()
		return client
	}

	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(uri)
	client = Nnrf_NFManagement.NewAPIClient(configuration)

	s.nfMngmntMu.RUnlock()
	s.nfMngmntMu.Lock()
	defer s.nfMngmntMu.Unlock()
	s.nfMngmntClients[uri] = client
	return client
}

func (s *nnrfService) getNFDiscClient(uri string) *Nnrf_NFDiscovery.APIClient {
	if uri == "" {
		return nil
	}
	s.nfDiscMu.RLock()
	client, ok := s.nfDiscClients[uri]
	if ok {
		s.nfDiscMu.RUnlock()
		return client
	}
	s.nfDiscMu.RUnlock()

	configuration := Nnrf_NFDiscovery.NewConfiguration()
	configuration.SetBasePath(uri)
	client = Nnrf_NFDiscovery.NewAPIClient(configuration)

	s.nfDiscMu.Lock()
	defer s.nfDiscMu.Unlock()
	s.nfDiscClients[uri] = client
	return client
}

func (s *nnrfService) SendSearchNFInstances(nrfUri string, targetNfType, requestNfType models.NrfNfManagementNfType,
	param *Nnrf_NFDiscovery.SearchNFInstancesRequest,
) (*models.SearchResult, error) {
	param.TargetNfType = &targetNfType
	param.RequesterNfType = &requestNfType

	client := s.getNFDiscClient(nrfUri)
	if client == nil {
		return nil, openapi.ReportError("nrf not found")
	}

	ctx, _, err := bsfContext.BsfSelf.GetTokenCtx(models.ServiceName_NNRF_DISC, models.NrfNfManagementNfType_NRF)
	if err != nil {
		return nil, err
	}

	res, err := client.NFInstancesStoreApi.SearchNFInstances(ctx, param)
	if err != nil {
		logger.ConsLog.Errorf("SearchNFInstances failed: %+v", err)
		return nil, err
	}

	result := &res.SearchResult
	return result, nil
}

func (s *nnrfService) BuildNFProfile() models.NrfNfManagementNfProfile {
	return bsfContext.BsfSelf.GetBsfProfile()
}

func (s *nnrfService) SendRegisterNFInstance(ctx context.Context) (
	*models.NrfNfManagementNfProfile, string, error) {
	bsfCtx := s.consumer.Context()

	client := s.getNFManagementClient(bsfCtx.NrfUri)
	if client == nil {
		return nil, "", openapi.ReportError("nrf not found")
	}

	nfProfile := s.BuildNFProfile()
	request := &Nnrf_NFManagement.RegisterNFInstanceRequest{
		NfInstanceID:             &bsfCtx.NfId,
		NrfNfManagementNfProfile: &nfProfile,
	}

	var res *Nnrf_NFManagement.RegisterNFInstanceResponse
	var err error
	var nfId string

	finish := false
	for !finish {
		select {
		case <-ctx.Done():
			return nil, "", fmt.Errorf("RegisterNFInstance context done")
		default:
			res, err = client.NFInstanceIDDocumentApi.RegisterNFInstance(ctx, request)
			if err != nil {
				if apiErr, ok := err.(*openapi.GenericOpenAPIError); ok {
					logger.ConsLog.Errorf("BSF register to NRF OpenAPI Error: %+v", apiErr.Error())
					logger.ConsLog.Errorf("BSF register to NRF Response Body: %s", string(apiErr.Body()))
				} else {
					logger.ConsLog.Errorf("BSF register to NRF Error[%v]", err)
				}
				time.Sleep(2 * time.Second)
				continue
			}
			if res == nil {
				logger.ConsLog.Errorf("BSF register to NRF: received nil response")
				time.Sleep(2 * time.Second)
				continue
			}

			if res.Location == "" {
				// NFUpdate
				logger.ConsLog.Infof("BSF registration to NRF updated")
				finish = true
			} else {
				// NFRegister — check OAuth2 flag from NRF response
				resourceUri := res.Location
				// Extract NRF instance ID from Location
				nfId = resourceUri[strings.LastIndex(resourceUri, "/")+1:]
				logger.ConsLog.Infof("BSF registration to NRF successful, resource: %s", resourceUri)

				nf := res.NrfNfManagementNfProfile
				oauth2 := false
				if nf.CustomInfo != nil {
					v, ok := nf.CustomInfo["oauth2"].(bool)
					if ok {
						oauth2 = v
						logger.ConsLog.Infof("OAuth2 setting received from NRF: %v", oauth2)
					}
				}
				bsfCtx.OAuth2Required = oauth2
				if oauth2 && bsfCtx.NrfCertPem == "" {
					logger.ConsLog.Error("OAuth2 enabled but no nrfCertPem provided in config.")
				}

				finish = true
			}
		}
	}
	return &res.NrfNfManagementNfProfile, nfId, nil
}

func (s *nnrfService) SendDeregisterNFInstance() (*models.ProblemDetails, error) {
	logger.ConsLog.Infof("[BSF] Send Deregister NFInstance")
	bsfCtx := s.consumer.Context()

	client := s.getNFManagementClient(bsfCtx.NrfUri)
	if client == nil {
		return nil, openapi.ReportError("nrf not found")
	}

	ctx, pd, err := bsfCtx.GetTokenCtx(models.ServiceName_NNRF_NFM, models.NrfNfManagementNfType_NRF)
	if err != nil {
		return pd, err
	}

	request := &Nnrf_NFManagement.DeregisterNFInstanceRequest{
		NfInstanceID: &bsfCtx.NfId,
	}

	_, err = client.NFInstanceIDDocumentApi.DeregisterNFInstance(ctx, request)
	if err != nil {
		logger.ConsLog.Warnf("BSF deregistration from NRF failed[%v]", err)
		return nil, err
	}

	logger.ConsLog.Infof("BSF deregistration from NRF successful")
	return nil, nil
}
