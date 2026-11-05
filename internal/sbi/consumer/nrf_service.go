/*
 * BSF NRF Consumer
 */

package consumer

import (
	"context"
	"errors"
	"fmt"
	"time"

	bsfContext "github.com/free5gc/bsf/internal/context"
	"github.com/free5gc/bsf/internal/logger"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	Nnrf_NFManagement "github.com/free5gc/openapi/nrf/NFMgmt"
)

const registerRetryInterval = 2 * time.Second

func BuildNFProfile(bsfContext *bsfContext.BSFContext) models.Nrf_NFMgmt_NFProfile {
	return bsfContext.GetBsfProfile()
}

func (s *nnrfService) nfManagementClient() *Nnrf_NFManagement.APIClient {
	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(s.consumer.Context().NrfUri)
	return Nnrf_NFManagement.NewAPIClient(configuration)
}

// SendRegisterNFInstance PUTs the BSF profile on its own instance ID (3GPP TS 29.510 clause 5.2.2.2.2) until it
// succeeds or ctx is done, and keeps the heartBeatTimer the NRF assigned.
func (s *nnrfService) SendRegisterNFInstance(ctx context.Context) (*models.Nrf_NFMgmt_NFProfile, error) {
	client := s.nfManagementClient()

	for {
		nfProfile := BuildNFProfile(s.consumer.Context())

		request := &Nnrf_NFManagement.RegisterNFInstanceRequest{
			NfInstanceID: &nfProfile.NfInstanceId,
			RequestBody:  &nfProfile,
		}

		res, err := client.NFInstanceIDDocumentApi.RegisterNFInstance(ctx, request)
		if err == nil && res != nil {
			s.heartbeatTimer = 0
			if res.Nrf_NFMgmt_NFProfile != nil {
				s.heartbeatTimer = res.Nrf_NFMgmt_NFProfile.HeartBeatTimer
			}
			// Check if NFUpdate (no Location header) or NFRegister (has Location header)
			if res.Location == "" {
				logger.ConsLog.Infof("BSF registration to NRF updated")
			} else {
				logger.ConsLog.Infof("BSF registration to NRF successful, resource: %s", res.Location)
			}
			return res.Nrf_NFMgmt_NFProfile, nil
		}

		if err != nil {
			// Check if it's an OpenAPI error with more details
			var apiErr openapi.GenericOpenAPIError
			if errors.As(err, &apiErr) {
				logger.ConsLog.Errorf("BSF register to NRF OpenAPI Error: %+v", apiErr.Error())
				logger.ConsLog.Errorf("BSF register to NRF Response Body: %s", string(apiErr.Body()))
				logger.ConsLog.Errorf("BSF register to NRF Response Model: %+v", apiErr.Model())
			} else {
				logger.ConsLog.Errorf("BSF register to NRF Error[%v]", err)
			}
		} else {
			logger.ConsLog.Errorf("BSF register to NRF: received nil response")
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("NFRegister aborted: %w (last error: %v)", ctx.Err(), err)
		case <-time.After(registerRetryInterval):
		}
	}
}

// SendUpdateNFInstance sends an NFUpdate PATCH to the NRF, honoring ctx. The raw err comes back alongside any
// ProblemDetails so callers can read its GenericOpenAPIError status.
func (s *nnrfService) SendUpdateNFInstance(ctx context.Context, patchItems []models.PatchItem) (
	nf models.Nrf_NFMgmt_NFProfile, problemDetails *models.ProblemDetails, err error,
) {
	nfId := s.consumer.Context().NfId
	request := &Nnrf_NFManagement.UpdateNFInstanceRequest{
		NfInstanceID: &nfId,
		RequestBody:  patchItems,
	}

	res, err := s.nfManagementClient().NFInstanceIDDocumentApi.UpdateNFInstance(ctx, request)
	if err != nil {
		var apiErr openapi.GenericOpenAPIError
		if errors.As(err, &apiErr) {
			if updateErr, ok := apiErr.Model().(Nnrf_NFManagement.UpdateNFInstanceError); ok {
				return nf, updateErr.ProblemDetails, err
			}
		}
		return nf, nil, err
	}
	if res == nil {
		return nf, nil, openapi.ReportError("empty NFUpdate response")
	}
	if res.Nrf_NFMgmt_NFProfile != nil {
		nf = *res.Nrf_NFMgmt_NFProfile
	}
	return nf, nil, nil
}

func (s *nnrfService) SendDeregisterNFInstance() (*models.ProblemDetails, error) {
	nfId := s.consumer.Context().NfId
	request := &Nnrf_NFManagement.DeregisterNFInstanceRequest{
		NfInstanceID: &nfId,
	}

	_, err := s.nfManagementClient().NFInstanceIDDocumentApi.DeregisterNFInstance(context.TODO(), request)
	if err != nil {
		logger.ConsLog.Warnf("BSF deregistration from NRF failed[%v]", err)
		return nil, err
	}

	logger.ConsLog.Infof("BSF deregistration from NRF successful")
	return nil, nil
}
