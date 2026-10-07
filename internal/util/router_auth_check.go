package util

import (
	"net/http"

	"github.com/gin-gonic/gin"

	bsf_context "github.com/free5gc/bsf/internal/context"
	"github.com/free5gc/bsf/internal/logger"
	"github.com/free5gc/openapi/models"
)

type RouterAuthorizationCheck struct {
	serviceName models.Nrf_NFMgmt_ServiceName
}

func NewRouterAuthorizationCheck(serviceName models.Nrf_NFMgmt_ServiceName) *RouterAuthorizationCheck {
	return &RouterAuthorizationCheck{
		serviceName: serviceName,
	}
}

func (rac *RouterAuthorizationCheck) Check(c *gin.Context, bsfContext bsf_context.NFContext) {
	token := c.Request.Header.Get("Authorization")
	err := bsfContext.AuthorizationCheck(token, rac.serviceName)
	if err != nil {
		logger.UtilLog.Debugf("RouterAuthorizationCheck: Check Unauthorized: %s", err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		c.Abort()
		return
	}

	logger.UtilLog.Debugf("RouterAuthorizationCheck: Check Authorized")
}
