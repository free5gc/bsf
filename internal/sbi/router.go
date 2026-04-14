/*
 * BSF SBI Router
 */

package sbi

import (
	"github.com/gin-gonic/gin"

	bsfContext "github.com/free5gc/bsf/internal/context"
	"github.com/free5gc/bsf/internal/logger"
	"github.com/free5gc/bsf/internal/util"
	"github.com/free5gc/openapi/models"
)

// AddService initializes the BSF SBI service with proper routing
func AddService(engine *gin.Engine) {
	managementGroup := engine.Group("/nbsf-management/v1")

	// Apply OAuth2 authorization check middleware (no-op when OAuth2Required == false)
	routerAuthorizationCheck := util.NewRouterAuthorizationCheck(models.ServiceName_NBSF_MANAGEMENT)
	managementGroup.Use(func(c *gin.Context) {
		routerAuthorizationCheck.Check(c, bsfContext.BsfSelf)
	})

	applyRoutes(managementGroup, getManagementRoutes())
	logger.SbiLog.Infof("BSF SBI server initialized")
}
