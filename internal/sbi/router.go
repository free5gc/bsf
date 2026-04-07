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
// This function maintains backward compatibility with existing BSF initialization
func AddService(engine *gin.Engine) {
	// Apply BSF Management routes to the provided engine
	managementGroup := engine.Group("/nbsf-management/v1")

	managementAuthCheck := util.NewRouterAuthorizationCheck(models.ServiceName_NBSF_MANAGEMENT)
	managementGroup.Use(func(c *gin.Context) {
		managementAuthCheck.Check(c, bsfContext.BsfSelf)
	})

	managementRoutes := getManagementRoutes()
	applyRoutes(managementGroup, managementRoutes)

	logger.SbiLog.Infof("BSF SBI server initialized")
}
