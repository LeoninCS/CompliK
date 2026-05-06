package complikviolation

import (
	"github.com/gin-gonic/gin"
	"sealos-complik-admin/internal/infra/database"
)

func InitRoutes(g *gin.Engine) {
	repository := NewRepository(database.Get())
	service := NewService(repository)
	handler := NewHandler(service)

	g.POST("/api/complik-violations", handler.CreateViolation)
	g.DELETE("/api/complik-violations/id/:id", handler.DeleteViolationByID)
	g.DELETE("/api/complik-violations/:namespace", handler.DeleteViolations)
	g.GET("/api/complik-violations/:namespace", handler.GetViolations)
	g.GET("/api/complik-violations", handler.ListViolations)
	g.GET("/api/namespaces/:namespace/complik-violations-status", handler.GetViolationStatus)
}
