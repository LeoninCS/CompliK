package projectconfig

import (
	"github.com/gin-gonic/gin"
	"sealos-complik-admin/internal/infra/database"
)

// InitProjectConfigRoutes wires module dependencies and registers project config APIs.
func InitProjectConfigRoutes(g *gin.Engine) {
	repository := NewRepository(database.Get())
	service := NewService(repository)
	handler := NewHandler(service)

	g.POST("/api/configs", handler.CreateProjectConfig)
	g.DELETE("/api/configs/:config_name", handler.DeleteProjectConfig)
	g.PUT("/api/configs/:config_name", handler.UpdateProjectConfig)
	g.GET("/api/configs/:config_name", handler.GetProjectConfig)
	g.GET("/api/configs", handler.ListProjectConfigs)
	g.GET("/api/configs/type/:config_type", handler.ListProjectConfigsByType)
}
