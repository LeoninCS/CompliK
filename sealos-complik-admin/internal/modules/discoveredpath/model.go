package discoveredpath

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

type DiscoveredPath struct {
	ID                  uint64     `gorm:"primaryKey;autoIncrement;index:idx_discovered_paths_route_top,priority:4;index:idx_discovered_paths_list,priority:2;index:idx_discovered_paths_namespace,priority:3;index:idx_discovered_paths_host,priority:3" json:"id"`
	Namespace           string     `gorm:"size:255;not null;index:idx_discovered_paths_namespace,priority:1"                                                                                                      json:"namespace"`
	IngressName         string     `gorm:"column:ingress_name;size:255;not null"                                                                                                                                  json:"ingress_name"`
	Host                string     `gorm:"size:255;not null;index:idx_discovered_paths_host,priority:1"                                                                                                           json:"host"`
	Path                string     `gorm:"size:1024;not null"                                                                                                                                                     json:"path"`
	RouteHash           string     `gorm:"column:route_hash;type:char(64);not null;uniqueIndex:uk_discovered_paths_route_path,priority:1;index:idx_discovered_paths_route_top,priority:1"                         json:"-"`
	PathHash            string     `gorm:"column:path_hash;type:char(64);not null;uniqueIndex:uk_discovered_paths_route_path,priority:2"                                                                          json:"-"`
	Count               uint64     `gorm:"not null;index:idx_discovered_paths_route_top,priority:2"                                                                                                               json:"count"`
	LastSeenAt          time.Time  `gorm:"column:last_seen_at;not null;index:idx_discovered_paths_route_top,priority:3"                                                                                           json:"last_seen_at"`
	LastDetectedAt      *time.Time `gorm:"column:last_detected_at"                                                                                                                                                json:"last_detected_at,omitempty"`
	LastDetectionStatus string     `gorm:"column:last_detection_status;size:32"                                                                                                                                   json:"last_detection_status,omitempty"`
	CreatedAt           time.Time  `gorm:"autoCreateTime"                                                                                                                                                        json:"created_at"`
	UpdatedAt           time.Time  `gorm:"autoUpdateTime;index:idx_discovered_paths_list,priority:1;index:idx_discovered_paths_namespace,priority:2;index:idx_discovered_paths_host,priority:2"                   json:"updated_at"`
}

func (DiscoveredPath) TableName() string {
	return "discovered_paths"
}

func AutoMigrate(db *gorm.DB) error {
	if db == nil {
		return errors.New("discovered path automigrate: database is nil")
	}

	if err := db.AutoMigrate(&DiscoveredPath{}); err != nil {
		return fmt.Errorf("discovered path automigrate: %w", err)
	}

	return nil
}
