package projectconfig

import (
	"context"
	"strings"

	"gorm.io/gorm"
	"sealos-complik-admin/internal/modules/pagequery"
)

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// CreateProjectConfig creates a new project configuration in the database.
func (r *Repository) CreateProjectConfig(ctx context.Context, projectConfig *ProjectConfig) error {
	return r.db.WithContext(ctx).Create(projectConfig).Error
}

// GetProjectConfigByName returns a project configuration by its config name.
func (r *Repository) GetProjectConfigByName(
	ctx context.Context,
	configName string,
) (*ProjectConfig, error) {
	var projectConfig ProjectConfig
	if err := r.db.WithContext(ctx).
		Where("config_name = ?", configName).
		First(&projectConfig).
		Error; err != nil {
		return nil, err
	}

	return &projectConfig, nil
}

// ListProjectConfigs returns all project configurations.
func (r *Repository) ListProjectConfigs(ctx context.Context) ([]ProjectConfig, error) {
	var projectConfigs []ProjectConfig
	if err := r.db.WithContext(ctx).Order("id ASC").Find(&projectConfigs).Error; err != nil {
		return nil, err
	}

	return projectConfigs, nil
}

func (r *Repository) ListProjectConfigsPage(
	ctx context.Context,
	options pagequery.Options,
	keyword string,
) ([]ProjectConfig, int64, error) {
	var total int64
	countQuery := r.buildListQuery(ctx, keyword)
	if err := countQuery.Model(&ProjectConfig{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var projectConfigs []ProjectConfig
	query := r.buildListQuery(ctx, keyword)
	if err := query.
		Order("updated_at DESC, id DESC").
		Limit(options.PageSize).
		Offset(options.Offset()).
		Find(&projectConfigs).Error; err != nil {
		return nil, 0, err
	}

	return projectConfigs, total, nil
}

func (r *Repository) buildListQuery(ctx context.Context, keyword string) *gorm.DB {
	query := r.db.WithContext(ctx).Model(&ProjectConfig{})
	if strings.TrimSpace(keyword) != "" {
		value := "%" + strings.ToLower(strings.TrimSpace(keyword)) + "%"
		query = query.Where("LOWER(config_name) LIKE ?", value)
	}

	return query
}

// ListProjectConfigsByType returns project configurations filtered by config type.
func (r *Repository) ListProjectConfigsByType(
	ctx context.Context,
	configType string,
) ([]ProjectConfig, error) {
	var projectConfigs []ProjectConfig
	if err := r.db.WithContext(ctx).
		Where("config_type = ?", configType).
		Order("id ASC").
		Find(&projectConfigs).Error; err != nil {
		return nil, err
	}

	return projectConfigs, nil
}

// UpdateProjectConfig updates an existing project configuration in the database.
func (r *Repository) UpdateProjectConfig(ctx context.Context, projectConfig *ProjectConfig) error {
	return r.db.WithContext(ctx).Save(projectConfig).Error
}

// DeleteProjectConfigByName deletes a project configuration by its config name.
func (r *Repository) DeleteProjectConfigByName(ctx context.Context, configName string) error {
	result := r.db.WithContext(ctx).Where("config_name = ?", configName).Delete(&ProjectConfig{})
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}
