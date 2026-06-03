package unban

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

// CreateUnban creates a new unban record.
func (r *Repository) CreateUnban(ctx context.Context, unban *Unban) error {
	return r.db.WithContext(ctx).Create(unban).Error
}

// GetUnbansByNamespace returns all unban records for the given namespace.
func (r *Repository) GetUnbansByNamespace(ctx context.Context, namespace string) ([]Unban, error) {
	var unbans []Unban
	if err := r.db.WithContext(ctx).
		Where("namespace = ?", namespace).
		Order("created_at DESC, id DESC").
		Find(&unbans).
		Error; err != nil {
		return nil, err
	}

	if len(unbans) == 0 {
		return nil, gorm.ErrRecordNotFound
	}

	return unbans, nil
}

// ListUnbans returns all unban records.
func (r *Repository) ListUnbans(ctx context.Context) ([]Unban, error) {
	var unbans []Unban
	if err := r.db.WithContext(ctx).
		Order("created_at DESC, id DESC").
		Find(&unbans).
		Error; err != nil {
		return nil, err
	}

	return unbans, nil
}

func (r *Repository) ListUnbansPage(
	ctx context.Context,
	options pagequery.Options,
	keyword string,
	operatorName string,
) ([]Unban, int64, error) {
	var total int64
	countQuery := r.buildListQuery(ctx, keyword, operatorName)
	if err := countQuery.Model(&Unban{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var unbans []Unban
	query := r.buildListQuery(ctx, keyword, operatorName)
	if err := query.
		Order("created_at DESC, id DESC").
		Limit(options.PageSize).
		Offset(options.Offset()).
		Find(&unbans).Error; err != nil {
		return nil, 0, err
	}

	return unbans, total, nil
}

func (r *Repository) buildListQuery(ctx context.Context, keyword string, operatorName string) *gorm.DB {
	query := r.db.WithContext(ctx).Model(&Unban{})
	if strings.TrimSpace(keyword) != "" {
		value := "%" + strings.ToLower(strings.TrimSpace(keyword)) + "%"
		query = query.Where("LOWER(namespace) LIKE ?", value)
	}
	if strings.TrimSpace(operatorName) != "" {
		query = query.Where("operator_name = ?", strings.TrimSpace(operatorName))
	}

	return query
}

// DeleteUnbanByID deletes a single unban record by id.
func (r *Repository) DeleteUnbanByID(ctx context.Context, id uint64) error {
	result := r.db.WithContext(ctx).Where("id = ?", id).Delete(&Unban{})
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}
