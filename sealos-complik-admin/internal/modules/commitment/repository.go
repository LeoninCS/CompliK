package commitment

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

// CreateCommitment creates a new commitment record.
func (r *Repository) CreateCommitment(ctx context.Context, commitment *Commitment) error {
	return r.db.WithContext(ctx).Create(commitment).Error
}

// GetCommitmentByNamespace returns a commitment by namespace.
func (r *Repository) GetCommitmentByNamespace(
	ctx context.Context,
	namespace string,
) (*Commitment, error) {
	var commitment Commitment
	if err := r.db.WithContext(ctx).
		Where("namespace = ?", namespace).
		First(&commitment).
		Error; err != nil {
		return nil, err
	}

	return &commitment, nil
}

// ListCommitments returns all commitment records.
func (r *Repository) ListCommitments(ctx context.Context) ([]Commitment, error) {
	var commitments []Commitment
	if err := r.db.WithContext(ctx).Order("id ASC").Find(&commitments).Error; err != nil {
		return nil, err
	}

	return commitments, nil
}

func (r *Repository) ListCommitmentsPage(
	ctx context.Context,
	options pagequery.Options,
	keyword string,
) ([]Commitment, int64, error) {
	var total int64
	countQuery := r.buildListQuery(ctx, keyword)
	if err := countQuery.Model(&Commitment{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var commitments []Commitment
	query := r.buildListQuery(ctx, keyword)
	if err := query.
		Order("updated_at DESC, id DESC").
		Limit(options.PageSize).
		Offset(options.Offset()).
		Find(&commitments).Error; err != nil {
		return nil, 0, err
	}

	return commitments, total, nil
}

func (r *Repository) buildListQuery(ctx context.Context, keyword string) *gorm.DB {
	query := r.db.WithContext(ctx).Model(&Commitment{})
	if strings.TrimSpace(keyword) != "" {
		value := "%" + strings.ToLower(strings.TrimSpace(keyword)) + "%"
		query = query.Where("LOWER(namespace) LIKE ?", value)
	}

	return query
}

// UpdateCommitment updates an existing commitment record.
func (r *Repository) UpdateCommitment(ctx context.Context, commitment *Commitment) error {
	return r.db.WithContext(ctx).Save(commitment).Error
}

// DeleteCommitmentByNamespace deletes commitment records for the given namespace.
func (r *Repository) DeleteCommitmentByNamespace(ctx context.Context, namespace string) error {
	result := r.db.WithContext(ctx).Where("namespace = ?", namespace).Delete(&Commitment{})
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}
