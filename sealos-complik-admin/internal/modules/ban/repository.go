package ban

import (
	"context"
	"time"

	"gorm.io/gorm"
)

const (
	banStatusActionBan   = "ban"
	banStatusActionUnban = "unban"
)

type Repository struct {
	db *gorm.DB
}

type banStatusAction struct {
	Kind      string
	ID        uint64
	CreatedAt time.Time
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// CreateBan creates a new ban record.
func (r *Repository) CreateBan(ctx context.Context, ban *Ban) error {
	return r.db.WithContext(ctx).Create(ban).Error
}

// GetBansByNamespace returns all ban records for the given namespace.
func (r *Repository) GetBansByNamespace(ctx context.Context, namespace string) ([]Ban, error) {
	var bans []Ban
	if err := r.db.WithContext(ctx).
		Where("namespace = ?", namespace).
		Order("ban_start_time DESC, id DESC").
		Find(&bans).
		Error; err != nil {
		return nil, err
	}

	if len(bans) == 0 {
		return nil, gorm.ErrRecordNotFound
	}

	return bans, nil
}

// ListBans returns all ban records.
func (r *Repository) ListBans(ctx context.Context) ([]Ban, error) {
	var bans []Ban
	if err := r.db.WithContext(ctx).
		Order("ban_start_time DESC, id DESC").
		Find(&bans).
		Error; err != nil {
		return nil, err
	}

	return bans, nil
}

// DeleteBanByID deletes a single ban record by id.
func (r *Repository) DeleteBanByID(ctx context.Context, id uint64) error {
	result := r.db.WithContext(ctx).Where("id = ?", id).Delete(&Ban{})
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}

// HasActiveBan reports whether active ban actions leave the namespace banned.
func (r *Repository) HasActiveBan(
	ctx context.Context,
	namespace string,
	now time.Time,
) (bool, error) {
	action, err := r.getLatestBanStatusAction(ctx, namespace, now)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, err
	}

	return action.Kind == banStatusActionBan, nil
}

func (r *Repository) getLatestBanStatusAction(
	ctx context.Context,
	namespace string,
	now time.Time,
) (*banStatusAction, error) {
	var action banStatusAction
	if err := r.db.WithContext(ctx).
		Raw(`
SELECT kind, id, created_at
FROM (
		SELECT ? AS kind, id, created_at, 0 AS action_rank
		FROM bans
		WHERE namespace = ?
			AND ban_start_time <= ?
			AND (ban_end_time IS NULL OR ban_end_time > ?)
		UNION ALL
		SELECT ? AS kind, id, created_at, 1 AS action_rank
		FROM unbans
		WHERE namespace = ?
) AS actions
ORDER BY created_at DESC, action_rank DESC, id DESC
LIMIT 1
	`, banStatusActionBan, namespace, now, now, banStatusActionUnban, namespace).
		Scan(&action).Error; err != nil {
		return nil, err
	}

	if action.ID == 0 && action.Kind == "" {
		return nil, gorm.ErrRecordNotFound
	}

	return &action, nil
}
