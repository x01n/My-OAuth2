package repository

import (
	"server/internal/model"

	"gorm.io/gorm"
)

/*
 * RiskEventRepository 风控事件数据仓储
 * 功能：封装风控事件持久化操作
 */
type RiskEventRepository struct {
	db *gorm.DB
}

type RiskEventFilter struct {
	Decision *model.RiskDecision
	Reason   string
}

func preloadRiskEventUserSummary(db *gorm.DB) *gorm.DB {
	return db.Select("id", "email", "username", "avatar", "status")
}

/*
 * NewRiskEventRepository 创建风控事件仓储实例
 * @param db - GORM 数据库连接
 */
func NewRiskEventRepository(db *gorm.DB) *RiskEventRepository {
	return &RiskEventRepository{db: db}
}

/* Create 创建新的风控事件 */
func (r *RiskEventRepository) Create(event *model.RiskEvent) error {
	return r.db.Create(event).Error
}

/*
 * FindRecent 分页查询最近风控事件
 * @param offset - 偏移量
 * @param limit  - 每页数量
 */
func (r *RiskEventRepository) FindRecent(offset, limit int) ([]model.RiskEvent, int64, error) {
	return r.FindRecentFiltered(RiskEventFilter{}, offset, limit)
}

/*
 * FindRecentByDecision 分页查询指定处置结果的最近风控事件
 * @param decision - 风控处置结果
 * @param offset   - 偏移量
 * @param limit    - 每页数量
 */
func (r *RiskEventRepository) FindRecentByDecision(decision model.RiskDecision, offset, limit int) ([]model.RiskEvent, int64, error) {
	return r.FindRecentFiltered(RiskEventFilter{Decision: &decision}, offset, limit)
}

/*
 * FindRecentFiltered 分页查询最近风控事件，可按处置结果和原因组合过滤
 * @param filter - 风控事件过滤条件
 * @param offset - 偏移量
 * @param limit  - 每页数量
 */
func (r *RiskEventRepository) FindRecentFiltered(filter RiskEventFilter, offset, limit int) ([]model.RiskEvent, int64, error) {
	var events []model.RiskEvent
	var total int64

	query := r.db.Model(&model.RiskEvent{})
	if filter.Decision != nil {
		query = query.Where("decision = ?", *filter.Decision)
	}
	if filter.Reason != "" {
		query = query.Where("reason = ?", filter.Reason)
	}
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	result := query.Preload("User", preloadRiskEventUserSummary).
		Order("created_at DESC").
		Offset(offset).Limit(limit).
		Find(&events)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return events, total, nil
}
