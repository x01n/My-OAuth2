package repository

import (
	"server/internal/model"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
 * DeviceCodeRepository 设备授权码数据仓储 (RFC 8628)
 * 功能：封装设备授权流程中 device_code / user_code 的全部 CRUD 操作
 */
type DeviceCodeRepository struct {
	db *gorm.DB
}

/*
 * NewDeviceCodeRepository 创建设备码仓储实例
 * @param db - GORM 数据库连接
 */
func NewDeviceCodeRepository(db *gorm.DB) *DeviceCodeRepository {
	return &DeviceCodeRepository{db: db}
}

/* Create 创建新的设备授权码 */
func (r *DeviceCodeRepository) Create(dc *model.DeviceCode) error {
	return r.db.Create(dc).Error
}

/*
 * FindByDeviceCode 根据 device_code 查找设备授权记录
 * @param deviceCode - 设备码字符串
 */
func (r *DeviceCodeRepository) FindByDeviceCode(deviceCode string) (*model.DeviceCode, error) {
	var dc model.DeviceCode
	err := r.db.Where("device_code = ?", deviceCode).First(&dc).Error
	if err != nil {
		return nil, err
	}
	return &dc, nil
}

/*
 * FindByUserCode 根据 user_code 查找设备授权记录
 * 功能：自动标准化用户输入的验证码后查询
 * @param userCode - 用户输入的验证码
 */
func (r *DeviceCodeRepository) FindByUserCode(userCode string) (*model.DeviceCode, error) {
	var dc model.DeviceCode
	// Normalize the user code before searching
	normalizedCode := model.NormalizeUserCode(userCode)
	err := r.db.Where("user_code = ?", normalizedCode).First(&dc).Error
	if err != nil {
		return nil, err
	}
	return &dc, nil
}

/* Update 更新设备授权记录 */
func (r *DeviceCodeRepository) Update(dc *model.DeviceCode) error {
	return r.db.Save(dc).Error
}

/*
 * Authorize 标记设备码为已授权
 * @param userCode - 用户验证码
 * @param userID   - 授权用户的 UUID
 */
func (r *DeviceCodeRepository) Authorize(userCode string, userID uuid.UUID) error {
	normalizedCode := model.NormalizeUserCode(userCode)
	return r.db.Model(&model.DeviceCode{}).
		Where("user_code = ? AND status = ?", normalizedCode, model.DeviceCodeStatusPending).
		Updates(map[string]interface{}{
			"user_id": userID,
			"status":  model.DeviceCodeStatusAuthorized,
		}).Error
}

/*
 * Deny 标记设备码为已拒绝
 * @param userCode - 用户验证码
 */
func (r *DeviceCodeRepository) Deny(userCode string) error {
	normalizedCode := model.NormalizeUserCode(userCode)
	return r.db.Model(&model.DeviceCode{}).
		Where("user_code = ? AND status = ?", normalizedCode, model.DeviceCodeStatusPending).
		Update("status", model.DeviceCodeStatusDenied).Error
}

/*
 * UpdateLastPolledAt 更新设备码的最后轮询时间
 * @param deviceCode - 设备码字符串
 * @param t          - 轮询时间
 */
func (r *DeviceCodeRepository) UpdateLastPolledAt(deviceCode string, t time.Time) error {
	return r.db.Model(&model.DeviceCode{}).
		Where("device_code = ?", deviceCode).
		Update("last_polled_at", t).Error
}

/**
 * ConsumeAuthorizedDeviceCode 原子消费已授权的 device_code
 *
 * @description
 *   先读取记录，再通过条件 UPDATE 把 status 从 authorized 改为 consumed。
 *   仅当 RowsAffected==1 时调用方拿到兑换所有权；并发轮询时只有一个请求能成功，
 *   其余请求会得到 claimed=false，避免同一个 device_code 被重复签发多对 token。
 *
 * @param  {string} deviceCode - 设备码字符串
 * @returns {(*model.DeviceCode, bool, error)}
 */
func (r *DeviceCodeRepository) ConsumeAuthorizedDeviceCode(deviceCode string) (*model.DeviceCode, bool, error) {
	var dc model.DeviceCode
	if err := r.db.Where("device_code = ?", deviceCode).First(&dc).Error; err != nil {
		return nil, false, err
	}

	res := r.db.Model(&model.DeviceCode{}).
		Where("id = ? AND status = ?", dc.ID, model.DeviceCodeStatusAuthorized).
		Update("status", model.DeviceCodeStatusConsumed)
	if res.Error != nil {
		return nil, false, res.Error
	}
	return &dc, res.RowsAffected == 1, nil
}

/* Delete 删除设备授权记录 */
func (r *DeviceCodeRepository) Delete(id uuid.UUID) error {
	return r.db.Delete(&model.DeviceCode{}, id).Error
}

/* DeleteByUserID 删除用户的所有设备授权记录 */
func (r *DeviceCodeRepository) DeleteByUserID(userID uuid.UUID) error {
	return r.db.Delete(&model.DeviceCode{}, "user_id = ?", userID).Error
}

/* DeleteExpired 清理所有已过期的设备授权记录 */
func (r *DeviceCodeRepository) DeleteExpired() error {
	return r.db.Where("expires_at < ?", time.Now()).Delete(&model.DeviceCode{}).Error
}

/*
 * FindPendingByClientID 查找客户端的所有待授权设备码
 * @param clientID - OAuth2 客户端 ID
 */
func (r *DeviceCodeRepository) FindPendingByClientID(clientID string) ([]model.DeviceCode, error) {
	var codes []model.DeviceCode
	err := r.db.Where("client_id = ? AND status = ? AND expires_at > ?",
		clientID, model.DeviceCodeStatusPending, time.Now()).
		Find(&codes).Error
	return codes, err
}
