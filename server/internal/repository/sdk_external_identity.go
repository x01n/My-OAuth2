package repository

import (
	"errors"
	"strings"

	"server/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

var ErrSDKExternalIdentityAlreadyExists = errors.New("sdk external identity already exists")

/*
 * SDKExternalIdentityRepository SDK 接入应用外部身份仓储
 * 功能：封装 SDK 外部身份关联的创建、查找和删除操作
 */
type SDKExternalIdentityRepository struct {
	db *gorm.DB
}

/* NewSDKExternalIdentityRepository 创建 SDK 外部身份仓储 */
func NewSDKExternalIdentityRepository(db *gorm.DB) *SDKExternalIdentityRepository {
	return &SDKExternalIdentityRepository{db: db}
}

/*
 * FindByExternalIdentity 根据来源系统和外部用户 ID 查找身份关联
 * @param externalSource - 来源系统
 * @param externalID     - 外部系统用户 ID
 */
func (r *SDKExternalIdentityRepository) FindByExternalIdentity(externalSource, externalID string) (*model.SDKExternalIdentity, error) {
	if externalSource == "" || externalID == "" {
		return nil, ErrUserNotFound
	}

	var identity model.SDKExternalIdentity
	result := r.db.First(&identity, "external_source = ? AND external_id = ?", externalSource, externalID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, result.Error
	}
	return &identity, nil
}

/*
 * FindByUserAndExternalIdentity 查找用户与指定外部身份的关联
 * @param userID         - 本地用户 UUID
 * @param externalSource - 来源系统
 * @param externalID     - 外部系统用户 ID
 */
func (r *SDKExternalIdentityRepository) FindByUserAndExternalIdentity(userID uuid.UUID, externalSource, externalID string) (*model.SDKExternalIdentity, error) {
	if userID == uuid.Nil || externalSource == "" || externalID == "" {
		return nil, ErrUserNotFound
	}

	var identity model.SDKExternalIdentity
	result := r.db.First(&identity, "user_id = ? AND external_source = ? AND external_id = ?", userID, externalSource, externalID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, result.Error
	}
	return &identity, nil
}

/*
 * Create 创建 SDK 外部身份关联
 * @param identity - SDK 外部身份关联实体
 */
func (r *SDKExternalIdentityRepository) Create(identity *model.SDKExternalIdentity) error {
	result := r.db.Create(identity)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrDuplicatedKey) || isSDKExternalIdentityDuplicateError(result.Error) {
			return ErrSDKExternalIdentityAlreadyExists
		}
		return result.Error
	}
	return nil
}

func isSDKExternalIdentityDuplicateError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed: sdk_external_identities.external_source, sdk_external_identities.external_id")
}

/* DeleteByUserID 删除用户的所有 SDK 外部身份关联 */
func (r *SDKExternalIdentityRepository) DeleteByUserID(userID uuid.UUID) error {
	return r.db.Delete(&model.SDKExternalIdentity{}, "user_id = ?", userID).Error
}
