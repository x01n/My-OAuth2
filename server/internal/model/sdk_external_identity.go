package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
 * SDKExternalIdentity SDK 接入应用外部身份关联模型
 * 功能：将同一个本地用户绑定到多个接入平台的外部用户 ID，支持多平台单用户
 * 表名：sdk_external_identities
 * 索引：user_id, (external_source, external_id)
 */
type SDKExternalIdentity struct {
	ID             uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	UserID         uuid.UUID `gorm:"type:uuid;not null;index" json:"user_id"`
	ExternalSource string    `gorm:"size:50;not null;uniqueIndex:idx_sdk_external_identity_source_id,priority:1" json:"external_source"`
	ExternalID     string    `gorm:"size:255;not null;uniqueIndex:idx_sdk_external_identity_source_id,priority:2" json:"external_id"`

	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`

	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

/*
 * BeforeCreate GORM 创建前钩子
 * @param tx - 当前数据库事务
 */
func (s *SDKExternalIdentity) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return nil
}

/* TableName 指定 GORM 表名为 sdk_external_identities */
func (SDKExternalIdentity) TableName() string {
	return "sdk_external_identities"
}
