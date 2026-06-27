package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
 * RiskDecision 风控决策枚举
 * @value RiskDecisionPass      - 放行
 * @value RiskDecisionChallenge - 触发挑战
 * @value RiskDecisionMFA       - 要求 MFA
 * @value RiskDecisionBlock     - 阻断
 */
type RiskDecision string

const (
	RiskDecisionPass      RiskDecision = "pass"
	RiskDecisionChallenge RiskDecision = "challenge"
	RiskDecisionMFA       RiskDecision = "mfa"
	RiskDecisionBlock     RiskDecision = "block"
)

/* 固定风控事件原因，集中定义以便后台筛选、告警和测试复用 */
const (
	RiskEventReasonSuspiciousLogin                = "suspicious login"
	RiskEventReasonAdditionalVerificationRequired = "additional verification required"
	RiskEventReasonAccountLockedAfterFailedLogins = "account locked after failed login attempts"
	RiskEventReasonRefreshTokenReplay             = "refresh token replay"
	RiskEventReasonSDKExternalIdentityConflict    = "sdk external identity conflict"
	RiskEventReasonCrossOriginRequestBlocked      = "Cross-origin request blocked"
	RiskEventReasonCSRFTokenMissing               = "CSRF token missing"
	RiskEventReasonCSRFTokenHeaderMissing         = "CSRF token header missing"
	RiskEventReasonCSRFTokenMismatch              = "CSRF token mismatch"
)

var riskEventReasons = []string{
	RiskEventReasonSuspiciousLogin,
	RiskEventReasonAdditionalVerificationRequired,
	RiskEventReasonAccountLockedAfterFailedLogins,
	RiskEventReasonRefreshTokenReplay,
	RiskEventReasonSDKExternalIdentityConflict,
	RiskEventReasonCrossOriginRequestBlocked,
	RiskEventReasonCSRFTokenMissing,
	RiskEventReasonCSRFTokenHeaderMissing,
	RiskEventReasonCSRFTokenMismatch,
}

func RiskEventReasons() []string {
	return append([]string(nil), riskEventReasons...)
}

func IsRiskEventReason(reason string) bool {
	for _, item := range riskEventReasons {
		if item == reason {
			return true
		}
	}
	return false
}

/*
 * RiskEvent 风控事件模型
 * 功能：记录被风控模型判定的安全事件，避免与登录统计混用
 *       UserID 可为空（注册、未知用户或匿名攻击场景）
 * 表名：risk_events
 * 索引：user_id, decision, reason, created_at, (decision, created_at), (reason, created_at)
 */
type RiskEvent struct {
	ID        uuid.UUID    `gorm:"type:uuid;primaryKey" json:"id"`
	UserID    *uuid.UUID   `gorm:"type:uuid;index" json:"user_id,omitempty"`
	RiskScore int          `gorm:"not null" json:"risk_score"`
	Decision  RiskDecision `gorm:"size:20;not null;index;index:idx_risk_events_decision_created_at,priority:1" json:"decision"`
	IPAddress string       `gorm:"size:45" json:"ip_address,omitempty"`
	UserAgent string       `gorm:"type:text" json:"user_agent,omitempty"`
	Reason    string       `gorm:"size:255;index;index:idx_risk_events_reason_created_at,priority:1" json:"reason,omitempty"`
	CreatedAt time.Time    `gorm:"autoCreateTime;index;index:idx_risk_events_decision_created_at,priority:2;index:idx_risk_events_reason_created_at,priority:2" json:"created_at"`

	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

/*
 * BeforeCreate GORM 创建前钩子
 * @param tx - 当前数据库事务
 */
func (e *RiskEvent) BeforeCreate(tx *gorm.DB) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	return nil
}

/* TableName 指定 GORM 表名为 risk_events */
func (RiskEvent) TableName() string {
	return "risk_events"
}
