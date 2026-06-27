package model

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/* RoleMappingMap 组/声明值到本地角色的映射 */
type RoleMappingMap map[string]UserRole

func parseRoleMappings(raw string) RoleMappingMap {
	mappings := make(RoleMappingMap)
	if strings.TrimSpace(raw) == "" {
		return mappings
	}
	_ = json.Unmarshal([]byte(raw), &mappings)
	return mappings
}

func marshalRoleMappings(mappings RoleMappingMap) string {
	data, _ := json.Marshal(mappings)
	return string(data)
}

func parseStringSliceJSON(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	var values []string
	_ = json.Unmarshal([]byte(raw), &values)
	if values == nil {
		return []string{}
	}
	return values
}

func marshalStringSliceJSON(values []string) string {
	data, _ := json.Marshal(values)
	return string(data)
}

/* LDAPProvider 企业目录提供者配置 */
type LDAPProvider struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	Name        string    `gorm:"size:100;not null;uniqueIndex" json:"name"`
	Slug        string    `gorm:"size:50;not null;uniqueIndex" json:"slug"`
	Description string    `gorm:"size:500" json:"description,omitempty"`

	LDAPURL            string `gorm:"size:500;not null" json:"ldap_url"`
	UseStartTLS        bool   `gorm:"default:true" json:"use_starttls"`
	InsecureSkipVerify bool   `gorm:"default:false" json:"insecure_skip_verify"`
	BindDN             string `gorm:"size:500" json:"bind_dn,omitempty"`
	BindPassword       string `gorm:"size:1000" json:"-"`
	BaseDN             string `gorm:"size:500;not null" json:"base_dn"`
	UserFilter         string `gorm:"size:1000" json:"user_filter,omitempty"`

	ExternalIDAttr   string `gorm:"size:100" json:"external_id_attr,omitempty"`
	PrincipalAttr    string `gorm:"size:100" json:"principal_attr,omitempty"`
	EmailAttr        string `gorm:"size:100" json:"email_attr,omitempty"`
	UsernameAttr     string `gorm:"size:100" json:"username_attr,omitempty"`
	EmployeeIDAttr   string `gorm:"size:100" json:"employee_id_attr,omitempty"`
	DisplayNameAttr  string `gorm:"size:100" json:"display_name_attr,omitempty"`
	GivenNameAttr    string `gorm:"size:100" json:"given_name_attr,omitempty"`
	FamilyNameAttr   string `gorm:"size:100" json:"family_name_attr,omitempty"`
	GroupAttr        string `gorm:"size:100" json:"group_attr,omitempty"`
	RoleMappings     string `gorm:"type:text" json:"-"`
	DefaultRole      UserRole `gorm:"size:20;default:user" json:"default_role"`

	Enabled            bool `gorm:"default:true" json:"enabled"`
	AutoCreateUser     bool `gorm:"default:true" json:"auto_create_user"`
	TrustEmailVerified bool `gorm:"default:true" json:"trust_email_verified"`
	SyncProfile        bool `gorm:"default:true" json:"sync_profile"`
	SyncEnabled        bool `gorm:"default:false" json:"sync_enabled"`
	SyncIntervalMin    int  `gorm:"default:60" json:"sync_interval_min"`
	SyncPageSize       int  `gorm:"default:200" json:"sync_page_size"`
	LastSyncAt         *time.Time `json:"last_sync_at,omitempty"`
	LastSyncStatus     string     `gorm:"size:2000" json:"last_sync_status,omitempty"`

	IconURL    string `gorm:"size:500" json:"icon_url,omitempty"`
	ButtonText string `gorm:"size:100" json:"button_text,omitempty"`

	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (p *LDAPProvider) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}

func (LDAPProvider) TableName() string {
	return "ldap_providers"
}

func (p *LDAPProvider) GetRoleMappings() RoleMappingMap {
	return parseRoleMappings(p.RoleMappings)
}

func (p *LDAPProvider) SetRoleMappings(mappings RoleMappingMap) {
	p.RoleMappings = marshalRoleMappings(mappings)
}

/* LDAPIdentity 本地用户与企业目录身份绑定 */
type LDAPIdentity struct {
	ID                 uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	UserID             uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_ldap_identity_user_provider,priority:1" json:"user_id"`
	ProviderID         uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_ldap_identity_user_provider,priority:2;uniqueIndex:idx_ldap_identity_provider_external,priority:1" json:"provider_id"`
	ExternalID         string    `gorm:"size:255;not null;uniqueIndex:idx_ldap_identity_provider_external,priority:2" json:"external_id"`
	Principal          string    `gorm:"size:255" json:"principal,omitempty"`
	ExternalEmail      string    `gorm:"size:255" json:"external_email,omitempty"`
	ExternalUsername   string    `gorm:"size:255" json:"external_username,omitempty"`
	ExternalEmployeeID string    `gorm:"size:255" json:"external_employee_id,omitempty"`
	Groups             string    `gorm:"type:text" json:"-"`
	LastSyncedAt       *time.Time `json:"last_synced_at,omitempty"`
	CreatedAt          time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt          time.Time  `gorm:"autoUpdateTime" json:"updated_at"`

	User     *User         `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Provider *LDAPProvider `gorm:"foreignKey:ProviderID" json:"provider,omitempty"`
}

func (i *LDAPIdentity) BeforeCreate(tx *gorm.DB) error {
	if i.ID == uuid.Nil {
		i.ID = uuid.New()
	}
	return nil
}

func (LDAPIdentity) TableName() string {
	return "ldap_identities"
}

func (i *LDAPIdentity) GetGroups() []string {
	return parseStringSliceJSON(i.Groups)
}

func (i *LDAPIdentity) SetGroups(groups []string) {
	i.Groups = marshalStringSliceJSON(groups)
}

/* SAMLProvider 企业 SAML 提供者配置 */
type SAMLProvider struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	Name        string    `gorm:"size:100;not null;uniqueIndex" json:"name"`
	Slug        string    `gorm:"size:50;not null;uniqueIndex" json:"slug"`
	Description string    `gorm:"size:500" json:"description,omitempty"`

	MetadataURL       string `gorm:"size:1000" json:"metadata_url,omitempty"`
	MetadataXML       string `gorm:"type:text" json:"-"`
	SPEntityID        string `gorm:"size:500" json:"sp_entity_id,omitempty"`
	CertificatePEM    string `gorm:"type:text" json:"-"`
	PrivateKeyPEM     string `gorm:"type:text" json:"-"`
	SignRequests      bool   `gorm:"default:true" json:"sign_requests"`
	AllowIDPInitiated bool   `gorm:"default:true" json:"allow_idp_initiated"`
	DefaultRedirectPath string `gorm:"size:500" json:"default_redirect_path,omitempty"`
	NameIDFormat      string `gorm:"size:255" json:"name_id_format,omitempty"`

	EmailAttribute      string `gorm:"size:255" json:"email_attribute,omitempty"`
	UsernameAttribute   string `gorm:"size:255" json:"username_attribute,omitempty"`
	EmployeeIDAttribute string `gorm:"size:255" json:"employee_id_attribute,omitempty"`
	DisplayNameAttribute string `gorm:"size:255" json:"display_name_attribute,omitempty"`
	GivenNameAttribute   string `gorm:"size:255" json:"given_name_attribute,omitempty"`
	FamilyNameAttribute  string `gorm:"size:255" json:"family_name_attribute,omitempty"`
	GroupAttribute       string `gorm:"size:255" json:"group_attribute,omitempty"`
	RoleMappings         string `gorm:"type:text" json:"-"`
	DefaultRole          UserRole `gorm:"size:20;default:user" json:"default_role"`

	Enabled            bool `gorm:"default:true" json:"enabled"`
	AutoCreateUser     bool `gorm:"default:true" json:"auto_create_user"`
	TrustEmailVerified bool `gorm:"default:true" json:"trust_email_verified"`
	SyncProfile        bool `gorm:"default:true" json:"sync_profile"`
	MetadataFetchedAt  *time.Time `json:"metadata_fetched_at,omitempty"`

	IconURL    string `gorm:"size:500" json:"icon_url,omitempty"`
	ButtonText string `gorm:"size:100" json:"button_text,omitempty"`

	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (p *SAMLProvider) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}

func (SAMLProvider) TableName() string {
	return "saml_providers"
}

func (p *SAMLProvider) GetRoleMappings() RoleMappingMap {
	return parseRoleMappings(p.RoleMappings)
}

func (p *SAMLProvider) SetRoleMappings(mappings RoleMappingMap) {
	p.RoleMappings = marshalRoleMappings(mappings)
}

/* SAMLIdentity 本地用户与 SAML 断言身份绑定 */
type SAMLIdentity struct {
	ID                 uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	UserID             uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_saml_identity_user_provider,priority:1" json:"user_id"`
	ProviderID         uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_saml_identity_user_provider,priority:2;uniqueIndex:idx_saml_identity_provider_external,priority:1" json:"provider_id"`
	ExternalID         string    `gorm:"size:500;not null;uniqueIndex:idx_saml_identity_provider_external,priority:2" json:"external_id"`
	NameIDFormat       string    `gorm:"size:255" json:"name_id_format,omitempty"`
	SessionIndex       string    `gorm:"size:255" json:"session_index,omitempty"`
	ExternalEmail      string    `gorm:"size:255" json:"external_email,omitempty"`
	ExternalUsername   string    `gorm:"size:255" json:"external_username,omitempty"`
	ExternalEmployeeID string    `gorm:"size:255" json:"external_employee_id,omitempty"`
	Groups             string    `gorm:"type:text" json:"-"`
	CreatedAt          time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt          time.Time `gorm:"autoUpdateTime" json:"updated_at"`

	User     *User         `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Provider *SAMLProvider `gorm:"foreignKey:ProviderID" json:"provider,omitempty"`
}

func (i *SAMLIdentity) BeforeCreate(tx *gorm.DB) error {
	if i.ID == uuid.Nil {
		i.ID = uuid.New()
	}
	return nil
}

func (SAMLIdentity) TableName() string {
	return "saml_identities"
}

func (i *SAMLIdentity) GetGroups() []string {
	return parseStringSliceJSON(i.Groups)
}

func (i *SAMLIdentity) SetGroups(groups []string) {
	i.Groups = marshalStringSliceJSON(groups)
}
