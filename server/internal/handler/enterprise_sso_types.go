package handler

import (
	"server/internal/model"
)

type LDAPProviderConfigSafe struct {
	ID                     string            `json:"id"`
	Name                   string            `json:"name"`
	Slug                   string            `json:"slug"`
	Description            string            `json:"description,omitempty"`
	LDAPURL                string            `json:"ldap_url"`
	UseStartTLS            bool              `json:"use_starttls"`
	InsecureSkipVerify     bool              `json:"insecure_skip_verify"`
	BindDN                 string            `json:"bind_dn,omitempty"`
	BindPasswordConfigured bool              `json:"bind_password_configured"`
	BaseDN                 string            `json:"base_dn"`
	UserFilter             string            `json:"user_filter,omitempty"`
	ExternalIDAttr         string            `json:"external_id_attr,omitempty"`
	PrincipalAttr          string            `json:"principal_attr,omitempty"`
	EmailAttr              string            `json:"email_attr,omitempty"`
	UsernameAttr           string            `json:"username_attr,omitempty"`
	EmployeeIDAttr         string            `json:"employee_id_attr,omitempty"`
	DisplayNameAttr        string            `json:"display_name_attr,omitempty"`
	GivenNameAttr          string            `json:"given_name_attr,omitempty"`
	FamilyNameAttr         string            `json:"family_name_attr,omitempty"`
	GroupAttr              string            `json:"group_attr,omitempty"`
	RoleMappings           map[string]string `json:"role_mappings,omitempty"`
	DefaultRole            string            `json:"default_role"`
	Enabled                bool              `json:"enabled"`
	AutoCreateUser         bool              `json:"auto_create_user"`
	TrustEmailVerified     bool              `json:"trust_email_verified"`
	SyncProfile            bool              `json:"sync_profile"`
	SyncEnabled            bool              `json:"sync_enabled"`
	SyncIntervalMin        int               `json:"sync_interval_min"`
	SyncPageSize           int               `json:"sync_page_size"`
	LastSyncAt             *string           `json:"last_sync_at,omitempty"`
	LastSyncStatus         string            `json:"last_sync_status,omitempty"`
	IconURL                string            `json:"icon_url,omitempty"`
	ButtonText             string            `json:"button_text,omitempty"`
	CreatedAt              string            `json:"created_at"`
	UpdatedAt              string            `json:"updated_at"`
}

type SAMLProviderConfigSafe struct {
	ID                    string            `json:"id"`
	Name                  string            `json:"name"`
	Slug                  string            `json:"slug"`
	Description           string            `json:"description,omitempty"`
	MetadataURL           string            `json:"metadata_url,omitempty"`
	MetadataXMLConfigured bool              `json:"metadata_xml_configured"`
	SPEntityID            string            `json:"sp_entity_id,omitempty"`
	CertificateConfigured bool              `json:"certificate_configured"`
	PrivateKeyConfigured  bool              `json:"private_key_configured"`
	SignRequests          bool              `json:"sign_requests"`
	AllowIDPInitiated     bool              `json:"allow_idp_initiated"`
	DefaultRedirectPath   string            `json:"default_redirect_path,omitempty"`
	NameIDFormat          string            `json:"name_id_format,omitempty"`
	EmailAttribute        string            `json:"email_attribute,omitempty"`
	UsernameAttribute     string            `json:"username_attribute,omitempty"`
	EmployeeIDAttribute   string            `json:"employee_id_attribute,omitempty"`
	DisplayNameAttribute  string            `json:"display_name_attribute,omitempty"`
	GivenNameAttribute    string            `json:"given_name_attribute,omitempty"`
	FamilyNameAttribute   string            `json:"family_name_attribute,omitempty"`
	GroupAttribute        string            `json:"group_attribute,omitempty"`
	RoleMappings          map[string]string `json:"role_mappings,omitempty"`
	DefaultRole           string            `json:"default_role"`
	Enabled               bool              `json:"enabled"`
	AutoCreateUser        bool              `json:"auto_create_user"`
	TrustEmailVerified    bool              `json:"trust_email_verified"`
	SyncProfile           bool              `json:"sync_profile"`
	MetadataFetchedAt     *string           `json:"metadata_fetched_at,omitempty"`
	IconURL               string            `json:"icon_url,omitempty"`
	ButtonText            string            `json:"button_text,omitempty"`
	CreatedAt             string            `json:"created_at"`
	UpdatedAt             string            `json:"updated_at"`
}

type LDAPProviderUpdateConfig struct {
	Name               *string           `json:"name,omitempty"`
	Slug               *string           `json:"slug,omitempty"`
	Description        *string           `json:"description,omitempty"`
	LDAPURL            *string           `json:"ldap_url,omitempty"`
	UseStartTLS        *bool             `json:"use_starttls,omitempty"`
	InsecureSkipVerify *bool             `json:"insecure_skip_verify,omitempty"`
	BindDN             *string           `json:"bind_dn,omitempty"`
	BindPassword       *string           `json:"bind_password,omitempty"`
	BaseDN             *string           `json:"base_dn,omitempty"`
	UserFilter         *string           `json:"user_filter,omitempty"`
	ExternalIDAttr     *string           `json:"external_id_attr,omitempty"`
	PrincipalAttr      *string           `json:"principal_attr,omitempty"`
	EmailAttr          *string           `json:"email_attr,omitempty"`
	UsernameAttr       *string           `json:"username_attr,omitempty"`
	EmployeeIDAttr     *string           `json:"employee_id_attr,omitempty"`
	DisplayNameAttr    *string           `json:"display_name_attr,omitempty"`
	GivenNameAttr      *string           `json:"given_name_attr,omitempty"`
	FamilyNameAttr     *string           `json:"family_name_attr,omitempty"`
	GroupAttr          *string           `json:"group_attr,omitempty"`
	RoleMappings       map[string]string `json:"role_mappings,omitempty"`
	DefaultRole        *string           `json:"default_role,omitempty"`
	Enabled            *bool             `json:"enabled,omitempty"`
	AutoCreateUser     *bool             `json:"auto_create_user,omitempty"`
	TrustEmailVerified *bool             `json:"trust_email_verified,omitempty"`
	SyncProfile        *bool             `json:"sync_profile,omitempty"`
	SyncEnabled        *bool             `json:"sync_enabled,omitempty"`
	SyncIntervalMin    *int              `json:"sync_interval_min,omitempty"`
	SyncPageSize       *int              `json:"sync_page_size,omitempty"`
	IconURL            *string           `json:"icon_url,omitempty"`
	ButtonText         *string           `json:"button_text,omitempty"`
}

type SAMLProviderUpdateConfig struct {
	Name                 *string           `json:"name,omitempty"`
	Slug                 *string           `json:"slug,omitempty"`
	Description          *string           `json:"description,omitempty"`
	MetadataURL          *string           `json:"metadata_url,omitempty"`
	MetadataXML          *string           `json:"metadata_xml,omitempty"`
	SPEntityID           *string           `json:"sp_entity_id,omitempty"`
	CertificatePEM       *string           `json:"certificate_pem,omitempty"`
	PrivateKeyPEM        *string           `json:"private_key_pem,omitempty"`
	SignRequests         *bool             `json:"sign_requests,omitempty"`
	AllowIDPInitiated    *bool             `json:"allow_idp_initiated,omitempty"`
	DefaultRedirectPath  *string           `json:"default_redirect_path,omitempty"`
	NameIDFormat         *string           `json:"name_id_format,omitempty"`
	EmailAttribute       *string           `json:"email_attribute,omitempty"`
	UsernameAttribute    *string           `json:"username_attribute,omitempty"`
	EmployeeIDAttribute  *string           `json:"employee_id_attribute,omitempty"`
	DisplayNameAttribute *string           `json:"display_name_attribute,omitempty"`
	GivenNameAttribute   *string           `json:"given_name_attribute,omitempty"`
	FamilyNameAttribute  *string           `json:"family_name_attribute,omitempty"`
	GroupAttribute       *string           `json:"group_attribute,omitempty"`
	RoleMappings         map[string]string `json:"role_mappings,omitempty"`
	DefaultRole          *string           `json:"default_role,omitempty"`
	Enabled              *bool             `json:"enabled,omitempty"`
	AutoCreateUser       *bool             `json:"auto_create_user,omitempty"`
	TrustEmailVerified   *bool             `json:"trust_email_verified,omitempty"`
	SyncProfile          *bool             `json:"sync_profile,omitempty"`
	IconURL              *string           `json:"icon_url,omitempty"`
	ButtonText           *string           `json:"button_text,omitempty"`
}

func userRoleToString(role model.UserRole) string {
	if role == "" {
		return string(model.RoleUser)
	}
	return string(role)
}
