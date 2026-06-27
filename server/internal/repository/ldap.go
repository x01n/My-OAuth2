package repository

import (
	"errors"
	"strings"
	"time"

	"server/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

var (
	ErrLDAPIdentityAlreadyExists = errors.New("ldap identity already exists")
)

type LDAPProviderRepository struct {
	db *gorm.DB
}

func NewLDAPProviderRepository(db *gorm.DB) *LDAPProviderRepository {
	return &LDAPProviderRepository{db: db}
}

func (r *LDAPProviderRepository) FindAll() ([]model.LDAPProvider, error) {
	var providers []model.LDAPProvider
	err := r.db.Order("name ASC").Find(&providers).Error
	return providers, err
}

func (r *LDAPProviderRepository) FindAllEnabled() ([]model.LDAPProvider, error) {
	var providers []model.LDAPProvider
	err := r.db.Where("enabled = ?", true).Order("name ASC").Find(&providers).Error
	return providers, err
}

func (r *LDAPProviderRepository) FindAllSyncEnabled() ([]model.LDAPProvider, error) {
	var providers []model.LDAPProvider
	err := r.db.Where("enabled = ? AND sync_enabled = ?", true, true).Order("name ASC").Find(&providers).Error
	return providers, err
}

func (r *LDAPProviderRepository) FindByID(id uuid.UUID) (*model.LDAPProvider, error) {
	var provider model.LDAPProvider
	err := r.db.First(&provider, "id = ?", id).Error
	return &provider, err
}

func (r *LDAPProviderRepository) FindBySlug(slug string) (*model.LDAPProvider, error) {
	var provider model.LDAPProvider
	err := r.db.First(&provider, "slug = ?", slug).Error
	return &provider, err
}

func (r *LDAPProviderRepository) CreateProvider(provider *model.LDAPProvider) error {
	if provider.ID == uuid.Nil {
		provider.ID = uuid.New()
	}
	now := time.Now().UTC()
	if provider.CreatedAt.IsZero() {
		provider.CreatedAt = now
	}
	provider.UpdatedAt = now

	type ldapProviderInsert struct {
		ID                 uuid.UUID
		Name               string
		Slug               string
		Description        string
		LDAPURL            string
		UseStartTLS        bool
		InsecureSkipVerify bool
		BindDN             string
		BindPassword       string
		BaseDN             string
		UserFilter         string
		ExternalIDAttr     string
		PrincipalAttr      string
		EmailAttr          string
		UsernameAttr       string
		EmployeeIDAttr     string
		DisplayNameAttr    string
		GivenNameAttr      string
		FamilyNameAttr     string
		GroupAttr          string
		RoleMappings       string
		DefaultRole        model.UserRole
		Enabled            bool
		AutoCreateUser     bool
		TrustEmailVerified bool
		SyncProfile        bool
		SyncEnabled        bool
		SyncIntervalMin    int
		SyncPageSize       int
		LastSyncAt         *time.Time
		LastSyncStatus     string
		IconURL            string
		ButtonText         string
		CreatedAt          time.Time
		UpdatedAt          time.Time
	}

	row := ldapProviderInsert{
		ID:                 provider.ID,
		Name:               provider.Name,
		Slug:               provider.Slug,
		Description:        provider.Description,
		LDAPURL:            provider.LDAPURL,
		UseStartTLS:        provider.UseStartTLS,
		InsecureSkipVerify: provider.InsecureSkipVerify,
		BindDN:             provider.BindDN,
		BindPassword:       provider.BindPassword,
		BaseDN:             provider.BaseDN,
		UserFilter:         provider.UserFilter,
		ExternalIDAttr:     provider.ExternalIDAttr,
		PrincipalAttr:      provider.PrincipalAttr,
		EmailAttr:          provider.EmailAttr,
		UsernameAttr:       provider.UsernameAttr,
		EmployeeIDAttr:     provider.EmployeeIDAttr,
		DisplayNameAttr:    provider.DisplayNameAttr,
		GivenNameAttr:      provider.GivenNameAttr,
		FamilyNameAttr:     provider.FamilyNameAttr,
		GroupAttr:          provider.GroupAttr,
		RoleMappings:       provider.RoleMappings,
		DefaultRole:        provider.DefaultRole,
		Enabled:            provider.Enabled,
		AutoCreateUser:     provider.AutoCreateUser,
		TrustEmailVerified: provider.TrustEmailVerified,
		SyncProfile:        provider.SyncProfile,
		SyncEnabled:        provider.SyncEnabled,
		SyncIntervalMin:    provider.SyncIntervalMin,
		SyncPageSize:       provider.SyncPageSize,
		LastSyncAt:         provider.LastSyncAt,
		LastSyncStatus:     provider.LastSyncStatus,
		IconURL:            provider.IconURL,
		ButtonText:         provider.ButtonText,
		CreatedAt:          provider.CreatedAt,
		UpdatedAt:          provider.UpdatedAt,
	}

	return r.db.Table(provider.TableName()).Create(&row).Error
}

func (r *LDAPProviderRepository) UpdateProvider(provider *model.LDAPProvider) error {
	return r.db.Save(provider).Error
}

func (r *LDAPProviderRepository) DeleteProvider(id uuid.UUID) error {
	return r.db.Delete(&model.LDAPProvider{}, "id = ?", id).Error
}

func (r *LDAPProviderRepository) UpdateSyncStatus(id uuid.UUID, syncedAt time.Time, status string) error {
	return r.db.Model(&model.LDAPProvider{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"last_sync_at":     &syncedAt,
			"last_sync_status": status,
		}).Error
}

type LDAPIdentityRepository struct {
	db *gorm.DB
}

func NewLDAPIdentityRepository(db *gorm.DB) *LDAPIdentityRepository {
	return &LDAPIdentityRepository{db: db}
}

func (r *LDAPIdentityRepository) FindByExternalID(providerID uuid.UUID, externalID string) (*model.LDAPIdentity, error) {
	var identity model.LDAPIdentity
	err := r.db.First(&identity, "provider_id = ? AND external_id = ?", providerID, externalID).Error
	return &identity, err
}

func (r *LDAPIdentityRepository) FindByPrincipal(providerID uuid.UUID, principal string) (*model.LDAPIdentity, error) {
	var identity model.LDAPIdentity
	err := r.db.First(&identity, "provider_id = ? AND principal = ?", providerID, principal).Error
	return &identity, err
}

func (r *LDAPIdentityRepository) FindByUserAndProvider(userID, providerID uuid.UUID) (*model.LDAPIdentity, error) {
	var identity model.LDAPIdentity
	err := r.db.First(&identity, "user_id = ? AND provider_id = ?", userID, providerID).Error
	return &identity, err
}

func (r *LDAPIdentityRepository) FindAllByProvider(providerID uuid.UUID) ([]model.LDAPIdentity, error) {
	var identities []model.LDAPIdentity
	err := r.db.Where("provider_id = ?", providerID).Order("created_at ASC").Find(&identities).Error
	return identities, err
}

func (r *LDAPIdentityRepository) FindByUserID(userID uuid.UUID) ([]model.LDAPIdentity, error) {
	var identities []model.LDAPIdentity
	err := r.db.Preload("Provider").Where("user_id = ?", userID).Find(&identities).Error
	return identities, err
}

func (r *LDAPIdentityRepository) Create(identity *model.LDAPIdentity) error {
	result := r.db.Create(identity)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrDuplicatedKey) || strings.Contains(result.Error.Error(), "UNIQUE constraint failed: ldap_identities.provider_id, ldap_identities.external_id") {
			return ErrLDAPIdentityAlreadyExists
		}
		return result.Error
	}
	return nil
}

func (r *LDAPIdentityRepository) Update(identity *model.LDAPIdentity) error {
	return r.db.Save(identity).Error
}

func (r *LDAPIdentityRepository) Delete(id uuid.UUID) error {
	return r.db.Delete(&model.LDAPIdentity{}, "id = ?", id).Error
}

func (r *LDAPIdentityRepository) DeleteByUserID(userID uuid.UUID) error {
	return r.db.Delete(&model.LDAPIdentity{}, "user_id = ?", userID).Error
}
