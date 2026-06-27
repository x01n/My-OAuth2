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
	ErrSAMLIdentityAlreadyExists = errors.New("saml identity already exists")
)

type SAMLProviderRepository struct {
	db *gorm.DB
}

func NewSAMLProviderRepository(db *gorm.DB) *SAMLProviderRepository {
	return &SAMLProviderRepository{db: db}
}

func (r *SAMLProviderRepository) FindAll() ([]model.SAMLProvider, error) {
	var providers []model.SAMLProvider
	err := r.db.Order("name ASC").Find(&providers).Error
	return providers, err
}

func (r *SAMLProviderRepository) FindAllEnabled() ([]model.SAMLProvider, error) {
	var providers []model.SAMLProvider
	err := r.db.Where("enabled = ?", true).Order("name ASC").Find(&providers).Error
	return providers, err
}

func (r *SAMLProviderRepository) FindByID(id uuid.UUID) (*model.SAMLProvider, error) {
	var provider model.SAMLProvider
	err := r.db.First(&provider, "id = ?", id).Error
	return &provider, err
}

func (r *SAMLProviderRepository) FindBySlug(slug string) (*model.SAMLProvider, error) {
	var provider model.SAMLProvider
	err := r.db.First(&provider, "slug = ?", slug).Error
	return &provider, err
}

func (r *SAMLProviderRepository) CreateProvider(provider *model.SAMLProvider) error {
	if provider.ID == uuid.Nil {
		provider.ID = uuid.New()
	}
	now := time.Now().UTC()
	if provider.CreatedAt.IsZero() {
		provider.CreatedAt = now
	}
	provider.UpdatedAt = now

	type samlProviderInsert struct {
		ID                   uuid.UUID
		Name                 string
		Slug                 string
		Description          string
		MetadataURL          string
		MetadataXML          string
		SPEntityID           string
		CertificatePEM       string
		PrivateKeyPEM        string
		SignRequests         bool
		AllowIDPInitiated    bool
		DefaultRedirectPath  string
		NameIDFormat         string
		EmailAttribute       string
		UsernameAttribute    string
		EmployeeIDAttribute  string
		DisplayNameAttribute string
		GivenNameAttribute   string
		FamilyNameAttribute  string
		GroupAttribute       string
		RoleMappings         string
		DefaultRole          model.UserRole
		Enabled              bool
		AutoCreateUser       bool
		TrustEmailVerified   bool
		SyncProfile          bool
		MetadataFetchedAt    *time.Time
		IconURL              string
		ButtonText           string
		CreatedAt            time.Time
		UpdatedAt            time.Time
	}

	row := samlProviderInsert{
		ID:                   provider.ID,
		Name:                 provider.Name,
		Slug:                 provider.Slug,
		Description:          provider.Description,
		MetadataURL:          provider.MetadataURL,
		MetadataXML:          provider.MetadataXML,
		SPEntityID:           provider.SPEntityID,
		CertificatePEM:       provider.CertificatePEM,
		PrivateKeyPEM:        provider.PrivateKeyPEM,
		SignRequests:         provider.SignRequests,
		AllowIDPInitiated:    provider.AllowIDPInitiated,
		DefaultRedirectPath:  provider.DefaultRedirectPath,
		NameIDFormat:         provider.NameIDFormat,
		EmailAttribute:       provider.EmailAttribute,
		UsernameAttribute:    provider.UsernameAttribute,
		EmployeeIDAttribute:  provider.EmployeeIDAttribute,
		DisplayNameAttribute: provider.DisplayNameAttribute,
		GivenNameAttribute:   provider.GivenNameAttribute,
		FamilyNameAttribute:  provider.FamilyNameAttribute,
		GroupAttribute:       provider.GroupAttribute,
		RoleMappings:         provider.RoleMappings,
		DefaultRole:          provider.DefaultRole,
		Enabled:              provider.Enabled,
		AutoCreateUser:       provider.AutoCreateUser,
		TrustEmailVerified:   provider.TrustEmailVerified,
		SyncProfile:          provider.SyncProfile,
		MetadataFetchedAt:    provider.MetadataFetchedAt,
		IconURL:              provider.IconURL,
		ButtonText:           provider.ButtonText,
		CreatedAt:            provider.CreatedAt,
		UpdatedAt:            provider.UpdatedAt,
	}

	return r.db.Table(provider.TableName()).Create(&row).Error
}

func (r *SAMLProviderRepository) UpdateProvider(provider *model.SAMLProvider) error {
	return r.db.Save(provider).Error
}

func (r *SAMLProviderRepository) DeleteProvider(id uuid.UUID) error {
	return r.db.Delete(&model.SAMLProvider{}, "id = ?", id).Error
}

func (r *SAMLProviderRepository) UpdateMetadataStatus(id uuid.UUID, fetchedAt time.Time, metadataXML string) error {
	return r.db.Model(&model.SAMLProvider{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"metadata_fetched_at": &fetchedAt,
			"metadata_xml":        metadataXML,
		}).Error
}

type SAMLIdentityRepository struct {
	db *gorm.DB
}

func NewSAMLIdentityRepository(db *gorm.DB) *SAMLIdentityRepository {
	return &SAMLIdentityRepository{db: db}
}

func (r *SAMLIdentityRepository) FindByExternalID(providerID uuid.UUID, externalID string) (*model.SAMLIdentity, error) {
	var identity model.SAMLIdentity
	err := r.db.First(&identity, "provider_id = ? AND external_id = ?", providerID, externalID).Error
	return &identity, err
}

func (r *SAMLIdentityRepository) FindByUserAndProvider(userID, providerID uuid.UUID) (*model.SAMLIdentity, error) {
	var identity model.SAMLIdentity
	err := r.db.First(&identity, "user_id = ? AND provider_id = ?", userID, providerID).Error
	return &identity, err
}

func (r *SAMLIdentityRepository) FindByUserID(userID uuid.UUID) ([]model.SAMLIdentity, error) {
	var identities []model.SAMLIdentity
	err := r.db.Preload("Provider").Where("user_id = ?", userID).Find(&identities).Error
	return identities, err
}

func (r *SAMLIdentityRepository) Create(identity *model.SAMLIdentity) error {
	result := r.db.Create(identity)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrDuplicatedKey) || strings.Contains(result.Error.Error(), "UNIQUE constraint failed: saml_identities.provider_id, saml_identities.external_id") {
			return ErrSAMLIdentityAlreadyExists
		}
		return result.Error
	}
	return nil
}

func (r *SAMLIdentityRepository) Update(identity *model.SAMLIdentity) error {
	return r.db.Save(identity).Error
}

func (r *SAMLIdentityRepository) Delete(id uuid.UUID) error {
	return r.db.Delete(&model.SAMLIdentity{}, "id = ?", id).Error
}

func (r *SAMLIdentityRepository) DeleteByUserID(userID uuid.UUID) error {
	return r.db.Delete(&model.SAMLIdentity{}, "user_id = ?", userID).Error
}
