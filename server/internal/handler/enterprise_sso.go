package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"server/internal/model"
	"server/internal/repository"
	"server/pkg/audit"

	"github.com/crewjam/saml/samlsp"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type EnterpriseSSOHandler struct {
	ldapProviderRepo *repository.LDAPProviderRepository
	samlProviderRepo *repository.SAMLProviderRepository
	baseURL          string
	httpClient       *http.Client
}

func NewEnterpriseSSOHandler(
	ldapProviderRepo *repository.LDAPProviderRepository,
	samlProviderRepo *repository.SAMLProviderRepository,
	baseURL string,
) *EnterpriseSSOHandler {
	return &EnterpriseSSOHandler{
		ldapProviderRepo: ldapProviderRepo,
		samlProviderRepo: samlProviderRepo,
		baseURL:          strings.TrimRight(baseURL, "/"),
		httpClient:       &http.Client{Timeout: 15 * time.Second},
	}
}

func (h *EnterpriseSSOHandler) ListPublicProviders(c *gin.Context) {
	ldapProviders, err := h.ldapProviderRepo.FindAllEnabled()
	if err != nil {
		InternalError(c, "Failed to fetch LDAP providers")
		return
	}
	samlProviders, err := h.samlProviderRepo.FindAllEnabled()
	if err != nil {
		InternalError(c, "Failed to fetch SAML providers")
		return
	}

	Success(c, gin.H{
		"ldap_providers": toPublicEnterpriseProvidersFromLDAP(ldapProviders),
		"saml_providers": toPublicEnterpriseProvidersFromSAML(samlProviders),
	})
}

func (h *EnterpriseSSOHandler) AdminListLDAPProviders(c *gin.Context) {
	providers, err := h.ldapProviderRepo.FindAll()
	if err != nil {
		InternalError(c, "Failed to fetch LDAP providers")
		return
	}
	result := make([]LDAPProviderConfigSafe, 0, len(providers))
	for _, provider := range providers {
		result = append(result, toLDAPProviderConfigSafe(provider))
	}
	Success(c, gin.H{"providers": result})
}

func (h *EnterpriseSSOHandler) AdminCreateLDAPProvider(c *gin.Context) {
	var req LDAPProviderUpdateConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}
	provider, err := newLDAPProviderFromUpdateConfig(req)
	if err != nil {
		BadRequest(c, err.Error())
		return
	}
	if err := h.ldapProviderRepo.CreateProvider(provider); err != nil {
		InternalError(c, "Failed to create LDAP provider: "+err.Error())
		return
	}
	audit.Log(audit.ActionProviderCreate, audit.ResultSuccess, getActorID(c), provider.ID.String(), c.ClientIP(), "provider", provider.Slug, "provider_type", "ldap")
	Success(c, toLDAPProviderConfigSafe(*provider))
}

func (h *EnterpriseSSOHandler) AdminUpdateLDAPProvider(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		BadRequest(c, "Invalid provider ID")
		return
	}
	provider, err := h.ldapProviderRepo.FindByID(id)
	if err != nil {
		NotFound(c, "LDAP provider not found")
		return
	}
	var req LDAPProviderUpdateConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}
	if err := applyLDAPProviderUpdate(provider, req); err != nil {
		BadRequest(c, err.Error())
		return
	}
	if err := h.ldapProviderRepo.UpdateProvider(provider); err != nil {
		InternalError(c, "Failed to update LDAP provider: "+err.Error())
		return
	}
	Success(c, toLDAPProviderConfigSafe(*provider))
}

func (h *EnterpriseSSOHandler) AdminDeleteLDAPProvider(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		BadRequest(c, "Invalid provider ID")
		return
	}
	if err := h.ldapProviderRepo.DeleteProvider(id); err != nil {
		InternalError(c, "Failed to delete LDAP provider")
		return
	}
	audit.Log(audit.ActionProviderDelete, audit.ResultSuccess, getActorID(c), id.String(), c.ClientIP(), "provider_type", "ldap")
	Success(c, gin.H{"message": "LDAP provider deleted"})
}

func (h *EnterpriseSSOHandler) AdminListSAMLProviders(c *gin.Context) {
	providers, err := h.samlProviderRepo.FindAll()
	if err != nil {
		InternalError(c, "Failed to fetch SAML providers")
		return
	}
	result := make([]SAMLProviderConfigSafe, 0, len(providers))
	for _, provider := range providers {
		result = append(result, toSAMLProviderConfigSafe(provider))
	}
	Success(c, gin.H{"providers": result})
}

func (h *EnterpriseSSOHandler) AdminCreateSAMLProvider(c *gin.Context) {
	var req SAMLProviderUpdateConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}
	provider, err := h.newSAMLProviderFromUpdateConfig(req)
	if err != nil {
		BadRequest(c, err.Error())
		return
	}
	if err := h.samlProviderRepo.CreateProvider(provider); err != nil {
		InternalError(c, "Failed to create SAML provider: "+err.Error())
		return
	}
	audit.Log(audit.ActionProviderCreate, audit.ResultSuccess, getActorID(c), provider.ID.String(), c.ClientIP(), "provider", provider.Slug, "provider_type", "saml")
	Success(c, toSAMLProviderConfigSafe(*provider))
}

func (h *EnterpriseSSOHandler) AdminUpdateSAMLProvider(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		BadRequest(c, "Invalid provider ID")
		return
	}
	provider, err := h.samlProviderRepo.FindByID(id)
	if err != nil {
		NotFound(c, "SAML provider not found")
		return
	}
	var req SAMLProviderUpdateConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}
	if err := h.applySAMLProviderUpdate(provider, req); err != nil {
		BadRequest(c, err.Error())
		return
	}
	if err := h.samlProviderRepo.UpdateProvider(provider); err != nil {
		InternalError(c, "Failed to update SAML provider: "+err.Error())
		return
	}
	Success(c, toSAMLProviderConfigSafe(*provider))
}

func (h *EnterpriseSSOHandler) AdminDeleteSAMLProvider(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		BadRequest(c, "Invalid provider ID")
		return
	}
	if err := h.samlProviderRepo.DeleteProvider(id); err != nil {
		InternalError(c, "Failed to delete SAML provider")
		return
	}
	audit.Log(audit.ActionProviderDelete, audit.ResultSuccess, getActorID(c), id.String(), c.ClientIP(), "provider_type", "saml")
	Success(c, gin.H{"message": "SAML provider deleted"})
}

func (h *EnterpriseSSOHandler) AdminRefreshSAMLMetadata(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		BadRequest(c, "Invalid provider ID")
		return
	}
	provider, err := h.samlProviderRepo.FindByID(id)
	if err != nil {
		NotFound(c, "SAML provider not found")
		return
	}
	metadataXML, fetchedAt, err := h.resolveSAMLMetadata(provider.MetadataURL, provider.MetadataXML)
	if err != nil {
		BadRequest(c, err.Error())
		return
	}
	provider.MetadataXML = metadataXML
	provider.MetadataFetchedAt = &fetchedAt
	if err := h.samlProviderRepo.UpdateProvider(provider); err != nil {
		InternalError(c, "Failed to refresh SAML metadata")
		return
	}
	Success(c, toSAMLProviderConfigSafe(*provider))
}

type enterpriseProviderPublic struct {
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	IconURL     string `json:"icon_url,omitempty"`
	ButtonText  string `json:"button_text,omitempty"`
}

func toPublicEnterpriseProvidersFromLDAP(providers []model.LDAPProvider) []enterpriseProviderPublic {
	result := make([]enterpriseProviderPublic, 0, len(providers))
	for _, provider := range providers {
		result = append(result, enterpriseProviderPublic{
			Slug:        provider.Slug,
			Name:        provider.Name,
			Description: provider.Description,
			IconURL:     provider.IconURL,
			ButtonText:  provider.ButtonText,
		})
	}
	return result
}

func toPublicEnterpriseProvidersFromSAML(providers []model.SAMLProvider) []enterpriseProviderPublic {
	result := make([]enterpriseProviderPublic, 0, len(providers))
	for _, provider := range providers {
		result = append(result, enterpriseProviderPublic{
			Slug:        provider.Slug,
			Name:        provider.Name,
			Description: provider.Description,
			IconURL:     provider.IconURL,
			ButtonText:  provider.ButtonText,
		})
	}
	return result
}

func toLDAPProviderConfigSafe(provider model.LDAPProvider) LDAPProviderConfigSafe {
	var lastSyncAt *string
	if provider.LastSyncAt != nil {
		formatted := provider.LastSyncAt.Format(time.RFC3339)
		lastSyncAt = &formatted
	}
	return LDAPProviderConfigSafe{
		ID:                     provider.ID.String(),
		Name:                   provider.Name,
		Slug:                   provider.Slug,
		Description:            provider.Description,
		LDAPURL:                provider.LDAPURL,
		UseStartTLS:            provider.UseStartTLS,
		InsecureSkipVerify:     provider.InsecureSkipVerify,
		BindDN:                 provider.BindDN,
		BindPasswordConfigured: provider.BindPassword != "",
		BaseDN:                 provider.BaseDN,
		UserFilter:             provider.UserFilter,
		ExternalIDAttr:         provider.ExternalIDAttr,
		PrincipalAttr:          provider.PrincipalAttr,
		EmailAttr:              provider.EmailAttr,
		UsernameAttr:           provider.UsernameAttr,
		EmployeeIDAttr:         provider.EmployeeIDAttr,
		DisplayNameAttr:        provider.DisplayNameAttr,
		GivenNameAttr:          provider.GivenNameAttr,
		FamilyNameAttr:         provider.FamilyNameAttr,
		GroupAttr:              provider.GroupAttr,
		RoleMappings:           roleMappingsToStrings(provider.GetRoleMappings()),
		DefaultRole:            userRoleToString(provider.DefaultRole),
		Enabled:                provider.Enabled,
		AutoCreateUser:         provider.AutoCreateUser,
		TrustEmailVerified:     provider.TrustEmailVerified,
		SyncProfile:            provider.SyncProfile,
		SyncEnabled:            provider.SyncEnabled,
		SyncIntervalMin:        provider.SyncIntervalMin,
		SyncPageSize:           provider.SyncPageSize,
		LastSyncAt:             lastSyncAt,
		LastSyncStatus:         provider.LastSyncStatus,
		IconURL:                provider.IconURL,
		ButtonText:             provider.ButtonText,
		CreatedAt:              provider.CreatedAt.Format(time.RFC3339),
		UpdatedAt:              provider.UpdatedAt.Format(time.RFC3339),
	}
}

func toSAMLProviderConfigSafe(provider model.SAMLProvider) SAMLProviderConfigSafe {
	var metadataFetchedAt *string
	if provider.MetadataFetchedAt != nil {
		formatted := provider.MetadataFetchedAt.Format(time.RFC3339)
		metadataFetchedAt = &formatted
	}
	return SAMLProviderConfigSafe{
		ID:                    provider.ID.String(),
		Name:                  provider.Name,
		Slug:                  provider.Slug,
		Description:           provider.Description,
		MetadataURL:           provider.MetadataURL,
		MetadataXMLConfigured: provider.MetadataXML != "",
		SPEntityID:            provider.SPEntityID,
		CertificateConfigured: provider.CertificatePEM != "",
		PrivateKeyConfigured:  provider.PrivateKeyPEM != "",
		SignRequests:          provider.SignRequests,
		AllowIDPInitiated:     provider.AllowIDPInitiated,
		DefaultRedirectPath:   provider.DefaultRedirectPath,
		NameIDFormat:          provider.NameIDFormat,
		EmailAttribute:        provider.EmailAttribute,
		UsernameAttribute:     provider.UsernameAttribute,
		EmployeeIDAttribute:   provider.EmployeeIDAttribute,
		DisplayNameAttribute:  provider.DisplayNameAttribute,
		GivenNameAttribute:    provider.GivenNameAttribute,
		FamilyNameAttribute:   provider.FamilyNameAttribute,
		GroupAttribute:        provider.GroupAttribute,
		RoleMappings:          roleMappingsToStrings(provider.GetRoleMappings()),
		DefaultRole:           userRoleToString(provider.DefaultRole),
		Enabled:               provider.Enabled,
		AutoCreateUser:        provider.AutoCreateUser,
		TrustEmailVerified:    provider.TrustEmailVerified,
		SyncProfile:           provider.SyncProfile,
		MetadataFetchedAt:     metadataFetchedAt,
		IconURL:               provider.IconURL,
		ButtonText:            provider.ButtonText,
		CreatedAt:             provider.CreatedAt.Format(time.RFC3339),
		UpdatedAt:             provider.UpdatedAt.Format(time.RFC3339),
	}
}

func newLDAPProviderFromUpdateConfig(req LDAPProviderUpdateConfig) (*model.LDAPProvider, error) {
	provider := &model.LDAPProvider{}
	if err := applyLDAPProviderUpdate(provider, req); err != nil {
		return nil, err
	}
	return provider, nil
}

func applyLDAPProviderUpdate(provider *model.LDAPProvider, req LDAPProviderUpdateConfig) error {
	if req.Name != nil {
		provider.Name = strings.TrimSpace(*req.Name)
	}
	if req.Slug != nil {
		provider.Slug = normalizeProviderSlug(*req.Slug)
	}
	if req.Description != nil {
		provider.Description = strings.TrimSpace(*req.Description)
	}
	if req.LDAPURL != nil {
		provider.LDAPURL = strings.TrimSpace(*req.LDAPURL)
	}
	if req.UseStartTLS != nil {
		provider.UseStartTLS = *req.UseStartTLS
	}
	if req.InsecureSkipVerify != nil {
		provider.InsecureSkipVerify = *req.InsecureSkipVerify
	}
	if req.BindDN != nil {
		provider.BindDN = strings.TrimSpace(*req.BindDN)
	}
	if req.BindPassword != nil && *req.BindPassword != "" {
		provider.BindPassword = *req.BindPassword
	}
	if req.BaseDN != nil {
		provider.BaseDN = strings.TrimSpace(*req.BaseDN)
	}
	if req.UserFilter != nil {
		provider.UserFilter = strings.TrimSpace(*req.UserFilter)
	}
	if req.ExternalIDAttr != nil {
		provider.ExternalIDAttr = defaultString(*req.ExternalIDAttr, "dn")
	}
	if req.PrincipalAttr != nil {
		provider.PrincipalAttr = defaultString(*req.PrincipalAttr, "userPrincipalName")
	}
	if req.EmailAttr != nil {
		provider.EmailAttr = defaultString(*req.EmailAttr, "mail")
	}
	if req.UsernameAttr != nil {
		provider.UsernameAttr = defaultString(*req.UsernameAttr, "sAMAccountName")
	}
	if req.EmployeeIDAttr != nil {
		provider.EmployeeIDAttr = defaultString(*req.EmployeeIDAttr, "employeeID")
	}
	if req.DisplayNameAttr != nil {
		provider.DisplayNameAttr = defaultString(*req.DisplayNameAttr, "displayName")
	}
	if req.GivenNameAttr != nil {
		provider.GivenNameAttr = defaultString(*req.GivenNameAttr, "givenName")
	}
	if req.FamilyNameAttr != nil {
		provider.FamilyNameAttr = defaultString(*req.FamilyNameAttr, "sn")
	}
	if req.GroupAttr != nil {
		provider.GroupAttr = defaultString(*req.GroupAttr, "memberOf")
	}
	if req.RoleMappings != nil {
		provider.SetRoleMappings(stringRoleMappingsToModel(req.RoleMappings))
	}
	if req.DefaultRole != nil {
		provider.DefaultRole = parseUserRole(*req.DefaultRole)
	}
	if req.Enabled != nil {
		provider.Enabled = *req.Enabled
	}
	if req.AutoCreateUser != nil {
		provider.AutoCreateUser = *req.AutoCreateUser
	}
	if req.TrustEmailVerified != nil {
		provider.TrustEmailVerified = *req.TrustEmailVerified
	}
	if req.SyncProfile != nil {
		provider.SyncProfile = *req.SyncProfile
	}
	if req.SyncEnabled != nil {
		provider.SyncEnabled = *req.SyncEnabled
	}
	if req.SyncIntervalMin != nil {
		provider.SyncIntervalMin = *req.SyncIntervalMin
	}
	if req.SyncPageSize != nil {
		provider.SyncPageSize = *req.SyncPageSize
	}
	if req.IconURL != nil {
		provider.IconURL = strings.TrimSpace(*req.IconURL)
	}
	if req.ButtonText != nil {
		provider.ButtonText = strings.TrimSpace(*req.ButtonText)
	}

	if provider.Name == "" || provider.Slug == "" || provider.LDAPURL == "" || provider.BaseDN == "" {
		return fmt.Errorf("name, slug, ldap_url and base_dn are required")
	}
	if provider.SyncIntervalMin <= 0 {
		provider.SyncIntervalMin = 60
	}
	if provider.SyncPageSize <= 0 {
		provider.SyncPageSize = 200
	}
	if provider.ExternalIDAttr == "" {
		provider.ExternalIDAttr = "dn"
	}
	if provider.PrincipalAttr == "" {
		provider.PrincipalAttr = "userPrincipalName"
	}
	if provider.EmailAttr == "" {
		provider.EmailAttr = "mail"
	}
	if provider.UsernameAttr == "" {
		provider.UsernameAttr = "sAMAccountName"
	}
	if provider.EmployeeIDAttr == "" {
		provider.EmployeeIDAttr = "employeeID"
	}
	if provider.DisplayNameAttr == "" {
		provider.DisplayNameAttr = "displayName"
	}
	if provider.GivenNameAttr == "" {
		provider.GivenNameAttr = "givenName"
	}
	if provider.FamilyNameAttr == "" {
		provider.FamilyNameAttr = "sn"
	}
	if provider.GroupAttr == "" {
		provider.GroupAttr = "memberOf"
	}
	if provider.DefaultRole == "" {
		provider.DefaultRole = model.RoleUser
	}
	return nil
}

func (h *EnterpriseSSOHandler) newSAMLProviderFromUpdateConfig(req SAMLProviderUpdateConfig) (*model.SAMLProvider, error) {
	provider := &model.SAMLProvider{}
	if err := h.applySAMLProviderUpdate(provider, req); err != nil {
		return nil, err
	}
	return provider, nil
}

func (h *EnterpriseSSOHandler) applySAMLProviderUpdate(provider *model.SAMLProvider, req SAMLProviderUpdateConfig) error {
	if req.Name != nil {
		provider.Name = strings.TrimSpace(*req.Name)
	}
	if req.Slug != nil {
		provider.Slug = normalizeProviderSlug(*req.Slug)
	}
	if req.Description != nil {
		provider.Description = strings.TrimSpace(*req.Description)
	}
	if req.MetadataURL != nil {
		provider.MetadataURL = strings.TrimSpace(*req.MetadataURL)
	}
	if req.MetadataXML != nil {
		provider.MetadataXML = strings.TrimSpace(*req.MetadataXML)
	}
	if req.SPEntityID != nil {
		provider.SPEntityID = strings.TrimSpace(*req.SPEntityID)
	}
	if req.CertificatePEM != nil && *req.CertificatePEM != "" {
		provider.CertificatePEM = *req.CertificatePEM
	}
	if req.PrivateKeyPEM != nil && *req.PrivateKeyPEM != "" {
		provider.PrivateKeyPEM = *req.PrivateKeyPEM
	}
	if req.SignRequests != nil {
		provider.SignRequests = *req.SignRequests
	}
	if req.AllowIDPInitiated != nil {
		provider.AllowIDPInitiated = *req.AllowIDPInitiated
	}
	if req.DefaultRedirectPath != nil {
		provider.DefaultRedirectPath = strings.TrimSpace(*req.DefaultRedirectPath)
	}
	if req.NameIDFormat != nil {
		provider.NameIDFormat = strings.TrimSpace(*req.NameIDFormat)
	}
	if req.EmailAttribute != nil {
		provider.EmailAttribute = defaultString(*req.EmailAttribute, "mail")
	}
	if req.UsernameAttribute != nil {
		provider.UsernameAttribute = defaultString(*req.UsernameAttribute, "uid")
	}
	if req.EmployeeIDAttribute != nil {
		provider.EmployeeIDAttribute = strings.TrimSpace(*req.EmployeeIDAttribute)
	}
	if req.DisplayNameAttribute != nil {
		provider.DisplayNameAttribute = defaultString(*req.DisplayNameAttribute, "displayName")
	}
	if req.GivenNameAttribute != nil {
		provider.GivenNameAttribute = defaultString(*req.GivenNameAttribute, "givenName")
	}
	if req.FamilyNameAttribute != nil {
		provider.FamilyNameAttribute = defaultString(*req.FamilyNameAttribute, "sn")
	}
	if req.GroupAttribute != nil {
		provider.GroupAttribute = defaultString(*req.GroupAttribute, "memberOf")
	}
	if req.RoleMappings != nil {
		provider.SetRoleMappings(stringRoleMappingsToModel(req.RoleMappings))
	}
	if req.DefaultRole != nil {
		provider.DefaultRole = parseUserRole(*req.DefaultRole)
	}
	if req.Enabled != nil {
		provider.Enabled = *req.Enabled
	}
	if req.AutoCreateUser != nil {
		provider.AutoCreateUser = *req.AutoCreateUser
	}
	if req.TrustEmailVerified != nil {
		provider.TrustEmailVerified = *req.TrustEmailVerified
	}
	if req.SyncProfile != nil {
		provider.SyncProfile = *req.SyncProfile
	}
	if req.IconURL != nil {
		provider.IconURL = strings.TrimSpace(*req.IconURL)
	}
	if req.ButtonText != nil {
		provider.ButtonText = strings.TrimSpace(*req.ButtonText)
	}

	if provider.Name == "" || provider.Slug == "" {
		return fmt.Errorf("name and slug are required")
	}
	if provider.DefaultRedirectPath == "" {
		provider.DefaultRedirectPath = "/dashboard"
	}
	if provider.SPEntityID == "" && h.baseURL != "" {
		provider.SPEntityID = h.baseURL + "/api/federation/saml/" + provider.Slug + "/metadata"
	}
	if provider.EmailAttribute == "" {
		provider.EmailAttribute = "mail"
	}
	if provider.UsernameAttribute == "" {
		provider.UsernameAttribute = "uid"
	}
	if provider.DisplayNameAttribute == "" {
		provider.DisplayNameAttribute = "displayName"
	}
	if provider.GivenNameAttribute == "" {
		provider.GivenNameAttribute = "givenName"
	}
	if provider.FamilyNameAttribute == "" {
		provider.FamilyNameAttribute = "sn"
	}
	if provider.GroupAttribute == "" {
		provider.GroupAttribute = "memberOf"
	}
	if provider.DefaultRole == "" {
		provider.DefaultRole = model.RoleUser
	}
	if provider.CertificatePEM == "" || provider.PrivateKeyPEM == "" {
		certPEM, keyPEM, err := generateSAMLKeyPair(provider.Name)
		if err != nil {
			return err
		}
		if provider.CertificatePEM == "" {
			provider.CertificatePEM = certPEM
		}
		if provider.PrivateKeyPEM == "" {
			provider.PrivateKeyPEM = keyPEM
		}
	}
	if provider.MetadataURL == "" && provider.MetadataXML == "" && provider.Enabled {
		return fmt.Errorf("metadata_url or metadata_xml is required for enabled SAML providers")
	}
	if provider.MetadataURL != "" || provider.MetadataXML != "" {
		metadataXML, fetchedAt, err := h.resolveSAMLMetadata(provider.MetadataURL, provider.MetadataXML)
		if err != nil {
			return err
		}
		provider.MetadataXML = metadataXML
		provider.MetadataFetchedAt = &fetchedAt
	}
	return nil
}

func (h *EnterpriseSSOHandler) resolveSAMLMetadata(metadataURL, metadataXML string) (string, time.Time, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if strings.TrimSpace(metadataXML) != "" {
		if _, err := samlsp.ParseMetadata([]byte(metadataXML)); err != nil {
			return "", time.Time{}, fmt.Errorf("invalid metadata_xml: %w", err)
		}
		return metadataXML, time.Now().UTC(), nil
	}
	if strings.TrimSpace(metadataURL) == "" {
		return "", time.Time{}, fmt.Errorf("metadata_url or metadata_xml is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to fetch metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", time.Time{}, fmt.Errorf("failed to fetch metadata: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", time.Time{}, err
	}
	if _, err := samlsp.ParseMetadata(body); err != nil {
		return "", time.Time{}, fmt.Errorf("invalid fetched metadata: %w", err)
	}
	return string(body), time.Now().UTC(), nil
}

func generateSAMLKeyPair(commonName string) (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return string(certPEM), string(keyPEM), nil
}

func normalizeProviderSlug(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	var b strings.Builder
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func defaultString(raw, fallback string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}

func parseUserRole(raw string) model.UserRole {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(model.RoleAdmin):
		return model.RoleAdmin
	default:
		return model.RoleUser
	}
}

func stringRoleMappingsToModel(mappings map[string]string) model.RoleMappingMap {
	result := make(model.RoleMappingMap, len(mappings))
	for key, role := range mappings {
		result[key] = parseUserRole(role)
	}
	return result
}

func roleMappingsToStrings(mappings model.RoleMappingMap) map[string]string {
	result := make(map[string]string, len(mappings))
	for key, role := range mappings {
		result[key] = userRoleToString(role)
	}
	return result
}
