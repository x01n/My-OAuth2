package service

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"server/internal/model"
	"server/internal/repository"
	"server/pkg/jwt"
	"server/pkg/password"
	"server/pkg/sanitize"

	"github.com/crewjam/saml"
	"github.com/google/uuid"
)

var (
	ErrSAMLAssertionInvalid = errors.New("saml assertion invalid")
)

type SAMLAuthService struct {
	providerRepo *repository.SAMLProviderRepository
	identityRepo *repository.SAMLIdentityRepository
	userRepo     *repository.UserRepository
	loginLogRepo *repository.LoginLogRepository
	authService  *AuthService
}

type SAMLLoginInput struct {
	Provider  *model.SAMLProvider
	Profile   SAMLUserProfile
	IPAddress string
	UserAgent string
}

type SAMLUserProfile struct {
	ExternalID         string
	NameIDFormat       string
	SessionIndex       string
	Email              string
	Username           string
	EmployeeID         string
	DisplayName        string
	GivenName          string
	FamilyName         string
	Groups             []string
	Issuer             string
	RawAttributeValues map[string][]string
}

func NewSAMLAuthService(
	providerRepo *repository.SAMLProviderRepository,
	identityRepo *repository.SAMLIdentityRepository,
	userRepo *repository.UserRepository,
	loginLogRepo *repository.LoginLogRepository,
	authService *AuthService,
) *SAMLAuthService {
	return &SAMLAuthService{
		providerRepo: providerRepo,
		identityRepo: identityRepo,
		userRepo:     userRepo,
		loginLogRepo: loginLogRepo,
		authService:  authService,
	}
}

func (s *SAMLAuthService) Login(input SAMLLoginInput) (*model.User, *AuthTokens, error) {
	if input.Provider == nil {
		s.recordLogin(nil, input, false, "provider not found")
		return nil, nil, ErrEnterpriseProviderNotFound
	}
	if !input.Provider.Enabled {
		s.recordLogin(nil, input, false, "provider disabled")
		return nil, nil, ErrEnterpriseProviderDisabled
	}
	if input.Profile.ExternalID == "" || input.Profile.Email == "" {
		s.recordLogin(nil, input, false, "missing assertion identity")
		return nil, nil, ErrSAMLAssertionInvalid
	}

	user, err := s.findOrCreateUser(input.Provider, &input.Profile)
	if err != nil {
		s.recordLogin(nil, input, false, err.Error())
		return nil, nil, err
	}
	if user.Status != "" && user.Status != "active" {
		s.recordLogin(&user.ID, input, false, "user "+user.Status)
		return nil, nil, ErrInvalidCredentials
	}

	if err := s.authService.RecordAuthenticatedSession(user, &LoginInput{
		Email:     user.Email,
		IPAddress: input.IPAddress,
		UserAgent: input.UserAgent,
		LoginType: model.LoginTypeSAML,
	}); err != nil {
		return nil, nil, err
	}

	tokens, err := s.authService.GenerateTokensForAuthenticatedUser(user, time.Now().Unix(), jwt.AuthenticationMethodFederated)
	if err != nil {
		return nil, nil, err
	}
	return user, tokens, nil
}

func (s *SAMLAuthService) ProfileFromAssertion(provider *model.SAMLProvider, assertion *saml.Assertion) (*SAMLUserProfile, error) {
	if assertion == nil || assertion.Subject == nil || assertion.Subject.NameID == nil {
		return nil, ErrSAMLAssertionInvalid
	}
	attrs := samlAttributes(assertion)
	profile := &SAMLUserProfile{
		ExternalID:         strings.TrimSpace(assertion.Subject.NameID.Value),
		NameIDFormat:       assertion.Subject.NameID.Format,
		Email:              sanitize.Email(firstSAMLAttribute(attrs, provider.EmailAttribute)),
		Username:           sanitize.String(firstSAMLAttribute(attrs, provider.UsernameAttribute), 100),
		EmployeeID:         sanitize.String(firstSAMLAttribute(attrs, provider.EmployeeIDAttribute), 50),
		DisplayName:        sanitize.PlainText(firstSAMLAttribute(attrs, provider.DisplayNameAttribute), 100),
		GivenName:          sanitize.PlainText(firstSAMLAttribute(attrs, provider.GivenNameAttribute), 100),
		FamilyName:         sanitize.PlainText(firstSAMLAttribute(attrs, provider.FamilyNameAttribute), 100),
		Groups:             attrs[strings.TrimSpace(provider.GroupAttribute)],
		Issuer:             assertion.Issuer.Value,
		RawAttributeValues: attrs,
	}
	if profile.Email == "" && strings.EqualFold(profile.NameIDFormat, string(saml.EmailAddressNameIDFormat)) {
		profile.Email = sanitize.Email(profile.ExternalID)
	}
	if profile.Username == "" && profile.Email != "" {
		profile.Username = strings.Split(profile.Email, "@")[0]
	}
	if len(assertion.AuthnStatements) > 0 {
		profile.SessionIndex = assertion.AuthnStatements[0].SessionIndex
	}
	if profile.ExternalID == "" || profile.Email == "" {
		return nil, ErrSAMLAssertionInvalid
	}
	return profile, nil
}

func samlAttributes(assertion *saml.Assertion) map[string][]string {
	attrs := make(map[string][]string)
	for _, statement := range assertion.AttributeStatements {
		for _, attr := range statement.Attributes {
			keys := []string{strings.TrimSpace(attr.Name), strings.TrimSpace(attr.FriendlyName)}
			values := make([]string, 0, len(attr.Values))
			for _, value := range attr.Values {
				v := strings.TrimSpace(value.Value)
				if v != "" {
					values = append(values, v)
				}
			}
			for _, key := range keys {
				if key == "" {
					continue
				}
				attrs[key] = append(attrs[key], values...)
			}
		}
	}
	return attrs
}

func firstSAMLAttribute(attrs map[string][]string, key string) string {
	values := attrs[strings.TrimSpace(key)]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (s *SAMLAuthService) findOrCreateUser(provider *model.SAMLProvider, profile *SAMLUserProfile) (*model.User, error) {
	identity, err := s.identityRepo.FindByExternalID(provider.ID, profile.ExternalID)
	if err == nil && identity != nil {
		user, err := s.userRepo.FindByID(identity.UserID)
		if err != nil {
			return nil, err
		}
		s.syncExistingUser(user, provider, profile)
		s.updateIdentity(identity, profile)
		return user, nil
	}

	user, err := s.userRepo.FindByEmail(profile.Email)
	if err == nil && user != nil {
		if !provider.TrustEmailVerified {
			return nil, ErrExternalEmailConflict
		}
		identity := newSAMLIdentity(user.ID, provider.ID, profile)
		if err := s.identityRepo.Create(identity); err != nil {
			return nil, err
		}
		s.syncExistingUser(user, provider, profile)
		return user, nil
	}

	if !provider.AutoCreateUser {
		return nil, ErrEnterpriseUserNotFound
	}
	user, err = s.createUser(provider, profile)
	if err != nil {
		return nil, err
	}
	identity = newSAMLIdentity(user.ID, provider.ID, profile)
	if err := s.identityRepo.Create(identity); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *SAMLAuthService) createUser(provider *model.SAMLProvider, profile *SAMLUserProfile) (*model.User, error) {
	username := profile.Username
	if username == "" {
		username = strings.Split(profile.Email, "@")[0]
	}
	username = s.ensureUniqueUsername(username)
	randomPwd, err := password.GenerateRandom(16)
	if err != nil {
		return nil, err
	}
	hashedPwd, err := password.Hash(randomPwd)
	if err != nil {
		return nil, err
	}
	user := &model.User{
		Email:          profile.Email,
		Username:       username,
		PasswordHash:   hashedPwd,
		Role:           resolveEnterpriseRole(provider.DefaultRole, provider.GetRoleMappings(), profile.Groups),
		EmailVerified:  provider.TrustEmailVerified,
		Status:         "active",
		GivenName:      profile.GivenName,
		FamilyName:     profile.FamilyName,
		Nickname:       profile.DisplayName,
		EmployeeID:     profile.EmployeeID,
		ExternalID:     profile.ExternalID,
		ExternalSource: "saml:" + provider.Slug,
	}
	if err := s.userRepo.Create(user); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *SAMLAuthService) syncExistingUser(user *model.User, provider *model.SAMLProvider, profile *SAMLUserProfile) {
	updated := false
	role := resolveEnterpriseRole(provider.DefaultRole, provider.GetRoleMappings(), profile.Groups)
	if role != "" && user.Role != role {
		user.Role = role
		updated = true
	}
	if user.ExternalSource == "" {
		user.ExternalSource = "saml:" + provider.Slug
		updated = true
	}
	if user.ExternalID == "" {
		user.ExternalID = profile.ExternalID
		updated = true
	}
	if provider.SyncProfile {
		if user.GivenName == "" && profile.GivenName != "" {
			user.GivenName = profile.GivenName
			updated = true
		}
		if user.FamilyName == "" && profile.FamilyName != "" {
			user.FamilyName = profile.FamilyName
			updated = true
		}
		if user.Nickname == "" && profile.DisplayName != "" {
			user.Nickname = profile.DisplayName
			updated = true
		}
		if user.EmployeeID == "" && profile.EmployeeID != "" {
			user.EmployeeID = profile.EmployeeID
			updated = true
		}
	}
	if updated {
		_ = s.userRepo.Update(user)
	}
}

func (s *SAMLAuthService) updateIdentity(identity *model.SAMLIdentity, profile *SAMLUserProfile) {
	identity.NameIDFormat = profile.NameIDFormat
	identity.SessionIndex = profile.SessionIndex
	identity.ExternalEmail = profile.Email
	identity.ExternalUsername = profile.Username
	identity.ExternalEmployeeID = profile.EmployeeID
	identity.SetGroups(profile.Groups)
	_ = s.identityRepo.Update(identity)
}

func newSAMLIdentity(userID, providerID uuid.UUID, profile *SAMLUserProfile) *model.SAMLIdentity {
	identity := &model.SAMLIdentity{
		UserID:             userID,
		ProviderID:         providerID,
		ExternalID:         profile.ExternalID,
		NameIDFormat:       profile.NameIDFormat,
		SessionIndex:       profile.SessionIndex,
		ExternalEmail:      profile.Email,
		ExternalUsername:   profile.Username,
		ExternalEmployeeID: profile.EmployeeID,
	}
	identity.SetGroups(profile.Groups)
	return identity
}

func (s *SAMLAuthService) ensureUniqueUsername(base string) string {
	base = sanitize.String(base, 50)
	if base == "" {
		base = "saml-user"
	}
	if username, ok := sanitize.Username(base); ok {
		base = username
	} else {
		base = "saml-user"
	}
	username := base
	for suffix := 1; suffix <= 1000; suffix++ {
		exists, _ := s.userRepo.ExistsByUsername(username)
		if !exists {
			return username
		}
		username = fmt.Sprintf("%s%d", base, suffix)
	}
	return base + "-" + uuid.New().String()[:8]
}

func (s *SAMLAuthService) recordLogin(userID *uuid.UUID, input SAMLLoginInput, success bool, failureReason string) {
	if s.loginLogRepo == nil {
		return
	}
	email := input.Profile.Email
	_ = s.loginLogRepo.CreateLoginLog(userID, nil, model.LoginTypeSAML, input.IPAddress, input.UserAgent, email, success, failureReason)
}
