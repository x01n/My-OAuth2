package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"server/internal/model"
	"server/internal/repository"
	"server/pkg/jwt"
	"server/pkg/password"
	"server/pkg/sanitize"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

var (
	ErrEnterpriseProviderNotFound = errors.New("enterprise provider not found")
	ErrEnterpriseProviderDisabled = errors.New("enterprise provider disabled")
	ErrEnterpriseUserNotFound     = errors.New("enterprise user not found")
	ErrEnterpriseUserConflict     = errors.New("enterprise user conflict")
)

type LDAPAuthService struct {
	providerRepo *repository.LDAPProviderRepository
	identityRepo *repository.LDAPIdentityRepository
	userRepo     *repository.UserRepository
	loginLogRepo *repository.LoginLogRepository
	authService  *AuthService
}

type LDAPLoginInput struct {
	ProviderSlug string
	Identifier   string
	Password     string
	IPAddress    string
	UserAgent    string
}

type ldapUserProfile struct {
	ExternalID  string
	Principal   string
	Email       string
	Username    string
	EmployeeID  string
	DisplayName string
	GivenName   string
	FamilyName  string
	Groups      []string
}

func NewLDAPAuthService(
	providerRepo *repository.LDAPProviderRepository,
	identityRepo *repository.LDAPIdentityRepository,
	userRepo *repository.UserRepository,
	loginLogRepo *repository.LoginLogRepository,
	authService *AuthService,
) *LDAPAuthService {
	return &LDAPAuthService{
		providerRepo: providerRepo,
		identityRepo: identityRepo,
		userRepo:     userRepo,
		loginLogRepo: loginLogRepo,
		authService:  authService,
	}
}

func (s *LDAPAuthService) Login(ctx context.Context, input LDAPLoginInput) (*model.User, *AuthTokens, error) {
	identifier := sanitize.String(input.Identifier, 255)
	if identifier == "" || input.Password == "" {
		s.recordLogin(nil, input, false, "missing credentials")
		return nil, nil, ErrInvalidCredentials
	}

	provider, err := s.providerRepo.FindBySlug(input.ProviderSlug)
	if err != nil {
		s.recordLogin(nil, input, false, "provider not found")
		return nil, nil, ErrEnterpriseProviderNotFound
	}
	if !provider.Enabled {
		s.recordLogin(nil, input, false, "provider disabled")
		return nil, nil, ErrEnterpriseProviderDisabled
	}

	profile, err := s.authenticateDirectoryUser(ctx, provider, identifier, input.Password)
	if err != nil {
		s.recordLogin(nil, input, false, "invalid credentials")
		return nil, nil, ErrInvalidCredentials
	}

	user, err := s.findOrCreateUser(provider, profile)
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
		LoginType: model.LoginTypeLDAP,
	}); err != nil {
		return nil, nil, err
	}

	tokens, err := s.authService.GenerateTokensForAuthenticatedUser(user, time.Now().Unix(), jwt.AuthenticationMethodPassword, jwt.AuthenticationMethodFederated)
	if err != nil {
		return nil, nil, err
	}
	return user, tokens, nil
}

func (s *LDAPAuthService) authenticateDirectoryUser(ctx context.Context, provider *model.LDAPProvider, identifier, userPassword string) (*ldapUserProfile, error) {
	conn, err := s.connect(provider)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if provider.BindDN != "" {
		if err := conn.Bind(provider.BindDN, provider.BindPassword); err != nil {
			return nil, err
		}
	}

	entry, err := s.searchUser(ctx, conn, provider, identifier)
	if err != nil {
		return nil, err
	}
	if err := conn.Bind(entry.DN, userPassword); err != nil {
		return nil, err
	}
	return s.profileFromEntry(provider, entry), nil
}

func (s *LDAPAuthService) connect(provider *model.LDAPProvider) (*ldap.Conn, error) {
	return ldapConnect(provider)
}

func ldapConnect(provider *model.LDAPProvider) (*ldap.Conn, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: provider.InsecureSkipVerify}
	conn, err := ldap.DialURL(provider.LDAPURL,
		ldap.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}),
		ldap.DialWithTLSConfig(tlsConfig),
	)
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(15 * time.Second)
	if provider.UseStartTLS && strings.HasPrefix(strings.ToLower(provider.LDAPURL), "ldap://") {
		if err := conn.StartTLS(tlsConfig); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func (s *LDAPAuthService) searchUser(ctx context.Context, conn *ldap.Conn, provider *model.LDAPProvider, identifier string) (*ldap.Entry, error) {
	filter := provider.UserFilter
	if strings.TrimSpace(filter) == "" {
		filter = "(|(userPrincipalName={identifier})(mail={identifier})(sAMAccountName={identifier})(employeeID={identifier}))"
	}
	filter = strings.ReplaceAll(filter, "{identifier}", ldap.EscapeFilter(identifier))
	attrs := ldapAttributes(provider)
	searchRequest := ldap.NewSearchRequest(
		provider.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2,
		15,
		false,
		filter,
		attrs,
		nil,
	)
	type searchResult struct {
		result *ldap.SearchResult
		err    error
	}
	ch := make(chan searchResult, 1)
	go func() {
		res, err := conn.Search(searchRequest)
		ch <- searchResult{result: res, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.err != nil {
			return nil, res.err
		}
		if res.result == nil || len(res.result.Entries) != 1 {
			return nil, ErrEnterpriseUserNotFound
		}
		return res.result.Entries[0], nil
	}
}

func ldapAttributes(provider *model.LDAPProvider) []string {
	seen := map[string]struct{}{}
	attrs := []string{"dn"}
	add := func(attr string) {
		attr = strings.TrimSpace(attr)
		if attr == "" || attr == "dn" {
			return
		}
		if _, ok := seen[attr]; ok {
			return
		}
		seen[attr] = struct{}{}
		attrs = append(attrs, attr)
	}
	add(provider.ExternalIDAttr)
	add(provider.PrincipalAttr)
	add(provider.EmailAttr)
	add(provider.UsernameAttr)
	add(provider.EmployeeIDAttr)
	add(provider.DisplayNameAttr)
	add(provider.GivenNameAttr)
	add(provider.FamilyNameAttr)
	add(provider.GroupAttr)
	return attrs
}

func (s *LDAPAuthService) profileFromEntry(provider *model.LDAPProvider, entry *ldap.Entry) *ldapUserProfile {
	profile := &ldapUserProfile{
		ExternalID:  valueFromLDAPEntry(entry, provider.ExternalIDAttr),
		Principal:   valueFromLDAPEntry(entry, provider.PrincipalAttr),
		Email:       sanitize.Email(valueFromLDAPEntry(entry, provider.EmailAttr)),
		Username:    sanitize.String(valueFromLDAPEntry(entry, provider.UsernameAttr), 100),
		EmployeeID:  sanitize.String(valueFromLDAPEntry(entry, provider.EmployeeIDAttr), 50),
		DisplayName: sanitize.PlainText(valueFromLDAPEntry(entry, provider.DisplayNameAttr), 100),
		GivenName:   sanitize.PlainText(valueFromLDAPEntry(entry, provider.GivenNameAttr), 100),
		FamilyName:  sanitize.PlainText(valueFromLDAPEntry(entry, provider.FamilyNameAttr), 100),
		Groups:      valuesFromLDAPEntry(entry, provider.GroupAttr),
	}
	if profile.ExternalID == "" || provider.ExternalIDAttr == "dn" {
		profile.ExternalID = entry.DN
	}
	if profile.Principal == "" {
		profile.Principal = profile.Email
	}
	if profile.Username == "" && profile.Email != "" {
		profile.Username = strings.Split(profile.Email, "@")[0]
	}
	return profile
}

func valueFromLDAPEntry(entry *ldap.Entry, attr string) string {
	attr = strings.TrimSpace(attr)
	if attr == "" {
		return ""
	}
	if attr == "dn" {
		return entry.DN
	}
	return strings.TrimSpace(entry.GetAttributeValue(attr))
}

func valuesFromLDAPEntry(entry *ldap.Entry, attr string) []string {
	attr = strings.TrimSpace(attr)
	if attr == "" {
		return []string{}
	}
	values := entry.GetAttributeValues(attr)
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func (s *LDAPAuthService) findOrCreateUser(provider *model.LDAPProvider, profile *ldapUserProfile) (*model.User, error) {
	if profile.ExternalID == "" || profile.Email == "" {
		return nil, ErrEnterpriseUserConflict
	}

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
		identity := newLDAPIdentity(user.ID, provider.ID, profile)
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
	identity = newLDAPIdentity(user.ID, provider.ID, profile)
	if err := s.identityRepo.Create(identity); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *LDAPAuthService) createUser(provider *model.LDAPProvider, profile *ldapUserProfile) (*model.User, error) {
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
		ExternalSource: "ldap:" + provider.Slug,
	}
	if err := s.userRepo.Create(user); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *LDAPAuthService) syncExistingUser(user *model.User, provider *model.LDAPProvider, profile *ldapUserProfile) {
	updated := false
	role := resolveEnterpriseRole(provider.DefaultRole, provider.GetRoleMappings(), profile.Groups)
	if role != "" && user.Role != role {
		user.Role = role
		updated = true
	}
	if user.ExternalSource == "" {
		user.ExternalSource = "ldap:" + provider.Slug
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

func (s *LDAPAuthService) updateIdentity(identity *model.LDAPIdentity, profile *ldapUserProfile) {
	identity.Principal = profile.Principal
	identity.ExternalEmail = profile.Email
	identity.ExternalUsername = profile.Username
	identity.ExternalEmployeeID = profile.EmployeeID
	identity.SetGroups(profile.Groups)
	now := time.Now().UTC()
	identity.LastSyncedAt = &now
	_ = s.identityRepo.Update(identity)
}

func newLDAPIdentity(userID, providerID uuid.UUID, profile *ldapUserProfile) *model.LDAPIdentity {
	now := time.Now().UTC()
	identity := &model.LDAPIdentity{
		UserID:             userID,
		ProviderID:         providerID,
		ExternalID:         profile.ExternalID,
		Principal:          profile.Principal,
		ExternalEmail:      profile.Email,
		ExternalUsername:   profile.Username,
		ExternalEmployeeID: profile.EmployeeID,
		LastSyncedAt:       &now,
	}
	identity.SetGroups(profile.Groups)
	return identity
}

func resolveEnterpriseRole(defaultRole model.UserRole, mappings model.RoleMappingMap, groups []string) model.UserRole {
	for _, group := range groups {
		if role, ok := mappings[group]; ok && role != "" {
			return role
		}
	}
	if defaultRole != "" {
		return defaultRole
	}
	return model.RoleUser
}

func (s *LDAPAuthService) ensureUniqueUsername(base string) string {
	base = sanitize.String(base, 50)
	if base == "" {
		base = "ldap-user"
	}
	if username, ok := sanitize.Username(base); ok {
		base = username
	} else {
		base = "ldap-user"
	}
	username := base
	for suffix := 1; suffix <= 1000; suffix++ {
		exists, _ := s.userRepo.ExistsByUsername(username)
		if !exists {
			return username
		}
		username = fmt.Sprintf("%s%d", base, suffix)
	}
	return fmt.Sprintf("%s-%s", base, uuid.New().String()[:8])
}

func (s *LDAPAuthService) recordLogin(userID *uuid.UUID, input LDAPLoginInput, success bool, failureReason string) {
	if s.loginLogRepo == nil {
		return
	}
	_ = s.loginLogRepo.CreateLoginLog(userID, nil, model.LoginTypeLDAP, input.IPAddress, input.UserAgent, input.Identifier, success, failureReason)
}
