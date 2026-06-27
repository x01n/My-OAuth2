package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"server/internal/model"
	"server/internal/repository"
	"server/pkg/logger"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

type ldapDirectoryClient interface {
	SearchWithPaging(searchRequest *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error)
}

type LDAPSyncService struct {
	providerRepo *repository.LDAPProviderRepository
	identityRepo *repository.LDAPIdentityRepository
	userRepo     *repository.UserRepository
}

type LDAPSyncStats struct {
	ProviderID   uuid.UUID
	ProviderSlug string
	Scanned      int
	UpdatedUsers int
	UpdatedRoles int
	UpdatedLinks int
}

type ldapUserProfileSync struct {
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

func NewLDAPSyncService(
	providerRepo *repository.LDAPProviderRepository,
	identityRepo *repository.LDAPIdentityRepository,
	userRepo *repository.UserRepository,
) *LDAPSyncService {
	return &LDAPSyncService{
		providerRepo: providerRepo,
		identityRepo: identityRepo,
		userRepo:     userRepo,
	}
}

func (s *LDAPSyncService) RunScheduledSync(ctx context.Context) {
	providers, err := s.providerRepo.FindAllSyncEnabled()
	if err != nil {
		logger.Warn("LDAP sync provider load failed", "error", err)
		return
	}
	now := time.Now().UTC()
	for _, provider := range providers {
		provider := provider
		if ctx.Err() != nil {
			return
		}
		if !shouldRunLDAPSync(&provider, now) {
			continue
		}
		stats, err := s.SyncProvider(ctx, &provider)
		if err != nil {
			status := truncateLDAPSyncStatus(err.Error())
			if updateErr := s.providerRepo.UpdateSyncStatus(provider.ID, time.Now().UTC(), status); updateErr != nil {
				logger.Warn("LDAP sync status update failed", "provider", provider.Slug, "error", updateErr)
			}
			logger.Warn("LDAP sync failed", "provider", provider.Slug, "error", err)
			continue
		}
		status := truncateLDAPSyncStatus(fmt.Sprintf("ok scanned=%d updated_users=%d updated_roles=%d updated_links=%d", stats.Scanned, stats.UpdatedUsers, stats.UpdatedRoles, stats.UpdatedLinks))
		if updateErr := s.providerRepo.UpdateSyncStatus(provider.ID, time.Now().UTC(), status); updateErr != nil {
			logger.Warn("LDAP sync status update failed", "provider", provider.Slug, "error", updateErr)
		}
		logger.Info("LDAP sync completed",
			"provider", provider.Slug,
			"scanned", stats.Scanned,
			"updated_users", stats.UpdatedUsers,
			"updated_roles", stats.UpdatedRoles,
			"updated_links", stats.UpdatedLinks,
		)
	}
}

func (s *LDAPSyncService) SyncProvider(ctx context.Context, provider *model.LDAPProvider) (*LDAPSyncStats, error) {
	if provider == nil {
		return nil, ErrEnterpriseProviderNotFound
	}
	if !provider.Enabled {
		return nil, ErrEnterpriseProviderDisabled
	}
	conn, err := ldapConnect(provider)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if provider.BindDN != "" {
		if err := conn.Bind(provider.BindDN, provider.BindPassword); err != nil {
			return nil, err
		}
	}
	return s.syncProviderWithClient(ctx, provider, conn)
}

func (s *LDAPSyncService) syncProviderWithClient(ctx context.Context, provider *model.LDAPProvider, client ldapDirectoryClient) (*LDAPSyncStats, error) {
	identities, err := s.identityRepo.FindAllByProvider(provider.ID)
	if err != nil {
		return nil, err
	}
	stats := &LDAPSyncStats{
		ProviderID:   provider.ID,
		ProviderSlug: provider.Slug,
	}
	if len(identities) == 0 {
		return stats, nil
	}
	for _, identity := range identities {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		stats.Scanned++
		profile, err := s.fetchProfileByIdentity(ctx, client, provider, &identity)
		if err != nil {
			logger.Warn("LDAP sync skipped identity", "provider", provider.Slug, "identity_id", identity.ID, "error", err)
			continue
		}
		user, err := s.userRepo.FindByID(identity.UserID)
		if err != nil {
			logger.Warn("LDAP sync user load failed", "provider", provider.Slug, "user_id", identity.UserID, "error", err)
			continue
		}
		changed, roleChanged := s.applySyncedProfile(user, provider, profile)
		if changed {
			if err := s.userRepo.Update(user); err != nil {
				logger.Warn("LDAP sync user update failed", "provider", provider.Slug, "user_id", user.ID, "error", err)
			} else {
				stats.UpdatedUsers++
				if roleChanged {
					stats.UpdatedRoles++
				}
			}
		}
		identityChanged := s.applySyncedIdentity(&identity, profile)
		if identityChanged {
			if err := s.identityRepo.Update(&identity); err != nil {
				logger.Warn("LDAP sync identity update failed", "provider", provider.Slug, "identity_id", identity.ID, "error", err)
			} else {
				stats.UpdatedLinks++
			}
		}
	}
	return stats, nil
}

func (s *LDAPSyncService) fetchProfileByIdentity(ctx context.Context, client ldapDirectoryClient, provider *model.LDAPProvider, identity *model.LDAPIdentity) (*ldapUserProfileSync, error) {
	filter, baseDN, scope, err := s.syncSearchTarget(provider, identity)
	if err != nil {
		return nil, err
	}
	attrs := ldapAttributes(provider)
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		scope,
		ldap.NeverDerefAliases,
		0,
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
		res, err := client.SearchWithPaging(searchRequest, uint32(normalizeLDAPSyncPageSize(provider.SyncPageSize)))
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
		return profileFromSyncEntry(provider, res.result.Entries[0]), nil
	}
}

func (s *LDAPSyncService) syncSearchTarget(provider *model.LDAPProvider, identity *model.LDAPIdentity) (string, string, int, error) {
	externalAttr := strings.TrimSpace(provider.ExternalIDAttr)
	if externalAttr == "" {
		externalAttr = "dn"
	}
	if externalAttr == "dn" {
		if strings.TrimSpace(identity.ExternalID) == "" {
			return "", "", 0, ErrEnterpriseUserConflict
		}
		return "(objectClass=*)", identity.ExternalID, ldap.ScopeBaseObject, nil
	}
	if strings.TrimSpace(identity.ExternalID) == "" {
		return "", "", 0, ErrEnterpriseUserConflict
	}
	return "(" + externalAttr + "=" + ldap.EscapeFilter(identity.ExternalID) + ")", provider.BaseDN, ldap.ScopeWholeSubtree, nil
}

func profileFromSyncEntry(provider *model.LDAPProvider, entry *ldap.Entry) *ldapUserProfileSync {
	profile := &ldapUserProfileSync{
		ExternalID:  valueFromLDAPEntry(entry, provider.ExternalIDAttr),
		Principal:   valueFromLDAPEntry(entry, provider.PrincipalAttr),
		Email:       strings.TrimSpace(valueFromLDAPEntry(entry, provider.EmailAttr)),
		Username:    strings.TrimSpace(valueFromLDAPEntry(entry, provider.UsernameAttr)),
		EmployeeID:  strings.TrimSpace(valueFromLDAPEntry(entry, provider.EmployeeIDAttr)),
		DisplayName: strings.TrimSpace(valueFromLDAPEntry(entry, provider.DisplayNameAttr)),
		GivenName:   strings.TrimSpace(valueFromLDAPEntry(entry, provider.GivenNameAttr)),
		FamilyName:  strings.TrimSpace(valueFromLDAPEntry(entry, provider.FamilyNameAttr)),
		Groups:      valuesFromLDAPEntry(entry, provider.GroupAttr),
	}
	if profile.ExternalID == "" || strings.TrimSpace(provider.ExternalIDAttr) == "dn" {
		profile.ExternalID = entry.DN
	}
	if profile.Principal == "" {
		profile.Principal = profile.Email
	}
	if profile.Username == "" && profile.Email != "" {
		parts := strings.Split(profile.Email, "@")
		if len(parts) > 0 {
			profile.Username = parts[0]
		}
	}
	return profile
}

func (s *LDAPSyncService) applySyncedProfile(user *model.User, provider *model.LDAPProvider, profile *ldapUserProfileSync) (bool, bool) {
	if user == nil || provider == nil || profile == nil {
		return false, false
	}
	changed := false
	roleChanged := false
	role := resolveEnterpriseRole(provider.DefaultRole, provider.GetRoleMappings(), profile.Groups)
	if role != "" && user.Role != role {
		user.Role = role
		changed = true
		roleChanged = true
	}
	if user.ExternalSource == "" {
		user.ExternalSource = "ldap:" + provider.Slug
		changed = true
	}
	if user.ExternalID == "" && profile.ExternalID != "" {
		user.ExternalID = profile.ExternalID
		changed = true
	}
	if provider.TrustEmailVerified && !user.EmailVerified {
		user.EmailVerified = true
		changed = true
	}
	if provider.SyncProfile {
		if profile.GivenName != "" && user.GivenName != profile.GivenName {
			user.GivenName = profile.GivenName
			changed = true
		}
		if profile.FamilyName != "" && user.FamilyName != profile.FamilyName {
			user.FamilyName = profile.FamilyName
			changed = true
		}
		if profile.DisplayName != "" && user.Nickname != profile.DisplayName {
			user.Nickname = profile.DisplayName
			changed = true
		}
		if profile.EmployeeID != "" && user.EmployeeID != profile.EmployeeID {
			user.EmployeeID = profile.EmployeeID
			changed = true
		}
	}
	return changed, roleChanged
}

func (s *LDAPSyncService) applySyncedIdentity(identity *model.LDAPIdentity, profile *ldapUserProfileSync) bool {
	if identity == nil || profile == nil {
		return false
	}
	changed := false
	if identity.Principal != profile.Principal {
		identity.Principal = profile.Principal
		changed = true
	}
	if identity.ExternalEmail != profile.Email {
		identity.ExternalEmail = profile.Email
		changed = true
	}
	if identity.ExternalUsername != profile.Username {
		identity.ExternalUsername = profile.Username
		changed = true
	}
	if identity.ExternalEmployeeID != profile.EmployeeID {
		identity.ExternalEmployeeID = profile.EmployeeID
		changed = true
	}
	oldGroups := identity.GetGroups()
	if !stringSlicesEqual(oldGroups, profile.Groups) {
		identity.SetGroups(profile.Groups)
		changed = true
	}
	now := time.Now().UTC()
	if identity.LastSyncedAt == nil || !identity.LastSyncedAt.Equal(now) {
		identity.LastSyncedAt = &now
		changed = true
	}
	return changed
}

func normalizeLDAPSyncPageSize(size int) int {
	if size <= 0 {
		return 200
	}
	if size > 1000 {
		return 1000
	}
	return size
}

func shouldRunLDAPSync(provider *model.LDAPProvider, now time.Time) bool {
	if provider == nil || !provider.Enabled || !provider.SyncEnabled {
		return false
	}
	interval := time.Duration(provider.SyncIntervalMin) * time.Minute
	if interval <= 0 {
		interval = 60 * time.Minute
	}
	if provider.LastSyncAt == nil {
		return true
	}
	return !provider.LastSyncAt.Add(interval).After(now)
}

func truncateLDAPSyncStatus(status string) string {
	status = strings.TrimSpace(status)
	if len(status) <= 2000 {
		return status
	}
	return status[:2000]
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
