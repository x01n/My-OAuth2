package service

import (
	"context"
	"testing"
	"time"

	"server/internal/model"
	"server/internal/repository"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type ldapSyncTestClient struct {
	searchWithPaging func(searchRequest *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error)
}

func (c *ldapSyncTestClient) SearchWithPaging(searchRequest *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error) {
	return c.searchWithPaging(searchRequest, pagingSize)
}

func (c *ldapSyncTestClient) Close() {}

func setupLDAPSyncServiceTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.LDAPProvider{}, &model.LDAPIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestLDAPSyncService_ApplySyncedProfileUpdatesRoleAndIdentity(t *testing.T) {
	db := setupLDAPSyncServiceTestDB(t)
	providerRepo := repository.NewLDAPProviderRepository(db)
	identityRepo := repository.NewLDAPIdentityRepository(db)
	userRepo := repository.NewUserRepository(db)
	svc := NewLDAPSyncService(providerRepo, identityRepo, userRepo)

	provider := &model.LDAPProvider{
		ID:                 uuid.New(),
		Name:               "Corp LDAP",
		Slug:               "corp-ldap",
		LDAPURL:            "ldaps://ldap.example.com:636",
		BaseDN:             "dc=example,dc=com",
		ExternalIDAttr:     "dn",
		PrincipalAttr:      "userPrincipalName",
		EmailAttr:          "mail",
		UsernameAttr:       "sAMAccountName",
		EmployeeIDAttr:     "employeeID",
		DisplayNameAttr:    "displayName",
		GivenNameAttr:      "givenName",
		FamilyNameAttr:     "sn",
		GroupAttr:          "memberOf",
		Enabled:            true,
		SyncEnabled:        true,
		SyncProfile:        true,
		DefaultRole:        model.RoleUser,
		TrustEmailVerified: true,
	}
	provider.SetRoleMappings(model.RoleMappingMap{
		"cn=admins,ou=groups,dc=example,dc=com": model.RoleAdmin,
	})
	if err := providerRepo.CreateProvider(provider); err != nil {
		t.Fatalf("create provider: %v", err)
	}

	user := &model.User{
		Email:    "ldap-sync@example.com",
		Username: "ldapsync",
		Role:     model.RoleUser,
		Status:   "active",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	identity := &model.LDAPIdentity{
		UserID:             user.ID,
		ProviderID:         provider.ID,
		ExternalID:         "cn=ldap-sync,ou=users,dc=example,dc=com",
		Principal:          "ldap-sync@example.com",
		ExternalEmail:      user.Email,
		ExternalUsername:   user.Username,
		ExternalEmployeeID: "E001",
	}
	identity.SetGroups([]string{"cn=users,ou=groups,dc=example,dc=com"})
	if err := identityRepo.Create(identity); err != nil {
		t.Fatalf("create identity: %v", err)
	}

	client := &ldapSyncTestClient{
		searchWithPaging: func(searchRequest *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error) {
			if pagingSize != 200 {
				t.Fatalf("pagingSize=%d want 200", pagingSize)
			}
			if searchRequest.BaseDN != identity.ExternalID {
				t.Fatalf("baseDN=%q want %q", searchRequest.BaseDN, identity.ExternalID)
			}
			if searchRequest.Scope != ldap.ScopeBaseObject {
				t.Fatalf("scope=%d want ScopeBaseObject", searchRequest.Scope)
			}
			entry := ldap.NewEntry(identity.ExternalID, map[string][]string{
				"userPrincipalName": {"ldap-sync@example.com"},
				"mail":              {"ldap-sync@example.com"},
				"sAMAccountName":    {"ldapsync"},
				"employeeID":        {"E777"},
				"displayName":       {"LDAP Sync User"},
				"givenName":         {"Sync"},
				"sn":                {"User"},
				"memberOf": {
					"cn=admins,ou=groups,dc=example,dc=com",
					"cn=users,ou=groups,dc=example,dc=com",
				},
			})
			return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
		},
	}

	stats, err := svc.syncProviderWithClient(context.Background(), provider, client)
	if err != nil {
		t.Fatalf("sync provider: %v", err)
	}
	if stats.Scanned != 1 {
		t.Fatalf("scanned=%d want 1", stats.Scanned)
	}
	if stats.UpdatedUsers != 1 {
		t.Fatalf("updated_users=%d want 1", stats.UpdatedUsers)
	}
	if stats.UpdatedRoles != 1 {
		t.Fatalf("updated_roles=%d want 1", stats.UpdatedRoles)
	}
	if stats.UpdatedLinks != 1 {
		t.Fatalf("updated_links=%d want 1", stats.UpdatedLinks)
	}

	storedUser, err := userRepo.FindByID(user.ID)
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if storedUser.Role != model.RoleAdmin {
		t.Fatalf("role=%q want admin", storedUser.Role)
	}
	if !storedUser.EmailVerified {
		t.Fatalf("email_verified=%v want true", storedUser.EmailVerified)
	}
	if storedUser.GivenName != "Sync" {
		t.Fatalf("given_name=%q want Sync", storedUser.GivenName)
	}
	if storedUser.FamilyName != "User" {
		t.Fatalf("family_name=%q want User", storedUser.FamilyName)
	}
	if storedUser.Nickname != "LDAP Sync User" {
		t.Fatalf("nickname=%q want LDAP Sync User", storedUser.Nickname)
	}
	if storedUser.EmployeeID != "E777" {
		t.Fatalf("employee_id=%q want E777", storedUser.EmployeeID)
	}

	storedIdentity, err := identityRepo.FindByExternalID(provider.ID, identity.ExternalID)
	if err != nil {
		t.Fatalf("find identity: %v", err)
	}
	if storedIdentity.ExternalEmployeeID != "E777" {
		t.Fatalf("external_employee_id=%q want E777", storedIdentity.ExternalEmployeeID)
	}
	if storedIdentity.LastSyncedAt == nil {
		t.Fatalf("last_synced_at is nil")
	}
	groups := storedIdentity.GetGroups()
	if len(groups) != 2 || groups[0] != "cn=admins,ou=groups,dc=example,dc=com" {
		t.Fatalf("groups=%v", groups)
	}
}

func TestLDAPSyncService_ApplySyncedProfileOverwritesChangedDirectoryFieldsWhenSyncProfileEnabled(t *testing.T) {
	db := setupLDAPSyncServiceTestDB(t)
	providerRepo := repository.NewLDAPProviderRepository(db)
	identityRepo := repository.NewLDAPIdentityRepository(db)
	userRepo := repository.NewUserRepository(db)
	svc := NewLDAPSyncService(providerRepo, identityRepo, userRepo)

	provider := &model.LDAPProvider{
		ID:                 uuid.New(),
		Name:               "Corp LDAP",
		Slug:               "corp-ldap",
		LDAPURL:            "ldaps://ldap.example.com:636",
		BaseDN:             "dc=example,dc=com",
		ExternalIDAttr:     "employeeNumber",
		PrincipalAttr:      "userPrincipalName",
		EmailAttr:          "mail",
		UsernameAttr:       "uid",
		EmployeeIDAttr:     "employeeNumber",
		DisplayNameAttr:    "displayName",
		GivenNameAttr:      "givenName",
		FamilyNameAttr:     "sn",
		GroupAttr:          "memberOf",
		Enabled:            true,
		SyncEnabled:        true,
		SyncProfile:        true,
		TrustEmailVerified: true,
		DefaultRole:        model.RoleUser,
	}
	if err := providerRepo.CreateProvider(provider); err != nil {
		t.Fatalf("create provider: %v", err)
	}

	user := &model.User{
		Email:          "overwrite@example.com",
		Username:       "overwrite",
		Role:           model.RoleUser,
		Status:         "active",
		EmailVerified:  false,
		GivenName:      "OldGiven",
		FamilyName:     "OldFamily",
		Nickname:       "Old Nick",
		EmployeeID:     "OLD-1",
		ExternalID:     "1002",
		ExternalSource: "ldap:corp-ldap",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	identity := &model.LDAPIdentity{
		UserID:             user.ID,
		ProviderID:         provider.ID,
		ExternalID:         "1002",
		Principal:          "overwrite@example.com",
		ExternalEmail:      user.Email,
		ExternalUsername:   user.Username,
		ExternalEmployeeID: "OLD-1",
	}
	identity.SetGroups([]string{"cn=users,ou=groups,dc=example,dc=com"})
	if err := identityRepo.Create(identity); err != nil {
		t.Fatalf("create identity: %v", err)
	}

	client := &ldapSyncTestClient{
		searchWithPaging: func(searchRequest *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error) {
			entry := ldap.NewEntry("cn=overwrite,ou=users,dc=example,dc=com", map[string][]string{
				"employeeNumber":    {"1002"},
				"userPrincipalName": {"overwrite@example.com"},
				"mail":              {"overwrite@example.com"},
				"uid":               {"overwrite-new"},
				"displayName":       {"Directory Nick"},
				"givenName":         {"DirectoryGiven"},
				"sn":                {"DirectoryFamily"},
				"memberOf":          {"cn=users,ou=groups,dc=example,dc=com"},
			})
			return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
		},
	}

	stats, err := svc.syncProviderWithClient(context.Background(), provider, client)
	if err != nil {
		t.Fatalf("sync provider: %v", err)
	}
	if stats.UpdatedUsers != 1 {
		t.Fatalf("updated_users=%d want 1", stats.UpdatedUsers)
	}

	storedUser, err := userRepo.FindByID(user.ID)
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if storedUser.GivenName != "DirectoryGiven" {
		t.Fatalf("given_name=%q want DirectoryGiven", storedUser.GivenName)
	}
	if storedUser.FamilyName != "DirectoryFamily" {
		t.Fatalf("family_name=%q want DirectoryFamily", storedUser.FamilyName)
	}
	if storedUser.Nickname != "Directory Nick" {
		t.Fatalf("nickname=%q want Directory Nick", storedUser.Nickname)
	}
	if storedUser.EmployeeID != "1002" {
		t.Fatalf("employee_id=%q want 1002", storedUser.EmployeeID)
	}
	if !storedUser.EmailVerified {
		t.Fatalf("email_verified=%v want true", storedUser.EmailVerified)
	}
}

func TestLDAPSyncService_ApplySyncedProfilePreservesExistingNamesWhenSyncProfileDisabled(t *testing.T) {
	db := setupLDAPSyncServiceTestDB(t)
	providerRepo := repository.NewLDAPProviderRepository(db)
	identityRepo := repository.NewLDAPIdentityRepository(db)
	userRepo := repository.NewUserRepository(db)
	svc := NewLDAPSyncService(providerRepo, identityRepo, userRepo)

	provider := &model.LDAPProvider{
		ID:                 uuid.New(),
		Name:               "Corp LDAP",
		Slug:               "corp-ldap",
		LDAPURL:            "ldaps://ldap.example.com:636",
		BaseDN:             "dc=example,dc=com",
		ExternalIDAttr:     "employeeNumber",
		PrincipalAttr:      "userPrincipalName",
		EmailAttr:          "mail",
		UsernameAttr:       "uid",
		EmployeeIDAttr:     "employeeNumber",
		DisplayNameAttr:    "displayName",
		GivenNameAttr:      "givenName",
		FamilyNameAttr:     "sn",
		GroupAttr:          "memberOf",
		Enabled:            true,
		SyncEnabled:        true,
		SyncProfile:        false,
		TrustEmailVerified: false,
		DefaultRole:        model.RoleUser,
	}
	if err := providerRepo.CreateProvider(provider); err != nil {
		t.Fatalf("create provider: %v", err)
	}

	user := &model.User{
		Email:          "preserve@example.com",
		Username:       "preserve",
		Role:           model.RoleUser,
		Status:         "active",
		GivenName:      "Existing",
		FamilyName:     "Name",
		Nickname:       "Existing Nick",
		EmployeeID:     "E100",
		ExternalID:     "1001",
		ExternalSource: "ldap:corp-ldap",
	}
	if err := userRepo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	identity := &model.LDAPIdentity{
		UserID:             user.ID,
		ProviderID:         provider.ID,
		ExternalID:         "1001",
		Principal:          "preserve@example.com",
		ExternalEmail:      user.Email,
		ExternalUsername:   user.Username,
		ExternalEmployeeID: "E100",
	}
	identity.SetGroups([]string{"cn=users,ou=groups,dc=example,dc=com"})
	if err := identityRepo.Create(identity); err != nil {
		t.Fatalf("create identity: %v", err)
	}

	client := &ldapSyncTestClient{
		searchWithPaging: func(searchRequest *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error) {
			if searchRequest.BaseDN != provider.BaseDN {
				t.Fatalf("baseDN=%q want %q", searchRequest.BaseDN, provider.BaseDN)
			}
			if searchRequest.Scope != ldap.ScopeWholeSubtree {
				t.Fatalf("scope=%d want ScopeWholeSubtree", searchRequest.Scope)
			}
			if searchRequest.Filter != "(employeeNumber=1001)" {
				t.Fatalf("filter=%q want %q", searchRequest.Filter, "(employeeNumber=1001)")
			}
			entry := ldap.NewEntry("cn=preserve,ou=users,dc=example,dc=com", map[string][]string{
				"employeeNumber":    {"1001"},
				"userPrincipalName": {"preserve@example.com"},
				"mail":              {"preserve@example.com"},
				"uid":               {"preserve-new"},
				"displayName":       {"Directory Display Name"},
				"givenName":         {"Directory"},
				"sn":                {"Updated"},
				"memberOf":          {"cn=users,ou=groups,dc=example,dc=com"},
			})
			return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
		},
	}

	stats, err := svc.syncProviderWithClient(context.Background(), provider, client)
	if err != nil {
		t.Fatalf("sync provider: %v", err)
	}
	if stats.UpdatedUsers != 0 {
		t.Fatalf("updated_users=%d want 0", stats.UpdatedUsers)
	}
	if stats.UpdatedRoles != 0 {
		t.Fatalf("updated_roles=%d want 0", stats.UpdatedRoles)
	}
	if stats.UpdatedLinks != 1 {
		t.Fatalf("updated_links=%d want 1", stats.UpdatedLinks)
	}

	storedUser, err := userRepo.FindByID(user.ID)
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if storedUser.GivenName != "Existing" {
		t.Fatalf("given_name=%q want Existing", storedUser.GivenName)
	}
	if storedUser.FamilyName != "Name" {
		t.Fatalf("family_name=%q want Name", storedUser.FamilyName)
	}
	if storedUser.Nickname != "Existing Nick" {
		t.Fatalf("nickname=%q want Existing Nick", storedUser.Nickname)
	}
	if storedUser.EmployeeID != "E100" {
		t.Fatalf("employee_id=%q want E100", storedUser.EmployeeID)
	}
}

func TestShouldRunLDAPSync(t *testing.T) {
	now := time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)
	provider := &model.LDAPProvider{Enabled: true, SyncEnabled: true, SyncIntervalMin: 60}
	if !shouldRunLDAPSync(provider, now) {
		t.Fatalf("expected first sync to run")
	}
	provider.LastSyncAt = ptrTime(now.Add(-30 * time.Minute))
	if shouldRunLDAPSync(provider, now) {
		t.Fatalf("expected sync to wait for interval")
	}
	provider.LastSyncAt = ptrTime(now.Add(-61 * time.Minute))
	if !shouldRunLDAPSync(provider, now) {
		t.Fatalf("expected sync to run after interval")
	}
	provider.SyncEnabled = false
	if shouldRunLDAPSync(provider, now) {
		t.Fatalf("expected disabled sync to skip")
	}
}

func ptrTime(v time.Time) *time.Time {
	return &v
}
