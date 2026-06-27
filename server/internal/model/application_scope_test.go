package model

import "testing"

func TestResolveClientCredentialsScope_rejectsUserCentric(t *testing.T) {
	app := &Application{
		AllowedScopes: `["api.read","api.write"]`,
		Scopes:        `["openid","profile","api.read"]`,
	}
	if scope, ok := app.ResolveClientCredentialsScope("openid profile"); ok {
		t.Fatalf("expected reject, got scope=%q", scope)
	}
}

func TestResolveClientCredentialsScope_allowsMachineScopes(t *testing.T) {
	app := &Application{
		AllowedScopes: `["api.read","api.write"]`,
	}
	scope, ok := app.ResolveClientCredentialsScope("api.read")
	if !ok || scope != "api.read" {
		t.Fatalf("got scope=%q ok=%v", scope, ok)
	}
}

func TestValidateUserAuthorizationScope_emptyAppScopesUsesDefault(t *testing.T) {
	app := &Application{}
	if !app.ValidateUserAuthorizationScope("openid profile email") {
		t.Fatal("expected default scopes to allow standard OIDC scopes")
	}
	if app.ValidateUserAuthorizationScope("custom.api") {
		t.Fatal("custom scope should not be allowed when app scopes empty")
	}
}

func TestResolveClientCredentialsScope_rejectsWildcardAll(t *testing.T) {
	app := &Application{
		Scopes: `["all","api.read"]`,
	}
	if scope, ok := app.ResolveClientCredentialsScope("all"); ok {
		t.Fatalf("expected reject all, got scope=%q", scope)
	}
}

func TestSupportsGrantType_aliases(t *testing.T) {
	app := &Application{GrantTypes: `["token_exchange"]`}
	if !app.SupportsGrantType("urn:ietf:params:oauth:grant-type:token-exchange") {
		t.Fatal("expected URN alias to match token_exchange")
	}
	if app.SupportsGrantType("client_credentials") {
		t.Fatal("client_credentials should not be enabled")
	}
}

func TestGetIssuedTokenTypes_dedupesRefreshToken(t *testing.T) {
	app := &Application{
		GrantTypes: `["authorization_code","device_code","refresh_token"]`,
		Scopes:     `["openid","profile","email"]`,
	}
	types := app.GetIssuedTokenTypes()
	var refreshCount int
	for _, typ := range types {
		if typ == "refresh_token" {
			refreshCount++
		}
	}
	if refreshCount != 1 {
		t.Fatalf("expected one refresh_token, got %v", types)
	}
}

func TestGetIssuedTokenTypesForRequest_idTokenOnlyWithOpenID(t *testing.T) {
	app := &Application{
		GrantTypes: `["authorization_code"]`,
		Scopes:     `["openid","profile","email"]`,
	}
	withOpenID := app.GetIssuedTokenTypesForRequest("openid profile email", "code")
	if !containsStr(withOpenID, "id_token") {
		t.Fatalf("expected id_token with openid scope, got %v", withOpenID)
	}
	withoutOpenID := app.GetIssuedTokenTypesForRequest("profile email", "code")
	if containsStr(withoutOpenID, "id_token") {
		t.Fatalf("expected no id_token without openid, got %v", withoutOpenID)
	}
}

func TestFilterRequestedUserScopes(t *testing.T) {
	app := &Application{Scopes: `["openid","profile","email","api.read"]`}
	got := app.FilterRequestedUserScopes("openid profile email phone api.read")
	want := []string{"profile", "email"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i, s := range want {
		if got[i] != s {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	br := app.ParseAuthorizeScopeRequest("openid profile email phone api.read")
	if len(br.InvalidScopes) != 2 {
		t.Fatalf("invalid scopes got %v", br.InvalidScopes)
	}
	if br.EffectiveScope != "openid profile email" {
		t.Fatalf("effective=%q", br.EffectiveScope)
	}
}

func TestGetUserAuthorizationScopes_excludesMachine(t *testing.T) {
	app := &Application{Scopes: `["openid","profile","api.read"]`}
	got := app.GetUserAuthorizationScopes()
	if len(got) != 2 || got[0] != "openid" || got[1] != "profile" {
		t.Fatalf("got %v", got)
	}
}

func containsStr(slice []string, v string) bool {
	for _, s := range slice {
		if s == v {
			return true
		}
	}
	return false
}
