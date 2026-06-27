package config

import (
	"os"
	"testing"
)

/* ========== applyEnvOverrides ========== */

func TestApplyEnvOverrides_ServerPort(t *testing.T) {
	cfg := defaultConfig()
	os.Setenv("SERVER_PORT", "9090")
	defer os.Unsetenv("SERVER_PORT")

	cfg.applyEnvOverrides()
	if cfg.Server.Port != 9090 {
		t.Errorf("Server.Port = %d, want 9090", cfg.Server.Port)
	}
}

func TestApplyEnvOverrides_InvalidPort_Ignored(t *testing.T) {
	cfg := defaultConfig()
	original := cfg.Server.Port
	os.Setenv("SERVER_PORT", "not-a-number")
	defer os.Unsetenv("SERVER_PORT")

	cfg.applyEnvOverrides()
	if cfg.Server.Port != original {
		t.Errorf("Server.Port changed to %d on invalid input, should stay %d", cfg.Server.Port, original)
	}
}

func TestApplyEnvOverrides_GinMode(t *testing.T) {
	cfg := defaultConfig()
	os.Setenv("GIN_MODE", "release")
	defer os.Unsetenv("GIN_MODE")

	cfg.applyEnvOverrides()
	if cfg.Server.Mode != "release" {
		t.Errorf("Server.Mode = %q, want %q", cfg.Server.Mode, "release")
	}
}

func TestApplyEnvOverrides_DBDriver(t *testing.T) {
	cfg := defaultConfig()
	os.Setenv("DB_DRIVER", "postgres")
	defer os.Unsetenv("DB_DRIVER")

	cfg.applyEnvOverrides()
	if cfg.Database.Driver != "postgres" {
		t.Errorf("Database.Driver = %q, want %q", cfg.Database.Driver, "postgres")
	}
}

func TestApplyEnvOverrides_DBDSN(t *testing.T) {
	cfg := defaultConfig()
	dsn := "postgres://user:pass@localhost/oauth2"
	os.Setenv("DB_DSN", dsn)
	defer os.Unsetenv("DB_DSN")

	cfg.applyEnvOverrides()
	if cfg.Database.DSN != dsn {
		t.Errorf("Database.DSN = %q, want %q", cfg.Database.DSN, dsn)
	}
}

func TestApplyEnvOverrides_JWTSecret(t *testing.T) {
	cfg := defaultConfig()
	os.Setenv("JWT_SECRET", "my-env-secret")
	defer os.Unsetenv("JWT_SECRET")

	cfg.applyEnvOverrides()
	if cfg.JWT.Secret != "my-env-secret" {
		t.Errorf("JWT.Secret = %q, want %q", cfg.JWT.Secret, "my-env-secret")
	}
}

func TestApplyEnvOverrides_EmailConfig(t *testing.T) {
	cfg := defaultConfig()
	os.Setenv("EMAIL_HOST", "smtp.test.com")
	os.Setenv("EMAIL_PORT", "465")
	os.Setenv("EMAIL_USERNAME", "user@test.com")
	os.Setenv("EMAIL_PASSWORD", "secret123")
	os.Setenv("EMAIL_FROM", "noreply@test.com")
	defer func() {
		os.Unsetenv("EMAIL_HOST")
		os.Unsetenv("EMAIL_PORT")
		os.Unsetenv("EMAIL_USERNAME")
		os.Unsetenv("EMAIL_PASSWORD")
		os.Unsetenv("EMAIL_FROM")
	}()

	cfg.applyEnvOverrides()
	if cfg.Email.Host != "smtp.test.com" {
		t.Errorf("Email.Host = %q, want %q", cfg.Email.Host, "smtp.test.com")
	}
	if cfg.Email.Port != 465 {
		t.Errorf("Email.Port = %d, want 465", cfg.Email.Port)
	}
	if cfg.Email.Username != "user@test.com" {
		t.Errorf("Email.Username = %q, want %q", cfg.Email.Username, "user@test.com")
	}
	if cfg.Email.Password != "secret123" {
		t.Errorf("Email.Password = %q, want %q", cfg.Email.Password, "secret123")
	}
	if cfg.Email.From != "noreply@test.com" {
		t.Errorf("Email.From = %q, want %q", cfg.Email.From, "noreply@test.com")
	}
}

func TestApplyEnvOverrides_CacheRedis(t *testing.T) {
	cfg := defaultConfig()
	os.Setenv("CACHE_DRIVER", "redis")
	os.Setenv("REDIS_URL", "redis://localhost:6379/1")
	defer func() {
		os.Unsetenv("CACHE_DRIVER")
		os.Unsetenv("REDIS_URL")
	}()

	cfg.applyEnvOverrides()
	if cfg.Cache.Driver != "redis" {
		t.Errorf("Cache.Driver = %q, want %q", cfg.Cache.Driver, "redis")
	}
	if cfg.Cache.RedisURL != "redis://localhost:6379/1" {
		t.Errorf("Cache.RedisURL = %q, want %q", cfg.Cache.RedisURL, "redis://localhost:6379/1")
	}
}

func TestApplyEnvOverrides_NoEnv_NoChange(t *testing.T) {
	cfg := defaultConfig()
	origPort := cfg.Server.Port
	origDriver := cfg.Database.Driver

	cfg.applyEnvOverrides()
	if cfg.Server.Port != origPort {
		t.Errorf("Server.Port changed without env var")
	}
	if cfg.Database.Driver != origDriver {
		t.Errorf("Database.Driver changed without env var")
	}
}

func TestApplyEnvOverrides_ExtendedFields(t *testing.T) {
	cfg := defaultConfig()
	os.Setenv("DB_MAX_OPEN_CONNS", "64")
	os.Setenv("DB_MAX_IDLE_CONNS", "16")
	os.Setenv("DB_CONN_MAX_LIFETIME_MIN", "30")
	os.Setenv("DB_CONN_MAX_IDLE_TIME_MIN", "5")
	os.Setenv("CACHE_PREFIX", "oauth2:test:")
	os.Setenv("CACHE_DEFAULT_TTL_SEC", "900")
	os.Setenv("MEMCACHED_SERVERS", "127.0.0.1:11211,127.0.0.1:11212")
	os.Setenv("BADGER_PATH", "/tmp/badger-cache")
	os.Setenv("CACHE_FILE_DIR", "/tmp/file-cache")
	os.Setenv("EMAIL_FROM_NAME", "OAuth2 Mailer")
	os.Setenv("EMAIL_USE_TLS", "false")
	os.Setenv("SOCIAL_ENABLED", "true")
	os.Setenv("SOCIAL_GITHUB_ENABLED", "true")
	os.Setenv("SOCIAL_GITHUB_CLIENT_ID", "gh-client")
	os.Setenv("SOCIAL_GITHUB_CLIENT_SECRET", "gh-secret")
	os.Setenv("SOCIAL_GOOGLE_ENABLED", "true")
	os.Setenv("SOCIAL_GOOGLE_CLIENT_ID", "google-client")
	os.Setenv("SOCIAL_GOOGLE_CLIENT_SECRET", "google-secret")
	os.Setenv("LOG_LEVEL", "debug")
	os.Setenv("LOG_FORMAT", "json")
	os.Setenv("LOG_FILE_OUTPUT", "/tmp/oauth2.log")
	os.Setenv("LOG_MAX_SIZE_MB", "256")
	os.Setenv("LOG_MAX_BACKUPS", "9")
	os.Setenv("LOG_MAX_AGE_DAYS", "14")
	os.Setenv("LOG_COMPRESS", "true")
	defer func() {
		os.Unsetenv("DB_MAX_OPEN_CONNS")
		os.Unsetenv("DB_MAX_IDLE_CONNS")
		os.Unsetenv("DB_CONN_MAX_LIFETIME_MIN")
		os.Unsetenv("DB_CONN_MAX_IDLE_TIME_MIN")
		os.Unsetenv("CACHE_PREFIX")
		os.Unsetenv("CACHE_DEFAULT_TTL_SEC")
		os.Unsetenv("MEMCACHED_SERVERS")
		os.Unsetenv("BADGER_PATH")
		os.Unsetenv("CACHE_FILE_DIR")
		os.Unsetenv("EMAIL_FROM_NAME")
		os.Unsetenv("EMAIL_USE_TLS")
		os.Unsetenv("SOCIAL_ENABLED")
		os.Unsetenv("SOCIAL_GITHUB_ENABLED")
		os.Unsetenv("SOCIAL_GITHUB_CLIENT_ID")
		os.Unsetenv("SOCIAL_GITHUB_CLIENT_SECRET")
		os.Unsetenv("SOCIAL_GOOGLE_ENABLED")
		os.Unsetenv("SOCIAL_GOOGLE_CLIENT_ID")
		os.Unsetenv("SOCIAL_GOOGLE_CLIENT_SECRET")
		os.Unsetenv("LOG_LEVEL")
		os.Unsetenv("LOG_FORMAT")
		os.Unsetenv("LOG_FILE_OUTPUT")
		os.Unsetenv("LOG_MAX_SIZE_MB")
		os.Unsetenv("LOG_MAX_BACKUPS")
		os.Unsetenv("LOG_MAX_AGE_DAYS")
		os.Unsetenv("LOG_COMPRESS")
	}()

	cfg.applyEnvOverrides()
	if cfg.Database.MaxOpenConns != 64 {
		t.Errorf("Database.MaxOpenConns = %d, want 64", cfg.Database.MaxOpenConns)
	}
	if cfg.Database.MaxIdleConns != 16 {
		t.Errorf("Database.MaxIdleConns = %d, want 16", cfg.Database.MaxIdleConns)
	}
	if cfg.Database.ConnMaxLifetimeMin != 30 {
		t.Errorf("Database.ConnMaxLifetimeMin = %d, want 30", cfg.Database.ConnMaxLifetimeMin)
	}
	if cfg.Database.ConnMaxIdleTimeMin != 5 {
		t.Errorf("Database.ConnMaxIdleTimeMin = %d, want 5", cfg.Database.ConnMaxIdleTimeMin)
	}
	if cfg.Cache.Prefix != "oauth2:test:" {
		t.Errorf("Cache.Prefix = %q, want %q", cfg.Cache.Prefix, "oauth2:test:")
	}
	if cfg.Cache.DefaultTTLSec != 900 {
		t.Errorf("Cache.DefaultTTLSec = %d, want 900", cfg.Cache.DefaultTTLSec)
	}
	if len(cfg.Cache.MemcachedServers) != 2 || cfg.Cache.MemcachedServers[0] != "127.0.0.1:11211" || cfg.Cache.MemcachedServers[1] != "127.0.0.1:11212" {
		t.Errorf("Cache.MemcachedServers = %#v, want parsed list", cfg.Cache.MemcachedServers)
	}
	if cfg.Cache.BadgerPath != "/tmp/badger-cache" {
		t.Errorf("Cache.BadgerPath = %q, want /tmp/badger-cache", cfg.Cache.BadgerPath)
	}
	if cfg.Cache.FileDir != "/tmp/file-cache" {
		t.Errorf("Cache.FileDir = %q, want /tmp/file-cache", cfg.Cache.FileDir)
	}
	if cfg.Email.FromName != "OAuth2 Mailer" {
		t.Errorf("Email.FromName = %q, want %q", cfg.Email.FromName, "OAuth2 Mailer")
	}
	if cfg.Email.UseTLS {
		t.Error("Email.UseTLS = true, want false")
	}
	if !cfg.Social.Enabled || !cfg.Social.GitHub.Enabled || !cfg.Social.Google.Enabled {
		t.Errorf("Social enabled flags not applied: %+v", cfg.Social)
	}
	if cfg.Social.GitHub.ClientID != "gh-client" || cfg.Social.GitHub.ClientSecret != "gh-secret" {
		t.Errorf("GitHub social config mismatch: %+v", cfg.Social.GitHub)
	}
	if cfg.Social.Google.ClientID != "google-client" || cfg.Social.Google.ClientSecret != "google-secret" {
		t.Errorf("Google social config mismatch: %+v", cfg.Social.Google)
	}
	if cfg.Log.Level != "debug" || cfg.Log.Format != "json" || cfg.Log.FileOutput != "/tmp/oauth2.log" {
		t.Errorf("Log config mismatch: %+v", cfg.Log)
	}
	if cfg.Log.MaxSizeMB != 256 || cfg.Log.MaxBackups != 9 || cfg.Log.MaxAgeDays != 14 || !cfg.Log.Compress {
		t.Errorf("Log rotation config mismatch: %+v", cfg.Log)
	}
}

/* ========== defaultConfig ========== */

func TestDefaultConfig_HasValidDefaults(t *testing.T) {
	cfg := defaultConfig()
	if cfg.Server.Port != 8080 {
		t.Errorf("default Server.Port = %d, want 8080", cfg.Server.Port)
	}
	if cfg.Database.Driver != "sqlite" {
		t.Errorf("default Database.Driver = %q, want %q", cfg.Database.Driver, "sqlite")
	}
	if cfg.JWT.Secret == "" {
		t.Error("default JWT.Secret should not be empty")
	}
	if cfg.JWT.AccessTokenTTLMin <= 0 {
		t.Error("default AccessTokenTTLMin should be positive")
	}
}

/* ========== GenerateRandomSecret ========== */

func TestGenerateRandomSecret_Length(t *testing.T) {
	s := GenerateRandomSecret(32)
	if s == "" {
		t.Error("GenerateRandomSecret() returned empty string")
	}
}

func TestGenerateRandomSecret_Unique(t *testing.T) {
	s1 := GenerateRandomSecret(32)
	s2 := GenerateRandomSecret(32)
	if s1 == s2 {
		t.Error("GenerateRandomSecret() should produce different values")
	}
}
