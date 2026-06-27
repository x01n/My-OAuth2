package service

import (
	"context"
	"fmt"
	"time"

	"server/internal/model"
	"server/internal/repository"
	"server/pkg/cache"
)

/*
 * CacheWarmer 缓存预热服务
 * 功能：在启动期主动填充 Redis/统一缓存中的热数据，降低冷启动回源抖动
 */
type CacheWarmer struct {
	cache          cache.Cache
	federationRepo *repository.CachedFederationRepository
	configRepo     *repository.CachedConfigRepository
}

/* NewCacheWarmer 创建缓存预热服务 */
func NewCacheWarmer(
	c cache.Cache,
	federationRepo *repository.CachedFederationRepository,
	configRepo *repository.CachedConfigRepository,
) *CacheWarmer {
	return &CacheWarmer{
		cache:          c,
		federationRepo: federationRepo,
		configRepo:     configRepo,
	}
}

/* Warmup 启动期预热热路径缓存 */
func (w *CacheWarmer) Warmup(ctx context.Context, allowRegistration bool) error {
	if w.cache == nil {
		return nil
	}
	if w.federationRepo != nil {
		if _, err := w.federationRepo.FindAllEnabled(); err != nil {
			return fmt.Errorf("warm federation providers: %w", err)
		}
	}
	if w.configRepo != nil {
		if _, err := w.configRepo.GetPublicConfig(&allowRegistration); err != nil {
			return fmt.Errorf("warm public config: %w", err)
		}
	}

	_ = cache.SetJSON(ctx, w.cache, "meta:cache_warmed", map[string]any{"at": time.Now().UTC().Format(time.RFC3339), "allow_registration": allowRegistration}, 5*time.Minute)
	return nil
}

/* WarmModelPlaceholders 预留模型类型引用，避免后续预热扩展时散落 import */
var _ model.SystemConfig
