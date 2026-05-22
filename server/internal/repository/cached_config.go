package repository

import (
	"context"
	"time"

	"server/pkg/cache"
)

const (
	publicConfigCacheKey = "config:public"
	publicConfigCacheTTL = 2 * time.Minute
)

/*
 * CachedConfigRepository 带缓存的系统配置仓储
 * 功能：缓存公开配置读取结果，减少 /api/config 热路径 DB 查询
 */
type CachedConfigRepository struct {
	*ConfigRepository
	cache cache.Cache
}

/* NewCachedConfigRepository 创建带缓存的配置仓储实例 */
func NewCachedConfigRepository(repo *ConfigRepository, c cache.Cache) *CachedConfigRepository {
	return &CachedConfigRepository{
		ConfigRepository: repo,
		cache:            c,
	}
}

/* GetPublicConfig 获取公开配置（优先缓存，未命中时回源 DB） */
func (r *CachedConfigRepository) GetPublicConfig(runtimeAllowRegistration *bool) (map[string]string, error) {
	ctx := context.Background()
	configs, err := cache.GetJSON[map[string]string](ctx, r.cache, publicConfigCacheKey)
	if err == nil {
		if runtimeAllowRegistration != nil {
			configs["allow_registration"] = map[bool]string{true: "true", false: "false"}[*runtimeAllowRegistration]
		}
		return configs, nil
	}

	allConfigs, err := r.ConfigRepository.GetAll()
	if err != nil {
		return nil, err
	}

	publicConfigs := map[string]string{}
	for _, key := range []string{"frontend_url", "server_url", "site_name"} {
		if value, ok := allConfigs[key]; ok {
			publicConfigs[key] = value
		}
	}
	_ = cache.SetJSON(ctx, r.cache, publicConfigCacheKey, publicConfigs, publicConfigCacheTTL)

	if runtimeAllowRegistration != nil {
		publicConfigs["allow_registration"] = map[bool]string{true: "true", false: "false"}[*runtimeAllowRegistration]
	}
	return publicConfigs, nil
}

/* invalidatePublicConfig 清除公开配置缓存 */
func (r *CachedConfigRepository) invalidatePublicConfig() {
	_ = r.cache.Delete(context.Background(), publicConfigCacheKey)
}

/* Set 更新配置并失效公开配置缓存 */
func (r *CachedConfigRepository) Set(key, value string) error {
	err := r.ConfigRepository.Set(key, value)
	if err == nil {
		r.invalidatePublicConfig()
	}
	return err
}

/* Delete 删除配置并失效公开配置缓存 */
func (r *CachedConfigRepository) Delete(key string) error {
	err := r.ConfigRepository.Delete(key)
	if err == nil {
		r.invalidatePublicConfig()
	}
	return err
}
