// src/core/services/CacheService.ts
import { logger } from '@/core/infra/logger';
import { AuthPayload } from '@/core/types';
import {RedisService} from "@/core/services/RedisService";

// In-memory cache for development/fallback
class MemoryCache {
    private cache = new Map<string, { value: any; expiry: number }>();
    private cleanupInterval: NodeJS.Timeout;

    constructor() {
        // Clean up expired entries every 5 minutes
        this.cleanupInterval = setInterval(() => {
            this.cleanup();
        }, 5 * 60 * 1000);
    }

    set(key: string, value: any, ttlSeconds: number): void {
        const expiry = Date.now() + (ttlSeconds * 1000);
        this.cache.set(key, { value, expiry });
    }

    get(key: string): any {
        const item = this.cache.get(key);
        if (!item) return null;

        if (Date.now() > item.expiry) {
            this.cache.delete(key);
            return null;
        }

        return item.value;
    }

    delete(key: string): void {
        this.cache.delete(key);
    }

    deletePattern(pattern: string): void {
        const regex = new RegExp(pattern.replace(/\*/g, '.*'));
        for (const key of this.cache.keys()) {
            if (regex.test(key)) {
                this.cache.delete(key);
            }
        }
    }

    clear(): void {
        this.cache.clear();
    }

    private cleanup(): void {
        const now = Date.now();
        for (const [key, item] of this.cache.entries()) {
            if (now > item.expiry) {
                this.cache.delete(key);
            }
        }
    }

    getStats(): { size: number; keys: string[] } {
        return {
            size: this.cache.size,
            keys: Array.from(this.cache.keys())
        };
    }

    destroy(): void {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
        }
        this.cache.clear();
    }
}

export class CacheService {
    private static memoryCache = new MemoryCache();
    private static isRedisAvailable = false;
    private static redisClient: any = null;

    /**
     * Initialize cache service with Redis if available
     */
    static async initialize(): Promise<void> {
        try {
            // In a real application, you would initialize Redis client here
            await RedisService.initialize();
            logger.info('Cache service initialized with memory cache');
        } catch (error) {
            logger.warn('Redis not available, using memory cache:', error);
            this.isRedisAvailable = false;
        }
    }

    /**
     * Set cache value with TTL
     */
    static async set(key: string, value: any, ttlSeconds: number = 300): Promise<void> {
        try {
            const serializedValue = JSON.stringify(value);

            if (this.isRedisAvailable && this.redisClient) {
                await this.redisClient.setex(key, ttlSeconds, serializedValue);
            } else {
                this.memoryCache.set(key, value, ttlSeconds);
            }

            logger.debug('Cache set', { key, ttl: ttlSeconds });
        } catch (error) {
            logger.error('Cache set error:', error);
        }
    }

    /**
     * Get cache value
     */
    static async get(key: string): Promise<any> {
        try {
            if (this.isRedisAvailable && this.redisClient) {
                const value = await this.redisClient.get(key);
                return value ? JSON.parse(value) : null;
            } else {
                return this.memoryCache.get(key);
            }
        } catch (error) {
            logger.error('Cache get error:', error);
            return null;
        }
    }

    /**
     * Delete cache entry
     */
    static async delete(key: string): Promise<void> {
        try {
            if (this.isRedisAvailable && this.redisClient) {
                await this.redisClient.del(key);
            } else {
                this.memoryCache.delete(key);
            }

            logger.debug('Cache deleted', { key });
        } catch (error) {
            logger.error('Cache delete error:', error);
        }
    }

    /**
     * Delete cache entries by pattern
     */
    static async deletePattern(pattern: string): Promise<void> {
        try {
            if (this.isRedisAvailable && this.redisClient) {
                const keys = await this.redisClient.keys(pattern);
                if (keys.length > 0) {
                    await this.redisClient.del(keys);
                }
            } else {
                this.memoryCache.deletePattern(pattern);
            }

            logger.debug('Cache pattern deleted', { pattern });
        } catch (error) {
            logger.error('Cache pattern delete error:', error);
        }
    }

    /**
     * Check if cache entry exists
     */
    static async exists(key: string): Promise<boolean> {
        try {
            if (this.isRedisAvailable && this.redisClient) {
                return await this.redisClient.exists(key) === 1;
            } else {
                return this.memoryCache.get(key) !== null;
            }
        } catch (error) {
            logger.error('Cache exists error:', error);
            return false;
        }
    }

    /**
     * Set cache with expiration time
     */
    static async setWithExpiry(key: string, value: any, expiryDate: Date): Promise<void> {
        const ttlSeconds = Math.max(0, Math.floor((expiryDate.getTime() - Date.now()) / 1000));
        await this.set(key, value, ttlSeconds);
    }

    /**
     * Get or set cache value (cache-aside pattern)
     */
    static async getOrSet<T>(
        key: string,
        fetchFunction: () => Promise<T>,
        ttlSeconds: number = 300
    ): Promise<T> {
        try {
            // Try to get from cache first
            const cachedValue = await this.get(key);
            if (cachedValue !== null) {
                return cachedValue;
            }

            // Fetch from source
            const value = await fetchFunction();

            // Store in cache
            await this.set(key, value, ttlSeconds);

            return value;
        } catch (error) {
            logger.error('Cache getOrSet error:', error);
            // Fallback to direct fetch
            return await fetchFunction();
        }
    }

    /**
     * Generate cache key for user list
     */
    static generateUserListCacheKey(user: AuthPayload, params: any): string {
        const keyParams = {
            userId: user.userId,
            role: user.role,
            tenantId: user.tenantId,
            page: params.page || 1,
            limit: params.limit || 10,
            search: params.search || '',
            role_filter: params.role || '',
            isActive: params.isActive || '',
            sortBy: params.sortBy || 'createdAt',
            sortOrder: params.sortOrder || 'desc',
            dateFrom: params.dateFrom || '',
            dateTo: params.dateTo || ''
        };

        const keyString = Object.entries(keyParams)
            .map(([k, v]) => `${k}:${v}`)
            .join('|');

        return `users:list:${Buffer.from(keyString).toString('base64')}`;
    }

    /**
     * Generate cache key for user details
     */
    static generateUserDetailsCacheKey(userId: string, requestingUserId: string): string {
        return `user:details:${userId}:${requestingUserId}`;
    }

    /**
     * Generate cache key for user permissions
     */
    static generateUserPermissionsCacheKey(userId: string): string {
        return `user:permissions:${userId}`;
    }

    /**
     * Generate cache key for user statistics
     */
    static generateUserStatsCacheKey(user: AuthPayload, params: any): string {
        const keyParams = {
            userId: user.userId,
            role: user.role,
            tenantId: user.tenantId,
            period: params.period || '30d',
            groupBy: params.groupBy || 'day',
            includeInactive: params.includeInactive || 'false'
        };

        const keyString = Object.entries(keyParams)
            .map(([k, v]) => `${k}:${v}`)
            .join('|');

        return `users:stats:${Buffer.from(keyString).toString('base64')}`;
    }

    /**
     * Invalidate all user-related caches for a specific user
     */
    static async invalidateUserCaches(userId: string): Promise<void> {
        const patterns = [
            `user:details:${userId}:*`,
            `user:permissions:${userId}`,
            `users:list:*`,
            `users:stats:*`,
            `user:activity:${userId}:*`,
            `user:sessions:${userId}`
        ];

        await Promise.all(patterns.map(pattern => this.deletePattern(pattern)));

        logger.debug('User caches invalidated', { userId });
    }

    /**
     * Invalidate tenant-related caches
     */
    static async invalidateTenantCaches(tenantId: string): Promise<void> {
        const patterns = [
            `tenant:${tenantId}:*`,
            `users:list:*`,
            `users:stats:*`
        ];

        await Promise.all(patterns.map(pattern => this.deletePattern(pattern)));

        logger.debug('Tenant caches invalidated', { tenantId });
    }

    /**
     * Warm up cache with frequently accessed data
     */
    static async warmUpCache(): Promise<void> {
        try {
            // In a real application, you would pre-load frequently accessed data
            logger.info('Cache warm-up started');

            // Example: Pre-load active user counts, role distributions, etc.
            // await this.preloadUserStatistics();
            // await this.preloadTenantData();

            logger.info('Cache warm-up completed');
        } catch (error) {
            logger.error('Cache warm-up error:', error);
        }
    }

    /**
     * Get cache statistics
     */
    static async getStats(): Promise<any> {
        try {
            if (this.isRedisAvailable && this.redisClient) {
                const info = await this.redisClient.info('memory');
                return {
                    type: 'redis',
                    connected: true,
                    memory: info
                };
            } else {
                return {
                    type: 'memory',
                    connected: true,
                    ...this.memoryCache.getStats()
                };
            }
        } catch (error) {
            logger.error('Cache stats error:', error);
            return {
                type: 'unknown',
                connected: false,
                error: error instanceof Error ? error.message : 'Unknown error'
            };
        }
    }

    /**
     * Cache middleware helper
     */
    static createCacheMiddleware(ttlSeconds: number = 300) {
        return async (req: any, res: any, next: any) => {
            try {
                // Generate cache key based on request
                const cacheKey = this.generateRequestCacheKey(req);

                // Try to get cached response
                const cachedResponse = await this.get(cacheKey);

                if (cachedResponse) {
                    // Add cache headers
                    res.set({
                        'X-Cache': 'HIT',
                        'X-Cache-Key': cacheKey,
                        'Cache-Control': `public, max-age=${ttlSeconds}`
                    });

                    return res.json(cachedResponse);
                }

                // Store original json method
                const originalJson = res.json;

                // Override json method to cache response
                res.json = function(body: any) {
                    // Cache the response
                    CacheService.set(cacheKey, body, ttlSeconds).catch(err => {
                        logger.error('Failed to cache response:', err);
                    });

                    // Add cache headers
                    res.set({
                        'X-Cache': 'MISS',
                        'X-Cache-Key': cacheKey,
                        'Cache-Control': `public, max-age=${ttlSeconds}`
                    });

                    // Call original json method
                    return originalJson.call(this, body);
                };

                next();
            } catch (error) {
                logger.error('Cache middleware error:', error);
                next();
            }
        };
    }

    /**
     * Generate cache key for HTTP requests
     */
    private static generateRequestCacheKey(req: any): string {
        const user = req.user;
        const keyData = {
            method: req.method,
            path: req.path,
            query: JSON.stringify(req.query),
            userId: user?.userId || 'anonymous',
            role: user?.role || 'none',
            tenantId: user?.tenantId || 'none'
        };

        const keyString = Object.entries(keyData)
            .map(([k, v]) => `${k}:${v}`)
            .join('|');

        return `request:${Buffer.from(keyString).toString('base64')}`;
    }

    /**
     * Clear all cache
     */
    static async clearAll(): Promise<void> {
        try {
            if (this.isRedisAvailable && this.redisClient) {
                await this.redisClient.flushall();
            } else {
                this.memoryCache.clear();
            }

            logger.info('All cache cleared');
        } catch (error) {
            logger.error('Cache clear all error:', error);
        }
    }

    /**
     * Set multiple cache entries at once
     */
    static async setMultiple(entries: Array<{ key: string; value: any; ttl?: number }>): Promise<void> {
        try {
            await Promise.all(
                entries.map(entry =>
                    this.set(entry.key, entry.value, entry.ttl || 300)
                )
            );
        } catch (error) {
            logger.error('Cache setMultiple error:', error);
        }
    }

    /**
     * Get multiple cache entries at once
     */
    static async getMultiple(keys: string[]): Promise<Record<string, any>> {
        try {
            const results: Record<string, any> = {};

            if (this.isRedisAvailable && this.redisClient) {
                const values = await this.redisClient.mget(keys);
                keys.forEach((key, index) => {
                    results[key] = values[index] ? JSON.parse(values[index]) : null;
                });
            } else {
                for (const key of keys) {
                    results[key] = this.memoryCache.get(key);
                }
            }

            return results;
        } catch (error) {
            logger.error('Cache getMultiple error:', error);
            return {};
        }
    }

    /**
     * Increment cache value (useful for counters)
     */
    static async increment(key: string, amount: number = 1): Promise<number> {
        try {
            if (this.isRedisAvailable && this.redisClient) {
                return await this.redisClient.incrby(key, amount);
            } else {
                const current = this.memoryCache.get(key) || 0;
                const newValue = current + amount;
                this.memoryCache.set(key, newValue, 3600); // 1 hour default
                return newValue;
            }
        } catch (error) {
            logger.error('Cache increment error:', error);
            return 0;
        }
    }

    /**
     * Cleanup method for graceful shutdown
     */
    static async cleanup(): Promise<void> {
        try {
            if (this.redisClient) {
                await this.redisClient.quit();
            }
            this.memoryCache.destroy();
            logger.info('Cache service cleaned up');
        } catch (error) {
            logger.error('Cache cleanup error:', error);
        }
    }

    /**
     * Rate limiting functionality
     */
    static async rateLimit(
        key: string,
        windowMs: number,
        maxRequests: number
    ): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
        try {
            if (RedisService.isRedisConnected()) {
                return await RedisService.rateLimit(key, windowMs, maxRequests);
            } else {
                // Simple memory-based rate limiting fallback
                const rateLimitKey = `rate_limit:${key}`;
                const now = Date.now();
                const window = Math.floor(now / windowMs);
                const windowKey = `${rateLimitKey}:${window}`;

                const current = (this.memoryCache.get(windowKey) || 0) + 1;
                this.memoryCache.set(windowKey, current, Math.ceil(windowMs / 1000));

                const allowed = current <= maxRequests;
                const remaining = Math.max(0, maxRequests - current);
                const resetTime = (window + 1) * windowMs;

                return { allowed, remaining, resetTime };
            }
        } catch (error) {
            logger.error('Cache rate limit error:', error);
            return { allowed: true, remaining: maxRequests - 1, resetTime: Date.now() + windowMs };
        }
    }


    /**
     * Set operations for Redis
     */
    static async setAdd(setKey: string, value: string): Promise<void> {
        if (RedisService.isRedisConnected()) {
            await RedisService.setAdd(setKey, value);
        }
        // For memory cache, we'd implement a simple Set simulation
        // but for now, we'll just skip if Redis isn't available
    }
}