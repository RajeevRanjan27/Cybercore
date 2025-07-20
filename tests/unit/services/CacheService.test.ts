
// ============================================================================
// tests/unit/services/CacheService.test.ts
// ============================================================================

import { CacheService } from '@/core/services/CacheService';
import {UserRole} from "../../../src/core/constants/roles";

describe('CacheService', () => {
    beforeEach(async () => {
        await CacheService.initialize();
    });

    describe('set and get', () => {
        it('should store and retrieve string values', async () => {
            await CacheService.set('test-key', 'test-value', 60);
            const result = await CacheService.get('test-key');
            expect(result).toBe('test-value');
        });

        it('should store and retrieve object values', async () => {
            const testObject = { name: 'test', value: 123, active: true };
            await CacheService.set('test-object', testObject, 60);
            const result = await CacheService.get('test-object');
            expect(result).toEqual(testObject);
        });

        it('should return null for non-existent keys', async () => {
            const result = await CacheService.get('non-existent-key');
            expect(result).toBeNull();
        });

        it('should handle TTL expiration', async () => {
            await CacheService.set('expiring-key', 'value', 1); // 1 second TTL

            // Immediately should be available
            let result = await CacheService.get('expiring-key');
            expect(result).toBe('value');

            // Wait for expiration
            await new Promise(resolve => setTimeout(resolve, 1100));
            result = await CacheService.get('expiring-key');
            expect(result).toBeNull();
        });
    });

    describe('delete', () => {
        it('should delete existing keys', async () => {
            await CacheService.set('delete-key', 'value', 60);
            await CacheService.delete('delete-key');
            const result = await CacheService.get('delete-key');
            expect(result).toBeNull();
        });

        it('should handle deletion of non-existent keys', async () => {
            await CacheService.delete('non-existent');
            // Should not throw error
        });
    });

    describe('exists', () => {
        it('should return true for existing keys', async () => {
            await CacheService.set('exists-key', 'value', 60);
            const exists = await CacheService.exists('exists-key');
            expect(exists).toBe(true);
        });

        it('should return false for non-existent keys', async () => {
            const exists = await CacheService.exists('non-existent');
            expect(exists).toBe(false);
        });
    });

    describe('getOrSet', () => {
        it('should fetch from cache if available', async () => {
            await CacheService.set('cached-key', 'cached-value', 60);

            const fetchFunction = jest.fn().mockResolvedValue('fresh-value');
            const result = await CacheService.getOrSet('cached-key', fetchFunction, 60);

            expect(result).toBe('cached-value');
            expect(fetchFunction).not.toHaveBeenCalled();
        });

        it('should fetch and cache if not available', async () => {
            const fetchFunction = jest.fn().mockResolvedValue('fresh-value');
            const result = await CacheService.getOrSet('new-key', fetchFunction, 60);

            expect(result).toBe('fresh-value');
            expect(fetchFunction).toHaveBeenCalledTimes(1);

            // Verify it was cached
            const cached = await CacheService.get('new-key');
            expect(cached).toBe('fresh-value');
        });
    });

    describe('invalidateUserCaches', () => {
        it('should clear user-related cache patterns', async () => {
            const userId = 'test-user-id';

            // Set some user-related cache entries
            await CacheService.set(`user:details:${userId}:requester`, { name: 'test' }, 60);
            await CacheService.set(`user:permissions:${userId}`, ['read'], 60);
            await CacheService.set(`users:list:containing:${userId}`, [], 60);

            await CacheService.invalidateUserCaches(userId);

            // Verify caches are cleared
            expect(await CacheService.get(`user:details:${userId}:requester`)).toBeNull();
            expect(await CacheService.get(`user:permissions:${userId}`)).toBeNull();
        });
    });

    describe('rateLimit', () => {
        it('should allow requests within limit', async () => {
            const result = await CacheService.rateLimit('test-key', 60000, 5);

            expect(result.allowed).toBe(true);
            expect(result.remaining).toBe(4);
            expect(result.resetTime).toBeGreaterThan(Date.now());
        });

        it('should block requests exceeding limit', async () => {
            const key = 'rate-limit-test';
            const windowMs = 60000;
            const maxRequests = 2;

            // Make requests up to limit
            for (let i = 0; i < maxRequests; i++) {
                const result = await CacheService.rateLimit(key, windowMs, maxRequests);
                expect(result.allowed).toBe(true);
            }

            // Next request should be blocked
            const blockedResult = await CacheService.rateLimit(key, windowMs, maxRequests);
            expect(blockedResult.allowed).toBe(false);
            expect(blockedResult.remaining).toBe(0);
        });
    });

    describe('generateUserListCacheKey', () => {
        it('should generate consistent cache keys', () => {
            const user = {
                userId: 'user-123',
                role: UserRole.USER,
                tenantId: 'tenant-123',
                permissions: ['user:read']
            };

            const params = {
                page: 1,
                limit: 10,
                search: 'test',
                role: UserRole.USER
            };

            const key1 = CacheService.generateUserListCacheKey(user, params);
            const key2 = CacheService.generateUserListCacheKey(user, params);

            expect(key1).toBe(key2);
            expect(key1).toContain('users:list:');
        });

        it('should generate different keys for different parameters', () => {
            const user = {
                userId: 'user-123',
                role: UserRole.USER,
                tenantId: 'tenant-123',
                permissions: ['user:read']
            };

            const params1 = { page: 1, limit: 10 };
            const params2 = { page: 2, limit: 10 };

            const key1 = CacheService.generateUserListCacheKey(user, params1);
            const key2 = CacheService.generateUserListCacheKey(user, params2);

            expect(key1).not.toBe(key2);
        });
    });
});
