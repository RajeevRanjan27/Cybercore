// tests/integration/cacheservice.integration.test.ts

import { CacheService } from '@/core/services/CacheService';

describe('CacheService Integration Tests', () => {
    beforeAll(async () => {
        await CacheService.initialize();
    });

    afterAll(async () => {
        await CacheService.cleanup();
    });

    beforeEach(async () => {
        // Clear cache before each test
        if (typeof CacheService.clear === 'function') {
            await CacheService.clear();
        } else {
            await CacheService.clearAll();
        }
    });

    describe('Connection and Status', () => {
        it('should be connected after initialization', () => {
            expect(typeof CacheService.isConnected).toBe('function');
            expect(CacheService.isConnected()).toBe(true);
        });

        it('should return connection status', () => {
            const status = CacheService.getConnectionStatus();
            expect(status).toHaveProperty('connected');
            expect(status).toHaveProperty('type');
            expect(status.connected).toBe(true);
            expect(['redis', 'memory']).toContain(status.type);
        });

        it('should wait for ready state', async () => {
            const isReady = await CacheService.waitForReady(1000);
            expect(isReady).toBe(true);
        });
    });

    describe('Basic Cache Operations', () => {
        it('should set and get values', async () => {
            await CacheService.set('test-key', 'test-value', 60);
            const value = await CacheService.get('test-key');
            expect(value).toBe('test-value');
        });

        it('should handle object values', async () => {
            const testObject = { name: 'test', value: 123, active: true };
            await CacheService.set('test-object', testObject, 60);
            const retrieved = await CacheService.get('test-object');
            expect(retrieved).toEqual(testObject);
        });

        it('should return null for non-existent keys', async () => {
            const value = await CacheService.get('non-existent-key');
            expect(value).toBeNull();
        });

        it('should delete cache entries', async () => {
            await CacheService.set('delete-me', 'value', 60);
            await CacheService.delete('delete-me');
            const value = await CacheService.get('delete-me');
            expect(value).toBeNull();
        });

        it('should check if keys exist', async () => {
            await CacheService.set('exists-key', 'value', 60);
            const exists = await CacheService.exists('exists-key');
            expect(exists).toBe(true);

            const notExists = await CacheService.exists('not-exists');
            expect(notExists).toBe(false);
        });
    });

    describe('Clear Operations', () => {
        it('should clear all cache using clear() method', async () => {
            await CacheService.set('key1', 'value1', 60);
            await CacheService.set('key2', 'value2', 60);

            // Test that clear() method exists and works
            expect(typeof CacheService.clear).toBe('function');
            await CacheService.clear();

            const value1 = await CacheService.get('key1');
            const value2 = await CacheService.get('key2');
            expect(value1).toBeNull();
            expect(value2).toBeNull();
        });

        it('should clear all cache using clearAll() method', async () => {
            await CacheService.set('key1', 'value1', 60);
            await CacheService.set('key2', 'value2', 60);

            await CacheService.clearAll();

            const value1 = await CacheService.get('key1');
            const value2 = await CacheService.get('key2');
            expect(value1).toBeNull();
            expect(value2).toBeNull();
        });
    });

    describe('Advanced Operations', () => {
        it('should handle getOrSet pattern', async () => {
            let fetchCalled = false;
            const fetchFunction = async () => {
                fetchCalled = true;
                return { data: 'fetched-value' };
            };

            // First call should fetch
            const result1 = await CacheService.getOrSet('cache-key', fetchFunction, 60);
            expect(result1).toEqual({ data: 'fetched-value' });
            expect(fetchCalled).toBe(true);

            // Second call should use cache
            fetchCalled = false;
            const result2 = await CacheService.getOrSet('cache-key', fetchFunction, 60);
            expect(result2).toEqual({ data: 'fetched-value' });
            expect(fetchCalled).toBe(false);
        });

        it('should handle multiple operations', async () => {
            const entries = [
                { key: 'multi1', value: 'value1', ttl: 60 },
                { key: 'multi2', value: 'value2', ttl: 60 },
                { key: 'multi3', value: 'value3', ttl: 60 }
            ];

            await CacheService.setMultiple(entries);

            const results = await CacheService.getMultiple(['multi1', 'multi2', 'multi3']);
            expect(results.multi1).toBe('value1');
            expect(results.multi2).toBe('value2');
            expect(results.multi3).toBe('value3');
        });

        it('should handle rate limiting', async () => {
            const result1 = await CacheService.rateLimit('test-rate', 60000, 2);
            expect(result1.allowed).toBe(true);
            expect(result1.remaining).toBe(1);

            const result2 = await CacheService.rateLimit('test-rate', 60000, 2);
            expect(result2.allowed).toBe(true);
            expect(result2.remaining).toBe(0);

            const result3 = await CacheService.rateLimit('test-rate', 60000, 2);
            expect(result3.allowed).toBe(false);
            expect(result3.remaining).toBe(0);
        });
    });

    describe('Pattern Deletion', () => {
        it('should delete keys by pattern', async () => {
            await CacheService.set('user:123:profile', 'profile-data', 60);
            await CacheService.set('user:123:settings', 'settings-data', 60);
            await CacheService.set('user:456:profile', 'other-profile', 60);

            await CacheService.deletePattern('user:123:*');

            const profile123 = await CacheService.get('user:123:profile');
            const settings123 = await CacheService.get('user:123:settings');
            const profile456 = await CacheService.get('user:456:profile');

            expect(profile123).toBeNull();
            expect(settings123).toBeNull();
            expect(profile456).toBe('other-profile'); // Should still exist
        });
    });

    describe('Cache Invalidation', () => {
        it('should invalidate user caches', async () => {
            const userId = 'test-user-123';

            await CacheService.set(`user:details:${userId}:requester`, 'details', 60);
            await CacheService.set(`user:permissions:${userId}`, 'permissions', 60);
            await CacheService.set('users:list:some-key', 'list', 60);

            await CacheService.invalidateUserCaches(userId);

            const details = await CacheService.get(`user:details:${userId}:requester`);
            const permissions = await CacheService.get(`user:permissions:${userId}`);

            expect(details).toBeNull();
            expect(permissions).toBeNull();
        });

        it('should invalidate tenant caches', async () => {
            const tenantId = 'test-tenant-123';

            await CacheService.set(`tenant:${tenantId}:settings`, 'settings', 60);
            await CacheService.set('users:list:tenant-key', 'list', 60);

            await CacheService.invalidateTenantCaches(tenantId);

            const settings = await CacheService.get(`tenant:${tenantId}:settings`);
            expect(settings).toBeNull();
        });
    });

    describe('Statistics and Monitoring', () => {
        it('should return cache stats', async () => {
            const stats = await CacheService.getStats();
            expect(stats).toHaveProperty('type');
            expect(stats).toHaveProperty('connected');
            expect(['redis', 'memory', 'unknown']).toContain(stats.type);
        });
    });
});