// ============================================================================
// tests/unit/core/services/RedisService.test.ts
// ============================================================================

import { RedisService as RedisServiceType } from '@/core/services/RedisService';
import { createClient } from 'redis';

// 1. Mock the 'redis' library at the top level. This is hoisted by Jest.
jest.mock('redis', () => ({
    createClient: jest.fn(),
}));

// 2. Cast the mocked import so TypeScript recognizes it as a mock function.
const mockedCreateClient = createClient as jest.Mock;

// 3. Define a consistent mock object for the Redis client.
const mockRedisClient = {
    on: jest.fn(),
    connect: jest.fn(),
    quit: jest.fn(),
    get: jest.fn(),
    setEx: jest.fn(),
    set: jest.fn(),
    del: jest.fn(),
    keys: jest.fn(),
    ping: jest.fn(),
    isReady: true, // Simulate a ready client by default for success cases
};

describe('RedisService', () => {
    let RedisService: typeof RedisServiceType;

    beforeEach(async () => {
        // 4. Clear mocks from previous runs.
        jest.clearAllMocks();

        // 5. Set the return value for the mocked createClient.
        mockedCreateClient.mockReturnValue(mockRedisClient);

        // 6. Set default successful promises for mocks.
        mockRedisClient.connect.mockResolvedValue(true);
        mockRedisClient.ping.mockResolvedValue('PONG');

        // 7. Use jest.isolateModulesAsync to get a fresh, un-cached version of the RedisService.
        // This ensures it uses the mock we just configured, not one from the global setup.
        await jest.isolateModulesAsync(async () => {
            RedisService = (await import('@/core/services/RedisService')).RedisService;
        });
    });

    it('should initialize and connect to Redis', async () => {
        await RedisService.initialize();
        expect(mockedCreateClient).toHaveBeenCalled();
        expect(mockRedisClient.connect).toHaveBeenCalled();
        expect(RedisService.isRedisConnected()).toBe(true);
    });

    it('should handle connection errors gracefully', async () => {
        // Override the default mock for this specific test case
        mockRedisClient.connect.mockRejectedValueOnce(new Error('Connection failed'));
        await RedisService.initialize();
        expect(RedisService.isRedisConnected()).toBe(false);
    });

    it('should set a value in Redis', async () => {
        await RedisService.initialize(); // Ensures service's internal state is "connected"
        await RedisService.set('my-key', { data: 'value' }, 300);
        expect(mockRedisClient.setEx).toHaveBeenCalledWith(
            'my-key',
            300,
            JSON.stringify({ data: 'value' })
        );
    });

    it('should get a value from Redis', async () => {
        await RedisService.initialize();
        mockRedisClient.get.mockResolvedValue(JSON.stringify({ data: 'value' }));

        const value = await RedisService.get('my-key');

        expect(mockRedisClient.get).toHaveBeenCalledWith('my-key');
        expect(value).toEqual({ data: 'value' });
    });

    it('should delete a key from Redis', async () => {
        await RedisService.initialize();
        await RedisService.delete('my-key');
        expect(mockRedisClient.del).toHaveBeenCalledWith('my-key');
    });

    it('should delete keys by pattern', async () => {
        await RedisService.initialize();
        mockRedisClient.keys.mockResolvedValue(['user:1', 'user:2']);

        await RedisService.deletePattern('user:*');

        expect(mockRedisClient.keys).toHaveBeenCalledWith('user:*');
        expect(mockRedisClient.del).toHaveBeenCalledWith(['user:1', 'user:2']);
    });

    it('should ping the Redis server', async () => {
        await RedisService.initialize();
        const result = await RedisService.ping();
        expect(mockRedisClient.ping).toHaveBeenCalled();
        expect(result).toBe('PONG');
    });

    it('should throw an error on ping if not connected', async () => {
        // The service is not initialized here, so isConnected is false.
        await expect(RedisService.ping()).rejects.toThrow('Redis not connected');
    });
});
