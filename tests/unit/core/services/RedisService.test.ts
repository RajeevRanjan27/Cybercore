// ============================================================================
// tests/unit/core/services/RedisService.test.ts - 100% Coverage Test Suite
// ============================================================================

import { RedisService as RedisServiceType } from '@/core/services/RedisService';
import { createClient } from 'redis';

// Mock the 'redis' library
jest.mock('redis', () => ({
    createClient: jest.fn(),
}));

// Mock the logger to avoid console noise during tests
jest.mock('@/core/infra/logger', () => ({
    logger: {
        info: jest.fn(),
        error: jest.fn(),
        warn: jest.fn(),
        debug: jest.fn(),
    }
}));

// Mock the config
jest.mock('@/config/env', () => ({
    config: {
        REDIS_URL: 'redis://localhost:6379',
        REDIS_PASSWORD: 'test-password'
    }
}));

const mockedCreateClient = createClient as jest.Mock;

describe('RedisService - 100% Coverage Test Suite', () => {
    let RedisService: typeof RedisServiceType;
    let mockRedisClient: any;

    beforeEach(async () => {
        jest.clearAllMocks();

        // Create a fresh mock client for each test
        mockRedisClient = {
            on: jest.fn(),
            connect: jest.fn(),
            quit: jest.fn(),
            disconnect: jest.fn(),
            get: jest.fn(),
            set: jest.fn(),
            setEx: jest.fn(),
            del: jest.fn(),
            keys: jest.fn(),
            ping: jest.fn(),
            exists: jest.fn(),
            expire: jest.fn(),
            ttl: jest.fn(),
            incrBy: jest.fn(),
            decrBy: jest.fn(),
            sAdd: jest.fn(),
            sRem: jest.fn(),
            sIsMember: jest.fn(),
            sMembers: jest.fn(),
            hSet: jest.fn(),
            hGet: jest.fn(),
            hGetAll: jest.fn(),
            hDel: jest.fn(),
            lPush: jest.fn(),
            rPush: jest.fn(),
            lPop: jest.fn(),
            lRange: jest.fn(),
            lLen: jest.fn(),
            publish: jest.fn(),
            flushDb: jest.fn(),
            flushAll: jest.fn(),
            dbSize: jest.fn(),
            info: jest.fn(),
            multi: jest.fn(),
            isReady: true,
            status: 'ready'
        };

        mockedCreateClient.mockReturnValue(mockRedisClient);
        mockRedisClient.connect.mockResolvedValue(true);

        // Get fresh instance of RedisService for each test
        await jest.isolateModulesAsync(async () => {
            RedisService = (await import('@/core/services/RedisService')).RedisService;
        });
    });

    describe('initialize()', () => {
        it('should successfully initialize Redis connection', async () => {
            await RedisService.initialize();

            expect(mockedCreateClient).toHaveBeenCalledWith({
                url: 'redis://localhost:6379',
                password: 'test-password',
                socket: {
                    connectTimeout: 10000,
                    reconnectStrategy: expect.any(Function)
                }
            });

            expect(mockRedisClient.on).toHaveBeenCalledWith('error', expect.any(Function));
            expect(mockRedisClient.on).toHaveBeenCalledWith('connect', expect.any(Function));
            expect(mockRedisClient.on).toHaveBeenCalledWith('ready', expect.any(Function));
            expect(mockRedisClient.on).toHaveBeenCalledWith('end', expect.any(Function));
            expect(mockRedisClient.connect).toHaveBeenCalled();
            expect(RedisService.isRedisConnected()).toBe(true);
        });

        it('should handle connection errors gracefully', async () => {
            mockRedisClient.connect.mockRejectedValueOnce(new Error('Connection failed'));

            await RedisService.initialize();

            expect(RedisService.isRedisConnected()).toBe(false);
        });

        it('should test reconnection strategy function', async () => {
            await RedisService.initialize();

            const createClientCall = mockedCreateClient.mock.calls[0][0];
            const reconnectStrategy = createClientCall.socket.reconnectStrategy;

            // Test the ACTUAL reconnection strategy logic:
            // if (retries > 10) return false
            // else return Math.min(retries * 100, 3000)

            // Test valid retries (retries <= 10)
            expect(reconnectStrategy(1)).toBe(100);   // Math.min(1 * 100, 3000) = 100
            expect(reconnectStrategy(5)).toBe(500);   // Math.min(5 * 100, 3000) = 500  
            expect(reconnectStrategy(10)).toBe(1000); // Math.min(10 * 100, 3000) = 1000

            // Test retries > 10 (should return false)
            expect(reconnectStrategy(11)).toBe(false); // 11 > 10, so false
            expect(reconnectStrategy(15)).toBe(false); // 15 > 10, so false
            expect(reconnectStrategy(30)).toBe(false); // 30 > 10, so false
            expect(reconnectStrategy(50)).toBe(false); // 50 > 10, so false

            // Test edge cases to verify the Math.min capping logic
            // Since retries must be <= 10 to not return false, max possible delay is:
            // Math.min(10 * 100, 3000) = Math.min(1000, 3000) = 1000
            // The 3000ms cap would only apply if retries > 30 were allowed, but they're not
        });

        it('should handle error event', async () => {
            await RedisService.initialize();

            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Test error'));

            expect(RedisService.isRedisConnected()).toBe(false);
        });

        it('should handle connect event', async () => {
            await RedisService.initialize();

            const connectHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'connect')[1];
            connectHandler();

            // Should just log, no state change expected
        });

        it('should handle ready event', async () => {
            await RedisService.initialize();

            const readyHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'ready')[1];
            readyHandler();

            expect(RedisService.isRedisConnected()).toBe(true);
        });

        it('should handle end event', async () => {
            await RedisService.initialize();

            const endHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'end')[1];
            endHandler();

            expect(RedisService.isRedisConnected()).toBe(false);
        });
    });

    describe('isRedisConnected()', () => {
        it('should return true when connected and client is ready', async () => {
            await RedisService.initialize();
            expect(RedisService.isRedisConnected()).toBe(true);
        });

        it('should return false when not initialized', () => {
            expect(RedisService.isRedisConnected()).toBe(false);
        });

        it('should return false when client is not ready', async () => {
            mockRedisClient.isReady = false;
            await RedisService.initialize();

            // Simulate error event to set isConnected to false
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Test error'));

            expect(RedisService.isRedisConnected()).toBe(false);
        });
    });

    describe('getClient()', () => {
        it('should return client when connected', async () => {
            await RedisService.initialize();
            const client = RedisService.getClient();
            expect(client).toBe(mockRedisClient);
        });

        it('should return null when not connected', () => {
            const client = RedisService.getClient();
            expect(client).toBeNull();
        });
    });

    describe('set()', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        it('should set value with TTL', async () => {
            const result = await RedisService.set('test-key', { data: 'value' }, 300);

            expect(mockRedisClient.setEx).toHaveBeenCalledWith(
                'test-key',
                300,
                JSON.stringify({ data: 'value' })
            );
            expect(result).toBe(true);
        });

        it('should set value without TTL', async () => {
            const result = await RedisService.set('test-key', { data: 'value' });

            expect(mockRedisClient.set).toHaveBeenCalledWith(
                'test-key',
                JSON.stringify({ data: 'value' })
            );
            expect(result).toBe(true);
        });

        it('should return false when not connected', async () => {
            // Simulate disconnection
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Connection lost'));

            const result = await RedisService.set('test-key', 'value');
            expect(result).toBe(false);
        });

        it('should handle Redis errors gracefully', async () => {
            mockRedisClient.setEx.mockRejectedValueOnce(new Error('Redis error'));

            const result = await RedisService.set('test-key', 'value', 300);
            expect(result).toBe(false);
        });
    });

    describe('get()', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        it('should get and parse JSON value', async () => {
            mockRedisClient.get.mockResolvedValueOnce(JSON.stringify({ data: 'value' }));

            const result = await RedisService.get('test-key');

            expect(mockRedisClient.get).toHaveBeenCalledWith('test-key');
            expect(result).toEqual({ data: 'value' });
        });

        it('should return null for non-existent key', async () => {
            mockRedisClient.get.mockResolvedValueOnce(null);

            const result = await RedisService.get('test-key');
            expect(result).toBeNull();
        });

        it('should return null when not connected', async () => {
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Connection lost'));

            const result = await RedisService.get('test-key');
            expect(result).toBeNull();
        });

        it('should handle Redis errors gracefully', async () => {
            mockRedisClient.get.mockRejectedValueOnce(new Error('Redis error'));

            const result = await RedisService.get('test-key');
            expect(result).toBeNull();
        });
    });

    describe('delete()', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        it('should delete existing key', async () => {
            mockRedisClient.del.mockResolvedValueOnce(1);

            const result = await RedisService.delete('test-key');

            expect(mockRedisClient.del).toHaveBeenCalledWith('test-key');
            expect(result).toBe(true);
        });

        it('should return false for non-existent key', async () => {
            mockRedisClient.del.mockResolvedValueOnce(0);

            const result = await RedisService.delete('test-key');
            expect(result).toBe(false);
        });

        it('should return false when not connected', async () => {
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Connection lost'));

            const result = await RedisService.delete('test-key');
            expect(result).toBe(false);
        });

        it('should handle Redis errors gracefully', async () => {
            mockRedisClient.del.mockRejectedValueOnce(new Error('Redis error'));

            const result = await RedisService.delete('test-key');
            expect(result).toBe(false);
        });
    });

    describe('deletePattern()', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        it('should delete keys matching pattern', async () => {
            mockRedisClient.keys.mockResolvedValueOnce(['user:1', 'user:2']);
            mockRedisClient.del.mockResolvedValueOnce(2);

            const result = await RedisService.deletePattern('user:*');

            expect(mockRedisClient.keys).toHaveBeenCalledWith('user:*');
            expect(mockRedisClient.del).toHaveBeenCalledWith(['user:1', 'user:2']);
            expect(result).toBe(2);
        });

        it('should return 0 when no keys match pattern', async () => {
            mockRedisClient.keys.mockResolvedValueOnce([]);

            const result = await RedisService.deletePattern('user:*');
            expect(result).toBe(0);
        });

        it('should return 0 when not connected', async () => {
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Connection lost'));

            const result = await RedisService.deletePattern('user:*');
            expect(result).toBe(0);
        });

        it('should handle Redis errors gracefully', async () => {
            mockRedisClient.keys.mockRejectedValueOnce(new Error('Redis error'));

            const result = await RedisService.deletePattern('user:*');
            expect(result).toBe(0);
        });
    });

    describe('exists()', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        it('should return true when key exists', async () => {
            mockRedisClient.exists.mockResolvedValueOnce(1);

            const result = await RedisService.exists('test-key');

            expect(mockRedisClient.exists).toHaveBeenCalledWith('test-key');
            expect(result).toBe(true);
        });

        it('should return false when key does not exist', async () => {
            mockRedisClient.exists.mockResolvedValueOnce(0);

            const result = await RedisService.exists('test-key');
            expect(result).toBe(false);
        });

        it('should return false when not connected', async () => {
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Connection lost'));

            const result = await RedisService.exists('test-key');
            expect(result).toBe(false);
        });

        it('should handle Redis errors gracefully', async () => {
            mockRedisClient.exists.mockRejectedValueOnce(new Error('Redis error'));

            const result = await RedisService.exists('test-key');
            expect(result).toBe(false);
        });
    });

    describe('expire()', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        it('should set expiration successfully', async () => {
            mockRedisClient.expire.mockResolvedValueOnce(true);

            const result = await RedisService.expire('test-key', 300);

            expect(mockRedisClient.expire).toHaveBeenCalledWith('test-key', 300);
            expect(result).toBe(true);
        });

        it('should return false when not connected', async () => {
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Connection lost'));

            const result = await RedisService.expire('test-key', 300);
            expect(result).toBe(false);
        });

        it('should handle Redis errors gracefully', async () => {
            mockRedisClient.expire.mockRejectedValueOnce(new Error('Redis error'));

            const result = await RedisService.expire('test-key', 300);
            expect(result).toBe(false);
        });
    });

    describe('getTTL()', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        it('should get TTL successfully', async () => {
            mockRedisClient.ttl.mockResolvedValueOnce(300);

            const result = await RedisService.getTTL('test-key');

            expect(mockRedisClient.ttl).toHaveBeenCalledWith('test-key');
            expect(result).toBe(300);
        });

        it('should return -1 when not connected', async () => {
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Connection lost'));

            const result = await RedisService.getTTL('test-key');
            expect(result).toBe(-1);
        });

        it('should handle Redis errors gracefully', async () => {
            mockRedisClient.ttl.mockRejectedValueOnce(new Error('Redis error'));

            const result = await RedisService.getTTL('test-key');
            expect(result).toBe(-1);
        });
    });

    describe('increment()', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        it('should increment with default amount', async () => {
            mockRedisClient.incrBy.mockResolvedValueOnce(2);

            const result = await RedisService.increment('counter-key');

            expect(mockRedisClient.incrBy).toHaveBeenCalledWith('counter-key', 1);
            expect(result).toBe(2);
        });

        it('should increment with custom amount', async () => {
            mockRedisClient.incrBy.mockResolvedValueOnce(15);

            const result = await RedisService.increment('counter-key', 10);

            expect(mockRedisClient.incrBy).toHaveBeenCalledWith('counter-key', 10);
            expect(result).toBe(15);
        });

        it('should return 0 when not connected', async () => {
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Connection lost'));

            const result = await RedisService.increment('counter-key');
            expect(result).toBe(0);
        });

        it('should handle Redis errors gracefully', async () => {
            mockRedisClient.incrBy.mockRejectedValueOnce(new Error('Redis error'));

            const result = await RedisService.increment('counter-key');
            expect(result).toBe(0);
        });
    });

    describe('decrement()', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        it('should decrement with default amount', async () => {
            mockRedisClient.decrBy.mockResolvedValueOnce(8);

            const result = await RedisService.decrement('counter-key');

            expect(mockRedisClient.decrBy).toHaveBeenCalledWith('counter-key', 1);
            expect(result).toBe(8);
        });

        it('should decrement with custom amount', async () => {
            mockRedisClient.decrBy.mockResolvedValueOnce(5);

            const result = await RedisService.decrement('counter-key', 5);

            expect(mockRedisClient.decrBy).toHaveBeenCalledWith('counter-key', 5);
            expect(result).toBe(5);
        });

        it('should return 0 when not connected', async () => {
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Connection lost'));

            const result = await RedisService.decrement('counter-key');
            expect(result).toBe(0);
        });

        it('should handle Redis errors gracefully', async () => {
            mockRedisClient.decrBy.mockRejectedValueOnce(new Error('Redis error'));

            const result = await RedisService.decrement('counter-key');
            expect(result).toBe(0);
        });
    });

    describe('Set Operations', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        describe('setAdd()', () => {
            it('should add members to set', async () => {
                mockRedisClient.sAdd.mockResolvedValueOnce(2);

                const result = await RedisService.setAdd('set-key', 'member1', 'member2');

                expect(mockRedisClient.sAdd).toHaveBeenCalledWith('set-key', ['member1', 'member2']);
                expect(result).toBe(2);
            });

            it('should return 0 when not connected', async () => {
                const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
                errorHandler(new Error('Connection lost'));

                const result = await RedisService.setAdd('set-key', 'member1');
                expect(result).toBe(0);
            });

            it('should handle Redis errors gracefully', async () => {
                mockRedisClient.sAdd.mockRejectedValueOnce(new Error('Redis error'));

                const result = await RedisService.setAdd('set-key', 'member1');
                expect(result).toBe(0);
            });
        });

        describe('setRemove()', () => {
            it('should remove members from set', async () => {
                mockRedisClient.sRem.mockResolvedValueOnce(1);

                const result = await RedisService.setRemove('set-key', 'member1');

                expect(mockRedisClient.sRem).toHaveBeenCalledWith('set-key', ['member1']);
                expect(result).toBe(1);
            });

            it('should return 0 when not connected', async () => {
                const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
                errorHandler(new Error('Connection lost'));

                const result = await RedisService.setRemove('set-key', 'member1');
                expect(result).toBe(0);
            });
        });

        describe('setIsMember()', () => {
            it('should check if member exists in set', async () => {
                mockRedisClient.sIsMember.mockResolvedValueOnce(true);

                const result = await RedisService.setIsMember('set-key', 'member1');

                expect(mockRedisClient.sIsMember).toHaveBeenCalledWith('set-key', 'member1');
                expect(result).toBe(true);
            });

            it('should return false when not connected', async () => {
                const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
                errorHandler(new Error('Connection lost'));

                const result = await RedisService.setIsMember('set-key', 'member1');
                expect(result).toBe(false);
            });
        });

        describe('setMembers()', () => {
            it('should get all set members', async () => {
                mockRedisClient.sMembers.mockResolvedValueOnce(['member1', 'member2']);

                const result = await RedisService.setMembers('set-key');

                expect(mockRedisClient.sMembers).toHaveBeenCalledWith('set-key');
                expect(result).toEqual(['member1', 'member2']);
            });

            it('should return empty array when not connected', async () => {
                const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
                errorHandler(new Error('Connection lost'));

                const result = await RedisService.setMembers('set-key');
                expect(result).toEqual([]);
            });
        });
    });

    describe('Hash Operations', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        describe('hashSet()', () => {
            it('should set hash field', async () => {
                mockRedisClient.hSet.mockResolvedValueOnce(1);

                const result = await RedisService.hashSet('hash-key', 'field1', { data: 'value' });

                expect(mockRedisClient.hSet).toHaveBeenCalledWith(
                    'hash-key',
                    'field1',
                    JSON.stringify({ data: 'value' })
                );
                expect(result).toBe(true);
            });

            it('should return false when field already exists', async () => {
                mockRedisClient.hSet.mockResolvedValueOnce(0);

                const result = await RedisService.hashSet('hash-key', 'field1', 'value');
                expect(result).toBe(false);
            });

            it('should return false when not connected', async () => {
                const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
                errorHandler(new Error('Connection lost'));

                const result = await RedisService.hashSet('hash-key', 'field1', 'value');
                expect(result).toBe(false);
            });
        });

        describe('hashGet()', () => {
            it('should get hash field value', async () => {
                mockRedisClient.hGet.mockResolvedValueOnce(JSON.stringify({ data: 'value' }));

                const result = await RedisService.hashGet('hash-key', 'field1');

                expect(mockRedisClient.hGet).toHaveBeenCalledWith('hash-key', 'field1');
                expect(result).toEqual({ data: 'value' });
            });

            it('should return null for non-existent field', async () => {
                mockRedisClient.hGet.mockResolvedValueOnce(null);

                const result = await RedisService.hashGet('hash-key', 'field1');
                expect(result).toBeNull();
            });

            it('should return null when not connected', async () => {
                const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
                errorHandler(new Error('Connection lost'));

                const result = await RedisService.hashGet('hash-key', 'field1');
                expect(result).toBeNull();
            });
        });

        describe('hashGetAll()', () => {
            it('should get all hash fields', async () => {
                mockRedisClient.hGetAll.mockResolvedValueOnce({
                    field1: JSON.stringify({ data: 'value1' }),
                    field2: JSON.stringify({ data: 'value2' }),
                    field3: 'plain-string' // Test non-JSON value
                });

                const result = await RedisService.hashGetAll('hash-key');

                expect(mockRedisClient.hGetAll).toHaveBeenCalledWith('hash-key');
                expect(result).toEqual({
                    field1: { data: 'value1' },
                    field2: { data: 'value2' },
                    field3: 'plain-string'
                });
            });

            it('should return empty object when not connected', async () => {
                const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
                errorHandler(new Error('Connection lost'));

                const result = await RedisService.hashGetAll('hash-key');
                expect(result).toEqual({});
            });
        });

        describe('hashDelete()', () => {
            it('should delete hash field', async () => {
                mockRedisClient.hDel.mockResolvedValueOnce(1);

                const result = await RedisService.hashDelete('hash-key', 'field1');

                expect(mockRedisClient.hDel).toHaveBeenCalledWith('hash-key', 'field1');
                expect(result).toBe(true);
            });

            it('should return false when field does not exist', async () => {
                mockRedisClient.hDel.mockResolvedValueOnce(0);

                const result = await RedisService.hashDelete('hash-key', 'field1');
                expect(result).toBe(false);
            });

            it('should return false when not connected', async () => {
                const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
                errorHandler(new Error('Connection lost'));

                const result = await RedisService.hashDelete('hash-key', 'field1');
                expect(result).toBe(false);
            });
        });
    });

    describe('List Operations', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        describe('listPushLeft()', () => {
            it('should push values to left of list', async () => {
                mockRedisClient.lPush.mockResolvedValueOnce(3);

                const result = await RedisService.listPushLeft('list-key', 'value1', { data: 'value2' });

                expect(mockRedisClient.lPush).toHaveBeenCalledWith(
                    'list-key',
                    [JSON.stringify('value1'), JSON.stringify({ data: 'value2' })]
                );
                expect(result).toBe(3);
            });

            it('should return 0 when not connected', async () => {
                const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
                errorHandler(new Error('Connection lost'));

                const result = await RedisService.listPushLeft('list-key', 'value1');
                expect(result).toBe(0);
            });
        });

        describe('listPushRight()', () => {
            it('should push values to right of list', async () => {
                mockRedisClient.rPush.mockResolvedValueOnce(2);

                const result = await RedisService.listPushRight('list-key', 'value1');

                expect(mockRedisClient.rPush).toHaveBeenCalledWith(
                    'list-key',
                    [JSON.stringify('value1')]
                );
                expect(result).toBe(2);
            });

            it('should return 0 when not connected', async () => {
                const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
                errorHandler(new Error('Connection lost'));

                const result = await RedisService.listPushRight('list-key', 'value1');
                expect(result).toBe(0);
            });
        });

        describe('listPopLeft()', () => {
            it('should pop value from left of list', async () => {
                mockRedisClient.lPop.mockResolvedValueOnce(JSON.stringify({ data: 'value' }));

                const result = await RedisService.listPopLeft('list-key');

                expect(mockRedisClient.lPop).toHaveBeenCalledWith('list-key');
                expect(result).toEqual({ data: 'value' });
            });

            it('should return null when list is empty', async () => {
                mockRedisClient.lPop.mockResolvedValueOnce(null);

                const result = await RedisService.listPopLeft('list-key');
                expect(result).toBeNull();
            });

            it('should return null when not connected', async () => {
                const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
                errorHandler(new Error('Connection lost'));

                const result = await RedisService.listPopLeft('list-key');
                expect(result).toBeNull();
            });

            it('should handle Redis errors gracefully', async () => {
                mockRedisClient.lPop.mockRejectedValueOnce(new Error('Redis error'));

                const result = await RedisService.listPopLeft('list-key');
                expect(result).toBeNull();
            });
        });

        describe('listRange()', () => {
            it('should get list range with default parameters', async () => {
                mockRedisClient.lRange.mockResolvedValueOnce([
                    JSON.stringify({ data: 'value1' }),
                    JSON.stringify({ data: 'value2' }),
                    'plain-string'
                ]);

                const result = await RedisService.listRange('list-key');

                expect(mockRedisClient.lRange).toHaveBeenCalledWith('list-key', 0, -1);
                expect(result).toEqual([
                    { data: 'value1' },
                    { data: 'value2' },
                    'plain-string'
                ]);
            });

            it('should get list range with custom parameters', async () => {
                mockRedisClient.lRange.mockResolvedValueOnce([JSON.stringify('value1')]);

                const result = await RedisService.listRange('list-key', 1, 5);

                expect(mockRedisClient.lRange).toHaveBeenCalledWith('list-key', 1, 5);
                expect(result).toEqual(['value1']);
            });

            it('should return empty array when not connected', async () => {
                const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
                errorHandler(new Error('Connection lost'));

                const result = await RedisService.listRange('list-key');
                expect(result).toEqual([]);
            });

            it('should handle Redis errors gracefully', async () => {
                mockRedisClient.lRange.mockRejectedValueOnce(new Error('Redis error'));

                const result = await RedisService.listRange('list-key');
                expect(result).toEqual([]);
            });
        });

        describe('listLength()', () => {
            it('should get list length', async () => {
                mockRedisClient.lLen.mockResolvedValueOnce(5);

                const result = await RedisService.listLength('list-key');

                expect(mockRedisClient.lLen).toHaveBeenCalledWith('list-key');
                expect(result).toBe(5);
            });

            it('should return 0 when not connected', async () => {
                const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
                errorHandler(new Error('Connection lost'));

                const result = await RedisService.listLength('list-key');
                expect(result).toBe(0);
            });

            it('should handle Redis errors gracefully', async () => {
                mockRedisClient.lLen.mockRejectedValueOnce(new Error('Redis error'));

                const result = await RedisService.listLength('list-key');
                expect(result).toBe(0);
            });
        });
    });

    describe('publish()', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        it('should publish message to channel', async () => {
            mockRedisClient.publish.mockResolvedValueOnce(3);

            const result = await RedisService.publish('channel', { event: 'test' });

            expect(mockRedisClient.publish).toHaveBeenCalledWith(
                'channel',
                JSON.stringify({ event: 'test' })
            );
            expect(result).toBe(3);
        });

        it('should return 0 when not connected', async () => {
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Connection lost'));

            const result = await RedisService.publish('channel', { event: 'test' });
            expect(result).toBe(0);
        });

        it('should handle Redis errors gracefully', async () => {
            mockRedisClient.publish.mockRejectedValueOnce(new Error('Redis error'));

            const result = await RedisService.publish('channel', { event: 'test' });
            expect(result).toBe(0);
        });
    });

    describe('keys()', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        it('should get keys matching pattern', async () => {
            mockRedisClient.keys.mockResolvedValueOnce(['user:1', 'user:2', 'user:3']);

            const result = await RedisService.keys('user:*');

            expect(mockRedisClient.keys).toHaveBeenCalledWith('user:*');
            expect(result).toEqual(['user:1', 'user:2', 'user:3']);
        });

        it('should return empty array when not connected', async () => {
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Connection lost'));

            const result = await RedisService.keys('user:*');
            expect(result).toEqual([]);
        });

        it('should handle Redis errors gracefully', async () => {
            mockRedisClient.keys.mockRejectedValueOnce(new Error('Redis error'));

            const result = await RedisService.keys('user:*');
            expect(result).toEqual([]);
        });
    });

    describe('flushDB()', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        it('should flush current database', async () => {
            mockRedisClient.flushDb.mockResolvedValueOnce('OK');

            const result = await RedisService.flushDB();

            expect(mockRedisClient.flushDb).toHaveBeenCalled();
            expect(result).toBe(true);
        });

        it('should return false when not connected', async () => {
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Connection lost'));

            const result = await RedisService.flushDB();
            expect(result).toBe(false);
        });

        it('should handle Redis errors gracefully', async () => {
            mockRedisClient.flushDb.mockRejectedValueOnce(new Error('Redis error'));

            const result = await RedisService.flushDB();
            expect(result).toBe(false);
        });
    });

    describe('dbSize()', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        it('should get database size', async () => {
            mockRedisClient.dbSize.mockResolvedValueOnce(1000);

            const result = await RedisService.dbSize();

            expect(mockRedisClient.dbSize).toHaveBeenCalled();
            expect(result).toBe(1000);
        });

        it('should return 0 when not connected', async () => {
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Connection lost'));

            const result = await RedisService.dbSize();
            expect(result).toBe(0);
        });

        it('should handle Redis errors gracefully', async () => {
            mockRedisClient.dbSize.mockRejectedValueOnce(new Error('Redis error'));

            const result = await RedisService.dbSize();
            expect(result).toBe(0);
        });
    });

    describe('info()', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        it('should get Redis info without section', async () => {
            mockRedisClient.info.mockResolvedValueOnce('redis_version:6.2.0\r\n');

            const result = await RedisService.info();

            expect(mockRedisClient.info).toHaveBeenCalledWith(undefined);
            expect(result).toBe('redis_version:6.2.0\r\n');
        });

        it('should get Redis info with section', async () => {
            mockRedisClient.info.mockResolvedValueOnce('used_memory:1000000\r\n');

            const result = await RedisService.info('memory');

            expect(mockRedisClient.info).toHaveBeenCalledWith('memory');
            expect(result).toBe('used_memory:1000000\r\n');
        });

        it('should return empty string when not connected', async () => {
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Connection lost'));

            const result = await RedisService.info('memory');
            expect(result).toBe('');
        });

        it('should handle Redis errors gracefully', async () => {
            mockRedisClient.info.mockRejectedValueOnce(new Error('Redis error'));

            const result = await RedisService.info('memory');
            expect(result).toBe('');
        });
    });

    describe('cleanup()', () => {
        it('should cleanup Redis connection', async () => {
            await RedisService.initialize();
            mockRedisClient.quit.mockResolvedValueOnce('OK');

            await RedisService.cleanup();

            expect(mockRedisClient.quit).toHaveBeenCalled();
            expect(RedisService.isRedisConnected()).toBe(false);
        });

        it('should handle cleanup errors', async () => {
            await RedisService.initialize();
            mockRedisClient.quit.mockRejectedValueOnce(new Error('Cleanup error'));

            await expect(RedisService.cleanup()).rejects.toThrow('Cleanup error');
        });

        it('should handle cleanup when client is null', async () => {
            // Don't initialize, so client is null
            await expect(RedisService.cleanup()).resolves.not.toThrow();
        });
    });

    describe('ping()', () => {
        it('should ping successfully when connected', async () => {
            await RedisService.initialize();
            mockRedisClient.ping.mockResolvedValueOnce('PONG');

            const result = await RedisService.ping();

            expect(mockRedisClient.ping).toHaveBeenCalled();
            expect(result).toBe('PONG');
        });

        it('should throw error when not connected', async () => {
            await expect(RedisService.ping()).rejects.toThrow('Redis not connected');
        });

        it('should throw error when client is null', async () => {
            await RedisService.initialize();

            // Simulate disconnection by triggering error event
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Connection lost'));

            await expect(RedisService.ping()).rejects.toThrow('Redis not connected');
        });

        it('should handle ping Redis errors', async () => {
            await RedisService.initialize();
            mockRedisClient.ping.mockRejectedValueOnce(new Error('Ping failed'));

            await expect(RedisService.ping()).rejects.toThrow('Ping failed');
        });
    });

    describe('flushAll()', () => {
        it('should flush all Redis data when connected', async () => {
            await RedisService.initialize();
            mockRedisClient.flushAll.mockResolvedValueOnce('OK');

            await RedisService.flushAll();

            expect(mockRedisClient.flushAll).toHaveBeenCalled();
        });

        it('should throw error when not connected', async () => {
            await expect(RedisService.flushAll()).rejects.toThrow('Redis not connected');
        });

        it('should throw error when client is null', async () => {
            await RedisService.initialize();

            // Simulate disconnection
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Connection lost'));

            await expect(RedisService.flushAll()).rejects.toThrow('Redis not connected');
        });

        it('should handle flushAll Redis errors', async () => {
            await RedisService.initialize();
            mockRedisClient.flushAll.mockRejectedValueOnce(new Error('Flush failed'));

            await expect(RedisService.flushAll()).rejects.toThrow('Flush failed');
        });
    });

    describe('pipeline()', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        it('should execute pipeline commands', async () => {
            const mockPipeline = {
                exec: jest.fn().mockResolvedValueOnce(['OK', 'OK'])
            };
            mockRedisClient.multi.mockReturnValueOnce(mockPipeline);

            const commands = [
                jest.fn(),
                jest.fn()
            ];

            const result = await RedisService.pipeline(commands);

            expect(mockRedisClient.multi).toHaveBeenCalled();
            expect(commands[0]).toHaveBeenCalled();
            expect(commands[1]).toHaveBeenCalled();
            expect(mockPipeline.exec).toHaveBeenCalled();
            expect(result).toEqual(['OK', 'OK']);
        });

        it('should return empty array when not connected', async () => {
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Connection lost'));

            const result = await RedisService.pipeline([]);
            expect(result).toEqual([]);
        });

        it('should handle pipeline errors gracefully', async () => {
            mockRedisClient.multi.mockImplementationOnce(() => {
                throw new Error('Pipeline error');
            });

            const result = await RedisService.pipeline([]);
            expect(result).toEqual([]);
        });
    });

    describe('getStats()', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        it('should get Redis statistics when connected', async () => {
            mockRedisClient.info.mockImplementation((section: string) => {
                if (section === 'stats') return Promise.resolve('total_commands_processed:1000');
                if (section === 'memory') return Promise.resolve('used_memory:1000000');
                if (section === 'clients') return Promise.resolve('connected_clients:5');
                return Promise.resolve('');
            });
            mockRedisClient.dbSize.mockResolvedValueOnce(500);

            const result = await RedisService.getStats();

            expect(result).toEqual({
                connected: true,
                dbSize: 500,
                info: {
                    stats: 'total_commands_processed:1000',
                    memory: 'used_memory:1000000',
                    clients: 'connected_clients:5'
                }
            });
        });

        it('should return error info when not connected', async () => {
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Connection lost'));

            const result = await RedisService.getStats();

            expect(result).toEqual({
                connected: false,
                error: 'Not connected to Redis'
            });
        });

        it('should handle stats errors gracefully', async () => {
            // Since info() and dbSize() catch their own errors and return defaults,
            // the getStats method's catch block is rarely triggered.
            // Let's test what actually happens when info calls fail:
            mockRedisClient.info.mockRejectedValue(new Error('Info failed'));
            mockRedisClient.dbSize.mockRejectedValueOnce(new Error('DbSize failed'));

            const result = await RedisService.getStats();

            // When info() catches errors, it returns '', and dbSize() returns 0
            // So getStats() should return success with empty/default values
            expect(result).toEqual({
                connected: true,
                dbSize: 0, // dbSize() catches error and returns 0
                info: {
                    stats: '',    // info() catches error and returns ''
                    memory: '',   // info() catches error and returns ''  
                    clients: ''   // info() catches error and returns ''
                }
            });
        });

        it('should handle getStats catch block when unexpected error occurs', async () => {
            // To test the actual catch block, we need to cause an error that's not caught
            // by the individual methods. Let's mock isRedisConnected to throw an error
            const originalIsConnected = RedisService.isRedisConnected;
            jest.spyOn(RedisService, 'isRedisConnected').mockImplementationOnce(() => {
                throw new Error('Unexpected connection check error');
            });

            const result = await RedisService.getStats();

            expect(result).toEqual({
                connected: false,
                error: 'Unexpected connection check error'
            });

            // Restore the original method
            (RedisService.isRedisConnected as jest.Mock).mockRestore();
        });
    });

    describe('rateLimit()', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        it('should handle rate limiting when connected', async () => {
            // Mock increment to return 1 (first request)
            mockRedisClient.incrBy.mockResolvedValueOnce(1);
            mockRedisClient.expire.mockResolvedValueOnce(true);

            const result = await RedisService.rateLimit('user:123', 60000, 5);

            expect(result.allowed).toBe(true);
            expect(result.remaining).toBe(4);
            expect(result.resetTime).toBeGreaterThan(Date.now());
        });

        it('should handle rate limiting for subsequent requests', async () => {
            // Mock increment to return 3 (third request)
            mockRedisClient.incrBy.mockResolvedValueOnce(3);

            const result = await RedisService.rateLimit('user:123', 60000, 5);

            expect(result.allowed).toBe(true);
            expect(result.remaining).toBe(2);
        });

        it('should block when rate limit exceeded', async () => {
            // Mock increment to return 6 (exceeds limit of 5)
            mockRedisClient.incrBy.mockResolvedValueOnce(6);

            const result = await RedisService.rateLimit('user:123', 60000, 5);

            expect(result.allowed).toBe(false);
            expect(result.remaining).toBe(0);
        });

        it('should return default when not connected', async () => {
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Connection lost'));

            const result = await RedisService.rateLimit('user:123', 60000, 5);

            expect(result.allowed).toBe(true);
            expect(result.remaining).toBe(4);
        });

        it('should handle rate limit errors gracefully', async () => {
            // Mock increment to reject, which causes increment() to return 0
            mockRedisClient.incrBy.mockRejectedValueOnce(new Error('Rate limit error'));

            const result = await RedisService.rateLimit('user:123', 60000, 5);

            // When increment() catches the error and returns 0:
            // remaining = Math.max(0, maxRequests - current) = Math.max(0, 5 - 0) = 5
            expect(result.allowed).toBe(true);
            expect(result.remaining).toBe(5); // maxRequests (5) - current (0) = 5
            expect(result.resetTime).toBeGreaterThan(Date.now());
        });
    });

    describe('Session Management', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        describe('storeSession()', () => {
            it('should store session successfully', async () => {
                mockRedisClient.hSet.mockResolvedValueOnce(1);
                mockRedisClient.expire.mockResolvedValueOnce(true);

                const result = await RedisService.storeSession('session-123', { userId: 'user-123' }, 3600);

                expect(mockRedisClient.hSet).toHaveBeenCalledWith(
                    'session:session-123',
                    'data',
                    JSON.stringify({ userId: 'user-123' })
                );
                expect(mockRedisClient.expire).toHaveBeenCalledWith('session:session-123', 3600);
                expect(result).toBe(true);
            });

            it('should use default TTL when not specified', async () => {
                mockRedisClient.hSet.mockResolvedValueOnce(1);
                mockRedisClient.expire.mockResolvedValueOnce(true);

                const result = await RedisService.storeSession('session-123', { userId: 'user-123' });

                expect(mockRedisClient.expire).toHaveBeenCalledWith('session:session-123', 3600);
                expect(result).toBe(true);
            });

            it('should return false when hashSet fails', async () => {
                mockRedisClient.hSet.mockResolvedValueOnce(0);
                mockRedisClient.expire.mockResolvedValueOnce(true);

                const result = await RedisService.storeSession('session-123', { userId: 'user-123' });

                expect(result).toBe(false);
            });

            it('should return false when expire fails', async () => {
                mockRedisClient.hSet.mockResolvedValueOnce(1);
                mockRedisClient.expire.mockResolvedValueOnce(false);

                const result = await RedisService.storeSession('session-123', { userId: 'user-123' });

                expect(result).toBe(false);
            });
        });

        describe('getSession()', () => {
            it('should get session data', async () => {
                mockRedisClient.hGet.mockResolvedValueOnce(JSON.stringify({ userId: 'user-123' }));

                const result = await RedisService.getSession('session-123');

                expect(mockRedisClient.hGet).toHaveBeenCalledWith('session:session-123', 'data');
                expect(result).toEqual({ userId: 'user-123' });
            });

            it('should return null for non-existent session', async () => {
                mockRedisClient.hGet.mockResolvedValueOnce(null);

                const result = await RedisService.getSession('session-123');
                expect(result).toBeNull();
            });
        });

        describe('deleteSession()', () => {
            it('should delete session successfully', async () => {
                mockRedisClient.del.mockResolvedValueOnce(1);

                const result = await RedisService.deleteSession('session-123');

                expect(mockRedisClient.del).toHaveBeenCalledWith('session:session-123');
                expect(result).toBe(true);
            });

            it('should return false when session does not exist', async () => {
                mockRedisClient.del.mockResolvedValueOnce(0);

                const result = await RedisService.deleteSession('session-123');
                expect(result).toBe(false);
            });
        });
    });

    describe('disconnect()', () => {
        it('should disconnect gracefully when connected', async () => {
            await RedisService.initialize();
            mockRedisClient.quit.mockResolvedValueOnce('OK');

            await RedisService.disconnect();

            expect(mockRedisClient.quit).toHaveBeenCalled();
            expect(RedisService.isRedisConnected()).toBe(false);
        });

        it('should handle disconnect errors gracefully', async () => {
            await RedisService.initialize();
            mockRedisClient.quit.mockRejectedValueOnce(new Error('Disconnect error'));

            await RedisService.disconnect();

            expect(RedisService.isRedisConnected()).toBe(false);
        });

        it('should handle disconnect when not connected', async () => {
            await expect(RedisService.disconnect()).resolves.not.toThrow();
            expect(RedisService.isRedisConnected()).toBe(false);
        });

        it('should set isConnected to false even when quit fails', async () => {
            await RedisService.initialize();
            mockRedisClient.quit.mockRejectedValueOnce(new Error('Quit failed'));

            await RedisService.disconnect();

            expect(RedisService.isRedisConnected()).toBe(false);
        });
    });

    describe('Error Handling Edge Cases', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        it('should handle all set operation errors', async () => {
            mockRedisClient.sRem.mockRejectedValueOnce(new Error('Redis error'));
            mockRedisClient.sIsMember.mockRejectedValueOnce(new Error('Redis error'));
            mockRedisClient.sMembers.mockRejectedValueOnce(new Error('Redis error'));

            expect(await RedisService.setRemove('set-key', 'member')).toBe(0);
            expect(await RedisService.setIsMember('set-key', 'member')).toBe(false);
            expect(await RedisService.setMembers('set-key')).toEqual([]);
        });

        it('should handle all hash operation errors', async () => {
            mockRedisClient.hSet.mockRejectedValueOnce(new Error('Redis error'));
            mockRedisClient.hGet.mockRejectedValueOnce(new Error('Redis error'));
            mockRedisClient.hGetAll.mockRejectedValueOnce(new Error('Redis error'));
            mockRedisClient.hDel.mockRejectedValueOnce(new Error('Redis error'));

            expect(await RedisService.hashSet('hash-key', 'field', 'value')).toBe(false);
            expect(await RedisService.hashGet('hash-key', 'field')).toBeNull();
            expect(await RedisService.hashGetAll('hash-key')).toEqual({});
            expect(await RedisService.hashDelete('hash-key', 'field')).toBe(false);
        });

        it('should handle all list operation errors', async () => {
            mockRedisClient.lPush.mockRejectedValueOnce(new Error('Redis error'));
            mockRedisClient.rPush.mockRejectedValueOnce(new Error('Redis error'));

            expect(await RedisService.listPushLeft('list-key', 'value')).toBe(0);
            expect(await RedisService.listPushRight('list-key', 'value')).toBe(0);
        });
    });

    describe('Connection State Edge Cases', () => {
        it('should handle isRedisConnected when client exists but isReady is false', async () => {
            await RedisService.initialize();
            mockRedisClient.isReady = false;

            // The service should still report connected because internal flag is true
            expect(RedisService.isRedisConnected()).toBe(true);
        });

        it('should handle getClient when isReady changes dynamically', async () => {
            await RedisService.initialize();

            // Initially connected
            expect(RedisService.getClient()).toBe(mockRedisClient);

            // Simulate disconnection
            const errorHandler = mockRedisClient.on.mock.calls.find((call: string[]) => call[0] === 'error')[1];
            errorHandler(new Error('Connection lost'));

            // Should return null after disconnection
            expect(RedisService.getClient()).toBeNull();
        });
    });

    describe('JSON Parsing Edge Cases', () => {
        beforeEach(async () => {
            await RedisService.initialize();
        });

        it('should handle malformed JSON in hashGetAll', async () => {
            mockRedisClient.hGetAll.mockResolvedValueOnce({
                validField: JSON.stringify({ data: 'value' }),
                invalidField: 'invalid-json{',
                plainField: 'plain-string'
            });

            const result = await RedisService.hashGetAll('hash-key');

            expect(result).toEqual({
                validField: { data: 'value' },
                invalidField: 'invalid-json{',
                plainField: 'plain-string'
            });
        });

        it('should handle malformed JSON in listRange', async () => {
            mockRedisClient.lRange.mockResolvedValueOnce([
                JSON.stringify({ valid: 'json' }),
                'invalid-json{',
                'plain-string'
            ]);

            const result = await RedisService.listRange('list-key');

            expect(result).toEqual([
                { valid: 'json' },
                'invalid-json{',
                'plain-string'
            ]);
        });
    });

    afterEach(() => {
        jest.clearAllMocks();
    });
});