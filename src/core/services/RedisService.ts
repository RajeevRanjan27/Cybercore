// src/core/services/RedisService.ts
import {createClient, RedisClientType} from 'redis';
import {logger} from '@/core/infra/logger';
import {config} from '@/config/env';

export class RedisService {
    private static client: RedisClientType;
    private static isConnected = false;

    /**
     * Initialize Redis connection
     */
    static async initialize(): Promise<void> {
        try {
            // Create Redis client
            this.client = createClient({
                url: config.REDIS_URL || 'redis://localhost:6379',
                password: config.REDIS_PASSWORD,
                socket: {
                    connectTimeout: 10000,
                    reconnectStrategy: (retries) => {
                        if (retries > 10) {
                            logger.error('Redis max reconnection attempts reached');
                            return false;
                        }
                        const delay = Math.min(retries * 100, 3000);
                        logger.warn(`Redis reconnecting in ${delay}ms (attempt ${retries})`);
                        return delay;
                    }
                }
            });

            // Event listeners
            this.client.on('error', (err) => {
                logger.error('Redis Client Error:', err);
                this.isConnected = false;
            });

            this.client.on('connect', () => {
                logger.info('Redis Client Connected');
            });

            this.client.on('ready', () => {
                logger.info('Redis Client Ready');
                this.isConnected = true;
            });

            this.client.on('end', () => {
                logger.info('Redis Client Disconnected');
                this.isConnected = false;
            });

            // Connect to Redis
            await this.client.connect();
            logger.info('🔴 Redis service initialized successfully');

        } catch (error) {
            logger.error('Failed to initialize Redis:', error);
            this.isConnected = false;
            // Don't throw error - fall back to memory cache
        }
    }

    /**
     * Check if Redis is connected
     */
    static isRedisConnected(): boolean {
        return this.isConnected && this.client?.isReady === true;
    }

    /**
     * Get Redis client instance
     */
    static getClient(): RedisClientType | null {
        return this.isRedisConnected() ? this.client : null;
    }

    /**
     * Set a key-value pair with optional TTL
     */
    static async set(key: string, value: any, ttlSeconds?: number): Promise<boolean> {
        try {
            if (!this.isRedisConnected()) {
                return false;
            }

            const serializedValue = JSON.stringify(value);

            if (ttlSeconds) {
                await this.client.setEx(key, ttlSeconds, serializedValue);
            } else {
                await this.client.set(key, serializedValue);
            }

            return true;
        } catch (error) {
            logger.error('Redis SET error:', { key, error });
            return false;
        }
    }

    /**
     * Get value by key
     */
    static async get(key: string): Promise<any | null> {
        try {
            if (!this.isRedisConnected()) {
                return null;
            }

            const value = await this.client.get(key);
            return value ? JSON.parse(value) : null;
        } catch (error) {
            logger.error('Redis GET error:', { key, error });
            return null;
        }
    }

    /**
     * Delete a key
     */
    static async delete(key: string): Promise<boolean> {
        try {
            if (!this.isRedisConnected()) {
                return false;
            }

            const result = await this.client.del(key);
            return result > 0;
        } catch (error) {
            logger.error('Redis DEL error:', { key, error });
            return false;
        }
    }

    /**
     * Delete keys by pattern
     */
    static async deletePattern(pattern: string): Promise<number> {
        try {
            if (!this.isRedisConnected()) {
                return 0;
            }

            const keys = await this.client.keys(pattern);
            if (keys.length === 0) {
                return 0;
            }

            const result = await this.client.del(keys);
            return result;
        } catch (error) {
            logger.error('Redis pattern delete error:', { pattern, error });
            return 0;
        }
    }

    /**
     * Check if key exists
     */
    static async exists(key: string): Promise<boolean> {
        try {
            if (!this.isRedisConnected()) {
                return false;
            }

            const result = await this.client.exists(key);
            return result > 0;
        } catch (error) {
            logger.error('Redis EXISTS error:', { key, error });
            return false;
        }
    }

    /**
     * Set expiration time for a key
     */
    static async expire(key: string, ttlSeconds: number): Promise<boolean> {
        try {
            if (!this.isRedisConnected()) {
                return false;
            }

            return await this.client.expire(key, ttlSeconds);
        } catch (error) {
            logger.error('Redis EXPIRE error:', { key, ttlSeconds, error });
            return false;
        }
    }

    /**
     * Get TTL for a key
     */
    static async getTTL(key: string): Promise<number> {
        try {
            if (!this.isRedisConnected()) {
                return -1;
            }

            return await this.client.ttl(key);
        } catch (error) {
            logger.error('Redis TTL error:', { key, error });
            return -1;
        }
    }

    /**
     * Increment a numeric value
     */
    static async increment(key: string, amount: number = 1): Promise<number> {
        try {
            if (!this.isRedisConnected()) {
                return 0;
            }

            return await this.client.incrBy(key, amount);
        } catch (error) {
            logger.error('Redis INCR error:', { key, amount, error });
            return 0;
        }
    }

    /**
     * Decrement a numeric value
     */
    static async decrement(key: string, amount: number = 1): Promise<number> {
        try {
            if (!this.isRedisConnected()) {
                return 0;
            }

            return await this.client.decrBy(key, amount);
        } catch (error) {
            logger.error('Redis DECR error:', { key, amount, error });
            return 0;
        }
    }

    /**
     * Add to a set
     */
    static async setAdd(key: string, ...members: string[]): Promise<number> {
        try {
            if (!this.isRedisConnected()) {
                return 0;
            }

            return await this.client.sAdd(key, members);
        } catch (error) {
            logger.error('Redis SADD error:', { key, members, error });
            return 0;
        }
    }

    /**
     * Remove from a set
     */
    static async setRemove(key: string, ...members: string[]): Promise<number> {
        try {
            if (!this.isRedisConnected()) {
                return 0;
            }

            return await this.client.sRem(key, members);
        } catch (error) {
            logger.error('Redis SREM error:', { key, members, error });
            return 0;
        }
    }

    /**
     * Check if member is in set
     */
    static async setIsMember(key: string, member: string): Promise<boolean> {
        try {
            if (!this.isRedisConnected()) {
                return false;
            }

            return await this.client.sIsMember(key, member);
        } catch (error) {
            logger.error('Redis SISMEMBER error:', { key, member, error });
            return false;
        }
    }

    /**
     * Get all members of a set
     */
    static async setMembers(key: string): Promise<string[]> {
        try {
            if (!this.isRedisConnected()) {
                return [];
            }

            return await this.client.sMembers(key);
        } catch (error) {
            logger.error('Redis SMEMBERS error:', { key, error });
            return [];
        }
    }

    /**
     * Hash operations - set field
     */
    static async hashSet(key: string, field: string, value: any): Promise<boolean> {
        try {
            if (!this.isRedisConnected()) {
                return false;
            }

            const result = await this.client.hSet(key, field, JSON.stringify(value));
            return result > 0;
        } catch (error) {
            logger.error('Redis HSET error:', { key, field, error });
            return false;
        }
    }

    /**
     * Hash operations - get field
     */
    static async hashGet(key: string, field: string): Promise<any | null> {
        try {
            if (!this.isRedisConnected()) {
                return null;
            }

            const value = await this.client.hGet(key, field);
            return value ? JSON.parse(value) : null;
        } catch (error) {
            logger.error('Redis HGET error:', { key, field, error });
            return null;
        }
    }

    /**
     * Hash operations - get all fields
     */
    static async hashGetAll(key: string): Promise<Record<string, any>> {
        try {
            if (!this.isRedisConnected()) {
                return {};
            }

            const hash = await this.client.hGetAll(key);
            const result: Record<string, any> = {};

            for (const [field, value] of Object.entries(hash)) {
                try {
                    result[field] = JSON.parse(value);
                } catch {
                    result[field] = value;
                }
            }

            return result;
        } catch (error) {
            logger.error('Redis HGETALL error:', { key, error });
            return {};
        }
    }

    /**
     * Hash operations - delete field
     */
    static async hashDelete(key: string, field: string): Promise<boolean> {
        try {
            if (!this.isRedisConnected()) {
                return false;
            }

            const result = await this.client.hDel(key, field);
            return result > 0;
        } catch (error) {
            logger.error('Redis HDEL error:', { key, field, error });
            return false;
        }
    }

    /**
     * List operations - push to left
     */
    static async listPushLeft(key: string, ...values: any[]): Promise<number> {
        try {
            if (!this.isRedisConnected()) {
                return 0;
            }

            const serializedValues = values.map(v => JSON.stringify(v));
            return await this.client.lPush(key, serializedValues);
        } catch (error) {
            logger.error('Redis LPUSH error:', { key, values, error });
            return 0;
        }
    }

    /**
     * List operations - push to right
     */
    static async listPushRight(key: string, ...values: any[]): Promise<number> {
        try {
            if (!this.isRedisConnected()) {
                return 0;
            }

            const serializedValues = values.map(v => JSON.stringify(v));
            return await this.client.rPush(key, serializedValues);
        } catch (error) {
            logger.error('Redis RPUSH error:', { key, values, error });
            return 0;
        }
    }

    /**
     * List operations - pop from left
     */
    static async listPopLeft(key: string): Promise<any | null> {
        try {
            if (!this.isRedisConnected()) {
                return null;
            }

            const value = await this.client.lPop(key);
            return value ? JSON.parse(value) : null;
        } catch (error) {
            logger.error('Redis LPOP error:', { key, error });
            return null;
        }
    }

    /**
     * List operations - get range
     */
    static async listRange(key: string, start: number = 0, stop: number = -1): Promise<any[]> {
        try {
            if (!this.isRedisConnected()) {
                return [];
            }

            const values = await this.client.lRange(key, start, stop);
            return values.map(v => {
                try {
                    return JSON.parse(v);
                } catch {
                    return v;
                }
            });
        } catch (error) {
            logger.error('Redis LRANGE error:', { key, start, stop, error });
            return [];
        }
    }

    /**
     * List operations - get length
     */
    static async listLength(key: string): Promise<number> {
        try {
            if (!this.isRedisConnected()) {
                return 0;
            }

            return await this.client.lLen(key);
        } catch (error) {
            logger.error('Redis LLEN error:', { key, error });
            return 0;
        }
    }

    /**
     * Publish a message to a channel
     */
    static async publish(channel: string, message: any): Promise<number> {
        try {
            if (!this.isRedisConnected()) {
                return 0;
            }

            return await this.client.publish(channel, JSON.stringify(message));
        } catch (error) {
            logger.error('Redis PUBLISH error:', { channel, message, error });
            return 0;
        }
    }

    /**
     * Get keys matching a pattern
     */
    static async keys(pattern: string): Promise<string[]> {
        try {
            if (!this.isRedisConnected()) {
                return [];
            }

            return await this.client.keys(pattern);
        } catch (error) {
            logger.error('Redis KEYS error:', { pattern, error });
            return [];
        }
    }

    /**
     * Flush all data from current database
     */
    static async flushDB(): Promise<boolean> {
        try {
            if (!this.isRedisConnected()) {
                return false;
            }

            await this.client.flushDb();
            return true;
        } catch (error) {
            logger.error('Redis FLUSHDB error:', error);
            return false;
        }
    }

    /**
     * Get database size
     */
    static async dbSize(): Promise<number> {
        try {
            if (!this.isRedisConnected()) {
                return 0;
            }

            return await this.client.dbSize();
        } catch (error) {
            logger.error('Redis DBSIZE error:', error);
            return 0;
        }
    }

    /**
     * Get Redis info
     */
    static async info(section?: string): Promise<string> {
        try {
            if (!this.isRedisConnected()) {
                return '';
            }

            return await this.client.info(section);
        } catch (error) {
            logger.error('Redis INFO error:', { section, error });
            return '';
        }
    }

    /**
     * Cleanup Redis connection
     */
    static async cleanup(): Promise<void> {
        try {
            if (this.client) {
                await this.client.quit();
            }
            this.isConnected = false;
            logger.info('RedisService cleaned up');
        } catch (error) {
            logger.error('RedisService cleanup error:', error);
            throw error;
        }
    }


    /**
     * Ping Redis server
     */
    static async ping(): Promise<string> {
        if (!this.isRedisConnected() || !this.client) {
            throw new Error('Redis not connected');
        }

        try {
            return await this.client.ping();
        } catch (error) {
            logger.error('Redis ping error:', error);
            throw error;
        }
    }


    /**
     * Flush all Redis data
     */
    static async flushAll(): Promise<void> {
        if (!this.isRedisConnected() || !this.client) {
            throw new Error('Redis not connected');
        }

        try {
            await this.client.flushAll();
            logger.info('Redis flushed all data');
        } catch (error) {
            logger.error('Redis flushAll error:', error);
            throw error;
        }
    }

    /**
     * Pipeline operations for batch commands
     */
    static async pipeline(commands: Array<() => Promise<any>>): Promise<any[]> {
        try {
            if (!this.isRedisConnected()) {
                return [];
            }

            const pipeline = this.client.multi();
            commands.forEach(command => command());
            return await pipeline.exec();
        } catch (error) {
            logger.error('Redis PIPELINE error:', error);
            return [];
        }
    }

    /**
     * Get Redis connection statistics
     */
    static async getStats(): Promise<any> {
        try {
            if (!this.isRedisConnected()) {
                return {
                    connected: false,
                    error: 'Not connected to Redis'
                };
            }

            const info = await this.info('stats');
            const memory = await this.info('memory');
            const clients = await this.info('clients');

            return {
                connected: true,
                dbSize: await this.dbSize(),
                info: {
                    stats: info,
                    memory: memory,
                    clients: clients
                }
            };
        } catch (error) {
            logger.error('Redis STATS error:', error);
            return {
                connected: false,
                error: error instanceof Error ? error.message : 'Unknown error'
            };
        }
    }

    /**
     * Rate limiting helper
     */
    static async rateLimit(
        key: string,
        windowMs: number,
        maxRequests: number
    ): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
        try {
            if (!this.isRedisConnected()) {
                return { allowed: true, remaining: maxRequests - 1, resetTime: Date.now() + windowMs };
            }

            const now = Date.now();
            const window = Math.floor(now / windowMs);
            const rateLimitKey = `rate_limit:${key}:${window}`;

            const current = await this.increment(rateLimitKey);

            if (current === 1) {
                await this.expire(rateLimitKey, Math.ceil(windowMs / 1000));
            }

            const allowed = current <= maxRequests;
            const remaining = Math.max(0, maxRequests - current);
            const resetTime = (window + 1) * windowMs;

            return { allowed, remaining, resetTime };
        } catch (error) {
            logger.error('Redis rate limit error:', { key, error });
            return { allowed: true, remaining: maxRequests - 1, resetTime: Date.now() + windowMs };
        }
    }

    /**
     * Session management
     */
    static async storeSession(sessionId: string, data: any, ttlSeconds: number = 3600): Promise<boolean> {
        return await this.hashSet(`session:${sessionId}`, 'data', data) &&
            await this.expire(`session:${sessionId}`, ttlSeconds);
    }

    static async getSession(sessionId: string): Promise<any | null> {
        return await this.hashGet(`session:${sessionId}`, 'data');
    }

    static async deleteSession(sessionId: string): Promise<boolean> {
        return await this.delete(`session:${sessionId}`);
    }

    /**
     * Graceful shutdown
     */
    static async disconnect(): Promise<void> {
        try {
            if (this.client && this.isConnected) {
                await this.client.quit();
                logger.info('Redis client disconnected gracefully');
            }
        } catch (error) {
            logger.error('Error disconnecting Redis client:', error);
        } finally {
            this.isConnected = false;
        }
    }
}