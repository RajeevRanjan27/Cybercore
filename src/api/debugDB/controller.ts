import { Request, Response, NextFunction } from 'express';
import { ApiResponse } from '@/core/types';
import mongoose, {Collection} from 'mongoose';
import {CacheService} from "@/core/services/CacheService";
import {AppError} from "@/core/middlewares/errorHandler";

interface DatabaseStats {
    database: string;
    status: string;
    collections: string[];
    documentCounts: Record<string, number>;
    totalDocuments: number;
    connectionState: string;
}

interface CollectionInfo {
    name: string;
    documentCount: number;
    size?: number;
    indexes?: number;
}

export class DbController {
    /**
     * Get database debug information including collections and document counts
     */
    static async getDebugDB(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            // Check if database connection exists
            if (!mongoose.connection.db) {
                const response: ApiResponse<null> = {
                    success: false,
                    message: 'Database connection not established',
                    timestamp: new Date().toISOString()
                };
                res.status(500).json(response);
                return;
            }

            const db = mongoose.connection.db;

            // Get connection state
            const connectionStates = {
                0: 'disconnected',
                1: 'connected',
                2: 'connecting',
                3: 'disconnecting'
            };

            // List all collections
            const collections = await db.listCollections().toArray();
            const collectionNames = collections.map(c => c.name);

            // Count documents in each collection with better error handling
            const collectionCounts: Record<string, number> = {};
            let totalDocuments = 0;

            await Promise.all(
                collectionNames.map(async (name) => {
                    try {
                        const count = await db.collection(name).countDocuments();
                        collectionCounts[name] = count;
                        totalDocuments += count;
                    } catch (error) {
                        console.error(`Error counting documents in ${name}:`, error);
                        collectionCounts[name] = -1; // Indicate error
                    }
                })
            );

            const databaseStats: DatabaseStats = {
                database: mongoose.connection.name || 'unknown',
                status: connectionStates[mongoose.connection.readyState as keyof typeof connectionStates] || 'unknown',
                collections: collectionNames,
                documentCounts: collectionCounts,
                totalDocuments,
                connectionState: `Ready State: ${mongoose.connection.readyState}`
            };

            const response: ApiResponse<DatabaseStats> = {
                success: true,
                data: databaseStats,
                message: 'Database information retrieved successfully',
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * Health check for a database and Redis connection
     */
    static async healthCheck(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const isDbConnected = mongoose.connection.readyState === 1;
            const cacheStats = await CacheService.getStats();

            const response: ApiResponse<{
                database: {
                    isConnected: boolean;
                    readyState: number;
                    host: string;
                    port: number;
                    database: string;
                };
                cache: any;
            }> = {
                success: isDbConnected && (cacheStats.connected || cacheStats.type === 'memory'),
                data: {
                    database: {
                        isConnected: isDbConnected,
                        readyState: mongoose.connection.readyState,
                        host: mongoose.connection.host || 'unknown',
                        port: mongoose.connection.port || 0,
                        database: mongoose.connection.name || 'unknown'
                    },
                    cache: cacheStats
                },
                message: isDbConnected ? 'Services are healthy' : 'Database connection issue',
                timestamp: new Date().toISOString()
            };

            res.status(response.success ? 200 : 503).json(response);
        } catch (error) {
            next(error);
        }
    }
    /**
     * Test cache functionality
     */
    static async testCache(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const testKey = `test:${Date.now()}`;
            const testValue = {
                message: 'Hello from Redis!',
                timestamp: new Date().toISOString(),
                random: Math.random()
            };

            // Test SET operation
            await CacheService.set(testKey, testValue, 60); // 60 seconds TTL

            // Test GET operation
            const retrieved = await CacheService.get(testKey);

            // Test cache stats
            const stats = await CacheService.getStats();

            const response: ApiResponse = {
                success: true,
                data: {
                    test: {
                        key: testKey,
                        originalValue: testValue,
                        retrievedValue: retrieved,
                        valuesMatch: JSON.stringify(testValue) === JSON.stringify(retrieved)
                    },
                    cacheStats: stats
                },
                message: 'Cache test completed successfully',
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * Test Redis rate limiting
     */
    static async testRateLimit(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const clientId = req.ip || 'test-client';
            const windowMs = 60000; // 1 minute
            const maxRequests = 5;

            const rateLimitResult = await CacheService.rateLimit(
                `test:ratelimit:${clientId}`,
                windowMs,
                maxRequests
            );

            const response: ApiResponse = {
                success: true,
                data: {
                    rateLimit: rateLimitResult,
                    clientId,
                    windowMs,
                    maxRequests
                },
                message: rateLimitResult.allowed ? 'Request allowed' : 'Rate limit exceeded',
                timestamp: new Date().toISOString()
            };

            res.status(rateLimitResult.allowed ? 200 : 429).json(response);
        } catch (error) {
            next(error);
        }
    }


    /**
     * Get cache statistics
     */
    static async getCacheStats(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const stats = await CacheService.getStats();

            const response: ApiResponse = {
                success: true,
                data: stats,
                message: 'Cache statistics retrieved successfully',
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }



    /**
     * Get detailed information about a specific collection
     */
    static async getCollectionInfo(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const { collectionName } = req.params;
            const collection = await this._getAndVerifyCollection(collectionName, res);

            // If a collection is null, an error response has already been sent.
            if (!collection) {
                return;
            }


            const db = mongoose.connection.db;

            // Quick check to satisfy TypeScript and handle potential edge cases
            if (!db) {
                throw new AppError('Database instance is not available', 500);
            }

            // Get collection stats
            const [documentCount, stats, indexes] = await Promise.all([
                collection.countDocuments(),
                db.command({ collStats: collectionName }).catch(() => null),
                collection.listIndexes().toArray().catch(() => [])
            ]);

            const collectionInfo: CollectionInfo = {
                name: collectionName,
                documentCount,
                size: stats?.size || undefined,
                indexes: indexes.length
            };

            const response: ApiResponse<CollectionInfo> = {
                success: true,
                data: collectionInfo,
                message: `Collection '${collectionName}' information retrieved successfully`,
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }
    /**
     * Get sample documents from a collection
     */
    static async getSampleDocuments(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const { collectionName } = req.params;
            const limit = parseInt(req.query.limit as string) || 5;
            const skip = parseInt(req.query.skip as string) || 0;

            const collection = await this._getAndVerifyCollection(collectionName, res);

            // If a collection is null, an error response has already been sent.
            if (!collection) {
                return;
            }

            // Get sample documents
            const documents = await collection
                .find({})
                .skip(skip)
                .limit(Math.min(limit, 50)) // Cap at 50 documents
                .toArray();

            const total = await collection.countDocuments();

            const response: ApiResponse<{
                documents: any[];
                pagination: {
                    skip: number;
                    limit: number;
                    total: number;
                    hasMore: boolean;
                };
            }> = {
                success: true,
                data: {
                    documents,
                    pagination: {
                        skip,
                        limit,
                        total,
                        hasMore: skip + limit < total
                    }
                },
                message: `Sample documents from '${collectionName}' retrieved successfully`,
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * A private helper method to get and verify a MongoDB collection.
     * It checks for a valid DB connection and the existence of the collection.
     * If validation fails, it sends an error response and returns null.
     * @param collectionName - The name of the collection to verify.
     * @param res - The Express response object.
     * @returns The collection object or null if validation fails.
     */
    private static async _getAndVerifyCollection(collectionName: string, res: Response): Promise<Collection | null> {
        if (!mongoose.connection.db) {
            const response: ApiResponse<null> = {
                success: false,
                message: 'Database connection not established',
                timestamp: new Date().toISOString()
            };
            res.status(500).json(response);
            return null;
        }

        const db = mongoose.connection.db;
        const collections = await db.listCollections({ name: collectionName }).toArray();

        if (collections.length === 0) {
            const response: ApiResponse<null> = {
                success: false,
                message: `Collection '${collectionName}' not found`,
                timestamp: new Date().toISOString()
            };
            res.status(404).json(response);
            return null;
        }

        // Explicitly cast the return value to the expected Collection type to resolve the conflict.
        return db.collection(collectionName) as Collection;
    }
}