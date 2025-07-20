// ============================================================================
// CACHE MIDDLEWARE
// ============================================================================

// src/core/middlewares/cache.ts
import { CacheService } from '@/core/services/CacheService';
import { Request, Response, NextFunction } from 'express';
import {AuthPayload} from "@/core/types";

export const cacheMiddleware = (ttlSeconds: number = 300) => {
    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            // Only cache GET requests
            if (req.method !== 'GET') {
                return next();
            }

            // Generate cache key
            const cacheKey = generateCacheKey(req);

            // Try to get cached response
            const cachedResponse = await CacheService.get(cacheKey);

            if (cachedResponse) {
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
                // Cache successful responses only
                if (res.statusCode < 400) {
                    CacheService.set(cacheKey, body, ttlSeconds).catch(err => {
                        console.error('Failed to cache response:', err);
                    });
                }

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
            next();
        }
    };
};

function generateCacheKey(req: Request): string {
    const user = req.user as AuthPayload;
    const keyData = {
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
