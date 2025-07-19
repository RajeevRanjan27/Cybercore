// src/core/middlewares/auditTrail.ts
import { Request, Response, NextFunction } from 'express';
import { AuditService } from '@/core/services/AuditService';
import { AuthPayload } from '@/core/types';

export const auditTrail = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const user = req.user as AuthPayload;

        if (user && shouldAuditRequest(req)) {
            // Store original end function
            const originalEnd = res.end;

            // Override end function to capture response
            res.end = function(chunk?: any, encoding?: any) {
                // Log the activity after response is sent
                setImmediate(async () => {
                    try {
                        const action = generateActionFromRequest(req, res.statusCode);
                        const details = extractRequestDetails(req, res);

                        await AuditService.logActivity(
                            user.userId,
                            action,
                            details,
                            {
                                ipAddress: req.ip,
                                userAgent: req.get('User-Agent'),
                                tenantId: user.tenantId
                            }
                        );
                    } catch (error) {
                        console.error('Audit logging failed:', error);
                    }
                });

                // Call original end function
                originalEnd.call(this, chunk, encoding);
            };
        }

        next();
    } catch (error) {
        next();
    }
};

function shouldAuditRequest(req: Request): boolean {
    // Skip GET requests for performance (except sensitive endpoints)
    if (req.method === 'GET') {
        const sensitiveEndpoints = ['/users/', '/export', '/stats', '/activity'];
        return sensitiveEndpoints.some(endpoint => req.path.includes(endpoint));
    }

    // Audit all non-GET requests
    return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method);
}

function generateActionFromRequest(req: Request, statusCode: number): string {
    const method = req.method;
    const path = req.path;

    if (statusCode >= 400) {
        return `${method}_FAILED`;
    }

    if (path.includes('/users/')) {
        if (method === 'POST') return 'USER_CREATE';
        if (method === 'PUT' || method === 'PATCH') return 'USER_UPDATE';
        if (method === 'DELETE') return 'USER_DELETE';
        if (method === 'GET' && path.includes('/activity')) return 'USER_ACTIVITY_VIEW';
        if (method === 'GET') return 'USER_VIEW';
    }

    if (path.includes('/bulk')) return 'BULK_OPERATION';
    if (path.includes('/export')) return 'DATA_EXPORT';
    if (path.includes('/stats')) return 'ANALYTICS_VIEW';

    return `${method}_${path.split('/')[2]?.toUpperCase() || 'UNKNOWN'}`;
}

function extractRequestDetails(req: Request, res: Response): any {
    const details: any = {
        method: req.method,
        path: req.path,
        statusCode: res.statusCode
    };

    // Add relevant body data (sanitized)
    if (req.body && Object.keys(req.body).length > 0) {
        details.requestData = sanitizeRequestData(req.body);
    }

    // Add query parameters
    if (req.query && Object.keys(req.query).length > 0) {
        details.queryParams = req.query;
    }

    return details;
}

function sanitizeRequestData(data: any): any {
    const sanitized = { ...data };

    // Remove sensitive fields
    delete sanitized.password;
    delete sanitized.currentPassword;
    delete sanitized.newPassword;
    delete sanitized.confirmPassword;
    delete sanitized.token;
    delete sanitized.refreshToken;

    return sanitized;
}

// ============================================================================
// CACHE MIDDLEWARE
// ============================================================================

// src/core/middlewares/cache.ts
import { CacheService } from '@/core/services/CacheService';
import {AppError} from "@/core/middlewares/errorHandler";

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

// ============================================================================
// COMPRESSION MIDDLEWARE
// ============================================================================

// src/core/middlewares/compression.ts
export const compressionMiddleware = (req: Request, res: Response, next: NextFunction) => {
    // Simple compression logic
    const originalJson = res.json;

    res.json = function(body: any) {
        // Add compression headers for large responses
        const bodyString = JSON.stringify(body);

        if (bodyString.length > 1024) { // If response is larger than 1KB
            res.set({
                'Content-Encoding': 'none', // Placeholder - in real app use gzip
                'X-Compressed': 'true',
                'X-Original-Size': bodyString.length.toString()
            });
        }

        return originalJson.call(this, body);
    };

    next();
};

// ============================================================================
// REQUEST VALIDATION MIDDLEWARE
// ============================================================================

// src/core/middlewares/requestValidation.ts
export const validateRequestSize = (maxSizeBytes: number = 1024 * 1024) => {
    return (req: Request, res: Response, next: NextFunction) => {
        const contentLength = parseInt(req.get('Content-Length') || '0');

        if (contentLength > maxSizeBytes) {
            return next(new AppError('Request too large', 413));
        }

        next();
    };
};

export const validateContentType = (allowedTypes: string[]) => {
    return (req: Request, res: Response, next: NextFunction) => {
        const contentType = req.get('Content-Type');

        if (req.method !== 'GET' && contentType) {
            const isAllowed = allowedTypes.some(type =>
                contentType.includes(type)
            );

            if (!isAllowed) {
                return next(new AppError('Unsupported content type', 415));
            }
        }

        next();
    };
};

// ============================================================================
// SECURITY HEADERS MIDDLEWARE
// ============================================================================

// src/core/middlewares/securityHeaders.ts
export const securityHeaders = (req: Request, res: Response, next: NextFunction) => {
    // Add security headers
    res.set({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    });

    next();
};

// ============================================================================
// API VERSION MIDDLEWARE
// ============================================================================

// src/core/middlewares/apiVersion.ts
export const apiVersion = (supportedVersions: string[] = ['v1']) => {
    return (req: Request, res: Response, next: NextFunction) => {
        const version = req.headers['api-version'] || 'v1';

        if (!supportedVersions.includes(version as string)) {
            return next(new AppError(`API version ${version} not supported`, 400));
        }

        req.apiVersion = version as string;
        res.set('API-Version', version as string);

        next();
    };
};

// Extend Request interface
declare global {
    namespace Express {
        interface Request {
            apiVersion?: string;
        }
    }
}