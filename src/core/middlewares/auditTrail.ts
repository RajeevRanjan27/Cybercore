// src/core/middlewares/auditTrail.ts
import { Request, Response, NextFunction } from 'express';
import { AuditService } from '@/core/services/AuditService';
import { AuthPayload } from '@/core/types';

export const auditTrail = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const user = req.user as AuthPayload;

        if (user && shouldAuditRequest(req)) {
            // Store original end function
            const originalEnd = res.end.bind(res);

            // Override end function to capture response
            res.end = function(chunk?: any, encoding?: BufferEncoding | (() => void), cb?: () => void): Response {
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

                // Call original end function with proper arguments
                if (typeof chunk === 'undefined') {
                    return originalEnd();
                } else if (typeof encoding === 'function') {
                    // encoding is actually the callback
                    return originalEnd(chunk, encoding);
                } else if (typeof encoding === 'string' && typeof cb === 'function') {
                    // encoding is BufferEncoding, cb is callback
                    return originalEnd(chunk, encoding as BufferEncoding, cb);
                } else if (typeof encoding === 'string') {
                    // encoding is BufferEncoding, no callback
                    return originalEnd(chunk, encoding as BufferEncoding);
                } else {
                    // chunk only, no encoding or callback
                    return originalEnd(chunk);
                }
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
    const sanitized = {...data};

    // Remove sensitive fields
    delete sanitized.password;
    delete sanitized.currentPassword;
    delete sanitized.newPassword;
    delete sanitized.confirmPassword;
    delete sanitized.token;
    delete sanitized.refreshToken;

    return sanitized;
}