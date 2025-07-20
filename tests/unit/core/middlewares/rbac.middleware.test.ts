// ============================================================================
// tests/unit/middleware/rbac.middleware.test.ts
// ============================================================================

import { Request, Response, NextFunction } from 'express';
import { authorize } from '@/core/middlewares/rbac';
import { AppError } from '@/core/middlewares/errorHandler';
import { UserRole } from '@/core/constants/roles';

describe('RBAC Middleware (authorize)', () => {
    let mockRequest: Partial<Request>;
    let mockResponse: Partial<Response>;
    let nextFunction: NextFunction;

    beforeEach(() => {
        mockRequest = {};
        mockResponse = {};
        nextFunction = jest.fn();
    });

    it('should call next() if user has the required permission', () => {
        // FIX: Cast mockRequest to 'any' to allow adding the 'user' property for testing.
        (mockRequest as any).user = {
            userId: 'user-id',
            role: UserRole.TENANT_ADMIN,
            tenantId: 'tenant-id',
            permissions: ['user:create', 'user:read'],
        };

        const middleware = authorize('user:create');
        middleware(mockRequest as Request, mockResponse as Response, nextFunction);

        expect(nextFunction).toHaveBeenCalledWith();
        expect(nextFunction).not.toHaveBeenCalledWith(expect.any(Error));
    });

    it('should call next with an AppError if user does not have the required permission', () => {
        // FIX: Cast mockRequest to 'any' to allow adding the 'user' property for testing.
        (mockRequest as any).user = {
            userId: 'user-id',
            role: UserRole.USER,
            tenantId: 'tenant-id',
            permissions: ['user:read', 'profile:update'],
        };

        const middleware = authorize('user:delete');
        middleware(mockRequest as Request, mockResponse as Response, nextFunction);

        expect(nextFunction).toHaveBeenCalledWith(expect.any(AppError));
        const error = (nextFunction as jest.Mock).mock.calls[0][0];
        expect(error.statusCode).toBe(403);
        expect(error.message).toBe('Insufficient permissions');
    });

    it('should call next with an AppError if user is not authenticated (req.user is missing)', () => {
        const middleware = authorize('user:read');
        middleware(mockRequest as Request, mockResponse as Response, nextFunction);

        expect(nextFunction).toHaveBeenCalledWith(expect.any(AppError));
        const error = (nextFunction as jest.Mock).mock.calls[0][0];
        expect(error.statusCode).toBe(401);
        expect(error.message).toBe('User not authenticated');
    });
});
