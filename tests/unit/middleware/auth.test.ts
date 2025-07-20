// ============================================================================
// tests/unit/middleware/auth.test.ts
// ============================================================================

import { Request, Response, NextFunction } from 'express';
import { authenticate } from '@/core/middlewares/auth';
import {AppError} from "../../../src/core/middlewares/errorHandler";
import {UserRole} from "../../../src/core/constants/roles";
import jwt from "jsonwebtoken";
import {config} from "@/config/env";

describe('Auth Middleware', () => {
    let mockRequest: Partial<Request>;
    let mockResponse: Partial<Response>;
    let nextFunction: NextFunction;

    beforeEach(() => {
        mockRequest = {
            headers: {}
        };
        mockResponse = {};
        nextFunction = jest.fn();
    });

    it('should authenticate valid bearer token', () => {
        const testUser = {
            _id: 'test-user-id',
            role: UserRole.USER,
            tenantId: 'test-tenant-id'
        };

        const token = jwt.sign(
            {
                userId: testUser._id,
                role: testUser.role,
                tenantId: testUser.tenantId,
                permissions: ['user:read']
            },
            config.JWT_SECRET
        );

        mockRequest.headers = {
            authorization: `Bearer ${token}`
        };

        authenticate(mockRequest as Request, mockResponse as Response, nextFunction);

        expect(nextFunction).toHaveBeenCalledWith();
        expect((mockRequest as any).user).toBeTruthy();
        expect((mockRequest as any).user?.userId).toBe(testUser._id);
    });

    it('should reject requests without authorization header', () => {
        authenticate(mockRequest as Request, mockResponse as Response, nextFunction);

        expect(nextFunction).toHaveBeenCalledWith(expect.any(AppError));
    });

    it('should reject invalid token format', () => {
        mockRequest.headers = {
            authorization: 'Invalid token-format'
        };

        authenticate(mockRequest as Request, mockResponse as Response, nextFunction);

        expect(nextFunction).toHaveBeenCalledWith(expect.any(AppError));
    });

    it('should reject malformed tokens', () => {
        mockRequest.headers = {
            authorization: 'Bearer invalid-token'
        };

        authenticate(mockRequest as Request, mockResponse as Response, nextFunction);

        expect(nextFunction).toHaveBeenCalledWith(expect.any(AppError));
    });
});
