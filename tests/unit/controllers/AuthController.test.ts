// ============================================================================
// tests/unit/controllers/AuthController.test.ts
// ============================================================================

import { AuthController } from '@/api/auth/controller';
import request from 'supertest';
import express from 'express';
import {RefreshToken} from "../../../src/core/models/RefreshToken";
import {AuthService} from "../../../src/core/services/AuthService";
import {UserRole} from "../../../src/core/constants/roles";
import {User} from "../../../src/core/models/User";
import {AppError} from "../../../src/core/middlewares/errorHandler";
import {ITenant, Tenant} from "../../../src/core/models/Tenant";

describe('AuthController', () => {
    let app: express.Application;
    let testTenant: ITenant;

    beforeEach(async () => {
        app = express();
        app.use(express.json());

        testTenant = await Tenant.create({
            name: 'Test Tenant',
            domain: 'test.com',
            subdomain: 'test',
            isDefault: true
        });
    });

    describe('register', () => {
        it('should register new user successfully', async () => {
            const userData = {
                email: 'newuser@test.com',
                password: 'TestPassword123!',
                firstName: 'New',
                lastName: 'User'
            };

            const mockReq = {
                body: userData
            } as any;

            const mockRes = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn()
            } as any;

            const mockNext = jest.fn();

            await AuthController.register(mockReq, mockRes, mockNext);

            expect(mockRes.status).toHaveBeenCalledWith(201);
            expect(mockRes.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    success: true,
                    data: expect.objectContaining({
                        user: expect.any(Object),
                        tokens: expect.any(Object)
                    })
                })
            );
        });

        it('should reject duplicate email registration', async () => {
            // Create existing user
            await User.create({
                email: 'existing@test.com',
                password: 'Password123!',
                firstName: 'Existing',
                lastName: 'User',
                role: UserRole.USER,
                tenantId: String(testTenant._id)
            });

            const userData = {
                email: 'existing@test.com',
                password: 'TestPassword123!',
                firstName: 'New',
                lastName: 'User'
            };

            const mockReq = { body: userData } as any;
            const mockRes = {} as any;
            const mockNext = jest.fn();

            await AuthController.register(mockReq, mockRes, mockNext);

            expect(mockNext).toHaveBeenCalledWith(expect.any(AppError));
        });
    });

    describe('login', () => {
        let testUser: any;

        beforeEach(async () => {
            testUser = await User.create({
                email: 'login@test.com',
                password: 'TestPassword123!',
                firstName: 'Login',
                lastName: 'User',
                role: UserRole.USER,
                tenantId: testTenant._id,
                isActive: true
            });
        });

        it('should login with valid credentials', async () => {
            const loginData = {
                email: 'logintest@test.com',
                password: 'TestPassword123!'
            };

            const response = await request(app)
                .post('/auth/login')
                .send(loginData)
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.user.email).toBe(loginData.email);
            expect(response.body.data.tokens).toHaveProperty('accessToken');
            expect(response.body.data.tokens).toHaveProperty('refreshToken');
        });

        it('should reject invalid credentials', async () => {
            const loginData = {
                email: 'logintest@test.com',
                password: 'WrongPassword123!'
            };

            const response = await request(app)
                .post('/auth/login')
                .send(loginData)
                .expect(401);

            expect(response.body.success).toBe(false);
            expect(response.body.error).toContain('Invalid credentials');
        });

        it('should handle rate limiting after multiple failed attempts', async () => {
            const loginData = {
                email: 'logintest@test.com',
                password: 'WrongPassword123!'
            };

            // Make multiple failed login attempts
            for (let i = 0; i < 6; i++) {
                await request(app)
                    .post('/auth/login')
                    .send(loginData);
            }

            const response = await request(app)
                .post('/auth/login')
                .send(loginData)
                .expect(429);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toContain('temporarily locked');
        });
    });

    describe('POST /auth/refresh', () => {
        let refreshToken: string;

        beforeEach(async () => {
            const user = await User.create({
                email: 'refresh@test.com',
                password: 'TestPassword123!',
                firstName: 'Refresh',
                lastName: 'Test',
                role: UserRole.USER,
                tenantId: testTenant._id,
                isActive: true
            });

            const tokens = AuthService.generateTokens(user);
            await AuthService.storeRefreshToken(String(user._id), tokens.refreshToken);
            refreshToken = tokens.refreshToken;
        });

        it('should refresh tokens with valid refresh token', async () => {
            const response = await request(app)
                .post('/auth/refresh')
                .send({ refreshToken })
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.tokens).toHaveProperty('accessToken');
            expect(response.body.data.tokens).toHaveProperty('refreshToken');
        });

        it('should reject invalid refresh token', async () => {
            const response = await request(app)
                .post('/auth/refresh')
                .send({ refreshToken: 'invalid-token' })
                .expect(401);

            expect(response.body.success).toBe(false);
        });

        it('should reject revoked refresh token', async () => {
            await AuthService.revokeRefreshToken(refreshToken);

            const response = await request(app)
                .post('/auth/refresh')
                .send({ refreshToken })
                .expect(401);

            expect(response.body.success).toBe(false);
        });
    });

    describe('GET /auth/me', () => {
        let accessToken: string;
        let testUser: any;

        beforeEach(async () => {
            testUser = await User.create({
                email: 'me@test.com',
                password: 'TestPassword123!',
                firstName: 'Me',
                lastName: 'Test',
                role: UserRole.USER,
                tenantId: testTenant._id,
                isActive: true
            });

            const tokens = AuthService.generateTokens(testUser);
            accessToken = tokens.accessToken;
        });

        it('should return user profile with valid token', async () => {
            const response = await request(app)
                .get('/auth/me')
                .set('Authorization', `Bearer ${accessToken}`)
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.user.email).toBe('me@test.com');
            expect(response.body.data.user.id).toBe(testUser._id.toString());
        });

        it('should reject request without authorization', async () => {
            const response = await request(app)
                .get('/auth/me')
                .expect(401);

            expect(response.body.success).toBe(false);
        });

        it('should reject request with invalid token', async () => {
            const response = await request(app)
                .get('/auth/me')
                .set('Authorization', 'Bearer invalid-token')
                .expect(401);

            expect(response.body.success).toBe(false);
        });
    });

    describe('POST /auth/logout', () => {
        let refreshToken: string;

        beforeEach(async () => {
            const user = await User.create({
                email: 'logout@test.com',
                password: 'TestPassword123!',
                firstName: 'Logout',
                lastName: 'Test',
                role: UserRole.USER,
                tenantId: testTenant._id,
                isActive: true
            });

            const tokens = AuthService.generateTokens(user);
            await AuthService.storeRefreshToken(String(user._id), tokens.refreshToken);
            refreshToken = tokens.refreshToken;
        });

        it('should logout successfully', async () => {
            const response = await request(app)
                .post('/auth/logout')
                .send({ refreshToken })
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.message).toContain('Logged out successfully');

            // Verify token is revoked
            const revokedToken = await RefreshToken.findOne({
                token: refreshToken,
                isRevoked: true
            });
            expect(revokedToken).toBeTruthy();
        });

        it('should handle logout without refresh token', async () => {
            const response = await request(app)
                .post('/auth/logout')
                .send({})
                .expect(200);

            expect(response.body.success).toBe(true);
        });
    });
});
