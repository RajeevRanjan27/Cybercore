// ============================================================================
// tests/integration/auth.integration.test.ts
// ============================================================================

import request from 'supertest';
import express from 'express';
import { authRoutes } from '@/api/auth/routes';
import { errorHandler } from '@/core/middlewares/errorHandler';
import { User } from "../../src/core/models/User";
import { UserRole } from "../../src/core/constants/roles";
import { Tenant, ITenant } from "../../src/core/models/Tenant";
import { RefreshToken } from '../../src/core/models/RefreshToken';

describe('Auth Integration Tests', () => {
    let app: express.Application;
    let testTenant: ITenant;

    // Setup express app once for all tests
    beforeAll(() => {
        app = express();
        app.use(express.json());
        app.use('/auth', authRoutes);
        app.use(errorHandler);
    });

    // Clean and setup database before each test
    beforeEach(async () => {
        await User.deleteMany({});
        await Tenant.deleteMany({});
        await RefreshToken.deleteMany({});

        testTenant = await Tenant.create({
            name: 'Test Tenant',
            domain: 'test.com',
            subdomain: 'test',
            isDefault: true
        });
    });

    // Final cleanup after all tests are done
    afterAll(async () => {
        await User.deleteMany({});
        await Tenant.deleteMany({});
        await RefreshToken.deleteMany({});
    });


    describe('POST /auth/register', () => {
        it('should register a new user and return tokens', async () => {
            const userData = {
                email: 'integration@test.com',
                password: 'TestPassword123!',
                firstName: 'Integration',
                lastName: 'Test'
            };

            const response = await request(app)
                .post('/auth/register')
                .send(userData)
                .expect(201);

            expect(response.body.success).toBe(true);
            expect(response.body.data.user.email).toBe(userData.email);
            expect(response.body.data.tokens).toHaveProperty('accessToken');
            expect(response.body.data.tokens).toHaveProperty('refreshToken');
        });

        it('should return 400 for invalid registration input', async () => {
            const invalidData = {
                email: 'invalid-email',
                password: 'weak',
                firstName: '',
                lastName: 'Test'
            };

            const response = await request(app)
                .post('/auth/register')
                .send(invalidData)
                .expect(400);

            expect(response.body.success).toBe(false);
            expect(response.body.error).toBeDefined();
        });

        it('should return 409 when registering with a duplicate email', async () => {
            const userData = {
                email: 'duplicate@test.com',
                password: 'TestPassword123!',
                firstName: 'Duplicate',
                lastName: 'Test',
                tenantId: String(testTenant._id)
            };
            await User.create(userData);

            const response = await request(app)
                .post('/auth/register')
                .send(userData)
                .expect(409);

            expect(response.body.success).toBe(false);
            expect(response.body.error.message).toContain('already exists');
        });
    });

    describe('POST /auth/login', () => {
        beforeEach(async () => {
            await User.create({
                email: 'logintest@test.com',
                password: 'TestPassword123!',
                firstName: 'Login',
                lastName: 'Test',
                role: UserRole.USER,
                tenantId: String(testTenant._id),
                isActive: true
            });
        });

        it('should login with valid credentials and return tokens', async () => {
            const loginData = {
                email: 'logintest@test.com',
                password: 'TestPassword123!',
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

        it('should return 401 for invalid credentials', async () => {
            const loginData = {
                email: 'logintest@test.com',
                password: 'WrongPassword123!',
            };

            const response = await request(app)
                .post('/auth/login')
                .send(loginData)
                .expect(401);

            expect(response.body.success).toBe(false);
            expect(response.body.error.message).toContain('Invalid credentials');
        });
    });

    describe('POST /auth/refresh-token', () => {
        it('should issue a new access token with a valid refresh token', async () => {
            // 1. Create user and login to get a refresh token
            await User.create({
                email: 'refresh@test.com',
                password: 'TestPassword123!',
                firstName: 'Refresh',
                lastName: 'Test',
                role: UserRole.USER,
                tenantId: String(testTenant._id),
                isActive: true
            });
            const loginResponse = await request(app)
                .post('/auth/login')
                .send({ email: 'refresh@test.com', password: 'TestPassword123!' });

            const { refreshToken, accessToken: oldAccessToken } = loginResponse.body.data.tokens;

            // 2. Use the refresh token to get a new access token
            const refreshResponse = await request(app)
                .post('/auth/refresh-token')
                .send({ refreshToken })
                .expect(200);

            expect(refreshResponse.body.success).toBe(true);
            expect(refreshResponse.body.data).toHaveProperty('accessToken');
            expect(refreshResponse.body.data.accessToken).not.toBe(oldAccessToken);
        });

        it('should return 401 for an invalid refresh token', async () => {
            const response = await request(app)
                .post('/auth/refresh-token')
                .send({ refreshToken: 'invalid-token' })
                .expect(401);

            expect(response.body.success).toBe(false);
        });
    });

    describe('POST /auth/logout', () => {
        it('should revoke the refresh token, preventing reuse', async () => {
            // 1. Create user and login
            await User.create({
                email: 'logout@test.com',
                password: 'TestPassword123!',
                firstName: 'Logout',
                lastName: 'Test',
                role: UserRole.USER,
                tenantId: String(testTenant._id),
                isActive: true
            });
            const loginResponse = await request(app)
                .post('/auth/login')
                .send({ email: 'logout@test.com', password: 'TestPassword123!' });
            const { refreshToken } = loginResponse.body.data.tokens;

            // 2. Logout
            const logoutResponse = await request(app)
                .post('/auth/logout')
                .send({ refreshToken })
                .expect(200);

            expect(logoutResponse.body.success).toBe(true);
            expect(logoutResponse.body.data.message).toContain('logged out');

            // 3. Verify the token is revoked by trying to use it again
            await request(app)
                .post('/auth/refresh-token')
                .send({ refreshToken })
                .expect(401);
        });
    });

    describe('GET /auth/me', () => {
        it('should return current user data with a valid access token', async () => {
            // 1. Create user and login
            await User.create({
                email: 'me@test.com',
                password: 'TestPassword123!',
                firstName: 'Me',
                lastName: 'Test',
                role: UserRole.USER,
                tenantId: String(testTenant._id),
                isActive: true
            });
            const loginResponse = await request(app)
                .post('/auth/login')
                .send({ email: 'me@test.com', password: 'TestPassword123!' });
            const { accessToken } = loginResponse.body.data.tokens;

            // 2. Access the /me endpoint
            const meResponse = await request(app)
                .get('/auth/me')
                .set('Authorization', `Bearer ${accessToken}`)
                .expect(200);

            expect(meResponse.body.success).toBe(true);
            expect(meResponse.body.data.email).toBe('me@test.com');
            expect(meResponse.body.data).not.toHaveProperty('password');
        });

        it('should return 401 without an access token', async () => {
            await request(app)
                .get('/auth/me')
                .expect(401);
        });

        it('should return 401 with an invalid or expired access token', async () => {
            await request(app)
                .get('/auth/me')
                .set('Authorization', 'Bearer invalidtoken')
                .expect(401);
        });
    });
});
