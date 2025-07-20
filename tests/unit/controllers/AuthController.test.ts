// ============================================================================
// tests/unit/controllers/AuthController.test.ts
// ============================================================================

import request from 'supertest';
import express, { Request, Response, NextFunction } from 'express';
// Aliases are restored and will work with the correct Jest config
import { authRoutes } from '@/api/auth/routes';
import { AppError } from '@/core/middlewares/errorHandler';
import { User } from '@/core/models/User';
import { Tenant } from '@/core/models/Tenant';
import { RefreshToken } from '@/core/models/RefreshToken';
import { AuthService } from '@/core/services/AuthService';
import { UserRole } from '@/core/constants/roles';
import { CacheService } from '@/core/services/CacheService';

// Mock the middleware to isolate the controller logic for unit testing
jest.mock('@/core/validators/middleware', () => ({
    validate: () => (req: Request, res: Response, next: NextFunction) => next(),
}));

jest.mock('@/core/middlewares/auth', () => ({
    authenticate: (req: Request, res: Response, next: NextFunction) => {
        // For the '/me' route, simulate an authenticated user
        (req as any).user = { userId: 'mockUserId' }; // Use a consistent mock ID
        next();
    },
}));

jest.mock('@/core/middlewares/rateLimiter', () => ({
    authRateLimiter: (req: Request, res: Response, next: NextFunction) => next(),
}));

// Mock the cache service to control its behavior in tests
jest.mock('@/core/services/CacheService');


// A simple mock for the global error handler
const testErrorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
    if (err instanceof AppError) {
        return res.status(err.statusCode).json({
            success: false,
            message: err.message,
            error: err.message,
        });
    }
    console.error('Test Server Error:', err);
    res.status(500).json({ success: false, error: 'Internal Server Error' });
};


describe('AuthController', () => {
    let app: express.Application;
    let testTenant: any;
    let testUser: any;
    let accessToken: string;
    let refreshToken: string;

    beforeEach(async () => {
        app = express();
        app.use(express.json());
        app.use('/api/auth', authRoutes);
        app.use(testErrorHandler);

        // Reset mocks before each test
        jest.clearAllMocks();

        // Clean database
        await Tenant.deleteMany({});
        await User.deleteMany({});
        await RefreshToken.deleteMany({});

        // Create common test data
        testTenant = await Tenant.create({
            name: 'Test Tenant',
            domain: 'test.com',
            subdomain: 'test',
            isDefault: true
        });

        testUser = await User.create({
            _id: 'mockUserId',
            email: 'test@test.com',
            password: 'TestPassword123!',
            firstName: 'Test',
            lastName: 'User',
            role: UserRole.USER,
            tenantId: testTenant._id,
            isActive: true
        });

        const tokens = AuthService.generateTokens(testUser);
        await AuthService.storeRefreshToken(String(testUser._id), tokens.refreshToken);
        accessToken = tokens.accessToken;
        refreshToken = tokens.refreshToken;
    });

    describe('POST /api/auth/register', () => {
        it('should register a new user successfully using default tenant', async () => {
            const userData = {
                email: 'newuser@test.com',
                password: 'TestPassword123!',
                firstName: 'New',
                lastName: 'User',
            };

            const response = await request(app)
                .post('/api/auth/register')
                .send(userData)
                .expect(201);

            expect(response.body.success).toBe(true);
            expect(response.body.data.user.email).toBe(userData.email);
            expect(response.body.data.user.tenantId).toBe(testTenant._id.toString());
        });

        it('should register a new user with a specific tenantId', async () => {
            const otherTenant = await Tenant.create({ name: 'Other Tenant' });
            const userData = {
                email: 'specifictenant@test.com',
                password: 'TestPassword123!',
                firstName: 'Specific',
                lastName: 'User',
                tenantId: String(otherTenant._id),
            };

            const response = await request(app)
                .post('/api/auth/register')
                .send(userData)
                .expect(201);

            expect(response.body.data.user.tenantId).toBe(String(otherTenant._id));
        });

        it('should return 409 for a duplicate email', async () => {
            const userData = { email: 'test@test.com', password: 'p' };
            await request(app).post('/api/auth/register').send(userData).expect(409);
        });

        it('should return 400 for an invalid tenantId', async () => {
            const userData = {
                email: 'invalidtenant@test.com',
                password: 'p',
                tenantId: '60c72b2f9b1e8b001f8e4d1a', // Non-existent ID
            };
            await request(app).post('/api/auth/register').send(userData).expect(400);
        });

        it('should return 500 if no default tenant is found', async () => {
            await Tenant.deleteMany({}); // Remove all tenants
            const userData = { email: 'nodefault@test.com', password: 'p' };
            const response = await request(app)
                .post('/api/auth/register')
                .send(userData)
                .expect(500);

            expect(response.body.message).toContain('Default tenant not found');
        });
    });

    describe('POST /api/auth/login', () => {
        it('should login with valid credentials', async () => {
            const response = await request(app)
                .post('/api/auth/login')
                .send({ email: 'test@test.com', password: 'TestPassword123!' })
                .expect(200);
            expect(response.body.success).toBe(true);
        });

        it('should reject invalid credentials', async () => {
            await request(app)
                .post('/api/auth/login')
                .send({ email: 'test@test.com', password: 'WrongPassword!' })
                .expect(401);
        });

        it('should reject login for an inactive user', async () => {
            await User.findByIdAndUpdate(testUser._id, { isActive: false });
            const response = await request(app)
                .post('/api/auth/login')
                .send({ email: 'test@test.com', password: 'TestPassword123!' })
                .expect(401);
            expect(response.body.message).toBe('Invalid credentials');
        });

        it('should reject login for a non-existent user', async () => {
            const response = await request(app)
                .post('/api/auth/login')
                .send({ email: 'nouser@test.com', password: 'p' })
                .expect(401);
            expect(response.body.message).toBe('Invalid credentials');
        });

        it('should return 429 if account is locked', async () => {
            jest.spyOn(AuthService, 'isAccountLocked').mockResolvedValue({ locked: true, reason: 'Too many attempts', retryAfter: 60 });
            const response = await request(app)
                .post('/api/auth/login')
                .send({ email: 'test@test.com', password: 'p' })
                .expect(429);
            expect(response.body.message).toContain('Account temporarily locked');
        });

        it('should get user from cache on second login attempt', async () => {
            // Mock getCachedUser to return null first, then the user
            (AuthService.getCachedUser as jest.Mock)
                .mockResolvedValueOnce(null)
                .mockResolvedValueOnce(testUser);

            // First login (populates cache)
            await request(app).post('/api/auth/login').send({ email: 'test@test.com', password: 'TestPassword123!' });
            expect(CacheService.set).toHaveBeenCalledTimes(1);

            // Second login (should hit cache)
            await request(app).post('/api/auth/login').send({ email: 'test@test.com', password: 'TestPassword123!' });
            expect(AuthService.getCachedUser).toHaveBeenCalledTimes(2);
        });

        it('should show security alert for suspicious activity', async () => {
            jest.spyOn(AuthService, 'checkSuspiciousActivity').mockResolvedValue(true);
            const response = await request(app)
                .post('/api/auth/login')
                .send({ email: 'test@test.com', password: 'TestPassword123!' })
                .expect(200);
            expect(response.body.data.securityAlert).toBe('Login from new location detected');
        });
    });

    describe('POST /api/auth/refresh', () => {
        it('should refresh tokens with a valid refresh token', async () => {
            const response = await request(app)
                .post('/api/auth/refresh')
                .send({ refreshToken })
                .expect(200);
            expect(response.body.data.tokens.refreshToken).not.toBe(refreshToken);
        });

        it('should reject an invalid refresh token', async () => {
            await request(app).post('/api/auth/refresh').send({ refreshToken: 'invalid' }).expect(401);
        });
    });

    describe('POST /api/auth/logout', () => {
        it('should logout successfully with a refresh token', async () => {
            const response = await request(app)
                .post('/api/auth/logout')
                .send({ refreshToken })
                .expect(200);
            expect(response.body.message).toBe('Logged out successfully');
            const dbToken = await RefreshToken.findOne({ token: refreshToken });
            expect(dbToken?.isRevoked).toBe(true);
        });

        it('should handle logout without a refresh token', async () => {
            const response = await request(app)
                .post('/api/auth/logout')
                .send({})
                .expect(200);
            expect(response.body.message).toBe('Logged out successfully');
        });
    });

    describe('GET /api/auth/me', () => {
        it('should return user profile for an authenticated request', async () => {
            const response = await request(app)
                .get('/api/auth/me')
                .set('Authorization', `Bearer ${accessToken}`)
                .expect(200);
            expect(response.body.data.user.id).toBe(testUser._id.toString());
        });

        it('should return 404 if authenticated user is not found', async () => {
            await User.deleteMany({}); // Delete the user after token is issued
            await request(app).get('/api/auth/me').set('Authorization', `Bearer ${accessToken}`).expect(404);
        });
    });
});
