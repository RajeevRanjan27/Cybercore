// tests/helpers/testHelpers.ts
import request from 'supertest';
import jwt from 'jsonwebtoken';
import {IUser, User} from '@/core/models/User';
import {ITenant, Tenant} from '@/core/models/Tenant';
import {RefreshToken} from '@/core/models/RefreshToken';
import {UserRole} from '@/core/constants/roles';
import {AuthService} from '@/core/services/AuthService';
import {config} from '@/config/env';
import {Application} from 'express';

export interface TestUser extends IUser {
    plainPassword: string;
}

export interface TestContext {
    user: TestUser;
    tenant: ITenant;
    accessToken: string;
    refreshToken: string;
}

export class TestHelpers {
    /**
     * Create a test tenant
     */
    static async createTestTenant(overrides: Partial<ITenant> = {}): Promise<ITenant> {
        const defaultTenant = {
            name: 'Test Tenant',
            domain: 'test.com',
            subdomain: 'test',
            settings: {
                maxUsers: 100,
                features: ['auth', 'rbac'],
                plan: 'pro' as const
            },
            isActive: true,
            isDefault: true,
            ...overrides
        };

        return await Tenant.create(defaultTenant);
    }

    /**
     * Create a test user with specified role
     */
    static async createTestUser(
        role: UserRole = UserRole.USER,
        tenantId?: string,
        overrides: Partial<IUser> = {}
    ): Promise<TestUser> {
        let finalTenantId = tenantId;

        if (!finalTenantId) {
            const tenant = await this.createTestTenant();
            finalTenantId = String(tenant._id);
        }

        const plainPassword = 'TestPassword123!';
        const userData = {
            email: `test.${Date.now()}@example.com`,
            password: plainPassword,
            firstName: 'Test',
            lastName: 'User',
            role,
            tenantId: finalTenantId,
            isActive: true,
            ...overrides
        };

        const user = await User.create(userData);
        return {...user.toObject(), plainPassword} as unknown as TestUser;
    }

    /**
     * Create a complete test context with user, tenant, and tokens
     */
    static async createTestContext(role: UserRole = UserRole.USER): Promise<TestContext> {
        const tenant = await this.createTestTenant();
        const user = await this.createTestUser(role, String(tenant._id));


        const tokens = AuthService.generateTokens(user);

        await AuthService.storeRefreshToken(String(user._id), tokens.refreshToken);

        return {
            user,
            tenant,
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken
        };
    }

    /**
     * Create multiple test users with different roles
     */
    static async createMultipleUsers(
        count: number,
        role: UserRole = UserRole.USER,
        tenantId?: string
    ): Promise<TestUser[]> {
        const users: TestUser[] = [];

        for (let i = 0; i < count; i++) {
            const user = await this.createTestUser(role, tenantId, {
                email: `test.user.${i}.${Date.now()}@example.com`,
                firstName: `Test${i}`,
                lastName: `User${i}`
            });
            users.push(user);
        }

        return users;
    }

    /**
     * Generate a valid JWT token for testing
     */
    static generateTestToken(
        userId: string,
        tenantId: string,
        role: UserRole = UserRole.USER,
        expiresIn: string = '1h'
    ): string {
        const payload = {
            userId,
            tenantId,
            role,
            permissions: AuthService.getUserPermissions(role)
        };

        return jwt.sign(payload, config.JWT_SECRET, { expiresIn });
    }

    /**
     * Generate an expired JWT token for testing
     */
    static generateExpiredToken(
        userId: string,
        tenantId: string,
        role: UserRole = UserRole.USER
    ): string {
        const payload = {
            userId,
            tenantId,
            role,
            permissions: AuthService.getUserPermissions(role)
        };

        return jwt.sign(payload, config.JWT_SECRET, { expiresIn: '-1h' });
    }

    /**
     * Generate an invalid JWT token
     */
    static generateInvalidToken(): string {
        return jwt.sign({ invalid: 'data' }, 'wrong_secret');
    }

    /**
     * Make authenticated request with token
     */
    static authenticatedRequest(
        app: Application,
        method: 'get' | 'post' | 'put' | 'patch' | 'delete',
        url: string,
        token: string
    ) {
        return request(app)[method](url)
            .set('Authorization', `Bearer ${token}`)
            .set('Content-Type', 'application/json');
    }

    /**
     * Create a refresh token for testing
     */
    static async createTestRefreshToken(
        userId: string,
        expiresInDays: number = 7
    ): Promise<string> {
        const refreshTokenPayload = { userId };
        const refreshToken = jwt.sign(
            refreshTokenPayload,
            config.JWT_REFRESH_SECRET,
            { expiresIn: `${expiresInDays}d` }
        );

        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + expiresInDays);

        await RefreshToken.create({
            userId,
            token: refreshToken,
            expiresAt
        });

        return refreshToken;
    }

    /**
     * Create an expired refresh token for testing
     */
    static async createExpiredRefreshToken(userId: string): Promise<string> {
        const refreshTokenPayload = { userId };
        const refreshToken = jwt.sign(
            refreshTokenPayload,
            config.JWT_REFRESH_SECRET,
            { expiresIn: '-1d' }
        );

        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() - 1); // Yesterday

        await RefreshToken.create({
            userId,
            token: refreshToken,
            expiresAt
        });

        return refreshToken;
    }

    /**
     * Create a revoked refresh token for testing
     */
    static async createRevokedRefreshToken(userId: string): Promise<string> {
        const refreshTokenPayload = { userId };
        const refreshToken = jwt.sign(
            refreshTokenPayload,
            config.JWT_REFRESH_SECRET,
            { expiresIn: '7d' }
        );

        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7);

        await RefreshToken.create({
            userId,
            token: refreshToken,
            expiresAt,
            isRevoked: true
        });

        return refreshToken;
    }

    /**
     * Clean up test data
     */
    static async cleanup(): Promise<void> {
        await Promise.all([
            User.deleteMany({}),
            Tenant.deleteMany({}),
            RefreshToken.deleteMany({})
        ]);
    }

    /**
     * Wait for a specified amount of time
     */
    static async wait(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Generate test email
     */
    static generateTestEmail(prefix: string = 'test'): string {
        return `${prefix}.${Date.now()}.${Math.random().toString(36).substring(7)}@example.com`;
    }

    /**
     * Generate test data for bulk operations
     */
    static async createBulkTestData(count: number = 5): Promise<{
        tenant: ITenant;
        users: TestUser[];
        superAdmin: TestUser;
        tenantAdmin: TestUser;
    }> {
        const tenant = await this.createTestTenant();
        const superAdmin = await this.createTestUser(UserRole.SUPER_ADMIN, String(tenant._id));
        const tenantAdmin = await this.createTestUser(UserRole.TENANT_ADMIN,String( tenant._id));

        const users = await this.createMultipleUsers(count, UserRole.USER, String(tenant._id));

        return {
            tenant,
            users,
            superAdmin,
            tenantAdmin
        };
    }

    /**
     * Validate API response structure
     */
    static validateApiResponse(response: any, expectedSuccess: boolean = true): void {
        expect(response.body).toHaveProperty('success');
        expect(response.body).toHaveProperty('timestamp');
        expect(response.body.success).toBe(expectedSuccess);

        if (expectedSuccess) {
            expect(response.body).toHaveProperty('data');
        } else {
            expect(response.body).toHaveProperty('error');
        }
    }

    /**
     * Validate pagination response
     */
    static validatePaginationResponse(response: any): void {
        expect(response.body.data).toHaveProperty('pagination');
        const pagination = response.body.data.pagination;

        expect(pagination).toHaveProperty('page');
        expect(pagination).toHaveProperty('limit');
        expect(pagination).toHaveProperty('total');
        expect(pagination).toHaveProperty('totalPages');
        expect(pagination).toHaveProperty('hasNext');
        expect(pagination).toHaveProperty('hasPrev');
    }

    /**
     * Validate user response data
     */
    static validateUserResponse(userData: any): void {
        expect(userData).toHaveProperty('id');
        expect(userData).toHaveProperty('email');
        expect(userData).toHaveProperty('firstName');
        expect(userData).toHaveProperty('lastName');
        expect(userData).toHaveProperty('role');
        expect(userData).not.toHaveProperty('password');
    }

    /**
     * Validate token response
     */
    static validateTokenResponse(tokenData: any): void {
        expect(tokenData).toHaveProperty('accessToken');
        expect(tokenData).toHaveProperty('refreshToken');
        expect(typeof tokenData.accessToken).toBe('string');
        expect(typeof tokenData.refreshToken).toBe('string');
        expect(tokenData.accessToken.length).toBeGreaterThan(0);
        expect(tokenData.refreshToken.length).toBeGreaterThan(0);
    }

    /**
     * Mock request IP address for rate limiting tests
     */
    static mockRequestIP(req: any, ip: string): void {
        req.ip = ip;
        req.connection = { remoteAddress: ip };
        req.headers = { ...req.headers, 'x-forwarded-for': ip };
    }

    /**
     * Create test data for search functionality
     */
    static async createSearchTestData(): Promise<{
        tenant: ITenant;
        users: TestUser[];
        adminUser: TestUser;
    }> {
        const tenant = await this.createTestTenant();
        const users = [
            await this.createTestUser(UserRole.USER, String(tenant._id), {
                firstName: 'Alice',
                lastName: 'Johnson',
                email: 'alice.johnson@example.com'
            }),
            await this.createTestUser(UserRole.USER, String(tenant._id), {
                firstName: 'Bob',
                lastName: 'Smith',
                email: 'bob.smith@example.com'
            }),
            await this.createTestUser(UserRole.USER, String(tenant._id), {
                firstName: 'Charlie',
                lastName: 'Brown',
                email: 'charlie.brown@example.com'
            }),
            await this.createTestUser(UserRole.TENANT_ADMIN,String( tenant._id), {
                firstName: 'Diana',
                lastName: 'Wilson',
                email: 'diana.wilson@example.com'
            })
        ];

        const adminUser = await this.createTestUser(UserRole.SUPER_ADMIN,String(tenant._id));

        return { tenant, users, adminUser };
    }
}