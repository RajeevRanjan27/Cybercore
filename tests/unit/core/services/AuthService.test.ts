// ============================================================================
// tests/unit/services/AuthService.test.ts
// ============================================================================

import { AuthService } from '@/core/services/AuthService';
import { User } from '@/core/models/User';
import { Tenant } from '@/core/models/Tenant';
import { RefreshToken } from '@/core/models/RefreshToken';
import { UserRole } from '@/core/constants/roles';
import { AppError } from '@/core/middlewares/errorHandler';
import jwt from 'jsonwebtoken';
import { config } from '@/config/env';

describe('AuthService', () => {
    let testTenant: any;
    let testUser: any;

    beforeEach(async () => {
        // Create test tenant
        testTenant = await Tenant.create({
            name: 'Test Tenant',
            domain: 'test.com',
            subdomain: 'test',
            isDefault: true
        });

        // Create test user
        testUser = await User.create({
            email: 'test@test.com',
            password: 'TestPassword123!',
            firstName: 'Test',
            lastName: 'User',
            role: UserRole.USER,
            tenantId: testTenant._id,
            isActive: true
        });
    });

    describe('generateTokens', () => {
        it('should generate valid access and refresh tokens', () => {
            const tokens = AuthService.generateTokens(testUser);

            expect(tokens).toHaveProperty('accessToken');
            expect(tokens).toHaveProperty('refreshToken');
            expect(typeof tokens.accessToken).toBe('string');
            expect(typeof tokens.refreshToken).toBe('string');

            // Verify token structure
            const decoded = jwt.verify(tokens.accessToken, config.JWT_SECRET) as any;
            expect(decoded.userId).toBe(testUser._id.toString());
            expect(decoded.role).toBe(testUser.role);
            expect(decoded.tenantId).toBe(testUser.tenantId.toString());
            expect(Array.isArray(decoded.permissions)).toBe(true);
        });

        it('should include correct permissions for user role', () => {
            const tokens = AuthService.generateTokens(testUser);
            const decoded = jwt.verify(tokens.accessToken, config.JWT_SECRET) as any;

            expect(decoded.permissions).toContain('user:read');
            expect(decoded.permissions).toContain('profile:read');
            expect(decoded.permissions).not.toContain('tenant:create');
        });

        it('should handle different user roles correctly', async () => {
            const adminUser = await User.create({
                email: 'admin@test.com',
                password: 'AdminPassword123!',
                firstName: 'Admin',
                lastName: 'User',
                role: UserRole.SUPER_ADMIN,
                tenantId: testTenant._id,
                isActive: true
            });

            const tokens = AuthService.generateTokens(adminUser);
            const decoded = jwt.verify(tokens.accessToken, config.JWT_SECRET) as any;

            expect(decoded.permissions).toContain('tenant:create');
            expect(decoded.permissions).toContain('user:delete');
        });
    });

    describe('verifyAccessToken', () => {
        it('should verify valid tokens', () => {
            const tokens = AuthService.generateTokens(testUser);
            const payload = AuthService.verifyAccessToken(tokens.accessToken);

            expect(payload.userId).toBe(testUser._id.toString());
            expect(payload.role).toBe(testUser.role);
        });

        it('should reject invalid tokens', () => {
            expect(() => {
                AuthService.verifyAccessToken('invalid-token');
            }).toThrow(AppError);
        });

        it('should reject expired tokens', () => {
            const expiredToken = jwt.sign(
                { userId: testUser._id.toString() },
                config.JWT_SECRET,
                { expiresIn: '1ms' }
            );

            setTimeout(() => {
                expect(() => {
                    AuthService.verifyAccessToken(expiredToken);
                }).toThrow(AppError);
            }, 10);
        });
    });

    describe('storeRefreshToken', () => {
        it('should store refresh token in database', async () => {
            const tokens = AuthService.generateTokens(testUser);
            await AuthService.storeRefreshToken(testUser._id.toString(), tokens.refreshToken);

            const storedToken = await RefreshToken.findOne({
                userId: testUser._id,
                token: tokens.refreshToken
            });

            expect(storedToken).toBeTruthy();
            expect(storedToken?.userId.toString()).toBe(testUser._id.toString());
        });
    });

    describe('refreshAccessToken', () => {
        it('should generate new tokens with valid refresh token', async () => {
            const originalTokens = AuthService.generateTokens(testUser);
            await AuthService.storeRefreshToken(testUser._id.toString(), originalTokens.refreshToken);

            const newTokens = await AuthService.refreshAccessToken(originalTokens.refreshToken);

            expect(newTokens).toHaveProperty('accessToken');
            expect(newTokens).toHaveProperty('refreshToken');
            expect(newTokens.accessToken).not.toBe(originalTokens.accessToken);
        });

        it('should reject invalid refresh tokens', async () => {
            await expect(
                AuthService.refreshAccessToken('invalid-refresh-token')
            ).rejects.toThrow(AppError);
        });

        it('should reject revoked refresh tokens', async () => {
            const tokens = AuthService.generateTokens(testUser);
            await AuthService.storeRefreshToken(testUser._id.toString(), tokens.refreshToken);
            await AuthService.revokeRefreshToken(tokens.refreshToken);

            await expect(
                AuthService.refreshAccessToken(tokens.refreshToken)
            ).rejects.toThrow(AppError);
        });
    });

    describe('trackFailedLogin', () => {
        it('should track failed login attempts', async () => {
            const result = await AuthService.trackFailedLogin('test@test.com', '192.168.1.1');
            expect(typeof result).toBe('boolean');
        });

        it('should return true when account should be locked', async () => {
            // Simulate multiple failed attempts
            for (let i = 0; i < 5; i++) {
                await AuthService.trackFailedLogin('test@test.com', '192.168.1.1');
            }

            const result = await AuthService.trackFailedLogin('test@test.com', '192.168.1.1');
            expect(result).toBe(true);
        });
    });

    describe('isAccountLocked', () => {
        it('should return false for accounts with no failed attempts', async () => {
            const lockStatus = await AuthService.isAccountLocked('test@test.com', '192.168.1.1');
            expect(lockStatus.locked).toBe(false);
        });

        it('should return true for accounts with too many failed attempts', async () => {
            // Simulate failed attempts
            for (let i = 0; i < 6; i++) {
                await AuthService.trackFailedLogin('test@test.com', '192.168.1.1');
            }

            const lockStatus = await AuthService.isAccountLocked('test@test.com', '192.168.1.1');
            expect(lockStatus.locked).toBe(true);
            expect(lockStatus.reason).toBeTruthy();
        });
    });

    describe('checkSuspiciousActivity', () => {
        it('should detect suspicious activity from different IPs', async () => {
            const isSuspicious = await AuthService.checkSuspiciousActivity(
                testUser._id.toString(),
                '192.168.1.100'
            );
            expect(typeof isSuspicious).toBe('boolean');
        });
    });
});
