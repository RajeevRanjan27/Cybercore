// ============================================================================
// tests/security/auth.security.test.ts
// ============================================================================

import { User, IUser } from "../../src/core/models/User";
import { UserRole } from "../../src/core/constants/roles";
import { AuthService } from "../../src/core/services/AuthService";
import jwt from "jsonwebtoken";
import { AppError } from "../../src/core/middlewares/errorHandler";
import { Tenant, ITenant } from "../../src/core/models/Tenant";
import { AuthController } from "../../src/api/auth/controller";
import { ValidationService } from "../../src/core/services/ValidationService";
import { UserService } from "../../src/core/services/UserService";
import { RefreshToken } from "../../src/core/models/RefreshToken";

describe('Auth Security Tests', () => {
    let testTenant: ITenant;

    beforeEach(async () => {
        // Clear previous test data
        await User.deleteMany({});
        await Tenant.deleteMany({});
        await RefreshToken.deleteMany({});

        testTenant = await Tenant.create({
            name: 'Security Test Tenant',
            domain: 'security.com',
            subdomain: 'security',
            isDefault: true
        });
    });

    describe('Password Security', () => {
        it('should hash passwords properly', async () => {
            const user = await User.create({
                email: 'security@test.com',
                password: 'TestPassword123!',
                firstName: 'Security',
                lastName: 'Test',
                role: UserRole.USER,
                tenantId: String(testTenant._id)
            });

            // Password should be hashed, not stored in plain text
            expect(user.password).not.toBe('TestPassword123!');
            expect(user.password).toMatch(/^\$2[aby]\$\d+\$/); // bcrypt format
        });

        it('should reject weak passwords', async () => {
            const weakPasswords = [
                'weak',
                'password',
                '12345678',
                'PASSWORD123',
                'password123'
            ];

            for (const weakPassword of weakPasswords) {
                await expect(
                    User.create({
                        email: `weak-${Math.random()}@test.com`,
                        password: weakPassword,
                        firstName: 'Weak',
                        lastName: 'Test',
                        role: UserRole.USER,
                        tenantId: String(testTenant._id)
                    })
                ).rejects.toThrow();
            }
        });
    });

    describe('Token Security', () => {
        let testUser: IUser;

        beforeEach(async () => {
            testUser = await User.create({
                email: 'token-sec@test.com',
                password: 'TestPassword123!',
                firstName: 'Token',
                lastName: 'Test',
                role: UserRole.USER,
                tenantId: String(testTenant._id)
            });
        });

        it('should generate cryptographically secure tokens', () => {
            const tokens1 = AuthService.generateTokens(testUser);
            const tokens2 = AuthService.generateTokens(testUser);

            // Tokens should be different even for same user
            expect(tokens1.accessToken).not.toBe(tokens2.accessToken);
            expect(tokens1.refreshToken).not.toBe(tokens2.refreshToken);
        });

        it('should include proper token expiration', () => {
            const tokens = AuthService.generateTokens(testUser);
            const decoded = jwt.decode(tokens.accessToken) as any;

            expect(decoded.exp).toBeTruthy();
            expect(decoded.iat).toBeTruthy();
            expect(decoded.exp > decoded.iat).toBe(true);
        });

        it('should prevent token replay attacks', async () => {
            const tokens = AuthService.generateTokens(testUser);
            await AuthService.storeRefreshToken(String(testUser._id), tokens.refreshToken);

            // Use refresh token once
            await AuthService.refreshAccessToken(tokens.refreshToken);

            // Using the same refresh token again should fail
            await expect(
                AuthService.refreshAccessToken(tokens.refreshToken)
            ).rejects.toThrow(AppError);
        });
    });

    describe('Rate Limiting Security', () => {
        it('should implement proper rate limiting', async () => {
            const email = 'ratelimit@test.com';
            const ip = '192.168.1.100';

            // Simulate failed login attempts
            for (let i = 0; i < 5; i++) {
                await AuthService.trackFailedLogin(email, ip);
            }

            const lockStatus = await AuthService.isAccountLocked(email, ip);
            expect(lockStatus.locked).toBe(true);
        });

        it('should prevent timing attacks', async () => {
            await User.create({
                email: 'timing@test.com',
                password: 'TestPassword123!',
                firstName: 'Timing',
                lastName: 'Test',
                role: UserRole.USER,
                tenantId: String(testTenant._id),
                isActive: true
            });

            // Test login with valid user but wrong password
            const startTime1 = Date.now();
            try {
                await AuthController.login({
                    body: { email: 'timing@test.com', password: 'WrongPassword123!' },
                    ip: '192.168.1.1'
                } as any, {} as any, jest.fn());
            } catch {}
            const duration1 = Date.now() - startTime1;

            // Test login with non-existent user
            const startTime2 = Date.now();
            try {
                await AuthController.login({
                    body: { email: 'nonexistent@test.com', password: 'TestPassword123!' },
                    ip: '192.168.1.1'
                } as any, {} as any, jest.fn());
            } catch {}
            const duration2 = Date.now() - startTime2;

            // Time difference should be minimal (e.g., within 100ms)
            expect(Math.abs(duration1 - duration2)).toBeLessThan(100);
        });
    });

    describe('Input Validation Security', () => {
        it('should prevent NoSQL injection in email field', async () => {
            const maliciousInputs = [
                "'; DROP TABLE users; --",
                "' OR '1'='1",
                "admin'/*",
                "' UNION SELECT * FROM users --"
            ];

            for (const maliciousInput of maliciousInputs) {
                await expect(
                    User.create({
                        email: maliciousInput,
                        password: 'TestPassword123!',
                        firstName: 'Malicious',
                        lastName: 'Test',
                        role: UserRole.USER,
                        tenantId: String(testTenant._id)
                    })
                ).rejects.toThrow();
            }
        });

        it('should sanitize XSS in user inputs', () => {
            const maliciousInputs = [
                '<script>alert("xss")</script>',
                'javascript:alert("xss")',
                '<img src="x" onerror="alert(1)">',
                '<svg onload="alert(1)">'
            ];

            maliciousInputs.forEach(input => {
                const sanitized = ValidationService.sanitizeInput(input);
                expect(sanitized).not.toContain('<script>');
                expect(sanitized).not.toContain('javascript:');
                expect(sanitized).not.toContain('onerror=');
                expect(sanitized).not.toContain('onload=');
            });
        });
    });

    describe('Session Security', () => {
        it('should invalidate sessions on password change', async () => {
            const user = await User.create({
                email: 'session@test.com',
                password: 'TestPassword123!',
                firstName: 'Session',
                lastName: 'Test',
                role: UserRole.USER,
                tenantId: String(testTenant._id),
                isActive: true
            });

            const tokens = AuthService.generateTokens(user);
            await AuthService.storeRefreshToken(String(user._id), tokens.refreshToken);

            // Change password
            user.password = 'NewPassword123!';
            await user.save();

            // Session should be invalidated
            await UserService.invalidateUserSessions(String(user._id));

            const refreshTokenRecord = await RefreshToken.findOne({
                userId: user._id,
                token: tokens.refreshToken,
                isRevoked: false
            });

            expect(refreshTokenRecord).toBeNull();
        });
    });

    describe('Login Security', () => {
        let testUser: IUser;

        beforeEach(async () => {
            testUser = await User.create({
                email: 'login@test.com',
                password: 'TestPassword123!',
                firstName: 'Login',
                lastName: 'Test',
                role: UserRole.USER,
                tenantId: String(testTenant._id),
                isActive: true
            });
        });

        it('should login successfully with valid credentials', async () => {
            const loginData = {
                email: 'login@test.com',
                password: 'TestPassword123!'
            };

            const mockReq = {
                body: loginData,
                ip: '192.168.1.1'
            } as any;

            const mockRes = {
                json: jest.fn()
            } as any;

            const mockNext = jest.fn();

            await AuthController.login(mockReq, mockRes, mockNext);

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

        it('should reject invalid credentials', async () => {
            const loginData = {
                email: 'login@test.com',
                password: 'WrongPassword123!'
            };

            const mockReq = {
                body: loginData,
                ip: '192.168.1.1'
            } as any;

            const mockRes = {} as any;
            const mockNext = jest.fn();

            await AuthController.login(mockReq, mockRes, mockNext);

            expect(mockNext).toHaveBeenCalledWith(expect.any(AppError));
        });

        it('should reject login for inactive users', async () => {
            await User.findByIdAndUpdate(testUser._id, { isActive: false });

            const loginData = {
                email: 'login@test.com',
                password: 'TestPassword123!'
            };

            const mockReq = {
                body: loginData,
                ip: '192.168.1.1'
            } as any;

            const mockRes = {} as any;
            const mockNext = jest.fn();

            await AuthController.login(mockReq, mockRes, mockNext);

            expect(mockNext).toHaveBeenCalledWith(expect.any(AppError));
        });
    });
});
