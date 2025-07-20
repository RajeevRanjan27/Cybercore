// ============================================================================
// tests/performance/auth.performance.test.ts
// ============================================================================

import {AuthService} from "../../src/core/services/AuthService";
import {AuthController} from "../../src/api/auth/controller";
import {UserRole} from "../../src/core/constants/roles";
import {ITenant, Tenant} from "../../src/core/models/Tenant";
import {IUser, User} from "../../src/core/models/User";

describe('Auth Performance Tests', () => {
    let testTenant: ITenant;
    let users: IUser[] = [];

    beforeAll(async () => {

        // Clear previous test data
        await User.deleteMany({});
        await Tenant.deleteMany({});

        testTenant = await Tenant.create({
            name: 'Performance Test Tenant',
            domain: 'perf.com',
            subdomain: 'perf',
            isDefault: true
        });

        // Create multiple users for performance testing
        const userPromises = Array.from({ length: 100 }, (_, i) =>
            User.create({
                email: `user${i}@perf.com`,
                password: 'TestPassword123!',
                firstName: `User${i}`,
                lastName: 'Test',
                role: UserRole.USER,
                tenantId: testTenant._id,
                isActive: true
            })
        );

        users = await Promise.all(userPromises);
    }, 3000); // Increase timeout for beforeAll hook

    it('should generate tokens efficiently', () => {
        const startTime = Date.now();

        for (let i = 0; i < 1000; i++) {
            AuthService.generateTokens(users[i % users.length]);
        }

        const endTime = Date.now();
        const duration = endTime - startTime;

        // Should generate 1000 tokens in less than 1 second
        expect(duration).toBeLessThan(1000);
    });

    it('should verify tokens efficiently', () => {
        const tokens = users.slice(0, 100).map(user =>
            AuthService.generateTokens(user).accessToken
        );

        const startTime = Date.now();

        tokens.forEach(token => {
            AuthService.verifyAccessToken(token);
        });

        const endTime = Date.now();
        const duration = endTime - startTime;

        // Should verify 100 tokens in less than 100ms
        expect(duration).toBeLessThan(100);
    });

    it('should handle concurrent authentication requests', async () => {
        const loginPromises = users.slice(0, 50).map(async (user, index) => {
            const mockReq = {
                body: {
                    email: user.email,
                    password: 'TestPassword123!'
                },
                ip: `192.168.1.${index + 1}`
            } as any;

            const mockRes = {
                json: jest.fn()
            } as any;

            const mockNext = jest.fn();

            return AuthController.login(mockReq, mockRes, mockNext);
        });

        const startTime = Date.now();
        await Promise.all(loginPromises);
        const endTime = Date.now();
        const duration = endTime - startTime;

        // Should handle 50 concurrent logins in less than 2 seconds
        expect(duration).toBeLessThan(2000);
    },10000);// Increase timeout for this specific test

});
