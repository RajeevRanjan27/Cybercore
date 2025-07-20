// ============================================================================
// tests/integration/users.integration.test.ts
// ============================================================================

import request from 'supertest';
import express from 'express';
import { userRoutes } from '@/api/users/routes';
import { errorHandler } from '@/core/middlewares/errorHandler';
import mongoose from "mongoose";
import { logger } from "../../src/core/infra/logger";
import { User, IUser } from "../../src/core/models/User";
import { UserRole } from "../../src/core/constants/roles";
import { AuthService } from "../../src/core/services/AuthService";
import { Tenant, ITenant } from "../../src/core/models/Tenant";
import { RefreshToken } from '../../src/core/models/RefreshToken';

describe('Users Integration Tests', () => {
    let app: express.Application;
    let testTenant: ITenant;
    let adminUser: IUser;
    let adminToken: string;
    let regularUser: IUser;
    let regularToken: string;

    // Setup express app once for all tests
    beforeAll(() => {
        app = express();
        app.use(express.json());
        // Assuming auth middleware is applied within userRoutes
        app.use('/users', userRoutes);
        app.use(errorHandler);
    });

    // Clean and setup database before each test
    beforeEach(async () => {
        await User.deleteMany({});
        await Tenant.deleteMany({});
        await RefreshToken.deleteMany({});

        testTenant = await Tenant.create({
            name: 'Users Integration Test',
            domain: 'usersint.com',
            subdomain: 'usersint',
            isDefault: true
        });

        adminUser = await User.create({
            email: 'admin@usersint.com',
            password: 'AdminPassword123!',
            firstName: 'Admin',
            lastName: 'User',
            role: UserRole.SUPER_ADMIN,
            tenantId: String(testTenant._id),
            isActive: true
        });

        regularUser = await User.create({
            email: 'user@usersint.com',
            password: 'UserPassword123!',
            firstName: 'Regular',
            lastName: 'User',
            role: UserRole.USER,
            tenantId: String(testTenant._id),
            isActive: true
        });

        adminToken = AuthService.generateTokens(adminUser).accessToken;
        regularToken = AuthService.generateTokens(regularUser).accessToken;
    });

    // Final cleanup after all tests are done
    afterAll(async () => {
        await User.deleteMany({});
        await Tenant.deleteMany({});
        await RefreshToken.deleteMany({});
        await mongoose.disconnect();
    });

    describe('GET /users', () => {
        it('should return user list for admin', async () => {
            const response = await request(app)
                .get('/users')
                .set('Authorization', `Bearer ${adminToken}`)
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.users).toBeDefined();
            expect(response.body.data.pagination).toBeDefined();
            expect(Array.isArray(response.body.data.users)).toBe(true);
        });

        it('should support pagination', async () => {
            const response = await request(app)
                .get('/users?page=1&limit=1')
                .set('Authorization', `Bearer ${adminToken}`)
                .expect(200);

            expect(response.body.data.pagination.page).toBe(1);
            expect(response.body.data.pagination.limit).toBe(1);
            expect(response.body.data.users.length).toBeLessThanOrEqual(1);
        });

        it('should support search functionality', async () => {
            const response = await request(app)
                .get('/users?search=Admin')
                .set('Authorization', `Bearer ${adminToken}`)
                .expect(200);

            expect(response.body.success).toBe(true);
            const adminFound = response.body.data.users.some((u: any) =>
                u.firstName === 'Admin'
            );
            expect(adminFound).toBe(true);
        });

        it('should support role filtering', async () => {
            const response = await request(app)
                .get(`/users?role=${UserRole.SUPER_ADMIN}`)
                .set('Authorization', `Bearer ${adminToken}`)
                .expect(200);

            expect(response.body.data.users.every((u: any) =>
                u.role === UserRole.SUPER_ADMIN
            )).toBe(true);
        });

        it('should deny access to non-admin users', async () => {
            await request(app)
                .get('/users')
                .set('Authorization', `Bearer ${regularToken}`)
                .expect(403);
        });
    });

    describe('GET /users/:id', () => {
        it('should return user details for admin', async () => {
            const response = await request(app)
                .get(`/users/${regularUser._id}`)
                .set('Authorization', `Bearer ${adminToken}`)
                .expect(200);

            expect(response.body.success).toBe(true);

            expect(response.body.data.user.id).toBe(String(regularUser._id));
            expect(response.body.data.user.email).toBe(regularUser.email);
        });

        it('should allow users to view their own profile', async () => {
            const response = await request(app)
                .get(`/users/${regularUser._id}`)
                .set('Authorization', `Bearer ${regularToken}`)
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.user.id).toBe(String(regularUser._id));
        });

        it('should prevent users from viewing other profiles', async () => {
            await request(app)
                .get(`/users/${adminUser._id}`)
                .set('Authorization', `Bearer ${regularToken}`)
                .expect(403);
        });


        it('should return 404 for non-existent user', async () => {
            const nonExistentId = new mongoose.Types.ObjectId();
            await request(app)
                .get(`/users/${nonExistentId}`)
                .set('Authorization', `Bearer ${adminToken}`)
                .expect(404);
        });
    });

    describe('PUT /users/:id', () => {
        it('should update user successfully by admin', async () => {
            const updateData = {
                firstName: 'Updated',
                lastName: 'Name'
            };

            const response = await request(app)
                .put(`/users/${regularUser._id}`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send(updateData)
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.user.firstName).toBe('Updated');
            expect(response.body.data.user.lastName).toBe('Name');
        });

        it('should allow users to update their own profile', async () => {
            const updateData = {
                firstName: 'SelfUpdated'
            };

            const response = await request(app)
                .put(`/users/${regularUser._id}`)
                .set('Authorization', `Bearer ${regularToken}`)
                .send(updateData)
                .expect(200);

            expect(response.body.data.user.firstName).toBe('SelfUpdated');
        });

        it('should prevent users from updating other profiles', async () => {
            const updateData = { firstName: 'MaliciousUpdate' };
            await request(app)
                .put(`/users/${adminUser._id}`)
                .set('Authorization', `Bearer ${regularToken}`)
                .send(updateData)
                .expect(403);
        });

        it('should validate update data', async () => {
            const invalidData = {
                email: 'invalid-email-format'
            };

            await request(app)
                .put(`/users/${regularUser._id}`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send(invalidData)
                .expect(400);
        });

        it('should prevent role escalation by regular users', async () => {
            const response = await request(app)
                .put(`/users/${regularUser._id}`)
                .set('Authorization', `Bearer ${regularToken}`)
                .send({ role: UserRole.SUPER_ADMIN })
                .expect(200);

            // Update should succeed but role should not change
            expect(response.body.data.user.role).toBe(UserRole.USER);
        });
    });

    describe('DELETE /users/:id', () => {
        it('should soft delete user by admin', async () => {
            const response = await request(app)
                .delete(`/users/${regularUser._id}`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send({ reason: 'Test deletion' })
                .expect(200);

            expect(response.body.success).toBe(true);

            // Verify user is soft deleted
            const deletedUser = await User.findById(regularUser._id);
            expect(deletedUser?.isActive).toBe(false);
        });

        it('should prevent regular users from deleting others', async () => {
            await request(app)
                .delete(`/users/${adminUser._id}`)
                .set('Authorization', `Bearer ${regularToken}`)
                .send({ reason: 'Malicious deletion attempt' })
                .expect(403);
        });

        it('should prevent self deletion', async () => {
            // Mock logger to avoid console noise during test
            jest.spyOn(logger, 'info').mockImplementation(() => ({} as any));
            jest.spyOn(logger, 'error').mockImplementation(() => ({} as any));

            await request(app)
                .delete(`/users/${adminUser._id}`)
                .set('Authorization', `Bearer ${adminToken}`)
                .send({ reason: 'Self deletion attempt' })
                .expect(400);
        });
    });
});
