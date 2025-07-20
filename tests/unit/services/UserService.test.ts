// ============================================================================
// tests/unit/services/UserService.test.ts
// ============================================================================

import { UserService } from '@/core/services/UserService';
import { ValidationService } from '@/core/services/ValidationService';
import {Tenant} from "../../../src/core/models/Tenant";
import {User} from "../../../src/core/models/User";
import {UserRole} from "../../../src/core/constants/roles";
import {AppError} from "../../../src/core/middlewares/errorHandler";

describe('UserService', () => {
    let testTenant: any;
    let testUser: any;
    let adminUser: any;

    beforeEach(async () => {
        testTenant = await Tenant.create({
            name: 'Test Tenant',
            domain: 'test.com',
            subdomain: 'test',
            isDefault: true
        });

        testUser = await User.create({
            email: 'user@test.com',
            password: 'TestPassword123!',
            firstName: 'Test',
            lastName: 'User',
            role: UserRole.USER,
            tenantId: testTenant._id,
            isActive: true
        });

        adminUser = await User.create({
            email: 'admin@test.com',
            password: 'AdminPassword123!',
            firstName: 'Admin',
            lastName: 'User',
            role: UserRole.SUPER_ADMIN,
            tenantId: testTenant._id,
            isActive: true
        });
    });

    describe('enhanceUserData', () => {
        it('should enhance user data with computed fields', async () => {
            const requestingUser = {
                userId: adminUser._id.toString(),
                role: UserRole.SUPER_ADMIN,
                tenantId: testTenant._id.toString(),
                permissions: ['user:read']
            };

            const enhanced = await UserService.enhanceUserData(testUser.toObject(), requestingUser);

            expect(enhanced.fullName).toBe('Test User');
            expect(enhanced.initials).toBe('TU');
            expect(enhanced).toHaveProperty('canEdit');
            expect(enhanced).toHaveProperty('canDelete');
            expect(enhanced).toHaveProperty('canViewSensitive');
        });

        it('should hide sensitive data for unauthorized users', async () => {
            const requestingUser = {
                userId: 'different-user-id',
                role: UserRole.USER,
                tenantId: 'different-tenant',
                permissions: ['user:read']
            };

            const enhanced = await UserService.enhanceUserData(testUser.toObject(), requestingUser);

            expect(enhanced.canViewSensitive).toBe(false);
        });
    });

    describe('detectChanges', () => {
        it('should detect changes between user data', () => {
            const updateData = {
                firstName: 'NewName',
                email: 'newemail@test.com',
                role: UserRole.TENANT_ADMIN
            };

            const changes = UserService.detectChanges(testUser, updateData);

            expect(changes).toHaveLength(3);
            expect(changes.find(c => c.field === 'firstName')).toBeTruthy();
            expect(changes.find(c => c.field === 'email')).toBeTruthy();
            expect(changes.find(c => c.field === 'role')).toBeTruthy();
        });

        it('should redact sensitive field values', () => {
            const updateData = { role: UserRole.SUPER_ADMIN };
            const changes = UserService.detectChanges(testUser, updateData);

            const roleChange = changes.find(c => c.field === 'role');
            expect(roleChange?.oldValue).toBe('[REDACTED]');
            expect(roleChange?.newValue).toBe('[REDACTED]');
        });
    });

    describe('sanitizeUpdateData', () => {
        it('should remove sensitive fields from update data', () => {
            const updateData = {
                firstName: 'New Name',
                password: 'newpassword',
                _id: 'malicious-id',
                __v: 1,
                createdAt: new Date()
            };

            const sanitized = UserService.sanitizeUpdateData(updateData, UserRole.USER);

            expect(sanitized.firstName).toBe('New Name');
            expect(sanitized.password).toBeUndefined();
            expect(sanitized._id).toBeUndefined();
            expect(sanitized.__v).toBeUndefined();
            expect(sanitized.createdAt).toBeUndefined();
        });

        it('should restrict role changes for non-admin users', () => {
            const updateData = {
                firstName: 'New Name',
                role: UserRole.SUPER_ADMIN,
                tenantId: 'new-tenant'
            };

            const sanitized = UserService.sanitizeUpdateData(updateData, UserRole.USER);

            expect(sanitized.firstName).toBe('New Name');
            expect(sanitized.role).toBeUndefined();
            expect(sanitized.tenantId).toBeUndefined();
        });
    });

    describe('executeBulkOperation', () => {
        let users: any[];

        beforeEach(async () => {
            users = await Promise.all([
                User.create({
                    email: 'bulk1@test.com',
                    password: 'Password123!',
                    firstName: 'Bulk',
                    lastName: 'User1',
                    role: UserRole.USER,
                    tenantId: testTenant._id,
                    isActive: true
                }),
                User.create({
                    email: 'bulk2@test.com',
                    password: 'Password123!',
                    firstName: 'Bulk',
                    lastName: 'User2',
                    role: UserRole.USER,
                    tenantId: testTenant._id,
                    isActive: true
                })
            ]);
        });

        it('should successfully activate users', async () => {
            // First deactivate users
            await User.updateMany(
                { _id: { $in: users.map(u => u._id) } },
                { isActive: false }
            );

            const result = await UserService.executeBulkOperation(
                users,
                'activate',
                { reason: 'Test activation' },
                adminUser._id.toString()
            );

            expect(result.success).toHaveLength(2);
            expect(result.failures).toHaveLength(0);

            const updatedUsers = await User.find({ _id: { $in: users.map(u => u._id) } });
            expect(updatedUsers.every(u => u.isActive)).toBe(true);
        });

        it('should handle role changes', async () => {
            const result = await UserService.executeBulkOperation(
                users,
                'changeRole',
                { role: UserRole.TENANT_ADMIN, reason: 'Promotion' },
                adminUser._id.toString()
            );

            expect(result.success).toHaveLength(2);
            expect(result.failures).toHaveLength(0);

            const updatedUsers = await User.find({ _id: { $in: users.map(u => u._id) } });
            expect(updatedUsers.every(u => u.role === UserRole.TENANT_ADMIN)).toBe(true);
        });

        it('should handle failures gracefully', async () => {
            // Create invalid operation
            const result = await UserService.executeBulkOperation(
                users,
                'changeRole',
                {}, // Missing required role
                adminUser._id.toString()
            );

            expect(result.failures).toHaveLength(2);
            expect(result.success).toHaveLength(0);
        });
    });

    describe('processProfileImage', () => {
        it('should validate file type', async () => {
            const invalidFile = {
                mimetype: 'text/plain',
                size: 1000,
                buffer: Buffer.from('test'),
                originalname: 'test.txt'
            } as Express.Multer.File;

            await expect(
                UserService.processProfileImage(invalidFile)
            ).rejects.toThrow(AppError);
        });

        it('should validate file size', async () => {
            const largeFile = {
                mimetype: 'image/jpeg',
                size: 10 * 1024 * 1024, // 10MB
                buffer: Buffer.from('test'),
                originalname: 'large.jpg'
            } as Express.Multer.File;

            await expect(
                UserService.processProfileImage(largeFile)
            ).rejects.toThrow(AppError);
        });

        it('should process valid image', async () => {
            const validFile = {
                mimetype: 'image/jpeg',
                size: 1024,
                buffer: Buffer.from('test-image-data'),
                originalname: 'profile.jpg'
            } as Express.Multer.File;

            const result = await UserService.processProfileImage(validFile);

            expect(result).toHaveProperty('url');
            expect(result).toHaveProperty('metadata');
            expect(result.metadata.format).toBe('jpeg');
        });
    });
});
