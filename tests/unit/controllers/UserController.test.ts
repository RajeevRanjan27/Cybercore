// ============================================================================
// tests/unit/controllers/UserController.test.ts
// ============================================================================

import { UserController } from '@/api/users/controller';
import { Request, Response } from 'express';
import {Tenant} from "../../../src/core/models/Tenant";
import {User} from "../../../src/core/models/User";
import {UserRole} from "../../../src/core/constants/roles";
import mongoose from "mongoose";
import {AppError} from "../../../src/core/middlewares/errorHandler";

describe('UserController', () => {
    let testTenant: any;
    let testUsers: any[];
    let adminUser: any;

    beforeEach(async () => {
        testTenant = await Tenant.create({
            name: 'User Controller Test Tenant',
            domain: 'usertest.com',
            subdomain: 'usertest',
            isDefault: true
        });

        adminUser = await User.create({
            email: 'admin@usertest.com',
            password: 'AdminPassword123!',
            firstName: 'Admin',
            lastName: 'User',
            role: UserRole.SUPER_ADMIN,
            tenantId: testTenant._id,
            isActive: true
        });

        testUsers = await Promise.all([
            User.create({
                email: 'user1@usertest.com',
                password: 'Password123!',
                firstName: 'User',
                lastName: 'One',
                role: UserRole.USER,
                tenantId: testTenant._id,
                isActive: true
            }),
            User.create({
                email: 'user2@usertest.com',
                password: 'Password123!',
                firstName: 'User',
                lastName: 'Two',
                role: UserRole.USER,
                tenantId: testTenant._id,
                isActive: false
            })
        ]);
    });

    describe('getUsers', () => {
        it('should return paginated user list for admin', async () => {
            const mockReq = {
                user: {
                    userId: adminUser._id.toString(),
                    role: UserRole.SUPER_ADMIN,
                    tenantId: testTenant._id.toString(),
                    permissions: ['user:read']
                },
                query: { page: '1', limit: '10' }
            } as any;

            const mockRes = {
                json: jest.fn()
            } as any;

            const mockNext = jest.fn();

            await UserController.getUsers(mockReq, mockRes, mockNext);

            expect(mockRes.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    success: true,
                    data: expect.objectContaining({
                        users: expect.any(Array),
                        pagination: expect.objectContaining({
                            page: 1,
                            limit: 10,
                            total: expect.any(Number)
                        })
                    })
                })
            );
        });

        it('should filter users by search query', async () => {
            const mockReq = {
                user: {
                    userId: adminUser._id.toString(),
                    role: UserRole.SUPER_ADMIN,
                    tenantId: testTenant._id.toString(),
                    permissions: ['user:read']
                },
                query: { search: 'User One' }
            } as any;

            const mockRes = {
                json: jest.fn()
            } as any;

            const mockNext = jest.fn();

            await UserController.getUsers(mockReq, mockRes, mockNext);

            expect(mockRes.json).toHaveBeenCalled();
            const response = mockRes.json.mock.calls[0][0];
            expect(response.data.users.some((u: any) => u.firstName === 'User' && u.lastName === 'One')).toBe(true);
        });

        it('should respect RBAC filtering for tenant admin', async () => {
            const tenantAdmin = await User.create({
                email: 'tenantadmin@usertest.com',
                password: 'Password123!',
                firstName: 'Tenant',
                lastName: 'Admin',
                role: UserRole.TENANT_ADMIN,
                tenantId: testTenant._id,
                isActive: true
            });
            const mockReq = {
                user: {
                    userId: String(tenantAdmin._id),
                    role: UserRole.TENANT_ADMIN,
                    tenantId: testTenant._id.toString(),
                    permissions: ['user:read']
                },
                query: {}
            } as any;

            const mockRes = {
                json: jest.fn()
            } as any;

            const mockNext = jest.fn();

            await UserController.getUsers(mockReq, mockRes, mockNext);

            expect(mockRes.json).toHaveBeenCalled();
            const response = mockRes.json.mock.calls[0][0];
            expect(response.success).toBe(true);
            // Should only see users from same tenant
            expect(response.data.users.every((u: any) => u.tenantId.toString() === testTenant._id.toString())).toBe(true);
        });
    });

    describe('getUserById', () => {
        it('should return user details for authorized request', async () => {
            const mockReq = {
                user: {
                    userId: adminUser._id.toString(),
                    role: UserRole.SUPER_ADMIN,
                    tenantId: testTenant._id.toString(),
                    permissions: ['user:read']
                },
                params: { id: testUsers[0]._id.toString() },
                query: {}
            } as any;

            const mockRes = {
                json: jest.fn()
            } as any;

            const mockNext = jest.fn();

            await UserController.getUserById(mockReq, mockRes, mockNext);

            expect(mockRes.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    success: true,
                    data: expect.objectContaining({
                        user: expect.objectContaining({
                            id: testUsers[0]._id.toString(),
                            email: testUsers[0].email
                        })
                    })
                })
            );
        });

        it('should return 404 for non-existent user', async () => {
            const mockReq = {
                user: {
                    userId: adminUser._id.toString(),
                    role: UserRole.SUPER_ADMIN,
                    tenantId: testTenant._id.toString(),
                    permissions: ['user:read']
                },
                params: { id: new mongoose.Types.ObjectId().toString() },
                query: {}
            } as any;

            const mockRes = {} as any;
            const mockNext = jest.fn();

            await UserController.getUserById(mockReq, mockRes, mockNext);

            expect(mockNext).toHaveBeenCalledWith(expect.any(AppError));
        });
    });

    describe('updateUser', () => {
        it('should update user successfully', async () => {
            const updateData = {
                firstName: 'Updated',
                lastName: 'Name'
            };

            const mockReq = {
                user: {
                    userId: adminUser._id.toString(),
                    role: UserRole.SUPER_ADMIN,
                    tenantId: testTenant._id.toString(),
                    permissions: ['user:update']
                },
                params: { id: testUsers[0]._id.toString() },
                body: updateData
            } as any;

            const mockRes = {
                json: jest.fn()
            } as any;

            const mockNext = jest.fn();

            await UserController.updateUser(mockReq, mockRes, mockNext);

            expect(mockRes.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    success: true,
                    data: expect.objectContaining({
                        user: expect.objectContaining({
                            firstName: 'Updated',
                            lastName: 'Name'
                        })
                    })
                })
            );
        });

        it('should prevent unauthorized role changes', async () => {
            const regularUser = await User.create({
                email: 'regular@usertest.com',
                password: 'Password123!',
                firstName: 'Regular',
                lastName: 'User',
                role: UserRole.USER,
                tenantId: testTenant._id,
                isActive: true
            });
            const mockReq = {
                user: {
                    userId: String(regularUser._id),
                    role: UserRole.USER,
                    tenantId: testTenant._id.toString(),
                    permissions: ['profile:update']
                },
                params: { id: testUsers[0]._id.toString() },
                body: { role: UserRole.SUPER_ADMIN }
            } as any;

            const mockRes = {} as any;
            const mockNext = jest.fn();

            await UserController.updateUser(mockReq, mockRes, mockNext);

            expect(mockNext).toHaveBeenCalledWith(expect.any(AppError));
        });

        it('should prevent self role modification', async () => {
            const mockReq = {
                user: {
                    userId: testUsers[0]._id.toString(),
                    role: UserRole.USER,
                    tenantId: testTenant._id.toString(),
                    permissions: ['profile:update']
                },
                params: { id: testUsers[0]._id.toString() },
                body: { role: UserRole.TENANT_ADMIN }
            } as any;

            const mockRes = {
                json: jest.fn()
            } as any;

            const mockNext = jest.fn();

            await UserController.updateUser(mockReq, mockRes, mockNext);

            // Should succeed but role change should be ignored
            expect(mockRes.json).toHaveBeenCalled();
            const updatedUser = await User.findById(testUsers[0]._id);
            expect(updatedUser?.role).toBe(UserRole.USER); // Role unchanged
        });
    });

    describe('deleteUser', () => {
        it('should soft delete user successfully', async () => {
            const mockReq = {
                user: {
                    userId: adminUser._id.toString(),
                    role: UserRole.SUPER_ADMIN,
                    tenantId: testTenant._id.toString(),
                    permissions: ['user:delete']
                },
                params: { id: testUsers[0]._id.toString() },
                body: { reason: 'Test deletion' }
            } as any;

            const mockRes = {
                json: jest.fn()
            } as any;

            const mockNext = jest.fn();

            await UserController.deleteUser(mockReq, mockRes, mockNext);

            expect(mockRes.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    success: true,
                    message: expect.stringContaining('deactivated successfully')
                })
            );

            const deletedUser = await User.findById(testUsers[0]._id);
            expect(deletedUser?.isActive).toBe(false);
        });

        it('should prevent self deletion', async () => {
            const mockReq = {
                user: {
                    userId: testUsers[0]._id.toString(),
                    role: UserRole.USER,
                    tenantId: testTenant._id.toString(),
                    permissions: ['user:delete']
                },
                params: { id: testUsers[0]._id.toString() },
                body: { reason: 'Self deletion attempt' }
            } as any;

            const mockRes = {} as any;
            const mockNext = jest.fn();

            await UserController.deleteUser(mockReq, mockRes, mockNext);

            expect(mockNext).toHaveBeenCalledWith(
                expect.objectContaining({
                    message: 'Cannot delete your own account'
                })
            );
        });
    });

    describe('bulkUserOperation', () => {
        it('should perform bulk activation', async () => {
            // Deactivate users first
            await User.updateMany(
                { _id: { $in: testUsers.map(u => u._id) } },
                { isActive: false }
            );

            const mockReq = {
                user: {
                    userId: adminUser._id.toString(),
                    role: UserRole.SUPER_ADMIN,
                    tenantId: testTenant._id.toString(),
                    permissions: ['user:bulkEdit']
                },
                body: {
                    userIds: testUsers.map(u => u._id.toString()),
                    operation: 'activate',
                    data: { reason: 'Bulk activation test' }
                }
            } as any;

            const mockRes = {
                json: jest.fn()
            } as any;

            const mockNext = jest.fn();

            await UserController.bulkUserOperation(mockReq, mockRes, mockNext);

            expect(mockRes.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    success: true,
                    data: expect.objectContaining({
                        successful: testUsers.length,
                        failed: 0
                    })
                })
            );
        });

        it('should handle mixed success/failure in bulk operations', async () => {
            const validUserId = testUsers[0]._id.toString();
            const invalidUserId = new mongoose.Types.ObjectId().toString();

            const mockReq = {
                user: {
                    userId: adminUser._id.toString(),
                    role: UserRole.SUPER_ADMIN,
                    tenantId: testTenant._id.toString(),
                    permissions: ['user:bulkEdit']
                },
                body: {
                    userIds: [validUserId, invalidUserId],
                    operation: 'activate',
                    data: { reason: 'Mixed result test' }
                }
            } as any;

            const mockRes = {
                json: jest.fn()
            } as any;

            const mockNext = jest.fn();

            await UserController.bulkUserOperation(mockReq, mockRes, mockNext);

            expect(mockRes.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    success: true,
                    data: expect.objectContaining({
                        successful: expect.any(Number),
                        failed: expect.any(Number)
                    })
                })
            );
        });
    });

    describe('getUserStats', () => {
        it('should return user statistics for admin', async () => {
            const mockReq = {
                user: {
                    userId: adminUser._id.toString(),
                    role: UserRole.SUPER_ADMIN,
                    tenantId: testTenant._id.toString(),
                    permissions: ['analytics:read']
                },
                query: { period: '30d' }
            } as any;

            const mockRes = {
                json: jest.fn()
            } as any;

            const mockNext = jest.fn();

            await UserController.getUserStats(mockReq, mockRes, mockNext);

            expect(mockRes.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    success: true,
                    data: expect.objectContaining({
                        totalUsers: expect.any(Number),
                        activeUsers: expect.any(Number),
                        inactiveUsers: expect.any(Number),
                        usersByRole: expect.any(Object)
                    })
                })
            );
        });

        it('should deny access to non-admin users', async () => {
            const mockReq = {
                user: {
                    userId: testUsers[0]._id.toString(),
                    role: UserRole.USER,
                    tenantId: testTenant._id.toString(),
                    permissions: ['user:read']
                },
                query: { period: '30d' }
            } as any;

            const mockRes = {} as any;
            const mockNext = jest.fn();

            await UserController.getUserStats(mockReq, mockRes, mockNext);

            expect(mockNext).toHaveBeenCalledWith(expect.any(AppError));
        });
    });
});
