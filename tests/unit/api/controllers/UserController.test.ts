// ============================================================================
// tests/unit/api/controllers/UserController.test.ts
// ============================================================================

import { Request, Response, NextFunction } from 'express';
import { UserController } from '@/api/users/controller';
import { UserService } from '@/core/services/UserService';
import { RBACService } from '@/core/services/RBACService';
import { CacheService } from '@/core/services/CacheService';
import { AuditService } from '@/core/services/AuditService';
import { NotificationService } from '@/core/services/NotificationService';
import { AppError } from '@/core/middlewares/errorHandler';
import { UserRole } from '@/core/constants/roles';
import mongoose from 'mongoose';
import {User} from "@/core/models/User";

// Mock all services
jest.mock('@/core/services/UserService');
jest.mock('@/core/services/RBACService');
jest.mock('@/core/services/CacheService');
jest.mock('@/core/services/AuditService');
jest.mock('@/core/services/NotificationService');
jest.mock('@/core/models/User'); // Also mock the model to control its static methods

const mockedUserService = UserService as jest.Mocked<typeof UserService>;
const mockedRBACService = RBACService as jest.Mocked<typeof RBACService>;
const mockedCacheService = CacheService as jest.Mocked<typeof CacheService>;
const mockedUser = User as jest.Mocked<typeof User>;

describe('UserController', () => {
    let mockRequest: Partial<Request>;
    let mockResponse: Partial<Response>;
    let nextFunction: NextFunction;
    let mockAdminUser: any;
    let mockRegularUser: any;

    beforeEach(() => {
        jest.clearAllMocks();

        mockRequest = {
            query: {},
            params: {},
            body: {},
        };

        mockResponse = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn(),
            send: jest.fn(),
            header: jest.fn().mockReturnThis(),
        };

        nextFunction = jest.fn();

        mockAdminUser = {
            userId: 'admin-id',
            role: UserRole.SUPER_ADMIN,
            tenantId: 'tenant-id',
            permissions: ['user:read', 'user:update', 'user:delete', 'user:bulkEdit', 'analytics:read'],
        };

        mockRegularUser = {
            _id: new mongoose.Types.ObjectId(),
            firstName: 'Test',
            lastName: 'User',
            email: 'test@example.com',
            role: UserRole.USER,
            isActive: true,
            toObject: () => ({...mockRegularUser}),
        };
    });

    describe('getUsers', () => {
        it('should return a paginated list of users', async () => {
            (mockRequest as any).user = mockAdminUser;
            mockRequest.query = { page: '1', limit: '10' };

            (mockedUser.aggregate as jest.Mock).mockResolvedValue([mockRegularUser]);
            (mockedUser.countDocuments as jest.Mock).mockResolvedValue(1);
            mockedUserService.enhanceUserData.mockResolvedValue(mockRegularUser);

            await UserController.getUsers(mockRequest as Request, mockResponse as Response, nextFunction);

            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    success: true,
                    data: expect.objectContaining({
                        users: expect.any(Array),
                        pagination: expect.any(Object),
                    }),
                })
            );
        });
    });

    describe('getUserById', () => {
        it('should return a single user with enhanced data', async () => {
            (mockRequest as any).user = mockAdminUser;
            mockRequest.params = { id: mockRegularUser._id.toString() };

            (mockedUser.aggregate as jest.Mock).mockResolvedValue([mockRegularUser]);
            mockedUserService.enhanceUserData.mockResolvedValue(mockRegularUser);

            await UserController.getUserById(mockRequest as Request, mockResponse as Response, nextFunction);

            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    success: true,
                    data: expect.objectContaining({ user: mockRegularUser }),
                })
            );
        });

        it('should return 404 if user not found', async () => {
            (mockRequest as any).user = mockAdminUser;
            mockRequest.params = { id: new mongoose.Types.ObjectId().toString() };
            (mockedUser.aggregate as jest.Mock).mockResolvedValue([]);

            await UserController.getUserById(mockRequest as Request, mockResponse as Response, nextFunction);

            expect(nextFunction).toHaveBeenCalledWith(expect.any(AppError));
            const error = (nextFunction as jest.Mock).mock.calls[0][0];
            expect(error.statusCode).toBe(404);
        });
    });

    describe('updateUser', () => {
        it('should update a user successfully', async () => {
            (mockRequest as any).user = mockAdminUser;
            mockRequest.params = { id: mockRegularUser._id.toString() };
            mockRequest.body = { firstName: 'Updated' };

            (mockedUser.findOne as jest.Mock).mockResolvedValue({
                ...mockRegularUser,
                save: jest.fn().mockResolvedValue(true)
            });
            (mockedUser.findOneAndUpdate as jest.Mock).mockReturnValue({
                select: jest.fn().mockReturnThis(),
                populate: jest.fn().mockResolvedValue({ ...mockRegularUser, firstName: 'Updated' })
            });
            mockedUserService.detectChanges.mockReturnValue([{ field: 'firstName', oldValue: 'Test', newValue: 'Updated', timestamp: new Date() }]);
            mockedUserService.enhanceUserData.mockResolvedValue({ ...mockRegularUser, firstName: 'Updated' });

            await UserController.updateUser(mockRequest as Request, mockResponse as Response, nextFunction);

            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    success: true,
                    message: 'User updated successfully',
                })
            );
            expect(mockedCacheService.invalidateUserCaches).toHaveBeenCalledWith(mockRegularUser._id.toString());
        });
    });

    describe('deleteUser', () => {
        it('should soft delete a user', async () => {
            (mockRequest as any).user = mockAdminUser;
            mockRequest.params = { id: mockRegularUser._id.toString() };
            mockRequest.body = { reason: 'Test deletion' };

            (mockedUser.findOne as jest.Mock).mockResolvedValue(mockRegularUser);
            (mockedUser.findOneAndUpdate as jest.Mock).mockReturnValue({
                select: jest.fn().mockResolvedValue({ ...mockRegularUser, isActive: false })
            });
            mockedRBACService.hasRoleLevel.mockReturnValue(true);

            await UserController.deleteUser(mockRequest as Request, mockResponse as Response, nextFunction);

            expect(mockResponse.json).toHaveBeenCalledWith(expect.objectContaining({ success: true }));
            expect(mockedUserService.cleanupUserSessions).toHaveBeenCalledWith(mockRegularUser._id.toString());
        });

        it('should prevent self-deletion', async () => {
            (mockRequest as any).user = { ...mockAdminUser, userId: mockRegularUser._id.toString() };
            mockRequest.params = { id: mockRegularUser._id.toString() };

            await UserController.deleteUser(mockRequest as Request, mockResponse as Response, nextFunction);

            expect(nextFunction).toHaveBeenCalledWith(expect.any(AppError));
            const error = (nextFunction as jest.Mock).mock.calls[0][0];
            expect(error.message).toBe('Cannot delete your own account');
        });
    });

    describe('bulkUserOperation', () => {
        it('should perform a bulk operation successfully', async () => {
            (mockRequest as any).user = mockAdminUser;
            mockRequest.body = {
                userIds: [mockRegularUser._id.toString()],
                operation: 'activate',
                data: { reason: 'Bulk test' },
            };

            (mockedUser.find as jest.Mock).mockResolvedValue([mockRegularUser]);
            mockedRBACService.canAccess.mockReturnValue(true);
            mockedUserService.executeBulkOperation.mockResolvedValue({
                success: [{ userId: mockRegularUser._id.toString(), email: mockRegularUser.email, operation: 'activate', result: {} }],
                failures: [],
            });

            await UserController.bulkUserOperation(mockRequest as Request, mockResponse as Response, nextFunction);

            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    success: true,
                    data: expect.objectContaining({ successful: 1, failed: 0 }),
                })
            );
        });
    });

    describe('getUserStats', () => {
        it('should return user statistics for an authorized user', async () => {
            (mockRequest as any).user = mockAdminUser;
            mockedRBACService.canAccess.mockReturnValue(true);
            mockedUserService.generateUserStatistics.mockResolvedValue({
                totalUsers: 100,
                activeUsers: 90,
                inactiveUsers: 10,
                usersByRole: { [UserRole.USER]: 90, [UserRole.TENANT_ADMIN]: 9, [UserRole.SUPER_ADMIN]: 1 },
                usersByTenant: { 'tenant-id': 100 },
                recentSignups: 5,
                averageUsersPerTenant: 100,
                growthRate: 10,
                registrationTrend: [{ date: '2023-01-01', count: 10 }],
                loginActivity: [{ date: '2023-01-01', count: 50 }],
            });

            await UserController.getUserStats(mockRequest as Request, mockResponse as Response, nextFunction);

            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    success: true,
                    data: expect.objectContaining({ totalUsers: 100 }),
                })
            );
        });

        it('should deny access if user lacks analytics:read permission', async () => {
            (mockRequest as any).user = { ...mockAdminUser, permissions: [] }; // No permissions
            mockedRBACService.canAccess.mockReturnValue(false);

            await UserController.getUserStats(mockRequest as Request, mockResponse as Response, nextFunction);

            expect(nextFunction).toHaveBeenCalledWith(expect.any(AppError));
            const error = (nextFunction as jest.Mock).mock.calls[0][0];
            expect(error.statusCode).toBe(403);
        });
    });
});
