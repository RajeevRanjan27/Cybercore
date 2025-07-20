// ============================================================================
// tests/unit/core/services/AuditService.test.ts
// ============================================================================

import { AuditService } from '@/core/services/AuditService';
import { IUser } from '@/core/models/User';
import { ITenant } from '@/core/models/Tenant';
import { UserRole } from '@/core/constants/roles';
import mongoose from 'mongoose';
import { AuditLog } from '@/core/models/AuditLog';

// --- Advanced Mocking Setup for Mongoose Model ---

// Create mock functions for all static and instance methods we'll use.
const mockSave = jest.fn().mockResolvedValue(true);
const mockAggregate = jest.fn().mockResolvedValue([]);
const mockCountDocuments = jest.fn().mockResolvedValue(0);
const mockDeleteMany = jest.fn().mockResolvedValue({ deletedCount: 0 });
const mockFind = jest.fn().mockResolvedValue([]);

// Mock the entire module.
// The key is to make the exported 'AuditLog' a mock constructor (jest.fn()).
// This allows us to both instantiate it (new AuditLog()) and attach static mocks to it.
jest.mock('@/core/models/AuditLog', () => ({
    AuditLog: jest.fn().mockImplementation(() => ({
        save: mockSave, // Mock the instance 'save' method
    })),
}));

// Cast the mocked AuditLog to access its static methods for mocking
const MockedAuditLog = AuditLog as jest.Mocked<typeof AuditLog> & {
    aggregate: jest.Mock;
    countDocuments: jest.Mock;
    deleteMany: jest.Mock;
    find: jest.Mock;
};

describe('AuditService', () => {
    let testUser: Partial<IUser>;
    let testTenant: Partial<ITenant>;

    beforeEach(() => {
        // Reset all mocks before each test to ensure isolation
        jest.clearAllMocks();

        // Re-assign the static method mocks before each test
        MockedAuditLog.aggregate = mockAggregate;
        MockedAuditLog.countDocuments = mockCountDocuments;
        MockedAuditLog.deleteMany = mockDeleteMany;
        MockedAuditLog.find = mockFind;

        testTenant = {
            _id: new mongoose.Types.ObjectId(),
            name: 'Test Tenant',
        };

        testUser = {
            _id: new mongoose.Types.ObjectId(),
            email: 'test@example.com',
            firstName: 'Test',
            lastName: 'User',
            role: UserRole.USER,
            tenantId: testTenant._id as mongoose.Types.ObjectId,
        };
    });

    describe('logActivity', () => {
        it('should create an audit log entry with correct details', async () => {
            const details = { target: 'user-profile', changes: ['firstName'] };
            const context = {
                ipAddress: '127.0.0.1',
                userAgent: 'jest-test',
                tenantId: testTenant._id!.toString(),
            };

            await AuditService.logActivity(
                testUser._id!.toString(),
                'USER_UPDATE',
                details,
                context
            );

            // Check that the constructor was called with the right data
            expect(MockedAuditLog).toHaveBeenCalledWith(expect.objectContaining({
                userId: testUser._id,
                action: 'USER_UPDATE',
                ipAddress: '127.0.0.1'
            }));
            // Check that the save method was called on the new instance
            expect(mockSave).toHaveBeenCalled();
        });

        it('should sanitize sensitive details before logging', async () => {
            const details = {
                password: 'new-password',
                token: 'some-token',
                other: 'info',
            };
            const context = { ipAddress: '127.0.0.1' };

            await AuditService.logActivity(
                testUser._id!.toString(),
                'PASSWORD_RESET',
                details,
                context
            );

            // Check the data passed to the constructor
            // FIX: Cast the original 'AuditLog' import, which is the mock constructor itself.
            const constructorCallArg = (AuditLog as unknown as jest.Mock).mock.calls[0][0];
            expect(constructorCallArg.details.password).toBe('[REDACTED]');
            expect(constructorCallArg.details.token).toBeUndefined();
            expect(mockSave).toHaveBeenCalled();
        });
    });

    describe('getUserActivity', () => {
        it('should build and execute a correct aggregation pipeline for user activity', async () => {
            await AuditService.getUserActivity(testUser._id!.toString());

            expect(MockedAuditLog.aggregate).toHaveBeenCalled();
            expect(MockedAuditLog.countDocuments).toHaveBeenCalled();
        });

        it('should exclude sensitive actions by default', async () => {
            await AuditService.getUserActivity(testUser._id!.toString());

            const matchQuery = MockedAuditLog.aggregate.mock.calls[0][0][0].$match;
            expect(matchQuery.action.$nin).toBeDefined();
        });

        it('should include sensitive actions when requested', async () => {
            await AuditService.getUserActivity(testUser._id!.toString(), {
                includeSensitive: true,
            });

            const matchQuery = MockedAuditLog.aggregate.mock.calls[0][0][0].$match;
            expect(matchQuery.action?.$nin).toBeUndefined();
        });
    });

    describe('getSystemAuditLogs', () => {
        it('should apply tenant filtering for non-super-admins', async () => {
            const tenantAdmin = {
                userId: 'tenant-admin-id',
                role: UserRole.TENANT_ADMIN,
                tenantId: new mongoose.Types.ObjectId().toString(),
                permissions: [],
            };

            await AuditService.getSystemAuditLogs(tenantAdmin);

            const matchQuery = MockedAuditLog.aggregate.mock.calls[0][0][0].$match;
            expect(matchQuery.tenantId).toBeInstanceOf(mongoose.Types.ObjectId);
            expect(matchQuery.tenantId.toString()).toBe(tenantAdmin.tenantId);
        });

        it('should not apply tenant filtering for super-admins', async () => {
            const superAdmin = {
                userId: 'super-admin-id',
                role: UserRole.SUPER_ADMIN,
                tenantId: 'any-tenant',
                permissions: [],
            };

            await AuditService.getSystemAuditLogs(superAdmin);

            const matchQuery = MockedAuditLog.aggregate.mock.calls[0][0][0].$match;
            expect(matchQuery.tenantId).toBeUndefined();
        });
    });
});
