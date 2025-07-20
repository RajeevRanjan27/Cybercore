// ============================================================================
// tests/unit/core/services/RBACService.test.ts
// ============================================================================

import { RBACService } from '@/core/services/RBACService';
import {UserRole} from "@/core/constants/roles";

describe('RBACService', () => {
    describe('canAccess', () => {
        it('should allow super admin access to all permissions', () => {
            expect(RBACService.canAccess(UserRole.SUPER_ADMIN, 'user:create')).toBe(true);
            expect(RBACService.canAccess(UserRole.SUPER_ADMIN, 'tenant:create')).toBe(true);
            expect(RBACService.canAccess(UserRole.SUPER_ADMIN, 'system:read')).toBe(true);
        });

        it('should restrict user permissions appropriately', () => {
            expect(RBACService.canAccess(UserRole.USER, 'user:read')).toBe(true);
            expect(RBACService.canAccess(UserRole.USER, 'profile:read')).toBe(true);
            expect(RBACService.canAccess(UserRole.USER, 'tenant:create')).toBe(false);
            expect(RBACService.canAccess(UserRole.USER, 'user:delete')).toBe(false);
        });

        it('should handle tenant admin permissions correctly', () => {
            expect(RBACService.canAccess(UserRole.TENANT_ADMIN, 'user:create')).toBe(true);
            expect(RBACService.canAccess(UserRole.TENANT_ADMIN, 'user:update')).toBe(true);
            expect(RBACService.canAccess(UserRole.TENANT_ADMIN, 'tenant:create')).toBe(false);
            expect(RBACService.canAccess(UserRole.TENANT_ADMIN, 'system:read')).toBe(false);
        });
    });

    describe('hasRoleLevel', () => {
        it('should correctly compare role hierarchy', () => {
            expect(RBACService.hasRoleLevel(UserRole.SUPER_ADMIN, UserRole.USER)).toBe(true);
            expect(RBACService.hasRoleLevel(UserRole.SUPER_ADMIN, UserRole.TENANT_ADMIN)).toBe(true);
            expect(RBACService.hasRoleLevel(UserRole.TENANT_ADMIN, UserRole.USER)).toBe(true);
            expect(RBACService.hasRoleLevel(UserRole.USER, UserRole.TENANT_ADMIN)).toBe(false);
            expect(RBACService.hasRoleLevel(UserRole.USER, UserRole.SUPER_ADMIN)).toBe(false);
        });

        it('should allow same role level access', () => {
            expect(RBACService.hasRoleLevel(UserRole.USER, UserRole.USER)).toBe(true);
            expect(RBACService.hasRoleLevel(UserRole.TENANT_ADMIN, UserRole.TENANT_ADMIN)).toBe(true);
        });
    });

    describe('createDatabaseFilter', () => {
        it('should create no filter for super admin', () => {
            const user = {
                id: 'admin-id',
                role: UserRole.SUPER_ADMIN,
                tenantId: 'tenant-id'
            };

            const filter = RBACService.createDatabaseFilter(user);
            expect(Object.keys(filter)).toHaveLength(0);
        });

        it('should create tenant filter for tenant admin', () => {
            const user = {
                id: 'admin-id',
                role: UserRole.TENANT_ADMIN,
                tenantId: 'tenant-id'
            };

            const filter = RBACService.createDatabaseFilter(user);
            expect(filter.tenantId).toBe('tenant-id');
        });

        it('should create user-specific filter for regular user', () => {
            const user = {
                id: 'user-id',
                role: UserRole.USER,
                tenantId: 'tenant-id'
            };

            const filter = RBACService.createDatabaseFilter(user);
            expect(filter.$or).toBeDefined();
            expect(filter.$or).toContainEqual({ userId: 'user-id' });
            expect(filter.$or).toContainEqual({ createdBy: 'user-id' });
        });
    });

    describe('canAccessResource', () => {
        const mockResource = {
            id: 'resource-id',
            userId: 'owner-id',
            tenantId: 'tenant-id'
        };

        it('should allow super admin access to any resource', () => {
            const user = {
                id: 'admin-id',
                role: UserRole.SUPER_ADMIN,
                tenantId: 'different-tenant'
            };

            expect(RBACService.canAccessResource(user, mockResource)).toBe(true);
        });

        it('should allow resource owner access', () => {
            const user = {
                id: 'owner-id',
                role: UserRole.USER,
                tenantId: 'tenant-id'
            };

            expect(RBACService.canAccessResource(user, mockResource)).toBe(true);
        });

        it('should allow tenant admin access to tenant resources', () => {
            const user = {
                id: 'admin-id',
                role: UserRole.TENANT_ADMIN,
                tenantId: 'tenant-id'
            };

            expect(RBACService.canAccessResource(user, mockResource)).toBe(true);
        });

        it('should deny access to unrelated users', () => {
            const user = {
                id: 'other-user',
                role: UserRole.USER,
                tenantId: 'different-tenant'
            };

            expect(RBACService.canAccessResource(user, mockResource)).toBe(false);
        });
    });

    describe('getEffectivePermissions', () => {
        it('should combine role and user permissions', () => {
            const user = {
                id: 'user-id',
                role: UserRole.USER,
                tenantId: 'tenant-id',
                permissions: ['custom:permission', 'user:read'] // user:read is duplicate
            };

            const effective = RBACService.getEffectivePermissions(user);

            expect(effective).toContain('user:read');
            expect(effective).toContain('profile:read');
            expect(effective).toContain('custom:permission');
            expect(effective.filter(p => p === 'user:read')).toHaveLength(1); // No duplicates
        });
    });
});

