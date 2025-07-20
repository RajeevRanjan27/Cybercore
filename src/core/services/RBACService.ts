import { UserRole, PERMISSIONS, PERMISSION_GROUPS } from '@/core/constants/roles';

interface User {
    id: string;
    role: UserRole;
    tenantId?: string;
    permissions?: string[];
}

interface DataWithOwnership {
    id: string;
    userId?: string;
    tenantId?: string;
    createdBy?: string;
    [key: string]: any;
}

interface FilterContext {
    userId?: string;
    tenantId?: string;
    includePublic?: boolean;
}

export class RBACService {
    /**
     * Check if user role has access to a specific permission
     */
    static canAccess(userRole: UserRole, permission: string): boolean {
        const allowedRoles = PERMISSIONS[permission as keyof typeof PERMISSIONS];
        return allowedRoles ? allowedRoles.includes(userRole) : false;
    }

    /**
     * Check if user has a specific permission in their permission array
     */
    static hasPermission(userPermissions: string[], requiredPermission: string): boolean {
        return userPermissions.includes(requiredPermission);
    }

    /**
     * Check if user has any of the required permissions
     */
    static hasAnyPermission(userRole: UserRole, permissions: string[]): boolean {
        return permissions.some(permission => this.canAccess(userRole, permission));
    }

    /**
     * Check if user has all required permissions
     */
    static hasAllPermissions(userRole: UserRole, permissions: string[]): boolean {
        return permissions.every(permission => this.canAccess(userRole, permission));
    }

    /**
     * Check if user has access to a permission group
     */
    static hasPermissionGroup(userRole: UserRole, group: keyof typeof PERMISSION_GROUPS): boolean {
        const permissions = PERMISSION_GROUPS[group];
        return this.hasAnyPermission(userRole, permissions);
    }

    /**
     * Get all permissions for a user role
     */
    static getRolePermissions(userRole: UserRole): string[] {
        return Object.keys(PERMISSIONS).filter(permission =>
            this.canAccess(userRole, permission)
        );
    }

    /**
     * Get permission groups that a user role has access to
     */
    static getUserPermissionGroups(userRole: UserRole): string[] {
        const userPermissions = this.getRolePermissions(userRole);
        const accessibleGroups: string[] = [];

        // Check each permission group
        Object.entries(PERMISSION_GROUPS).forEach(([groupName, groupPermissions]) => {
            // Check if user has at least one permission from this group
            const hasGroupAccess = groupPermissions.some(permission =>
                userPermissions.includes(permission)
            );

            if (hasGroupAccess) {
                accessibleGroups.push(groupName);
            }
        });

        return accessibleGroups;
    }

    /**
     * Filter data based on user role and context
     */
    static filterByRole<T extends DataWithOwnership>(
        userRole: UserRole,
        data: T[],
        context: FilterContext = {}
    ): T[] {
        const { userId, tenantId, includePublic = false } = context;

        switch (userRole) {
            case UserRole.SUPER_ADMIN:
                // Super admin sees everything
                return data;

            case UserRole.TENANT_ADMIN:
                // Tenant admin sees data within their tenant
                if (!tenantId) {
                    console.warn('Tenant ID not provided for TENANT_ADMIN filtering');
                    return [];
                }
                return data.filter(item => {
                    const itemTenantId = item.tenantId || item.createdBy;
                    return itemTenantId === tenantId || (includePublic && !itemTenantId);
                });

            case UserRole.USER:
                // User sees only their own data
                if (!userId) {
                    console.warn('User ID not provided for USER filtering');
                    return [];
                }
                return data.filter(item => {
                    const isOwner = item.userId === userId || item.createdBy === userId;
                    const isInTenant = tenantId && item.tenantId === tenantId;
                    return isOwner || (includePublic && !item.userId && !item.createdBy) || isInTenant;
                });

            default:
                return [];
        }
    }

    /**
     * Check if user can access a specific resource
     */
    static canAccessResource(
        user: User,
        resource: DataWithOwnership,
        operation: 'read' | 'write' | 'delete' = 'read'
    ): boolean {
        // Super admin can access everything
        if (user.role === UserRole.SUPER_ADMIN) {
            return true;
        }

        // Check if user owns the resource
        const isOwner = resource.userId === user.id || resource.createdBy === user.id;
        if (isOwner) {
            return true;
        }

        // Check tenant-level access
        if (user.role === UserRole.TENANT_ADMIN && user.tenantId) {
            const isSameTenant = resource.tenantId === user.tenantId;
            if (isSameTenant) {
                return true;
            }
        }

        // Check specific permissions based on operation
        const basePermission = this.getResourcePermission(resource, operation);
        if (basePermission && this.canAccess(user.role, basePermission)) {
            return true;
        }

        return false;
    }

    /**
     * Get permission string for a resource operation
     */
    private static getResourcePermission(
        resource: DataWithOwnership,
        operation: 'read' | 'write' | 'delete'
    ): string | null {
        // You can extend this to map resource types to permissions
        // For now, using generic patterns
        const resourceType = resource.constructor.name.toLowerCase() || 'resource';
        return `${resourceType}:${operation}`;
    }

    /**
     * Create a context filter for MongoDB/database queries
     */
    static createDatabaseFilter(user: User): Record<string, any> {
        switch (user.role) {
            case UserRole.SUPER_ADMIN:
                return {}; // No filter - see everything

            case UserRole.TENANT_ADMIN:
                return user.tenantId ? { tenantId: user.tenantId } : { tenantId: null };

            case UserRole.USER:
                return {
                    $or: [
                        { userId: user.id },
                        { createdBy: user.id },
                        ...(user.tenantId ? [{ tenantId: user.tenantId, isPublic: true }] : [])
                    ]
                };

            default:
                return { _id: null }; // Return empty result
        }
    }

    /**
     * Validate user permissions for API endpoints
     */
    static validateEndpointAccess(
        user: User,
        endpoint: string,
        method: string = 'GET'
    ): boolean {
        // Map HTTP methods to permission operations
        const operationMap: Record<string, string> = {
            'GET': 'read',
            'POST': 'create',
            'PUT': 'update',
            'PATCH': 'update',
            'DELETE': 'delete'
        };

        // Extract resource type from endpoint
        const resourceMatch = endpoint.match(/\/api\/([^\/]+)/);
        if (!resourceMatch) return false;

        const resourceType = resourceMatch[1];
        const operation = operationMap[method.toUpperCase()] || 'read';
        const permission = `${resourceType}:${operation}`;

        return this.canAccess(user.role, permission);
    }

    /**
     * Get user's effective permissions (including inherited ones)
     */
    static getEffectivePermissions(user: User): string[] {
        const rolePermissions = this.getRolePermissions(user.role);
        const userPermissions = user.permissions || [];

        // Combine and deduplicate permissions
        return [...new Set([...rolePermissions, ...userPermissions])];
    }

    /**
     * Check if user role is higher than or equal to required role
     */
    static hasRoleLevel(userRole: UserRole, requiredRole: UserRole): boolean {
        const roleHierarchy = {
            [UserRole.SUPER_ADMIN]: 3,
            [UserRole.TENANT_ADMIN]: 2,
            [UserRole.USER]: 1
        };

        const userLevel = roleHierarchy[userRole] || 0;
        const requiredLevel = roleHierarchy[requiredRole] || 0;

        return userLevel >= requiredLevel;
    }

    /**
     * Create a permission checker function for a specific user
     */
    static createPermissionChecker(user: User) {
        return {
            can: (permission: string) => this.canAccess(user.role, permission),
            hasAny: (permissions: string[]) => this.hasAnyPermission(user.role, permissions),
            hasAll: (permissions: string[]) => this.hasAllPermissions(user.role, permissions),
            canAccess: (resource: DataWithOwnership, operation: 'read' | 'write' | 'delete' = 'read') =>
                this.canAccessResource(user, resource, operation),
            isSuperAdmin: () => user.role === UserRole.SUPER_ADMIN,
            isTenantAdmin: () => user.role === UserRole.TENANT_ADMIN,
            isUser: () => user.role === UserRole.USER
        };
    }

    /**
     * Environment-specific permission check
     */
    static canAccessInEnvironment(
        userRole: UserRole,
        permission: string,
        environment: string = process.env.NODE_ENV || 'production'
    ): boolean {
        // Base permission check
        if (this.canAccess(userRole, permission)) {
            return true;
        }

        // In development, allow more permissive access for debugging
        if (environment === 'development' && permission.startsWith('database:')) {
            return userRole === UserRole.TENANT_ADMIN || userRole === UserRole.SUPER_ADMIN;
        }

        return false;
    }
}