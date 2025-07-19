export enum UserRole {
    SUPER_ADMIN = 'SUPER_ADMIN',
    TENANT_ADMIN = 'TENANT_ADMIN',
    USER = 'USER'
}

// Create a type for permissions
type PermissionMap = {
    [key: string]: UserRole[];
};

// Permission categories for better organization
export const PERMISSIONS: PermissionMap = {
    // User management permissions
    'user:create': [UserRole.SUPER_ADMIN, UserRole.TENANT_ADMIN],
    'user:read': [UserRole.SUPER_ADMIN, UserRole.TENANT_ADMIN, UserRole.USER],
    'user:update': [UserRole.SUPER_ADMIN, UserRole.TENANT_ADMIN],
    'user:delete': [UserRole.SUPER_ADMIN, UserRole.TENANT_ADMIN],
    'user:list': [UserRole.SUPER_ADMIN, UserRole.TENANT_ADMIN],

    // Tenant management permissions
    'tenant:create': [UserRole.SUPER_ADMIN],
    'tenant:read': [UserRole.SUPER_ADMIN, UserRole.TENANT_ADMIN],
    'tenant:update': [UserRole.SUPER_ADMIN, UserRole.TENANT_ADMIN],
    'tenant:delete': [UserRole.SUPER_ADMIN],
    'tenant:list': [UserRole.SUPER_ADMIN],

    // Database debug permissions
    'database:read': [UserRole.SUPER_ADMIN, UserRole.TENANT_ADMIN],
    'database:admin': [UserRole.SUPER_ADMIN],
    'database:health': [UserRole.SUPER_ADMIN, UserRole.TENANT_ADMIN],

    // System administration permissions
    'system:read': [UserRole.SUPER_ADMIN],
    'system:write': [UserRole.SUPER_ADMIN],
    'system:logs': [UserRole.SUPER_ADMIN],
    'system:config': [UserRole.SUPER_ADMIN],

    // Analytics and reporting permissions
    'analytics:read': [UserRole.SUPER_ADMIN, UserRole.TENANT_ADMIN],
    'analytics:export': [UserRole.SUPER_ADMIN, UserRole.TENANT_ADMIN],

    // Profile management permissions
    'profile:read': [UserRole.SUPER_ADMIN, UserRole.TENANT_ADMIN, UserRole.USER],
    'profile:update': [UserRole.SUPER_ADMIN, UserRole.TENANT_ADMIN, UserRole.USER],
    'profile:delete': [UserRole.SUPER_ADMIN, UserRole.TENANT_ADMIN, UserRole.USER],
};

// Permission groups for easier management
export const PERMISSION_GROUPS = {
    USER_MANAGEMENT: [
        'user:create',
        'user:read',
        'user:update',
        'user:delete',
        'user:list'
    ],
    TENANT_MANAGEMENT: [
        'tenant:create',
        'tenant:read',
        'tenant:update',
        'tenant:delete',
        'tenant:list'
    ],
    DATABASE_MANAGEMENT: [
        'database:read',
        'database:admin',
        'database:health'
    ],
    SYSTEM_MANAGEMENT: [
        'system:read',
        'system:write',
        'system:logs',
        'system:config'
    ],
    PROFILE_MANAGEMENT: [
        'profile:read',
        'profile:update',
        'profile:delete'
    ]
};

// Type for permission groups
export type PermissionGroup = keyof typeof PERMISSION_GROUPS;