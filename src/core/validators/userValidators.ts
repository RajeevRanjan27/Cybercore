// src/core/validators/userValidators.ts
import Joi from 'joi';
import { UserRole } from '@/core/constants/roles';

export const updateUserSchema = Joi.object({
    firstName: Joi.string().min(1).max(50).trim(),
    lastName: Joi.string().min(1).max(50).trim(),
    email: Joi.string().email(),
    role: Joi.string().valid(...Object.values(UserRole)),
    tenantId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/),
    isActive: Joi.boolean(),
    customFields: Joi.object().max(20),
    reason: Joi.string().max(500),
    phone: Joi.string().pattern(/^\+?[1-9]\d{1,14}$/),
    department: Joi.string().max(100),
    jobTitle: Joi.string().max(100),
    preferences: Joi.object({
        language: Joi.string().valid('en', 'es', 'fr', 'de', 'zh', 'ja'),
        timezone: Joi.string(),
        theme: Joi.string().valid('light', 'dark', 'auto'),
        notifications: Joi.object({
            email: Joi.boolean(),
            sms: Joi.boolean(),
            push: Joi.boolean(),
            inApp: Joi.boolean()
        })
    })
});

export const bulkOperationSchema = Joi.object({
    userIds: Joi.array()
        .items(Joi.string().pattern(/^[0-9a-fA-F]{24}$/))
        .min(1)
        .max(100)
        .required(),
    operation: Joi.string()
        .valid('activate', 'deactivate', 'delete', 'changeRole', 'changeTenant')
        .required(),
    data: Joi.object({
        role: Joi.string().valid(...Object.values(UserRole)),
        tenantId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/),
        reason: Joi.string().max(500)
    }).when('operation', {
        is: 'changeRole',
        then: Joi.object({ role: Joi.required() }),
        otherwise: Joi.object()
    }).when('operation', {
        is: 'changeTenant',
        then: Joi.object({ tenantId: Joi.required() }),
        otherwise: Joi.object()
    })
});

export const searchUsersSchema = Joi.object({
    q: Joi.string().min(1).max(200).required(),
    filters: Joi.string().custom((value, helpers) => {
        try {
            const parsed = JSON.parse(value);
            // Validate filter structure
            const filterSchema = Joi.object({
                role: Joi.string().valid(...Object.values(UserRole)),
                isActive: Joi.boolean(),
                tenantId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/),
                dateFrom: Joi.date().iso(),
                dateTo: Joi.date().iso().min(Joi.ref('dateFrom'))
            });
            const { error } = filterSchema.validate(parsed);
            if (error) return helpers.error('any.invalid');
            return value;
        } catch {
            return helpers.error('any.invalid');
        }
    }),
    advanced: Joi.string().valid('true', 'false'),
    highlight: Joi.string().valid('true', 'false'),
    fuzzy: Joi.string().valid('true', 'false')
});

export const resetPasswordSchema = Joi.object({
    newPassword: Joi.string()
        .min(8)
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$/)
        .required()
        .messages({
            'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
        }),
    forceChange: Joi.boolean().default(true),
    notifyUser: Joi.boolean().default(true),
    reason: Joi.string().max(500)
});

export const toggleStatusSchema = Joi.object({
    reason: Joi.string().max(500).required()
});

export const exportUsersSchema = Joi.object({
    format: Joi.string().valid('csv', 'xlsx', 'pdf', 'json').default('csv'),
    filters: Joi.string().custom((value, helpers) => {
        try {
            JSON.parse(value);
            return value;
        } catch {
            return helpers.error('any.invalid');
        }
    }),
    fields: Joi.string().pattern(/^[a-zA-Z,._]+$/),
    includeInactive: Joi.string().valid('true', 'false').default('false')
});

export const getUsersByRoleSchema = Joi.object({
    role: Joi.string().valid(...Object.values(UserRole)).required()
});

export const uploadProfilePictureSchema = Joi.object({
    file: Joi.any().required()
});

export const changePasswordSchema = Joi.object({
    currentPassword: Joi.string().required(),
    newPassword: Joi.string()
        .min(8)
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$/)
        .required()
        .messages({
            'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
        }),
    confirmPassword: Joi.string()
        .valid(Joi.ref('newPassword'))
        .required()
        .messages({
            'any.only': 'Password confirmation does not match'
        })
});

export const updateProfileSchema = Joi.object({
    firstName: Joi.string().min(1).max(50).trim(),
    lastName: Joi.string().min(1).max(50).trim(),
    phone: Joi.string().pattern(/^\+?[1-9]\d{1,14}$/),
    department: Joi.string().max(100),
    jobTitle: Joi.string().max(100),
    bio: Joi.string().max(500),
    preferences: Joi.object({
        language: Joi.string().valid('en', 'es', 'fr', 'de', 'zh', 'ja'),
        timezone: Joi.string(),
        theme: Joi.string().valid('light', 'dark', 'auto'),
        notifications: Joi.object({
            email: Joi.boolean(),
            sms: Joi.boolean(),
            push: Joi.boolean(),
            inApp: Joi.boolean()
        })
    }),
    socialLinks: Joi.object({
        linkedin: Joi.string().uri(),
        twitter: Joi.string().uri(),
        github: Joi.string().uri(),
        website: Joi.string().uri()
    })
});

export const inviteUserSchema = Joi.object({
    email: Joi.string().email().required(),
    firstName: Joi.string().min(1).max(50).trim().required(),
    lastName: Joi.string().min(1).max(50).trim().required(),
    role: Joi.string().valid(...Object.values(UserRole)).default(UserRole.USER),
    tenantId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/),
    message: Joi.string().max(500),
    expiresIn: Joi.number().min(1).max(168).default(72), // Hours, max 1 week
    sendWelcomeEmail: Joi.boolean().default(true)
});

export const activateUserSchema = Joi.object({
    token: Joi.string().required(),
    password: Joi.string()
        .min(8)
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$/)
        .required(),
    confirmPassword: Joi.string()
        .valid(Joi.ref('password'))
        .required()
        .messages({
            'any.only': 'Password confirmation does not match'
        })
});

export const userActivitySchema = Joi.object({
    page: Joi.number().min(1).default(1),
    limit: Joi.number().min(1).max(100).default(20),
    type: Joi.string().max(50),
    dateFrom: Joi.date().iso(),
    dateTo: Joi.date().iso().min(Joi.ref('dateFrom')),
    severity: Joi.string().valid('low', 'medium', 'high', 'critical')
});

export const userStatsSchema = Joi.object({
    period: Joi.string().valid('7d', '30d', '90d', '1y').default('30d'),
    groupBy: Joi.string().valid('day', 'week', 'month').default('day'),
    includeInactive: Joi.string().valid('true', 'false').default('false'),
    tenantId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/)
});

export const sessionManagementSchema = Joi.object({
    action: Joi.string().valid('revoke', 'revokeAll', 'list').required(),
    sessionId: Joi.string().when('action', {
        is: 'revoke',
        then: Joi.required(),
        otherwise: Joi.forbidden()
    })
});

export const userPreferencesSchema = Joi.object({
    language: Joi.string().valid('en', 'es', 'fr', 'de', 'zh', 'ja'),
    timezone: Joi.string(),
    theme: Joi.string().valid('light', 'dark', 'auto'),
    dateFormat: Joi.string().valid('MM/DD/YYYY', 'DD/MM/YYYY', 'YYYY-MM-DD'),
    timeFormat: Joi.string().valid('12h', '24h'),
    currency: Joi.string().length(3), // ISO 4217 currency codes
    notifications: Joi.object({
        email: Joi.boolean(),
        sms: Joi.boolean(),
        push: Joi.boolean(),
        inApp: Joi.boolean(),
        digest: Joi.string().valid('daily', 'weekly', 'monthly', 'never')
    }),
    privacy: Joi.object({
        profileVisibility: Joi.string().valid('public', 'team', 'private'),
        showEmail: Joi.boolean(),
        showPhone: Joi.boolean(),
        allowDirectMessages: Joi.boolean()
    }),
    accessibility: Joi.object({
        fontSize: Joi.string().valid('small', 'medium', 'large'),
        highContrast: Joi.boolean(),
        reducedMotion: Joi.boolean(),
        screenReader: Joi.boolean()
    })
});

export const twoFactorAuthSchema = Joi.object({
    action: Joi.string().valid('enable', 'disable', 'verify', 'backup').required(),
    code: Joi.string().pattern(/^\d{6}$/).when('action', {
        is: Joi.valid('enable', 'verify'),
        then: Joi.required(),
        otherwise: Joi.forbidden()
    }),
    backupCodes: Joi.array().items(Joi.string()).when('action', {
        is: 'backup',
        then: Joi.required(),
        otherwise: Joi.forbidden()
    })
});

export const deviceManagementSchema = Joi.object({
    action: Joi.string().valid('list', 'revoke', 'rename').required(),
    deviceId: Joi.string().when('action', {
        is: Joi.valid('revoke', 'rename'),
        then: Joi.required(),
        otherwise: Joi.optional()
    }),
    name: Joi.string().max(100).when('action', {
        is: 'rename',
        then: Joi.required(),
        otherwise: Joi.forbidden()
    })
});

export const dataExportRequestSchema = Joi.object({
    dataTypes: Joi.array()
        .items(Joi.string().valid('profile', 'activity', 'preferences', 'sessions'))
        .min(1)
        .required(),
    format: Joi.string().valid('json', 'csv').default('json'),
    includeMetadata: Joi.boolean().default(true),
    reason: Joi.string().max(500)
});

export const accountDeletionSchema = Joi.object({
    password: Joi.string().required(),
    reason: Joi.string().valid(
        'no_longer_needed',
        'privacy_concerns',
        'switching_service',
        'too_complex',
        'other'
    ).required(),
    feedback: Joi.string().max(1000),
    deleteImmediately: Joi.boolean().default(false),
    confirmEmail: Joi.string().email().required()
});

// Custom validation for file uploads
export const fileUploadValidation = {
    profilePicture: {
        maxSize: 5 * 1024 * 1024, // 5MB
        allowedTypes: ['image/jpeg', 'image/png', 'image/webp'],
        dimensions: {
            minWidth: 100,
            minHeight: 100,
            maxWidth: 2000,
            maxHeight: 2000
        }
    },
    documents: {
        maxSize: 10 * 1024 * 1024, // 10MB
        allowedTypes: [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ]
    }
};

// Rate limiting schemas for different operations
export const rateLimitSchemas = {
    passwordReset: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 3 // 3 attempts per window
    },
    profileUpdate: {
        windowMs: 60 * 1000, // 1 minute
        max: 5 // 5 updates per minute
    },
    fileUpload: {
        windowMs: 60 * 1000, // 1 minute
        max: 10 // 10 uploads per minute
    },
    export: {
        windowMs: 60 * 60 * 1000, // 1 hour
        max: 5 // 5 exports per hour
    },
    search: {
        windowMs: 60 * 1000, // 1 minute
        max: 30 // 30 searches per minute
    }
};

// Validation for admin operations
export const adminOperationSchema = Joi.object({
    targetUserId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/).required(),
    operation: Joi.string().valid(
        'impersonate',
        'unlock',
        'force_logout',
        'reset_2fa',
        'extend_trial',
        'change_limits'
    ).required(),
    reason: Joi.string().max(500).required(),
    duration: Joi.number().when('operation', {
        is: Joi.valid('impersonate', 'unlock'),
        then: Joi.required(),
        otherwise: Joi.optional()
    }),
    newLimits: Joi.object().when('operation', {
        is: 'change_limits',
        then: Joi.required(),
        otherwise: Joi.forbidden()
    })
});

// Custom error messages
export const customMessages = {
    'string.email': 'Please provide a valid email address',
    'string.min': '{#label} must be at least {#limit} characters long',
    'string.max': '{#label} cannot exceed {#limit} characters',
    'string.pattern.base': 'Invalid format for {#label}',
    'any.required': '{#label} is required',
    'array.min': 'At least {#limit} item(s) required',
    'array.max': 'Cannot exceed {#limit} item(s)',
    'number.min': '{#label} must be at least {#limit}',
    'number.max': '{#label} cannot exceed {#limit}',
    'date.min': '{#label} must be after {#limit}',
    'date.max': '{#label} must be before {#limit}'
};