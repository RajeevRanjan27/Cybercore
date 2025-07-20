// src/core/services/ValidationService.ts
import { UserRole } from '@/core/constants/roles';
import { AppError } from '@/core/middlewares/errorHandler';
import mongoose from 'mongoose';
import Joi from 'joi';

interface BulkOperationData {
    role?: UserRole;
    tenantId?: string;
    reason?: string;
}

export class ValidationService {
    /**
     * Validate MongoDB ObjectId
     */
    static validateObjectId(id: string): void {
        if (!mongoose.Types.ObjectId.isValid(id)) {
            throw new AppError('Invalid ID format', 400);
        }
    }

    /**
     * Validate user role
     */
    static validateUserRole(role: string): void {
        if (!Object.values(UserRole).includes(role as UserRole)) {
            throw new AppError('Invalid user role', 400);
        }
    }

    /**
     * Validate password strength
     */
    static validatePassword(password: string): void {
        const minLength = 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

        if (password.length < minLength) {
            throw new AppError(`Password must be at least ${minLength} characters long`, 400);
        }

        if (!hasUpperCase) {
            throw new AppError('Password must contain at least one uppercase letter', 400);
        }

        if (!hasLowerCase) {
            throw new AppError('Password must contain at least one lowercase letter', 400);
        }

        if (!hasNumbers) {
            throw new AppError('Password must contain at least one number', 400);
        }

        if (!hasSpecialChar) {
            throw new AppError('Password must contain at least one special character', 400);
        }

        // Check for common weak passwords
        const commonPasswords = [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey'
        ];

        if (commonPasswords.includes(password.toLowerCase())) {
            throw new AppError('Password is too common. Please choose a stronger password', 400);
        }
    }

    /**
     * Validate email format
     */
    static validateEmail(email: string): void {
        // Use Joi for robust, standard-compliant email validation
        const { error } = Joi.string().email().validate(email);
        if (error) {
            throw new AppError('Invalid email format', 400);
        }

        // Check for disposable email domains
        const disposableDomains = [
            '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
            'mailinator.com', 'yopmail.com'
        ];

        const domain = email.split('@')[1]?.toLowerCase();
        // Ensure domain exists before checking against the list
        if (domain && disposableDomains.includes(domain)) {
            throw new AppError('Disposable email addresses are not allowed', 400);
        }
    }

    /**
     * Validate user update data
     */
    static validateUserUpdateData(updateData: any, userRole: UserRole): void {
        const schema = Joi.object({
            firstName: Joi.string().min(1).max(50).trim(),
            lastName: Joi.string().min(1).max(50).trim(),
            email: Joi.string().email(),
            role: Joi.string().valid(...Object.values(UserRole)),
            tenantId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/),
            isActive: Joi.boolean(),
            customFields: Joi.object(),
            reason: Joi.string().max(500)
        });

        const { error } = schema.validate(updateData, { allowUnknown: false });
        if (error) {
            throw new AppError(`Validation error: ${error.details[0].message}`, 400);
        }

        // Additional email validation
        if (updateData.email) {
            this.validateEmail(updateData.email);
        }

        // Role-specific validations
        if (updateData.role && userRole !== UserRole.SUPER_ADMIN) {
            if (userRole !== UserRole.TENANT_ADMIN) {
                throw new AppError('Insufficient permissions to change user role', 403);
            }

            // Tenant admins can't assign super admin role
            if (updateData.role === UserRole.SUPER_ADMIN) {
                throw new AppError('Cannot assign super admin role', 403);
            }
        }
    }

    /**
     * Validate bulk operation
     */
    static validateBulkOperation(
        userIds: string[],
        operation: string,
        data?: BulkOperationData
    ): void {
        if (!Array.isArray(userIds) || userIds.length === 0) {
            throw new AppError('User IDs array is required and cannot be empty', 400);
        }

        if (userIds.length > 100) {
            throw new AppError('Cannot perform bulk operation on more than 100 users at once', 400);
        }

        const validOperations = ['activate', 'deactivate', 'delete', 'changeRole', 'changeTenant'];
        if (!validOperations.includes(operation)) {
            throw new AppError(`Invalid operation. Must be one of: ${validOperations.join(', ')}`, 400);
        }

        // Validate operation-specific data
        if (operation === 'changeRole') {
            if (!data?.role) {
                throw new AppError('Role is required for changeRole operation', 400);
            }
            this.validateUserRole(data.role);
        }

        if (operation === 'changeTenant') {
            if (!data?.tenantId) {
                throw new AppError('Tenant ID is required for changeTenant operation', 400);
            }
            this.validateObjectId(data.tenantId);
        }

        // Validate reason if provided
        if (data?.reason && data.reason.length > 500) {
            throw new AppError('Reason cannot exceed 500 characters', 400);
        }
    }

    /**
     * Validate search parameters
     */
    static validateSearchParams(params: any): void {
        const schema = Joi.object({
            q: Joi.string().min(1).max(200).required(),
            filters: Joi.string().custom((value, helpers) => {
                try {
                    JSON.parse(value);
                    return value;
                } catch {
                    return helpers.error('any.invalid');
                }
            }),
            advanced: Joi.string().valid('true', 'false'),
            highlight: Joi.string().valid('true', 'false'),
            fuzzy: Joi.string().valid('true', 'false')
        });

        const { error } = schema.validate(params);
        if (error) {
            throw new AppError(`Search validation error: ${error.details[0].message}`, 400);
        }
    }

    /**
     * Validate export parameters
     */
    static validateExportParams(params: any): void {
        const schema = Joi.object({
            format: Joi.string().valid('csv', 'xlsx', 'pdf').default('csv'),
            filters: Joi.string().custom((value, helpers) => {
                try {
                    JSON.parse(value);
                    return value;
                } catch {
                    return helpers.error('any.invalid');
                }
            }),
            fields: Joi.string(),
            includeInactive: Joi.string().valid('true', 'false').default('false')
        });

        const { error } = schema.validate(params);
        if (error) {
            throw new AppError(`Export validation error: ${error.details[0].message}`, 400);
        }
    }

    /**
     * Validate date range
     */
    static validateDateRange(dateFrom?: string, dateTo?: string): void {
        if (dateFrom && isNaN(Date.parse(dateFrom))) {
            throw new AppError('Invalid dateFrom format. Use ISO 8601 format', 400);
        }

        if (dateTo && isNaN(Date.parse(dateTo))) {
            throw new AppError('Invalid dateTo format. Use ISO 8601 format', 400);
        }

        if (dateFrom && dateTo) {
            const from = new Date(dateFrom);
            const to = new Date(dateTo);

            if (from >= to) {
                throw new AppError('dateFrom must be before dateTo', 400);
            }

            // Check for reasonable date range (not more than 2 years)
            const maxRange = 2 * 365 * 24 * 60 * 60 * 1000; // 2 years in milliseconds
            if (to.getTime() - from.getTime() > maxRange) {
                throw new AppError('Date range cannot exceed 2 years', 400);
            }
        }
    }

    /**
     * Validate and parse field selection
     */
    static validateAndParseFields(fieldsStr: string): string {
        const allowedFields = [
            'firstName', 'lastName', 'email', 'role', 'isActive',
            'createdAt', 'updatedAt', 'lastLogin', 'tenantId'
        ];

        const requestedFields = fieldsStr.split(',').map(f => f.trim());
        const invalidFields = requestedFields.filter(field => !allowedFields.includes(field));

        if (invalidFields.length > 0) {
            throw new AppError(`Invalid fields: ${invalidFields.join(', ')}`, 400);
        }

        return requestedFields.join(' ');
    }

    /**
     * Validate pagination parameters
     */
    static validatePagination(page?: string, limit?: string): { page: number; limit: number } {
        const pageNum = page ? parseInt(page) : 1;
        const limitNum = limit ? parseInt(limit) : 10;

        if (isNaN(pageNum) || pageNum < 1) {
            throw new AppError('Page must be a positive integer', 400);
        }

        if (isNaN(limitNum) || limitNum < 1 || limitNum > 100) {
            throw new AppError('Limit must be between 1 and 100', 400);
        }

        return { page: pageNum, limit: limitNum };
    }

    /**
     * Validate sort parameters
     */
    static validateSort(sortBy?: string, sortOrder?: string): { sortBy: string; sortOrder: 'asc' | 'desc' } {
        const allowedSortFields = [
            'createdAt', 'updatedAt', 'lastName', 'firstName', 'email', 'lastLogin', 'role'
        ];

        const validSortBy = sortBy && allowedSortFields.includes(sortBy) ? sortBy : 'createdAt';
        const validSortOrder = sortOrder === 'asc' ? 'asc' : 'desc';

        return { sortBy: validSortBy, sortOrder: validSortOrder };
    }

    /**
     * Validate file upload
     */
    static validateFileUpload(file: Express.Multer.File): void {
        if (!file) {
            throw new AppError('No file uploaded', 400);
        }

        // Validate file type for profile pictures
        const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/webp'];
        if (!allowedMimeTypes.includes(file.mimetype)) {
            throw new AppError('Invalid file type. Only JPEG, PNG, and WebP are allowed', 400);
        }

        // Validate file size (5MB limit)
        const maxSize = 5 * 1024 * 1024;
        if (file.size > maxSize) {
            throw new AppError('File size too large. Maximum 5MB allowed', 400);
        }

        // Validate filename
        if (file.originalname.length > 255) {
            throw new AppError('Filename too long', 400);
        }

        // Check for malicious file extensions in filename
        const dangerousExtensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.jar'];
        const haseDangerousExt = dangerousExtensions.some(ext =>
            file.originalname.toLowerCase().includes(ext)
        );

        if (haseDangerousExt) {
            throw new AppError('File type not allowed for security reasons', 400);
        }
    }

    /**
     * Validate analytics parameters
     */
    static validateAnalyticsParams(params: any): void {
        const schema = Joi.object({
            period: Joi.string().valid('7d', '30d', '90d', '1y').default('30d'),
            groupBy: Joi.string().valid('day', 'week', 'month').default('day'),
            includeInactive: Joi.string().valid('true', 'false').default('false'),
            tenantId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/)
        });

        const { error } = schema.validate(params);
        if (error) {
            throw new AppError(`Analytics validation error: ${error.details[0].message}`, 400);
        }
    }

    /**
     * Validate phone number format
     */
    static validatePhoneNumber(phone: string): void {
        // Simple international phone number validation
        const phoneRegex = /^\+?[1-9]\d{1,14}$/;
        if (!phoneRegex.test(phone.replace(/[\s-()]/g, ''))) {
            throw new AppError('Invalid phone number format', 400);
        }
    }

    /**
     * Validate custom field data
     */
    static validateCustomFields(customFields: Record<string, any>): void {
        if (!customFields || typeof customFields !== 'object') {
            return;
        }

        // Limit number of custom fields
        const maxFields = 20;
        if (Object.keys(customFields).length > maxFields) {
            throw new AppError(`Cannot have more than ${maxFields} custom fields`, 400);
        }

        // Validate field names and values
        Object.entries(customFields).forEach(([key, value]) => {
            // Field name validation
            if (key.length > 50) {
                throw new AppError('Custom field name cannot exceed 50 characters', 400);
            }

            if (!/^[a-zA-Z][a-zA-Z0-9_]*$/.test(key)) {
                throw new AppError('Custom field names must start with a letter and contain only letters, numbers, and underscores', 400);
            }

            // Value validation
            if (typeof value === 'string' && value.length > 1000) {
                throw new AppError('Custom field values cannot exceed 1000 characters', 400);
            }

            if (typeof value === 'object' && value !== null) {
                try {
                    JSON.stringify(value);
                } catch {
                    throw new AppError('Custom field values must be JSON serializable', 400);
                }
            }
        });
    }

    /**
     * Validate IP address
     */
    static validateIPAddress(ip: string): void {
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;

        if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
            throw new AppError('Invalid IP address format', 400);
        }
    }

    /**
     * Validate webhook URL
     */
    static validateWebhookURL(url: string): void {
        try {
            const urlObject = new URL(url);

            if (!['http:', 'https:'].includes(urlObject.protocol)) {
                throw new AppError('Webhook URL must use HTTP or HTTPS protocol', 400);
            }

            if (urlObject.hostname === 'localhost' || urlObject.hostname === '127.0.0.1') {
                throw new AppError('Localhost URLs are not allowed for webhooks', 400);
            }

        } catch (error) {
            if (error instanceof AppError) throw error;
            throw new AppError('Invalid webhook URL format', 400);
        }
    }

    /**
     * Sanitize user input to prevent XSS
     */
    static sanitizeInput(input: string): string {
        if (typeof input !== 'string') {
            return input;
        }

        return input
            .replace(/[<>]/g, '') // Remove < and >
            .replace(/javascript:/gi, '') // Remove javascript: protocol
            .replace(/on\w+=/gi, '') // Remove event handlers
            .trim();
    }

    /**
     * Validate API key format
     */
    static validateAPIKey(apiKey: string): void {
        // API key should be at least 32 characters and alphanumeric
        const apiKeyRegex = /^[a-zA-Z0-9]{32,}$/;
        if (!apiKeyRegex.test(apiKey)) {
            throw new AppError('Invalid API key format', 400);
        }
    }

    /**
     * Validate rate limit parameters
     */
    static validateRateLimit(windowMs?: number, max?: number): void {
        if (windowMs !== undefined) {
            if (!Number.isInteger(windowMs) || windowMs < 1000 || windowMs > 86400000) {
                throw new AppError('Window must be between 1 second and 24 hours', 400);
            }
        }

        if (max !== undefined) {
            if (!Number.isInteger(max) || max < 1 || max > 10000) {
                throw new AppError('Max requests must be between 1 and 10000', 400);
            }
        }
    }
}