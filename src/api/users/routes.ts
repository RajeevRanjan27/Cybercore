// src/api/users/routes.ts
import { Router } from 'express';
import { UserController } from './controller';
import { authenticate } from '@/core/middlewares/auth';
import { authorize } from '@/core/middlewares/rbac';
import { createRateLimiter } from '@/core/middlewares/rateLimiter';
import { validate } from '@/core/validators/middleware';
import {
    updateUserSchema,
    bulkOperationSchema,
    searchUsersSchema,
    resetPasswordSchema,
    toggleStatusSchema,
    exportUsersSchema,
    getUsersByRoleSchema,
    accountDeletionSchema,
    dataExportRequestSchema, changePasswordSchema, userPreferencesSchema,
    activateUserSchema,
    inviteUserSchema
} from '@/core/validators/userValidators';
import { upload } from '@/core/middlewares/upload';
import { auditTrail } from '@/core/middlewares/auditTrail';
import { cacheMiddleware } from '@/core/middlewares/cache';
import { compressionMiddleware } from '@/core/middlewares/compression';
import {AuditService} from "@/core/services/AuditService";
import { UserService } from '@/core/services/UserService';
import { AppError } from '@/core/middlewares/errorHandler';
import { User } from '@/core/models/User';
import {ExportService} from "@/core/services/ExportService";
import {CacheService} from "@/core/services/CacheService";
import { RBACService } from '@/core/services/RBACService';
import {NotificationService} from "@/core/services/NotificationService";
import { AuthService } from '@/core/services/AuthService';
import jwt from "jsonwebtoken";
import { config } from '@/config/env'; // NOT from 'process'
import {ValidationService} from "@/core/services/ValidationService";
import { UserRole } from '@/core/constants/roles';
import { AuthPayload } from '@/core/types';

const router = Router();

// Apply global middleware
router.use(createRateLimiter()); // Rate limiting
router.use(authenticate); // Authentication required for all routes
router.use(auditTrail); // Audit trail for all operations

// ============================================================================
// USER LISTING AND RETRIEVAL ROUTES
// ============================================================================

/**
 * GET /users - Get paginated list of users with advanced filtering
 * Query params: page, limit, search, role, isActive, sortBy, sortOrder,
 *               tenantId, dateFrom, dateTo, includeStats, export, fields
 */
router.get('/',
    authorize('user:read'),
    cacheMiddleware(300), // 5 minutes cache
    compressionMiddleware,
    UserController.getUsers
);

/**
 * GET /users/search - Advanced user search with multiple criteria
 * Query params: q (query), filters, advanced, highlight, fuzzy
 */
router.get('/search',
    authorize('user:read'),
    validate(searchUsersSchema),
    createRateLimiter(60000, 30), // 30 requests per minute for search
    UserController.searchUsers
);

/**
 * GET /users/stats - Get comprehensive user statistics and analytics
 * Query params: period, groupBy, includeInactive, tenantId
 */
router.get('/stats',
    authorize('analytics:read'),
    cacheMiddleware(900), // 15 minutes cache for stats
    compressionMiddleware,
    UserController.getUserStats
);

/**
 * GET /users/export - Export user data in various formats
 * Query params: format, filters, fields, includeInactive
 */
router.get('/export',
    authorize('user:export'),
    validate(exportUsersSchema),
    createRateLimiter(300000, 5), // 5 exports per 5 minutes
    UserController.exportUserData
);

/**
 * GET /users/role/:role - Get users by specific role
 * Params: role
 * Query params: page, limit, isActive, tenantId, sortBy, sortOrder
 */
router.get('/role/:role',
    authorize('user:list'),
    validate(getUsersByRoleSchema),
    cacheMiddleware(300),
    UserController.getUsersByRole
);

/**
 * GET /users/:id - Get detailed user information
 * Params: id
 * Query params: includeActivity, includePermissions, includeStats
 */
router.get('/:id',
    authorize('user:read'),
    cacheMiddleware(600), // 10 minutes cache for individual users
    UserController.getUserById
);

// ============================================================================
// USER MODIFICATION ROUTES
// ============================================================================

/**
 * PUT /users/:id - Update user information
 * Params: id
 * Body: firstName, lastName, role, tenantId, isActive, customFields, reason
 */
router.put('/:id',
    authorize('user:update'),
    validate(updateUserSchema),
    createRateLimiter(60000, 20), // 20 updates per minute
    UserController.updateUser
);

/**
 * POST /users/bulk - Bulk operations on multiple users
 * Body: { userIds, operation, data }
 * Operations: activate, deactivate, delete, changeRole, changeTenant
 */
router.post('/bulk',
    authorize('user:bulkEdit'),
    validate(bulkOperationSchema),
    createRateLimiter(300000, 3), // 3 bulk operations per 5 minutes
    UserController.bulkUserOperation
);

/**
 * PATCH /users/:id/status - Toggle user activation status
 * Params: id
 * Body: { reason }
 */
router.patch('/:id/status',
    authorize('user:update'),
    validate(toggleStatusSchema),
    createRateLimiter(60000, 10), // 10 status changes per minute
    UserController.toggleUserStatus
);

/**
 * POST /users/:id/reset-password - Reset user password (admin only)
 * Params: id
 * Body: { newPassword, forceChange, notifyUser, reason }
 */
router.post('/:id/reset-password',
    authorize('user:resetPassword'),
    validate(resetPasswordSchema),
    createRateLimiter(300000, 5), // 5 password resets per 5 minutes
    UserController.resetUserPassword
);

// ============================================================================
// USER PROFILE AND MEDIA ROUTES
// ============================================================================

/**
 * POST /users/:id/profile-picture - Upload user profile picture
 * Params: id
 * Form data: file (image)
 */
router.post('/:id/profile-picture',
    authorize('user:update'),
    upload.single('profilePicture'), // Multer middleware for file upload
    createRateLimiter(60000, 5), // 5 uploads per minute
    UserController.uploadProfilePicture
);

/**
 * DELETE /users/:id/profile-picture - Remove user profile picture
 * Params: id
 */
router.delete('/:id/profile-picture',
    authorize('user:update'),
    createRateLimiter(60000, 10),
    async (req, res, next) => {
        // Simple profile picture removal
        try {
            const { id } = req.params;
            const user = req.user;

            // Permission check - users can only update their own profile or admins can update others
            if (id !== user?.userId && !authorize('user:update')) {
                throw new AppError('Insufficient permissions', 403);
            }

            await User.findByIdAndUpdate(id, {
                $unset: { profilePicture: 1, profilePictureMetadata: 1 },
                updatedAt: new Date()
            });

            // Clear cache
            await CacheService.invalidateUserCaches(id);

            res.json({
                success: true,
                message: 'Profile picture removed successfully',
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            next(error);
        }
    }
);

// ============================================================================
// USER ACTIVITY AND ANALYTICS ROUTES
// ============================================================================

/**
 * GET /users/:id/activity - Get user activity timeline
 * Params: id
 * Query params: page, limit, type, dateFrom, dateTo
 */
router.get('/:id/activity',
    authorize('user:read'),
    cacheMiddleware(180), // 3 minutes cache for activity
    UserController.getUserActivity
);

/**
 * GET /users/:id/permissions - Get user permissions and access levels
 * Params: id
 */
router.get('/:id/permissions',
    authorize('user:read'),
    cacheMiddleware(600), // 10 minutes cache for permissions
    UserController.getUserPermissions
);

/**
 * GET /users/:id/sessions - Get user's active sessions
 * Params: id
 */
router.get('/:id/sessions',
    authorize('user:read'),
    async (req, res, next) => {
        try {
            const { id } = req.params;
            const user = req.user as AuthPayload | undefined;
            if (!user) {
                throw new AppError('User not authenticated', 401);
            }

            // Permission check
            if (id !== user?.userId && !RBACService.canAccess(user.role, 'user:read')) {
                throw new AppError('Insufficient permissions', 403);
            }

            const sessions = await UserService.getUserActiveSessions(id);

            res.json({
                success: true,
                data: { sessions },
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * DELETE /users/:id/sessions - Invalidate all user sessions
 * Params: id
 */
router.delete('/:id/sessions',
    authorize('user:update'),
    createRateLimiter(300000, 5), // 5 session invalidations per 5 minutes
    async (req, res, next) => {
        try {
            const { id } = req.params;
            const user = req.user as AuthPayload | undefined;
            if (!user) {
                throw new AppError('User not authenticated', 401);
            }
            // Permission check
            if (id !== user?.userId && !RBACService.canAccess(user.role, 'user:update')) {
                throw new AppError('Insufficient permissions', 403);
            }

            await UserService.invalidateUserSessions(id);

            // Log activity
            await AuditService.logActivity(user.userId, 'USER_SESSIONS_INVALIDATED', {
                targetUserId: id
            });

            res.json({
                success: true,
                message: 'All user sessions invalidated',
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            next(error);
        }
    }
);

// ============================================================================
// USER DELETION ROUTES
// ============================================================================

/**
 * DELETE /users/:id - Soft delete user
 * Params: id
 * Body: { reason }
 */
router.delete('/:id',
    authorize('user:delete'),
    createRateLimiter(300000, 3), // 3 deletions per 5 minutes
    UserController.deleteUser
);

/**
 * DELETE /users/:id/permanent - Permanently delete user (super admin only)
 * Params: id
 * Body: { reason, confirmEmail }
 */
router.delete('/:id/permanent',
    authorize('user:permanentDelete'),
    createRateLimiter(900000, 1), // 1 permanent deletion per 15 minutes
    async (req, res, next) => {
        try {
            const { id } = req.params;
            const { reason, confirmEmail } = req.body;
            const user = req.user;

            // Only super admins can permanently delete
            if (user?.role !== UserRole.SUPER_ADMIN) {
                throw new AppError('Only super admins can permanently delete users', 403);
            }

            // Get target user for email confirmation
            const targetUser = await User.findById(id);
            if (!targetUser) {
                throw new AppError('User not found', 404);
            }

            // Require email confirmation for permanent deletion
            if (confirmEmail !== targetUser.email) {
                throw new AppError('Email confirmation does not match', 400);
            }

            // Perform permanent deletion
            await UserService.performPermanentDeletion(targetUser, user.userId, reason);

            // Log permanent deletion
            await AuditService.logActivity(user.userId, 'USER_PERMANENT_DELETE', {
                targetUserId: id,
                targetUserEmail: targetUser.email,
                reason
            });

            res.json({
                success: true,
                message: 'User permanently deleted',
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            next(error);
        }
    }
);

// ============================================================================
// USER RESTORATION ROUTES
// ============================================================================

/**
 * POST /users/:id/restore - Restore soft-deleted user
 * Params: id
 * Body: { reason }
 */
router.post('/:id/restore',
    authorize('user:restore'),
    createRateLimiter(300000, 5), // 5 restorations per 5 minutes
    async (req, res, next) => {
        try {
            const { id } = req.params;
            const { reason } = req.body;
            const user = req.user as AuthPayload | undefined;
            if (!user) {
                throw new AppError('User not authenticated', 401);
            }
            ValidationService.validateObjectId(id);

            // Find the soft-deleted user
            const targetUser = await User.findOne({
                _id: id,
                isActive: false,
                deletedAt: { $exists: true }
            });

            if (!targetUser) {
                throw new AppError('User not found or not deleted', 404);
            }

            // RBAC check
            if (!RBACService.hasRoleLevel(user.role, targetUser.role)) {
                throw new AppError('Cannot restore user with equal or higher role', 403);
            }

            // Restore user
            const restoredUser = await User.findByIdAndUpdate(
                id,
                {
                    isActive: true,
                    $unset: {
                        deletedAt: 1,
                        deletedBy: 1,
                        deletionReason: 1
                    },
                    restoredAt: new Date(),
                    restoredBy: user.userId,
                    restorationReason: reason,
                    updatedAt: new Date()
                },
                { new: true }
            ).select('-password');
            // Check if update was successful
            if (!restoredUser) {
                throw new AppError('Failed to restore user', 500);
            }

            // Clear caches
            await CacheService.invalidateUserCaches(id);

            // Log restoration
            await AuditService.logActivity(user.userId, 'USER_RESTORE', {
                targetUserId: id,
                targetUserEmail: targetUser.email,
                reason
            });

            // Send notification
            await NotificationService.sendUserRestorationNotification(
                restoredUser,
                user.userId,
                reason
            );

            res.json({
                success: true,
                data: { user: restoredUser },
                message: 'User restored successfully',
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            next(error);
        }
    }
);

// ============================================================================
// ADVANCED USER MANAGEMENT ROUTES
// ============================================================================

/**
 * POST /users/invite - Invite new user via email
 * Body: { email, firstName, lastName, role, tenantId, message, expiresIn }
 */
router.post('/invite',
    authorize('user:invite'),
    validate(inviteUserSchema),
    createRateLimiter(300000, 10), // 10 invites per 5 minutes
    async (req, res, next) => {
        try {
            const user = req.user as AuthPayload | undefined;
            if (!user) {
                throw new AppError('User not authenticated', 401);
            }
            const inviteData = req.body;

            // Generate invitation token
            const invitationToken = jwt.sign(
                {
                    email: inviteData.email,
                    role: inviteData.role,
                    tenantId: inviteData.tenantId || user.tenantId,
                    invitedBy: user.userId
                },
                config.JWT_SECRET,
                { expiresIn: `${inviteData.expiresIn || 72}h` }
            );

            // Send invitation email
            await NotificationService.sendUserInvitation(inviteData, invitationToken);

            // Log invitation
            await AuditService.logActivity(user.userId, 'USER_INVITE', {
                invitedEmail: inviteData.email,
                role: inviteData.role,
                expiresIn: inviteData.expiresIn
            });

            res.json({
                success: true,
                message: 'Invitation sent successfully',
                data: {
                    email: inviteData.email,
                    expiresAt: new Date(Date.now() + (inviteData.expiresIn || 72) * 60 * 60 * 1000)
                },
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * POST /users/activate - Activate user account from invitation
 * Body: { token, password, confirmPassword }
 */
router.post('/activate',
    validate(activateUserSchema),
    createRateLimiter(300000, 5), // 5 activations per 5 minutes
    async (req, res, next) => {
        try {
            const { token, password } = req.body;

            // Verify invitation token
            const decoded = jwt.verify(token, config.JWT_SECRET) as any;

            // Check if user already exists
            const existingUser = await User.findOne({ email: decoded.email });
            if (existingUser) {
                throw new AppError('User already activated', 400);
            }

            // Create user account
            const user = await User.create({
                email: decoded.email,
                password,
                firstName: decoded.firstName,
                lastName: decoded.lastName,
                role: decoded.role,
                tenantId: decoded.tenantId,
                isActive: true,
                activatedAt: new Date()
            });

            // Generate auth tokens
            const tokens = AuthService.generateTokens(user);
            await AuthService.storeRefreshToken(String(user._id), tokens.refreshToken);

            // Send welcome email
            await NotificationService.sendWelcomeEmail(user);

            // Log activation
            await AuditService.logActivity(String(user._id), 'USER_ACTIVATE', {
                invitedBy: decoded.invitedBy
            });

            res.status(201).json({
                success: true,
                data: {
                    user: {
                        id: user._id,
                        email: user.email,
                        firstName: user.firstName,
                        lastName: user.lastName,
                        role: user.role
                    },
                    tokens
                },
                message: 'Account activated successfully',
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * PUT /users/:id/preferences - Update user preferences
 * Params: id
 * Body: { language, timezone, theme, notifications, privacy, accessibility }
 */
router.put('/:id/preferences',
    authorize('profile:update'),
    validate(userPreferencesSchema),
    createRateLimiter(60000, 10), // 10 updates per minute
    async (req, res, next) => {
        try {
            const { id } = req.params;
            const user = req.user as AuthPayload | undefined;
            if (!user) {
                throw new AppError('User not authenticated', 401);
            }
            const preferences = req.body;

            // Permission check
            if (id !== user?.userId && !RBACService.canAccess(user.role, 'user:update')) {
                throw new AppError('Insufficient permissions', 403);
            }

            const updatedUser = await User.findByIdAndUpdate(
                id,
                {
                    preferences,
                    updatedAt: new Date()
                },
                { new: true }
            ).select('-password');

            if (!updatedUser) {
                throw new AppError('User not found', 404);
            }

            // Clear cache
            await CacheService.invalidateUserCaches(id);

            // Log preference update
            await AuditService.logActivity(user.userId, 'PREFERENCES_UPDATE', {
                targetUserId: id,
                updatedPreferences: Object.keys(preferences)
            });

            res.json({
                success: true,
                data: {
                    preferences: updatedUser.preferences
                },
                message: 'Preferences updated successfully',
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * POST /users/:id/change-password - Change user password
 * Params: id
 * Body: { currentPassword, newPassword, confirmPassword }
 */
router.post('/:id/change-password',
    authenticate,
    validate(changePasswordSchema),
    createRateLimiter(300000, 3), // 3 attempts per 5 minutes
    async (req, res, next) => {
        try {
            const { id } = req.params;
            const user = req.user;
            const { currentPassword, newPassword } = req.body;

            // Only allow users to change their own password
            if (id !== user?.userId) {
                throw new AppError('Can only change your own password', 403);
            }

            const targetUser = await User.findById(id).select('+password');
            if (!targetUser) {
                throw new AppError('User not found', 404);
            }

            // Verify current password
            const isCurrentPasswordValid = await targetUser.comparePassword(currentPassword);
            if (!isCurrentPasswordValid) {
                throw new AppError('Current password is incorrect', 400);
            }

            // Update password
            targetUser.password = newPassword;
            targetUser.passwordChangedAt = new Date();
            await targetUser.save();

            // Invalidate all sessions except current
            await UserService.invalidateUserSessions(id);

            // Log password change
            await AuditService.logActivity(user.userId, 'PASSWORD_CHANGE', {
                selfChange: true
            });

            res.json({
                success: true,
                message: 'Password changed successfully',
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            next(error);
        }
    }
);

/**
 * GET /users/:id/export-data - Export user's personal data (GDPR compliance)
 * Params: id
 * Query: dataTypes, format, includeMetadata
 */
router.get('/:id/export-data',
    authenticate,
    validate(dataExportRequestSchema),
    createRateLimiter(3600000, 3), // 3 exports per hour
    async (req, res, next) => {
        try {
            const { id } = req.params;
            const user = req.user;
            const { dataTypes, format, includeMetadata } = req.query;

            // Only allow users to export their own data
            if (id !== user?.userId) {
                throw new AppError('Can only export your own data', 403);
            }

            const exportData = await UserService.exportUserData(
                id,
                dataTypes as string[],
                format as string,
                includeMetadata === 'true'
            );

            // Log data export
            await AuditService.logActivity(user.userId, 'DATA_EXPORT', {
                dataTypes,
                format
            });

            const filename = `user_data_${id}_${new Date().toISOString().split('T')[0]}.${format}`;

            res.set({
                'Content-Disposition': `attachment; filename="${filename}"`,
                'Content-Type': ExportService.getContentType(format as string)
            });

            res.send(exportData);
        } catch (error) {
            next(error);
        }
    }
);

/**
 * DELETE /users/:id/account - Delete user account (GDPR compliance)
 * Params: id
 * Body: { password, reason, feedback, confirmEmail }
 */
router.delete('/:id/account',
    authenticate,
    validate(accountDeletionSchema),
    createRateLimiter(86400000, 1), // 1 deletion per day
    async (req, res, next) => {
        try {
            const { id } = req.params;
            const user = req.user;
            const { password, reason, feedback, confirmEmail } = req.body;

            // Only allow users to delete their own account
            if (id !== user?.userId) {
                throw new AppError('Can only delete your own account', 403);
            }

            const targetUser = await User.findById(id).select('+password');
            if (!targetUser) {
                throw new AppError('User not found', 404);
            }

            // Verify password
            const isPasswordValid = await targetUser.comparePassword(password);
            if (!isPasswordValid) {
                throw new AppError('Password is incorrect', 400);
            }

            // Verify email confirmation
            if (confirmEmail !== targetUser.email) {
                throw new AppError('Email confirmation does not match', 400);
            }

            // Perform account deletion
            await UserService.deleteUserAccount(targetUser, reason, feedback);

            // Log account deletion
            await AuditService.logActivity(user.userId, 'ACCOUNT_DELETION', {
                reason,
                selfDeletion: true
            });

            res.json({
                success: true,
                message: 'Account deletion initiated. You will receive a confirmation email.',
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            next(error);
        }
    }
);

export { router as userRoutes };