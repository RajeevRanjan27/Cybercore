// src/api/users/controller.ts
import { Request, Response, NextFunction } from 'express';
import { User, IUser } from '@/core/models/User';
import { Tenant } from '@/core/models/Tenant';
import { AppError } from '@/core/middlewares/errorHandler';
import { ApiResponse, PaginatedResponse, AuthPayload } from '@/core/types';
import { UserRole } from '@/core/constants/roles';
import { RBACService } from '@/core/services/RBACService';
import { UserService } from '@/core/services/UserService';
import { AuditService } from '@/core/services/AuditService';
import { NotificationService } from '@/core/services/NotificationService';
import { CacheService } from '@/core/services/CacheService';
import { ValidationService } from '@/core/services/ValidationService';
import { ExportService } from '@/core/services/ExportService';
import { SearchService } from '@/core/services/SearchService';
import { logger } from '@/core/infra/logger';
import mongoose from 'mongoose';

interface UserQueryParams {
    page?: string;
    limit?: string;
    search?: string;
    role?: UserRole;
    isActive?: string;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
    tenantId?: string;
    dateFrom?: string;
    dateTo?: string;
    includeStats?: string;
    export?: string;
    fields?: string;
}

interface BulkUserOperation {
    userIds: string[];
    operation: 'activate' | 'deactivate' | 'delete' | 'changeRole' | 'changeTenant';
    data?: {
        role?: UserRole;
        tenantId?: string;
        reason?: string;
    };
}

interface UserStatsResponse {
    totalUsers: number;
    activeUsers: number;
    inactiveUsers: number;
    usersByRole: Record<UserRole, number>;
    usersByTenant: Record<string, number>;
    recentSignups: number;
    averageUsersPerTenant: number;
    growthRate: number;
}

export class UserController {
    /**
     * Advanced user listing with comprehensive filtering, searching, and pagination
     */
    static async getUsers(req: Request, res: Response, next: NextFunction) {
        try {
            const user = req.user as AuthPayload;
            const params = req.query as UserQueryParams;

            // Parse and validate query parameters
            const page = Math.max(1, parseInt(params.page || '1'));
            const limit = Math.min(100, Math.max(1, parseInt(params.limit || '10')));
            const skip = (page - 1) * limit;

            // Build dynamic query with RBAC filtering
            let baseQuery = RBACService.createDatabaseFilter({
                id: user.userId,
                role: user.role,
                tenantId: user.tenantId
            });

            // Advanced search functionality
            if (params.search) {
                const searchQuery = SearchService.buildUserSearchQuery(params.search);
                baseQuery = { ...baseQuery, ...searchQuery };
            }

            // Additional filters
            if (params.role) {
                ValidationService.validateUserRole(params.role);
                baseQuery.role = params.role;
            }

            if (params.isActive !== undefined) {
                baseQuery.isActive = params.isActive === 'true';
            }

            if (params.tenantId && user.role === UserRole.SUPER_ADMIN) {
                ValidationService.validateObjectId(params.tenantId);
                baseQuery.tenantId = params.tenantId;
            }

            // Date range filtering
            if (params.dateFrom || params.dateTo) {
                const dateQuery = SearchService.buildDateRangeQuery(
                    params.dateFrom,
                    params.dateTo,
                    'createdAt'
                );
                baseQuery = { ...baseQuery, ...dateQuery };
            }

            // Check cache first
            const cacheKey = CacheService.generateUserListCacheKey(user, params);
            const cachedResult = await CacheService.get(cacheKey);

            if (cachedResult && !params.export) {
                logger.debug('Returning cached user list', { userId: user.userId, cacheKey });
                return res.json(cachedResult);
            }

            // Build sort criteria
            const sortCriteria = SearchService.buildSortCriteria(
                params.sortBy || 'createdAt',
                params.sortOrder || 'desc'
            );

            // Field selection optimization
            const selectFields = params.fields
                ? ValidationService.validateAndParseFields(params.fields)
                : '-password -__v';

            // Execute query with aggregation for better performance
            const aggregationPipeline = [
                { $match: baseQuery },
                { $sort: sortCriteria },
                { $skip: skip },
                { $limit: limit },
                {
                    $lookup: {
                        from: 'tenants',
                        localField: 'tenantId',
                        foreignField: '_id',
                        as: 'tenant',
                        pipeline: [{ $project: { name: 1, domain: 1, subdomain: 1 } }]
                    }
                },
                { $unwind: { path: '$tenant', preserveNullAndEmptyArrays: true } },
                {
                    $project: {
                        password: 0,
                        __v: 0,
                        ...(params.fields && SearchService.convertFieldsToProjection(params.fields))
                    }
                }
            ];

            // Add stats aggregation if requested
            if (params.includeStats === 'true') {
                aggregationPipeline.push({
                    $facet: {
                        users: [{ $skip: 0 }], // Get all users for this stage
                        stats: [
                            {
                                $group: {
                                    _id: null,
                                    totalUsers: { $sum: 1 },
                                    activeUsers: {
                                        $sum: { $cond: [{ $eq: ['$isActive', true] }, 1, 0] }
                                    },
                                    roleDistribution: {
                                        $push: '$role'
                                    }
                                }
                            }
                        ]
                    }
                });
            }

            const [users, totalCount] = await Promise.all([
                User.aggregate(aggregationPipeline),
                User.countDocuments(baseQuery)
            ]);

            // Handle export functionality
            if (params.export) {
                const exportData = await ExportService.exportUsers(
                    users,
                    params.export as 'csv' | 'xlsx' | 'pdf',
                    user
                );

                // Log export activity
                await AuditService.logActivity(user.userId, 'USER_EXPORT', {
                    format: params.export,
                    count: users.length,
                    filters: params
                });

                return res
                    .header('Content-Disposition', `attachment; filename=users.${params.export}`)
                    .header('Content-Type', ExportService.getContentType(params.export))
                    .send(exportData);
            }

            // Enhance user data with additional context
            const enhancedUsers = await Promise.all(
                users.map(async (userDoc) => {
                    const enhanced = await UserService.enhanceUserData(userDoc, user);
                    return enhanced;
                })
            );

            const responseData: PaginatedResponse<any> = {
                data: enhancedUsers,
                pagination: {
                    page,
                    limit,
                    total: totalCount,
                    totalPages: Math.ceil(totalCount / limit),
                    hasNext: page * limit < totalCount,
                    hasPrev: page > 1
                }
            };

            // Add aggregated stats if requested
            if (params.includeStats === 'true' && users.length > 0 && users[0].stats) {
                responseData.stats = users[0].stats[0];
            }

            const response: ApiResponse<PaginatedResponse<any>> = {
                success: true,
                data: responseData,
                meta: {
                    searchQuery: params.search || null,
                    appliedFilters: SearchService.getAppliedFilters(params),
                    cacheHit: false
                },
                timestamp: new Date().toISOString()
            };

            // Cache the response
            await CacheService.set(cacheKey, response, 300); // 5 minutes cache

            // Log access
            logger.info('User list accessed', {
                userId: user.userId,
                totalResults: totalCount,
                page,
                filters: params
            });

            res.json(response);
        } catch (error) {
            logger.error('Error in getUsers:', error);
            next(error);
        }
    }

    /**
     * Get detailed user information with comprehensive data
     */
    static async getUserById(req: Request, res: Response, next: NextFunction) {
        try {
            const { id } = req.params;
            const user = req.user as AuthPayload;
            const { includeActivity, includePermissions, includeStats } = req.query;

            ValidationService.validateObjectId(id);

            // Build query with RBAC
            let query = RBACService.createDatabaseFilter({
                id: user.userId,
                role: user.role,
                tenantId: user.tenantId
            });
            query._id = new mongoose.Types.ObjectId(id);

            // Check cache first
            const cacheKey = `user:${id}:${user.userId}:${includeActivity}:${includePermissions}:${includeStats}`;
            const cachedUser = await CacheService.get(cacheKey);

            if (cachedUser) {
                return res.json(cachedUser);
            }

            // Advanced aggregation query
            const aggregationPipeline = [
                { $match: query },
                {
                    $lookup: {
                        from: 'tenants',
                        localField: 'tenantId',
                        foreignField: '_id',
                        as: 'tenant'
                    }
                },
                { $unwind: { path: '$tenant', preserveNullAndEmptyArrays: true } },
                {
                    $project: {
                        password: 0,
                        __v: 0
                    }
                }
            ];

            const users = await User.aggregate(aggregationPipeline);
            const foundUser = users[0];

            if (!foundUser) {
                throw new AppError('User not found', 404);
            }

            // Enhance user data
            let enhancedUser = await UserService.enhanceUserData(foundUser, user);

            // Add activity history if requested
            if (includeActivity === 'true') {
                enhancedUser.activityHistory = await AuditService.getUserActivity(id, {
                    limit: 50,
                    includeSensitive: user.role === UserRole.SUPER_ADMIN
                });
            }

            // Add detailed permissions if requested
            if (includePermissions === 'true') {
                enhancedUser.permissions = {
                    effective: RBACService.getEffectivePermissions({
                        id: foundUser._id.toString(),
                        role: foundUser.role,
                        tenantId: foundUser.tenantId?.toString()
                    }),
                    groups: RBACService.getUserPermissionGroups(foundUser.role),
                    inherited: RBACService.getRolePermissions(foundUser.role)
                };
            }

            // Add user statistics if requested
            if (includeStats === 'true') {
                enhancedUser.stats = await UserService.getUserStatistics(id, user);
            }

            const response: ApiResponse = {
                success: true,
                data: { user: enhancedUser },
                meta: {
                    lastAccessed: new Date().toISOString(),
                    accessedBy: user.userId
                },
                timestamp: new Date().toISOString()
            };

            // Cache the response
            await CacheService.set(cacheKey, response, 600); // 10 minutes cache

            // Log access for audit
            await AuditService.logActivity(user.userId, 'USER_VIEW', {
                targetUserId: id,
                includeActivity: includeActivity === 'true',
                includePermissions: includePermissions === 'true',
                includeStats: includeStats === 'true'
            });

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * Advanced user update with comprehensive validation and audit
     */
    static async updateUser(req: Request, res: Response, next: NextFunction) {
        try {
            const { id } = req.params;
            const user = req.user as AuthPayload;
            const updateData = req.body;

            ValidationService.validateObjectId(id);
            ValidationService.validateUserUpdateData(updateData, user.role);

            // Build query with RBAC
            let query = RBACService.createDatabaseFilter({
                id: user.userId,
                role: user.role,
                tenantId: user.tenantId
            });
            query._id = new mongoose.Types.ObjectId(id);

            // Get current user data for comparison
            const currentUser = await User.findOne(query).select('-password');
            if (!currentUser) {
                throw new AppError('User not found', 404);
            }

            // Advanced permission checks
            if (updateData.role && updateData.role !== currentUser.role) {
                if (!RBACService.canAccess(user.role, 'user:changeRole')) {
                    throw new AppError('Insufficient permissions to change user role', 403);
                }

                // Prevent role escalation beyond own level
                if (!RBACService.hasRoleLevel(user.role, updateData.role)) {
                    throw new AppError('Cannot assign role higher than your own', 403);
                }
            }

            if (updateData.tenantId && updateData.tenantId !== currentUser.tenantId.toString()) {
                if (!RBACService.canAccess(user.role, 'user:changeTenant')) {
                    throw new AppError('Insufficient permissions to change user tenant', 403);
                }

                // Validate target tenant exists and is accessible
                const targetTenant = await Tenant.findById(updateData.tenantId);
                if (!targetTenant || !targetTenant.isActive) {
                    throw new AppError('Invalid target tenant', 400);
                }
            }

            // Self-update restrictions
            if (id === user.userId) {
                delete updateData.role; // Users can't change their own role
                delete updateData.isActive; // Users can't deactivate themselves
                delete updateData.tenantId; // Users can't change their own tenant
            }

            // Sanitize and prepare update data
            const sanitizedUpdateData = UserService.sanitizeUpdateData(updateData, user.role);

            // Track changes for audit
            const changes = UserService.detectChanges(currentUser, sanitizedUpdateData);

            // Perform update with optimistic locking
            const updatedUser = await User.findOneAndUpdate(
                { ...query, updatedAt: currentUser.updatedAt }, // Optimistic locking
                {
                    ...sanitizedUpdateData,
                    updatedAt: new Date(),
                    updatedBy: user.userId
                },
                {
                    new: true,
                    runValidators: true,
                    context: 'query'
                }
            ).select('-password').populate('tenantId', 'name domain subdomain');

            if (!updatedUser) {
                throw new AppError('User was modified by another process. Please refresh and try again.', 409);
            }

            // Clear related caches
            await CacheService.invalidateUserCaches(id);

            // Log audit trail
            await AuditService.logActivity(user.userId, 'USER_UPDATE', {
                targetUserId: id,
                changes,
                reason: updateData.reason || 'User profile update'
            });

            // Send notifications for significant changes
            if (changes.length > 0) {
                await NotificationService.sendUserUpdateNotification(
                    updatedUser,
                    changes,
                    user.userId
                );
            }

            // Enhance response data
            const enhancedUser = await UserService.enhanceUserData(updatedUser.toObject(), user);

            const response: ApiResponse = {
                success: true,
                data: {
                    user: enhancedUser,
                    changes: changes.map(change => ({
                        field: change.field,
                        previousValue: change.oldValue,
                        newValue: change.newValue,
                        changedAt: new Date().toISOString()
                    }))
                },
                message: 'User updated successfully',
                timestamp: new Date().toISOString()
            };

            logger.info('User updated successfully', {
                userId: user.userId,
                targetUserId: id,
                changes: changes.length
            });

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * Soft delete user with comprehensive cleanup
     */
    static async deleteUser(req: Request, res: Response, next: NextFunction) {
        try {
            const { id } = req.params;
            const user = req.user as AuthPayload;
            const { permanent, reason } = req.body;

            ValidationService.validateObjectId(id);

            // Prevent self-deletion
            if (id === user.userId) {
                throw new AppError('Cannot delete your own account', 400);
            }

            // Build query with RBAC
            let query = RBACService.createDatabaseFilter({
                id: user.userId,
                role: user.role,
                tenantId: user.tenantId
            });
            query._id = new mongoose.Types.ObjectId(id);

            const targetUser = await User.findOne(query);
            if (!targetUser || !targetUser.isActive) {
                throw new AppError('User not found or already deleted', 404);
            }

            // Permission check for permanent deletion
            if (permanent && user.role !== UserRole.SUPER_ADMIN) {
                throw new AppError('Only super admins can permanently delete users', 403);
            }

            // Role hierarchy check
            if (!RBACService.hasRoleLevel(user.role, targetUser.role)) {
                throw new AppError('Cannot delete user with equal or higher role', 403);
            }

            let deletedUser;

            if (permanent) {
                // Permanent deletion with cleanup
                await UserService.performPermanentDeletion(targetUser, user.userId, reason);
                deletedUser = targetUser.toObject();
            } else {
                // Soft deletion
                deletedUser = await User.findOneAndUpdate(
                    query,
                    {
                        isActive: false,
                        deletedAt: new Date(),
                        deletedBy: user.userId,
                        deletionReason: reason
                    },
                    { new: true }
                ).select('-password');

                // Cleanup user sessions and tokens
                await UserService.cleanupUserSessions(id);
            }

            // Clear caches
            await CacheService.invalidateUserCaches(id);

            // Log deletion
            await AuditService.logActivity(user.userId, permanent ? 'USER_PERMANENT_DELETE' : 'USER_DELETE', {
                targetUserId: id,
                targetUserEmail: targetUser.email,
                reason,
                permanent
            });

            // Send notification
            await NotificationService.sendUserDeletionNotification(
                targetUser,
                user.userId,
                permanent,
                reason
            );

            const response: ApiResponse = {
                success: true,
                data: {
                    deletedUser: {
                        id: deletedUser._id,
                        email: deletedUser.email,
                        deletedAt: deletedUser.deletedAt || new Date(),
                        permanent
                    }
                },
                message: `User ${permanent ? 'permanently deleted' : 'deactivated'} successfully`,
                timestamp: new Date().toISOString()
            };

            logger.info('User deletion completed', {
                userId: user.userId,
                targetUserId: id,
                permanent,
                reason
            });

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * Advanced bulk operations on users
     */
    static async bulkUserOperation(req: Request, res: Response, next: NextFunction) {
        try {
            const user = req.user as AuthPayload;
            const { userIds, operation, data }: BulkUserOperation = req.body;

            ValidationService.validateBulkOperation(userIds, operation, data);

            // Validate all user IDs
            userIds.forEach(id => ValidationService.validateObjectId(id));

            // Remove self from bulk operations for safety
            const filteredUserIds = userIds.filter(id => id !== user.userId);

            if (filteredUserIds.length === 0) {
                throw new AppError('No valid users selected for bulk operation', 400);
            }

            // Permission checks based on operation
            const requiredPermission = UserService.getBulkOperationPermission(operation);
            if (!RBACService.canAccess(user.role, requiredPermission)) {
                throw new AppError(`Insufficient permissions for ${operation} operation`, 403);
            }

            // Build query with RBAC
            let query = RBACService.createDatabaseFilter({
                id: user.userId,
                role: user.role,
                tenantId: user.tenantId
            });
            query._id = { $in: filteredUserIds.map(id => new mongoose.Types.ObjectId(id)) };

            // Get target users
            const targetUsers = await User.find(query);

            if (targetUsers.length === 0) {
                throw new AppError('No accessible users found for bulk operation', 404);
            }

            // Role hierarchy validation for sensitive operations
            if (['delete', 'changeRole'].includes(operation)) {
                const invalidTargets = targetUsers.filter(targetUser =>
                    !RBACService.hasRoleLevel(user.role, targetUser.role)
                );

                if (invalidTargets.length > 0) {
                    throw new AppError(
                        `Cannot perform ${operation} on users with equal or higher roles`,
                        403
                    );
                }
            }

            // Execute bulk operation
            const results = await UserService.executeBulkOperation(
                targetUsers,
                operation,
                data,
                user.userId
            );

            // Clear affected caches
            await Promise.all(
                targetUsers.map(targetUser =>
                    CacheService.invalidateUserCaches(targetUser._id.toString())
                )
            );

            // Log bulk operation
            await AuditService.logActivity(user.userId, 'USER_BULK_OPERATION', {
                operation,
                targetUserIds: targetUsers.map(u => u._id.toString()),
                data,
                successCount: results.success.length,
                failureCount: results.failures.length
            });

            // Send notifications for successful operations
            if (results.success.length > 0) {
                await NotificationService.sendBulkOperationNotification(
                    results.success,
                    operation,
                    user.userId,
                    data
                );
            }

            const response: ApiResponse = {
                success: true,
                data: {
                    operation,
                    totalRequested: filteredUserIds.length,
                    successful: results.success.length,
                    failed: results.failures.length,
                    results: {
                        success: results.success,
                        failures: results.failures
                    }
                },
                message: `Bulk ${operation} completed. ${results.success.length} successful, ${results.failures.length} failed.`,
                timestamp: new Date().toISOString()
            };

            logger.info('Bulk user operation completed', {
                userId: user.userId,
                operation,
                successCount: results.success.length,
                failureCount: results.failures.length
            });

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * Get comprehensive user statistics and analytics
     */
    static async getUserStats(req: Request, res: Response, next: NextFunction) {
        try {
            const user = req.user as AuthPayload;
            const {
                period = '30d',
                groupBy = 'day',
                includeInactive = 'false',
                tenantId
            } = req.query;

            // Permission check
            if (!RBACService.canAccess(user.role, 'analytics:read')) {
                throw new AppError('Insufficient permissions to view statistics', 403);
            }

            // Build base query with RBAC
            let baseQuery = RBACService.createDatabaseFilter({
                id: user.userId,
                role: user.role,
                tenantId: user.tenantId
            });

            if (includeInactive === 'false') {
                baseQuery.isActive = true;
            }

            if (tenantId && user.role === UserRole.SUPER_ADMIN) {
                ValidationService.validateObjectId(tenantId as string);
                baseQuery.tenantId = new mongoose.Types.ObjectId(tenantId as string);
            }

            // Check cache
            const cacheKey = `user_stats:${user.userId}:${period}:${groupBy}:${includeInactive}:${tenantId || 'all'}`;
            const cachedStats = await CacheService.get(cacheKey);

            if (cachedStats) {
                return res.json(cachedStats);
            }

            // Calculate date range
            const dateRange = SearchService.calculatePeriodRange(period as string);

            // Build comprehensive aggregation pipeline
            const stats = await UserService.generateUserStatistics(
                baseQuery,
                dateRange,
                groupBy as string,
                user
            );

            const response: ApiResponse<UserStatsResponse> = {
                success: true,
                data: stats,
                meta: {
                    period,
                    groupBy,
                    dateRange,
                    includeInactive: includeInactive === 'true',
                    generatedAt: new Date().toISOString()
                },
                timestamp: new Date().toISOString()
            };

            // Cache for 15 minutes
            await CacheService.set(cacheKey, response, 900);

            // Log analytics access
            await AuditService.logActivity(user.userId, 'USER_ANALYTICS_VIEW', {
                period,
                groupBy,
                includeInactive,
                tenantId
            });

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * Advanced user search with multiple criteria
     */
    static async searchUsers(req: Request, res: Response, next: NextFunction) {
        try {
            const user = req.user as AuthPayload;
            const {
                q: query,
                filters,
                advanced = 'false',
                highlight = 'true',
                fuzzy = 'false'
            } = req.query;

            if (!query || typeof query !== 'string') {
                throw new AppError('Search query is required', 400);
            }

            // Build search query with RBAC
            const searchResults = await SearchService.searchUsers({
                query: query as string,
                filters: filters ? JSON.parse(filters as string) : {},
                user,
                options: {
                    advanced: advanced === 'true',
                    highlight: highlight === 'true',
                    fuzzy: fuzzy === 'true',
                    limit: 50
                }
            });

            // Log search activity
            await AuditService.logActivity(user.userId, 'USER_SEARCH', {
                query,
                filters,
                resultCount: searchResults.results.length,
                advanced: advanced === 'true'
            });

            const response: ApiResponse = {
                success: true,
                data: {
                    query,
                    results: searchResults.results,
                    facets: searchResults.facets,
                    suggestions: searchResults.suggestions,
                    totalResults: searchResults.total,
                    searchTime: searchResults.searchTime
                },
                meta: {
                    advanced: advanced === 'true',
                    highlight: highlight === 'true',
                    fuzzy: fuzzy === 'true'
                },
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * User profile picture upload and management
     */
    static async uploadProfilePicture(req: Request, res: Response, next: NextFunction) {
        try {
            const { id } = req.params;
            const user = req.user as AuthPayload;

            ValidationService.validateObjectId(id);

            // Permission check - users can only update their own profile or admins can update others
            if (id !== user.userId && !RBACService.canAccess(user.role, 'user:update')) {
                throw new AppError('Insufficient permissions to update profile picture', 403);
            }

            if (!req.file) {
                throw new AppError('No file uploaded', 400);
            }

            // Validate and process image
            const processedImage = await UserService.processProfileImage(req.file);

            // Update user record
            const updatedUser = await User.findByIdAndUpdate(
                id,
                {
                    profilePicture: processedImage.url,
                    profilePictureMetadata: processedImage.metadata,
                    updatedAt: new Date()
                },
                { new: true }
            ).select('-password');

            if (!updatedUser) {
                throw new AppError('User not found', 404);
            }

            // Clear cache
            await CacheService.invalidateUserCaches(id);

            // Log activity
            await AuditService.logActivity(user.userId, 'PROFILE_PICTURE_UPDATE', {
                targetUserId: id,
                imageSize: processedImage.metadata.size,
                imageFormat: processedImage.metadata.format
            });

            const response: ApiResponse = {
                success: true,
                data: {
                    profilePicture: processedImage.url,
                    metadata: processedImage.metadata
                },
                message: 'Profile picture updated successfully',
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * Get user activity timeline
     */
    static async getUserActivity(req: Request, res: Response, next: NextFunction) {
        try {
            const { id } = req.params;
            const user = req.user as AuthPayload;
            const {
                page = '1',
                limit = '20',
                type,
                dateFrom,
                dateTo
            } = req.query;

            ValidationService.validateObjectId(id);

            // Permission check
            if (id !== user.userId && !RBACService.canAccess(user.role, 'user: