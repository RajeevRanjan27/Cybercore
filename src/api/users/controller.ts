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
import mongoose, {PipelineStage} from 'mongoose';

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
    registrationTrend: Array<{
        date: string;
        count: number;
    }>;
    loginActivity: Array<{
        date: string;
        count: number;
    }>;
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
            let users: any[];
            let stats: any = null;

            if (params.includeStats === 'true') {
                // When including stats, we need a different aggregation approach
                const statsAggregationPipeline: PipelineStage[] = [
                    { $match: baseQuery },
                    {
                        $facet: {
                            users: [
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
                            ],
                            stats: [
                                {
                                    $group: {
                                        _id: null,
                                        totalUsers: { $sum: 1 },
                                        activeUsers: {
                                            $sum: { $cond: [{ $eq: ['$isActive', true] }, 1, 0] }
                                        },
                                        inactiveUsers: {
                                            $sum: { $cond: [{ $eq: ['$isActive', false] }, 1, 0] }
                                        }
                                    }
                                }
                            ],
                            roleDistribution: [
                                {
                                    $group: {
                                        _id: '$role',
                                        count: { $sum: 1 }
                                    }
                                }
                            ]
                        }
                    }
                ];

                const facetResults = await User.aggregate(statsAggregationPipeline);
                const facetData = facetResults[0] || { users: [], stats: [], roleDistribution: [] };

                users = facetData.users || [];

                // Process stats
                if (facetData.stats && facetData.stats[0]) {
                    const roleStats: Record<string, number> = {};
                    (facetData.roleDistribution || []).forEach((item: any) => {
                        if (item._id) {
                            roleStats[item._id] = item.count;
                        }
                    });

                    stats = {
                        ...facetData.stats[0],
                        roleDistribution: roleStats
                    };
                }
            } else {
                // Normal aggregation without stats
                const aggregationPipeline: PipelineStage[] = [
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

                users = await User.aggregate(aggregationPipeline);
            }

            const totalCount = await User.countDocuments(baseQuery);

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

            // Build response data with meta included
            const responseData: any = {
                users: enhancedUsers,
                pagination: {
                    page,
                    limit,
                    total: totalCount,
                    totalPages: Math.ceil(totalCount / limit),
                    hasNext: page * limit < totalCount,
                    hasPrev: page > 1
                },
                meta: {
                    searchQuery: params.search || null,
                    appliedFilters: SearchService.getAppliedFilters(params),
                    cacheHit: false,
                    includeStats: params.includeStats === 'true'
                }
            };

            // Add aggregated stats if requested
            if (params.includeStats === 'true' && stats) {
                responseData.stats = stats;
            }

            const response: ApiResponse = {
                success: true,
                data: responseData,
                message: `Retrieved ${enhancedUsers.length} users`,
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
    }    /**
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

            // Create response with meta included in data
            const responseData = {
                user: enhancedUser,
                meta: {
                    lastAccessed: new Date().toISOString(),
                    accessedBy: user.userId,
                    includesActivity: includeActivity === 'true',
                    includesPermissions: includePermissions === 'true',
                    includesStats: includeStats === 'true'
                }
            };

            const response: ApiResponse = {
                success: true,
                data: responseData,
                message: 'User details retrieved successfully',
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

                if (!deletedUser) {
                    // This handles the case where the user wasn't found by the update query.
                    throw new AppError('User not found or could not be updated', 404);
                }

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
                    CacheService.invalidateUserCaches(String(targetUser._id))
                )
            );

            // Log bulk operation
            await AuditService.logActivity(user.userId, 'USER_BULK_OPERATION', {
                operation,
                targetUserIds: targetUsers.map(u => String(u._id)),
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


            const responseData = {
                ...stats,
                meta: {
                    period,
                    groupBy,
                    dateRange,
                    includeInactive: includeInactive === 'true',
                    generatedAt: new Date().toISOString()
                }
            };

            const response: ApiResponse = {
                success: true,
                data: responseData,
                message: 'User statistics retrieved successfully',
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


            // Create response with meta included in data
            const responseData = {
                query,
                results: searchResults.results,
                facets: searchResults.facets,
                suggestions: searchResults.suggestions,
                totalResults: searchResults.total,
                searchTime: searchResults.searchTime,
                meta: {
                    advanced: advanced === 'true',
                    highlight: highlight === 'true',
                    fuzzy: fuzzy === 'true'
                }
            };

            const response: ApiResponse = {
                success: true,
                data: responseData,
                message: `Found ${searchResults.total} users matching your search`,
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
            if (id !== user.userId && !RBACService.canAccess(user.role, 'user:read')) {
                throw new AppError('Insufficient permissions to view user activity', 403);
            }

            // Validate date range if provided
            if (dateFrom || dateTo) {
                ValidationService.validateDateRange(dateFrom as string, dateTo as string);
            }

            // Parse pagination
            const pageNum = parseInt(page as string);
            const limitNum = parseInt(limit as string);

            // Get user to ensure they exist
            const targetUser = await User.findById(id);
            if (!targetUser) {
                throw new AppError('User not found', 404);
            }

            // Check if requesting user can view activity for target user
            if (user.role !== UserRole.SUPER_ADMIN) {
                if (user.role === UserRole.TENANT_ADMIN) {
                    // Tenant admin can only view users in their tenant
                    if (targetUser.tenantId.toString() !== user.tenantId) {
                        throw new AppError('Cannot view activity for users outside your tenant', 403);
                    }
                } else if (user.role === UserRole.USER) {
                    // Regular users can only view their own activity
                    if (id !== user.userId) {
                        throw new AppError('Cannot view activity for other users', 403);
                    }
                }
            }

            // Get activity from AuditService
            const activityData = await AuditService.getUserActivity(id, {
                page: pageNum,
                limit: limitNum,
                type: type as string,
                dateFrom: dateFrom as string,
                dateTo: dateTo as string,
                includeSensitive: user.role === UserRole.SUPER_ADMIN || id === user.userId
            });

            // Enhance activity data with additional context
            const enhancedActivity = {
                ...activityData,
                user: {
                    id: targetUser._id,
                    firstName: targetUser.firstName,
                    lastName: targetUser.lastName,
                    email: targetUser.email,
                    role: targetUser.role
                },
                meta: {
                    requestedBy: user.userId,
                    requestedAt: new Date().toISOString(),
                    filters: {
                        type: type || null,
                        dateFrom: dateFrom || null,
                        dateTo: dateTo || null
                    }
                }
            };

            const response: ApiResponse = {
                success: true,
                data: enhancedActivity,
                message: 'User activity retrieved successfully',
                timestamp: new Date().toISOString()
            };

            // Log access for audit
            await AuditService.logActivity(user.userId, 'USER_ACTIVITY_VIEW', {
                targetUserId: id,
                filters: {
                    type,
                    dateFrom,
                    dateTo,
                    page: pageNum,
                    limit: limitNum
                }
            });

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * Export user data in specified format
     */
    static async exportUserData(req: Request, res: Response, next: NextFunction) {
        try {
            const user = req.user as AuthPayload;
            const { format = 'csv', filters, fields, includeInactive } = req.query;

            // Parse filters if provided
            const parsedFilters = filters ? JSON.parse(filters as string) : {};

            // Build query with RBAC
            let baseQuery = RBACService.createDatabaseFilter({
                id: user.userId,
                role: user.role,
                tenantId: user.tenantId
            });

            // Apply filters
            if (includeInactive !== 'true') {
                baseQuery.isActive = true;
            }

            // Apply additional filters
            Object.assign(baseQuery, parsedFilters);

            // Get users for export
            const users = await User.find(baseQuery)
                .populate('tenantId', 'name domain')
                .select(fields as string || '-password -__v')
                .lean();

            // Export data
            const exportData = await ExportService.exportUsers(
                users,
                format as 'csv' | 'xlsx' | 'pdf' | 'json',
                user
            );

            // Log export
            await AuditService.logActivity(user.userId, 'USER_EXPORT', {
                format,
                count: users.length,
                filters: parsedFilters
            });

            // Set response headers
            const filename = ExportService.generateFileName('users', format as string);
            res.set({
                'Content-Disposition': `attachment; filename="${filename}"`,
                'Content-Type': ExportService.getContentType(format as string)
            });

            res.send(exportData);
        } catch (error) {
            next(error);
        }
    }

    /**
     * Get users by specific role
     */
    static async getUsersByRole(req: Request, res: Response, next: NextFunction) {
        try {
            const user = req.user as AuthPayload;
            const { role } = req.params;
            const { page = '1', limit = '10', isActive, tenantId, sortBy = 'createdAt', sortOrder = 'desc' } = req.query;

            // Validate role
            ValidationService.validateUserRole(role);

            // Parse pagination
            const pageNum = parseInt(page as string);
            const limitNum = parseInt(limit as string);
            const skip = (pageNum - 1) * limitNum;

            // Build query with RBAC
            let baseQuery = RBACService.createDatabaseFilter({
                id: user.userId,
                role: user.role,
                tenantId: user.tenantId
            });

            // Add role filter
            baseQuery.role = role as UserRole;

            // Add optional filters
            if (isActive !== undefined) {
                baseQuery.isActive = isActive === 'true';
            }

            if (tenantId && user.role === UserRole.SUPER_ADMIN) {
                ValidationService.validateObjectId(tenantId as string);
                baseQuery.tenantId = tenantId;
            }

            // Get users and count
            const [users, total] = await Promise.all([
                User.find(baseQuery)
                    .populate('tenantId', 'name domain')
                    .sort({ [sortBy as string]: sortOrder === 'asc' ? 1 : -1 })
                    .skip(skip)
                    .limit(limitNum)
                    .select('-password -__v')
                    .lean(),
                User.countDocuments(baseQuery)
            ]);

            // Enhance user data
            const enhancedUsers = await Promise.all(
                users.map(userDoc => UserService.enhanceUserData(userDoc, user))
            );

            const response: ApiResponse = {
                success: true,
                data: {
                    users: enhancedUsers,
                    pagination: {
                        page: pageNum,
                        limit: limitNum,
                        total,
                        totalPages: Math.ceil(total / limitNum),
                        hasNext: pageNum * limitNum < total,
                        hasPrev: pageNum > 1
                    },
                    role
                },
                message: `Found ${users.length} users with role ${role}`,
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * Toggle user activation status
     */
    static async toggleUserStatus(req: Request, res: Response, next: NextFunction) {
        try {
            const { id } = req.params;
            const { reason } = req.body;
            const user = req.user as AuthPayload;

            ValidationService.validateObjectId(id);

            // Get current user
            const targetUser = await User.findById(id);
            if (!targetUser) {
                throw new AppError('User not found', 404);
            }

            // Permission checks
            if (id === user.userId) {
                throw new AppError('Cannot change your own status', 400);
            }

            if (!RBACService.hasRoleLevel(user.role, targetUser.role)) {
                throw new AppError('Cannot modify user with equal or higher role', 403);
            }

            // Toggle status
            const newStatus = !targetUser.isActive;
            const updatedUser = await User.findByIdAndUpdate(
                id,
                {
                    isActive: newStatus,
                    ...(newStatus ? {
                        activatedAt: new Date(),
                        activatedBy: user.userId
                    } : {
                        deactivatedAt: new Date(),
                        deactivatedBy: user.userId,
                        deactivationReason: reason
                    }),
                    updatedAt: new Date()
                },
                { new: true }
            ).select('-password');

            // If deactivating, invalidate sessions
            if (!newStatus) {
                await UserService.invalidateUserSessions(id);
            }

            // Clear cache
            await CacheService.invalidateUserCaches(id);

            // Log activity
            await AuditService.logActivity(user.userId, newStatus ? 'USER_ACTIVATE' : 'USER_DEACTIVATE', {
                targetUserId: id,
                reason
            });

            // Send notification
            await NotificationService.sendUserStatusChangeNotification(
                updatedUser!,
                newStatus,
                user.userId,
                reason
            );

            const response: ApiResponse = {
                success: true,
                data: {
                    user: await UserService.enhanceUserData(updatedUser!.toObject(), user),
                    statusChanged: true,
                    newStatus
                },
                message: `User ${newStatus ? 'activated' : 'deactivated'} successfully`,
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * Reset user password (admin only)
     */
    static async resetUserPassword(req: Request, res: Response, next: NextFunction) {
        try {
            const { id } = req.params;
            const { newPassword, forceChange = true, notifyUser = true, reason } = req.body;
            const user = req.user as AuthPayload;

            ValidationService.validateObjectId(id);
            ValidationService.validatePassword(newPassword);

            // Get target user
            const targetUser = await User.findById(id);
            if (!targetUser) {
                throw new AppError('User not found', 404);
            }

            // Permission checks
            if (!RBACService.hasRoleLevel(user.role, targetUser.role)) {
                throw new AppError('Cannot reset password for user with equal or higher role', 403);
            }

            // Update password
            targetUser.password = newPassword;
            if (forceChange) {
                (targetUser as any).requirePasswordChange = true;
            }
            (targetUser as any).passwordResetAt = new Date();
            (targetUser as any).passwordResetBy = user.userId;
            await targetUser.save();

            // Invalidate all user sessions
            await UserService.invalidateUserSessions(id);

            // Log activity
            await AuditService.logActivity(user.userId, 'PASSWORD_RESET', {
                targetUserId: id,
                forceChange,
                reason
            });

            // Send notification if requested
            if (notifyUser) {
                await NotificationService.sendPasswordResetNotification(
                    targetUser,
                    user.userId,
                    forceChange
                );
            }

            const response: ApiResponse = {
                success: true,
                data: {
                    userId: id,
                    forceChange,
                    notificationSent: notifyUser
                },
                message: 'Password reset successfully',
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * Get user permissions and access levels
     */
    static async getUserPermissions(req: Request, res: Response, next: NextFunction) {
        try {
            const { id } = req.params;
            const user = req.user as AuthPayload;

            ValidationService.validateObjectId(id);

            // Get target user
            const targetUser = await User.findById(id).select('-password');
            if (!targetUser) {
                throw new AppError('User not found', 404);
            }

            // Permission check
            if (id !== user.userId && !RBACService.canAccess(user.role, 'user:read')) {
                throw new AppError('Insufficient permissions to view user permissions', 403);
            }

            // Get permissions data
            const permissions = {
                role: targetUser.role,
                effectivePermissions: RBACService.getEffectivePermissions({
                    id: String(targetUser._id),
                    role: targetUser.role,
                    tenantId: targetUser.tenantId?.toString()
                }),
                permissionGroups: RBACService.getUserPermissionGroups(targetUser.role),
                inheritedPermissions: RBACService.getRolePermissions(targetUser.role),
                roleHierarchy: {
                    canManage: Object.values(UserRole).filter(role =>
                        RBACService.hasRoleLevel(targetUser.role, role) && role !== targetUser.role
                    ),
                    isManagedBy: Object.values(UserRole).filter(role =>
                        RBACService.hasRoleLevel(role, targetUser.role) && role !== targetUser.role
                    )
                }
            };

            const response: ApiResponse = {
                success: true,
                data: {
                    user: {
                        id: targetUser._id,
                        email: targetUser.email,
                        firstName: targetUser.firstName,
                        lastName: targetUser.lastName,
                        role: targetUser.role
                    },
                    permissions
                },
                message: 'User permissions retrieved successfully',
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

}

