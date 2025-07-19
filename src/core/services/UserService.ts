// src/core/services/UserService.ts
import { IUser, User } from '@/core/models/User';
import { RefreshToken } from '@/core/models/RefreshToken';
import { UserRole } from '@/core/constants/roles';
import { AuthPayload } from '@/core/types';
import { AppError } from '@/core/middlewares/errorHandler';
import { logger } from '@/core/infra/logger';
import mongoose from 'mongoose';
import sharp from 'sharp';
import { v4 as uuidv4 } from 'uuid';

interface UserChange {
    field: string;
    oldValue: any;
    newValue: any;
    timestamp: Date;
}

interface BulkOperationResult {
    success: Array<{
        userId: string;
        email: string;
        operation: string;
        result: any;
    }>;
    failures: Array<{
        userId: string;
        email?: string;
        error: string;
        operation: string;
    }>;
}

interface ProcessedImage {
    url: string;
    metadata: {
        size: number;
        format: string;
        width: number;
        height: number;
        originalName: string;
    };
}

interface UserStatistics {
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

export class UserService {
    /**
     * Enhance user data with additional computed fields and context
     */
    static async enhanceUserData(userDoc: any, requestingUser: AuthPayload): Promise<any> {
        const enhanced = { ...userDoc };

        // Add computed fields
        enhanced.fullName = `${userDoc.firstName} ${userDoc.lastName}`;
        enhanced.initials = `${userDoc.firstName?.[0] || ''}${userDoc.lastName?.[0] || ''}`.toUpperCase();

        // Add status indicators
        enhanced.isOnline = await this.checkUserOnlineStatus(userDoc._id);
        enhanced.lastSeenAt = await this.getUserLastSeen(userDoc._id);

        // Add permission context for requesting user
        enhanced.canEdit = this.canUserEdit(userDoc, requestingUser);
        enhanced.canDelete = this.canUserDelete(userDoc, requestingUser);
        enhanced.canViewSensitive = this.canViewSensitiveData(userDoc, requestingUser);

        // Add account metrics
        if (enhanced.canViewSensitive) {
            enhanced.accountMetrics = {
                daysActive: this.calculateDaysActive(userDoc.createdAt, userDoc.lastLogin),
                loginCount: await this.getUserLoginCount(userDoc._id),
                profileCompleteness: this.calculateProfileCompleteness(userDoc)
            };
        }

        // Sanitize sensitive data based on permissions
        if (!enhanced.canViewSensitive) {
            delete enhanced.email;
            delete enhanced.lastLogin;
            delete enhanced.createdAt;
        }

        return enhanced;
    }

    /**
     * Detect changes between current and updated user data
     */
    static detectChanges(currentUser: IUser, updateData: any): UserChange[] {
        const changes: UserChange[] = [];
        const sensitiveFields = ['password', 'role', 'tenantId', 'isActive'];
        const trackableFields = ['firstName', 'lastName', 'email', 'role', 'tenantId', 'isActive'];

        trackableFields.forEach(field => {
            if (updateData[field] !== undefined && updateData[field] !== currentUser[field as keyof IUser]) {
                changes.push({
                    field,
                    oldValue: sensitiveFields.includes(field) ? '[REDACTED]' : currentUser[field as keyof IUser],
                    newValue: sensitiveFields.includes(field) ? '[REDACTED]' : updateData[field],
                    timestamp: new Date()
                });
            }
        });

        return changes;
    }

    /**
     * Sanitize update data based on user role and permissions
     */
    static sanitizeUpdateData(updateData: any, userRole: UserRole): any {
        const sanitized = { ...updateData };

        // Remove sensitive fields that shouldn't be updated directly
        delete sanitized.password;
        delete sanitized._id;
        delete sanitized.__v;
        delete sanitized.createdAt;
        delete sanitized.updatedAt;
        delete sanitized.lastLogin;

        // Role-based sanitization
        if (userRole !== UserRole.SUPER_ADMIN) {
            // Only super admin can change certain fields
            if (userRole !== UserRole.TENANT_ADMIN) {
                delete sanitized.role;
                delete sanitized.tenantId;
            }
        }

        // Validate role if present
        if (sanitized.role && !Object.values(UserRole).includes(sanitized.role)) {
            delete sanitized.role;
        }

        return sanitized;
    }

    /**
     * Execute bulk operations on users
     */
    static async executeBulkOperation(
        targetUsers: IUser[],
        operation: string,
        data: any,
        executingUserId: string
    ): Promise<BulkOperationResult> {
        const results: BulkOperationResult = {
            success: [],
            failures: []
        };

        for (const user of targetUsers) {
            try {
                let result;

                switch (operation) {
                    case 'activate':
                        result = await User.findByIdAndUpdate(
                            user._id,
                            {
                                isActive: true,
                                activatedAt: new Date(),
                                activatedBy: executingUserId
                            },
                            { new: true }
                        );
                        break;

                    case 'deactivate':
                        result = await User.findByIdAndUpdate(
                            user._id,
                            {
                                isActive: false,
                                deactivatedAt: new Date(),
                                deactivatedBy: executingUserId,
                                deactivationReason: data?.reason
                            },
                            { new: true }
                        );
                        // Invalidate user sessions
                        await this.invalidateUserSessions(user._id.toString());
                        break;

                    case 'changeRole':
                        if (!data?.role) {
                            throw new Error('Role is required for role change operation');
                        }
                        result = await User.findByIdAndUpdate(
                            user._id,
                            {
                                role: data.role,
                                roleChangedAt: new Date(),
                                roleChangedBy: executingUserId,
                                roleChangeReason: data?.reason
                            },
                            { new: true }
                        );
                        break;

                    case 'changeTenant':
                        if (!data?.tenantId) {
                            throw new Error('Tenant ID is required for tenant change operation');
                        }
                        result = await User.findByIdAndUpdate(
                            user._id,
                            {
                                tenantId: data.tenantId,
                                tenantChangedAt: new Date(),
                                tenantChangedBy: executingUserId,
                                tenantChangeReason: data?.reason
                            },
                            { new: true }
                        );
                        break;

                    case 'delete':
                        result = await User.findByIdAndUpdate(
                            user._id,
                            {
                                isActive: false,
                                deletedAt: new Date(),
                                deletedBy: executingUserId,
                                deletionReason: data?.reason
                            },
                            { new: true }
                        );
                        await this.invalidateUserSessions(user._id.toString());
                        break;

                    default:
                        throw new Error(`Unknown operation: ${operation}`);
                }

                results.success.push({
                    userId: user._id.toString(),
                    email: user.email,
                    operation,
                    result: result ? {
                        id: result._id,
                        email: result.email,
                        updatedAt: result.updatedAt
                    } : null
                });

            } catch (error) {
                results.failures.push({
                    userId: user._id.toString(),
                    email: user.email,
                    error: error instanceof Error ? error.message : 'Unknown error',
                    operation
                });
            }
        }

        return results;
    }

    /**
     * Get permission string for bulk operations
     */
    static getBulkOperationPermission(operation: string): string {
        const permissionMap: Record<string, string> = {
            'activate': 'user:update',
            'deactivate': 'user:update',
            'delete': 'user:delete',
            'changeRole': 'user:changeRole',
            'changeTenant': 'user:changeTenant'
        };

        return permissionMap[operation] || 'user:update';
    }

    /**
     * Generate comprehensive user statistics
     */
    static async generateUserStatistics(
        baseQuery: any,
        dateRange: { start: Date; end: Date },
        groupBy: string,
        requestingUser: AuthPayload
    ): Promise<UserStatistics> {
        const pipeline = [
            { $match: baseQuery },
            {
                $facet: {
                    totalCounts: [
                        {
                            $group: {
                                _id: null,
                                total: { $sum: 1 },
                                active: {
                                    $sum: { $cond: [{ $eq: ['$isActive', true] }, 1, 0] }
                                },
                                inactive: {
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
                    ],
                    tenantDistribution: [
                        {
                            $group: {
                                _id: '$tenantId',
                                count: { $sum: 1 }
                            }
                        }
                    ],
                    registrationTrend: [
                        {
                            $match: {
                                createdAt: {
                                    $gte: dateRange.start,
                                    $lte: dateRange.end
                                }
                            }
                        },
                        {
                            $group: {
                                _id: {
                                    $dateToString: {
                                        format: groupBy === 'day' ? '%Y-%m-%d' :
                                            groupBy === 'week' ? '%Y-W%U' : '%Y-%m',
                                        date: '$createdAt'
                                    }
                                },
                                count: { $sum: 1 }
                            }
                        },
                        { $sort: { '_id': 1 } }
                    ],
                    loginActivity: [
                        {
                            $match: {
                                lastLogin: {
                                    $gte: dateRange.start,
                                    $lte: dateRange.end,
                                    $exists: true
                                }
                            }
                        },
                        {
                            $group: {
                                _id: {
                                    $dateToString: {
                                        format: groupBy === 'day' ? '%Y-%m-%d' :
                                            groupBy === 'week' ? '%Y-W%U' : '%Y-%m',
                                        date: '$lastLogin'
                                    }
                                },
                                count: { $sum: 1 }
                            }
                        },
                        { $sort: { '_id': 1 } }
                    ],
                    recentSignups: [
                        {
                            $match: {
                                createdAt: {
                                    $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) // Last 7 days
                                }
                            }
                        },
                        {
                            $group: {
                                _id: null,
                                count: { $sum: 1 }
                            }
                        }
                    ]
                }
            }
        ];

        const [aggregationResults] = await User.aggregate(pipeline);

        // Process results
        const totalCounts = aggregationResults.totalCounts[0] || { total: 0, active: 0, inactive: 0 };

        const usersByRole: Record<UserRole, number> = Object.values(UserRole).reduce((acc, role) => {
            acc[role] = 0;
            return acc;
        }, {} as Record<UserRole, number>);

        aggregationResults.roleDistribution.forEach((item: any) => {
            if (item._id in usersByRole) {
                usersByRole[item._id as UserRole] = item.count;
            }
        });

        const usersByTenant: Record<string, number> = {};
        aggregationResults.tenantDistribution.forEach((item: any) => {
            usersByTenant[item._id?.toString() || 'unknown'] = item.count;
        });

        // Calculate growth rate
        const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        const sixtyDaysAgo = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000);

        const [currentPeriodUsers, previousPeriodUsers] = await Promise.all([
            User.countDocuments({ ...baseQuery, createdAt: { $gte: thirtyDaysAgo } }),
            User.countDocuments({
                ...baseQuery,
                createdAt: { $gte: sixtyDaysAgo, $lt: thirtyDaysAgo }
            })
        ]);

        const growthRate = previousPeriodUsers > 0
            ? ((currentPeriodUsers - previousPeriodUsers) / previousPeriodUsers) * 100
            : 0;

        return {
            totalUsers: totalCounts.total,
            activeUsers: totalCounts.active,
            inactiveUsers: totalCounts.inactive,
            usersByRole,
            usersByTenant,
            recentSignups: aggregationResults.recentSignups[0]?.count || 0,
            averageUsersPerTenant: Object.keys(usersByTenant).length > 0
                ? totalCounts.total / Object.keys(usersByTenant).length
                : 0,
            growthRate,
            registrationTrend: aggregationResults.registrationTrend.map((item: any) => ({
                date: item._id,
                count: item.count
            })),
            loginActivity: aggregationResults.loginActivity.map((item: any) => ({
                date: item._id,
                count: item.count
            }))
        };
    }

    /**
     * Process profile image upload
     */
    static async processProfileImage(file: Express.Multer.File): Promise<ProcessedImage> {
        if (!file) {
            throw new AppError('No file provided', 400);
        }

        // Validate file type
        const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
        if (!allowedTypes.includes(file.mimetype)) {
            throw new AppError('Invalid file type. Only JPEG, PNG, and WebP are allowed', 400);
        }

        // Validate file size (5MB limit)
        const maxSize = 5 * 1024 * 1024;
        if (file.size > maxSize) {
            throw new AppError('File size too large. Maximum 5MB allowed', 400);
        }

        try {
            // Process image with Sharp
            const processedBuffer = await sharp(file.buffer)
                .resize(300, 300, {
                    fit: 'cover',
                    position: 'center'
                })
                .jpeg({ quality: 90 })
                .toBuffer();

            // In a real application, you would upload to cloud storage (AWS S3, Cloudinary, etc.)
            // For this example, we'll create a mock URL
            const filename = `profile_${uuidv4()}.jpg`;
            const url = `/uploads/profiles/${filename}`;

            // Here you would save the processedBuffer to your storage system
            // await cloudStorage.upload(processedBuffer, filename);

            return {
                url,
                metadata: {
                    size: processedBuffer.length,
                    format: 'jpeg',
                    width: 300,
                    height: 300,
                    originalName: file.originalname
                }
            };
        } catch (error) {
            logger.error('Error processing profile image:', error);
            throw new AppError('Failed to process image', 500);
        }
    }

    /**
     * Perform permanent user deletion with cleanup
     */
    static async performPermanentDeletion(
        user: IUser,
        deletingUserId: string,
        reason?: string
    ): Promise<void> {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            // Delete user record
            await User.findByIdAndDelete(user._id).session(session);

            // Clean up related data
            await RefreshToken.deleteMany({ userId: user._id }).session(session);

            // Clean up other related collections (add as needed)
            // await UserSessions.deleteMany({ userId: user._id }).session(session);
            // await UserPreferences.deleteMany({ userId: user._id }).session(session);
            // await UserNotifications.deleteMany({ userId: user._id }).session(session);

            await session.commitTransaction();

            logger.info('User permanently deleted', {
                deletedUserId: user._id,
                deletedUserEmail: user.email,
                deletingUserId,
                reason
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error('Error during permanent user deletion:', error);
            throw new AppError('Failed to permanently delete user', 500);
        } finally {
            await session.endSession();
        }
    }

    /**
     * Invalidate all user sessions
     */
    static async invalidateUserSessions(userId: string): Promise<void> {
        try {
            // Revoke all refresh tokens
            await RefreshToken.updateMany(
                { userId, isRevoked: false },
                { isRevoked: true, revokedAt: new Date() }
            );

            // In a real application, you might also need to:
            // - Remove sessions from Redis/cache
            // - Add tokens to blacklist
            // - Notify other services

            logger.info('User sessions invalidated', { userId });
        } catch (error) {
            logger.error('Error invalidating user sessions:', error);
            throw new AppError('Failed to invalidate user sessions', 500);
        }
    }

    /**
     * Clean up user sessions and tokens
     */
    static async cleanupUserSessions(userId: string): Promise<void> {
        await this.invalidateUserSessions(userId);
    }

    /**
     * Get user's active sessions
     */
    static async getUserActiveSessions(userId: string): Promise<any[]> {
        const activeSessions = await RefreshToken.find({
            userId,
            isRevoked: false,
            expiresAt: { $gt: new Date() }
        }).sort({ createdAt: -1 });

        return activeSessions.map(session => ({
            id: session._id,
            createdAt: session.createdAt,
            expiresAt: session.expiresAt,
            // Add more session details as needed
        }));
    }

    /**
     * Get user statistics for individual user
     */
    static async getUserStatistics(userId: string, requestingUser: AuthPayload): Promise<any> {
        const user = await User.findById(userId);
        if (!user) {
            throw new AppError('User not found', 404);
        }

        return {
            accountAge: this.calculateDaysActive(user.createdAt, new Date()),
            loginCount: await this.getUserLoginCount(userId),
            profileCompleteness: this.calculateProfileCompleteness(user),
            lastLogin: user.lastLogin,
            sessionsCount: await this.getActiveSessionsCount(userId)
        };
    }

    /**
     * Get user restrictions based on role and context
     */
    static getUserRestrictions(targetUser: IUser, requestingUser: AuthPayload): string[] {
        const restrictions: string[] = [];

        if (targetUser._id.toString() === requestingUser.userId) {
            restrictions.push('cannot_delete_self', 'cannot_change_own_role');
        }

        if (targetUser.role === UserRole.SUPER_ADMIN && requestingUser.role !== UserRole.SUPER_ADMIN) {
            restrictions.push('cannot_modify_super_admin');
        }

        if (!targetUser.isActive) {
            restrictions.push('user_inactive');
        }

        return restrictions;
    }

    // ============================================================================
    // PRIVATE HELPER METHODS
    // ============================================================================

    private static async checkUserOnlineStatus(userId: string): Promise<boolean> {
        // In a real application, you would check Redis or another cache
        // to see if the user has an active session
        return false; // Placeholder
    }

    private static async getUserLastSeen(userId: string): Promise<Date | null> {
        const user = await User.findById(userId).select('lastLogin');
        return user?.lastLogin || null;
    }

    private static canUserEdit(targetUser: any, requestingUser: AuthPayload): boolean {
        if (requestingUser.role === UserRole.SUPER_ADMIN) return true;
        if (requestingUser.role === UserRole.TENANT_ADMIN &&
            targetUser.tenantId?.toString() === requestingUser.tenantId) return true;
        if (targetUser._id.toString() === requestingUser.userId) return true;
        return false;
    }

    private static canUserDelete(targetUser: any, requestingUser: AuthPayload): boolean {
        if (targetUser._id.toString() === requestingUser.userId) return false;
        if (requestingUser.role === UserRole.SUPER_ADMIN) return true;
        if (requestingUser.role === UserRole.TENANT_ADMIN &&
            targetUser.tenantId?.toString() === requestingUser.tenantId &&
            targetUser.role !== UserRole.SUPER_ADMIN) return true;
        return false;
    }

    private static canViewSensitiveData(targetUser: any, requestingUser: AuthPayload): boolean {
        if (requestingUser.role === UserRole.SUPER_ADMIN) return true;
        if (targetUser._id.toString() === requestingUser.userId) return true;
        if (requestingUser.role === UserRole.TENANT_ADMIN &&
            targetUser.tenantId?.toString() === requestingUser.tenantId) return true;
        return false;
    }

    private static calculateDaysActive(createdAt: Date, lastLogin?: Date): number {
        const endDate = lastLogin || new Date();
        const diffTime = Math.abs(endDate.getTime() - createdAt.getTime());
        return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    }

    private static async getUserLoginCount(userId: string): Promise<number> {
        // In a real application, you would track login counts
        // This is a placeholder
        return 0;
    }

    private static calculateProfileCompleteness(user: IUser): number {
        const fields = ['firstName', 'lastName', 'email'];
        const completed = fields.filter(field => user[field as keyof IUser]).length;
        return Math.round((completed / fields.length) * 100);
    }

    private static async getActiveSessionsCount(userId: string): Promise<number> {
        return RefreshToken.countDocuments({
            userId,
            isRevoked: false,
            expiresAt: {$gt: new Date()}
        });
    }
}