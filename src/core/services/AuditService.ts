// src/core/services/AuditService.ts
import mongoose, { Schema, Document } from 'mongoose';
import { logger } from '@/core/infra/logger';
import { AuthPayload } from '@/core/types';

// Audit Log Model
interface IAuditLog extends Document {
    userId: mongoose.Types.ObjectId;
    action: string;
    resource: string;
    resourceId?: string;
    details: any;
    ipAddress?: string;
    userAgent?: string;
    timestamp: Date;
    tenantId?: mongoose.Types.ObjectId;
    metadata?: any;
}

const auditLogSchema = new Schema<IAuditLog>({
    userId: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
    },
    action: {
        type: String,
        required: true,
        index: true
    },
    resource: {
        type: String,
        required: true,
        index: true
    },
    resourceId: {
        type: String,
        index: true
    },
    details: {
        type: Schema.Types.Mixed,
        default: {}
    },
    ipAddress: {
        type: String
    },
    userAgent: {
        type: String
    },
    timestamp: {
        type: Date,
        default: Date.now,
        index: true
    },
    tenantId: {
        type: Schema.Types.ObjectId,
        ref: 'Tenant',
        index: true
    },
    metadata: {
        type: Schema.Types.Mixed,
        default: {}
    }
}, {
    timestamps: true
});

// Create compound indexes for better query performance
auditLogSchema.index({ userId: 1, timestamp: -1 });
auditLogSchema.index({ tenantId: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });
auditLogSchema.index({ resource: 1, resourceId: 1 });

// TTL index for automatic log cleanup (optional - keep logs for 2 years)
auditLogSchema.index({ timestamp: 1 }, { expireAfterSeconds: 2 * 365 * 24 * 60 * 60 });

const AuditLog = mongoose.model<IAuditLog>('AuditLog', auditLogSchema);

interface ActivityOptions {
    page?: number;
    limit?: number;
    type?: string;
    dateFrom?: string;
    dateTo?: string;
    includeSensitive?: boolean;
}

interface AuditContext {
    ipAddress?: string;
    userAgent?: string;
    tenantId?: string;
    metadata?: any;
}

export class AuditService {
    // Sensitive actions that require special handling
    private static sensitiveActions = [
        'PASSWORD_RESET', 'PASSWORD_CHANGE', 'ROLE_CHANGE', 'PERMISSION_CHANGE',
        'USER_DELETE', 'USER_PERMANENT_DELETE', 'DATA_EXPORT', 'BULK_OPERATION'
    ];

    // Actions that should be logged with minimal details for privacy
    private static privacyActions = [
        'LOGIN', 'LOGOUT', 'PROFILE_VIEW', 'USER_VIEW'
    ];

    /**
     * Log user activity with comprehensive details
     */
    static async logActivity(
        userId: string,
        action: string,
        details: any = {},
        context: AuditContext = {}
    ): Promise<void> {
        try {
            const resource = this.extractResourceFromAction(action);
            const sanitizedDetails = this.sanitizeDetails(action, details);

            const auditEntry = new AuditLog({
                userId: new mongoose.Types.ObjectId(userId),
                action,
                resource,
                resourceId: details.targetUserId || details.resourceId || details.id,
                details: sanitizedDetails,
                ipAddress: context.ipAddress,
                userAgent: context.userAgent,
                tenantId: context.tenantId ? new mongoose.Types.ObjectId(context.tenantId) : undefined,
                metadata: {
                    ...context.metadata,
                    severity: this.getActionSeverity(action),
                    category: this.getActionCategory(action)
                }
            });

            await auditEntry.save();

            // Log to application logger for immediate visibility
            logger.info('Activity logged', {
                userId,
                action,
                resource,
                resourceId: auditEntry.resourceId,
                timestamp: auditEntry.timestamp,
                severity: auditEntry.metadata?.severity
            });

            // For critical actions, also log to security log
            if (this.isCriticalAction(action)) {
                await this.logCriticalAction(auditEntry);
            }

        } catch (error) {
            logger.error('Failed to log activity:', error);
            // Don't throw error to avoid disrupting main application flow
        }
    }

    /**
     * Get user activity history with filtering and pagination
     */
    static async getUserActivity(
        userId: string,
        options: ActivityOptions = {}
    ): Promise<any> {
        try {
            const {
                page = 1,
                limit = 20,
                type,
                dateFrom,
                dateTo,
                includeSensitive = false
            } = options;

            const skip = (page - 1) * limit;

            // Build query
            let query: any = { userId: new mongoose.Types.ObjectId(userId) };

            if (type) {
                query.action = { $regex: type, $options: 'i' };
            }

            if (dateFrom || dateTo) {
                query.timestamp = {};
                if (dateFrom) query.timestamp.$gte = new Date(dateFrom);
                if (dateTo) query.timestamp.$lte = new Date(dateTo);
            }

            // Filter out sensitive actions if not authorized
            if (!includeSensitive) {
                query.action = {
                    $nin: this.sensitiveActions,
                    ...(query.action || {})
                };
            }

            // Execute query with aggregation for better performance
            const pipeline = [
                { $match: query },
                { $sort: { timestamp: -1 } },
                { $skip: skip },
                { $limit: limit },
                {
                    $lookup: {
                        from: 'users',
                        localField: 'userId',
                        foreignField: '_id',
                        as: 'user',
                        pipeline: [
                            { $project: { firstName: 1, lastName: 1, email: 1 } }
                        ]
                    }
                },
                { $unwind: { path: '$user', preserveNullAndEmptyArrays: true } },
                {
                    $project: {
                        action: 1,
                        resource: 1,
                        resourceId: 1,
                        details: includeSensitive ? 1 : this.createSafeDetailsProjection(),
                        timestamp: 1,
                        ipAddress: includeSensitive ? 1 : 0,
                        metadata: 1,
                        user: 1
                    }
                }
            ];

            const [activities, totalCount] = await Promise.all([
                AuditLog.aggregate(pipeline),
                AuditLog.countDocuments(query)
            ]);

            return {
                activities: activities.map(activity => ({
                    ...activity,
                    description: this.generateActivityDescription(activity),
                    icon: this.getActivityIcon(activity.action),
                    severity: activity.metadata?.severity || 'info'
                })),
                pagination: {
                    page,
                    limit,
                    total: totalCount,
                    totalPages: Math.ceil(totalCount / limit),
                    hasNext: page * limit < totalCount,
                    hasPrev: page > 1
                }
            };

        } catch (error) {
            logger.error('Error fetching user activity:', error);
            throw error;
        }
    }

    /**
     * Get system-wide audit logs (admin only)
     */
    static async getSystemAuditLogs(
        user: AuthPayload,
        options: any = {}
    ): Promise<any> {
        try {
            const {
                page = 1,
                limit = 50,
                action,
                userId,
                resource,
                dateFrom,
                dateTo,
                tenantId
            } = options;

            const skip = (page - 1) * limit;

            // Build query
            let query: any = {};

            // Tenant filtering
            if (user.role !== 'SUPER_ADMIN') {
                query.tenantId = new mongoose.Types.ObjectId(user.tenantId);
            } else if (tenantId) {
                query.tenantId = new mongoose.Types.ObjectId(tenantId);
            }

            if (action) query.action = action;
            if (userId) query.userId = new mongoose.Types.ObjectId(userId);
            if (resource) query.resource = resource;

            if (dateFrom || dateTo) {
                query.timestamp = {};
                if (dateFrom) query.timestamp.$gte = new Date(dateFrom);
                if (dateTo) query.timestamp.$lte = new Date(dateTo);
            }

            const pipeline = [
                { $match: query },
                { $sort: { timestamp: -1 } },
                { $skip: skip },
                { $limit: limit },
                {
                    $lookup: {
                        from: 'users',
                        localField: 'userId',
                        foreignField: '_id',
                        as: 'user',
                        pipeline: [
                            { $project: { firstName: 1, lastName: 1, email: 1, role: 1 } }
                        ]
                    }
                },
                { $unwind: { path: '$user', preserveNullAndEmptyArrays: true } },
                {
                    $lookup: {
                        from: 'tenants',
                        localField: 'tenantId',
                        foreignField: '_id',
                        as: 'tenant',
                        pipeline: [
                            { $project: { name: 1, domain: 1 } }
                        ]
                    }
                },
                { $unwind: { path: '$tenant', preserveNullAndEmptyArrays: true } }
            ];

            const [logs, totalCount] = await Promise.all([
                AuditLog.aggregate(pipeline),
                AuditLog.countDocuments(query)
            ]);

            return {
                logs,
                pagination: {
                    page,
                    limit,
                    total: totalCount,
                    totalPages: Math.ceil(totalCount / limit)
                }
            };

        } catch (error) {
            logger.error('Error fetching system audit logs:', error);
            throw error;
        }
    }

    /**
     * Get audit statistics
     */
    static async getAuditStatistics(
        user: AuthPayload,
        dateRange: { start: Date; end: Date }
    ): Promise<any> {
        try {
            let baseQuery: any = {
                timestamp: {
                    $gte: dateRange.start,
                    $lte: dateRange.end
                }
            };

            // Apply tenant filtering
            if (user.role !== 'SUPER_ADMIN') {
                baseQuery.tenantId = new mongoose.Types.ObjectId(user.tenantId);
            }

            const pipeline = [
                { $match: baseQuery },
                {
                    $facet: {
                        actionCounts: [
                            {
                                $group: {
                                    _id: '$action',
                                    count: { $sum: 1 }
                                }
                            },
                            { $sort: { count: -1 } }
                        ],
                        resourceCounts: [
                            {
                                $group: {
                                    _id: '$resource',
                                    count: { $sum: 1 }
                                }
                            },
                            { $sort: { count: -1 } }
                        ],
                        dailyActivity: [
                            {
                                $group: {
                                    _id: {
                                        $dateToString: {
                                            format: '%Y-%m-%d',
                                            date: '$timestamp'
                                        }
                                    },
                                    count: { $sum: 1 }
                                }
                            },
                            { $sort: { '_id': 1 } }
                        ],
                        topUsers: [
                            {
                                $group: {
                                    _id: '$userId',
                                    count: { $sum: 1 }
                                }
                            },
                            { $sort: { count: -1 } },
                            { $limit: 10 },
                            {
                                $lookup: {
                                    from: 'users',
                                    localField: '_id',
                                    foreignField: '_id',
                                    as: 'user',
                                    pipeline: [
                                        { $project: { firstName: 1, lastName: 1, email: 1 } }
                                    ]
                                }
                            },
                            { $unwind: { path: '$user', preserveNullAndEmptyArrays: true } }
                        ],
                        severityDistribution: [
                            {
                                $group: {
                                    _id: '$metadata.severity',
                                    count: { $sum: 1 }
                                }
                            }
                        ]
                    }
                }
            ];

            const [results] = await AuditLog.aggregate(pipeline);

            return {
                totalEvents: await AuditLog.countDocuments(baseQuery),
                actionCounts: results.actionCounts,
                resourceCounts: results.resourceCounts,
                dailyActivity: results.dailyActivity,
                topUsers: results.topUsers,
                severityDistribution: results.severityDistribution,
                dateRange
            };

        } catch (error) {
            logger.error('Error fetching audit statistics:', error);
            throw error;
        }
    }

    /**
     * Export audit logs
     */
    static async exportAuditLogs(
        user: AuthPayload,
        filters: any = {},
        format: 'csv' | 'json' = 'csv'
    ): Promise<any> {
        try {
            let query: any = {};

            // Apply tenant filtering
            if (user.role !== 'SUPER_ADMIN') {
                query.tenantId = new mongoose.Types.ObjectId(user.tenantId);
            }

            // Apply additional filters
            Object.assign(query, filters);

            const logs = await AuditLog.find(query)
                .populate('userId', 'firstName lastName email')
                .populate('tenantId', 'name domain')
                .sort({ timestamp: -1 })
                .limit(10000) // Limit to prevent memory issues
                .lean();

            if (format === 'json') {
                return JSON.stringify(logs, null, 2);
            }

            // Convert to CSV
            const csvHeaders = [
                'Timestamp', 'User', 'Action', 'Resource', 'Resource ID',
                'IP Address', 'Details', 'Tenant'
            ];

            const csvRows = logs.map(log => [
                log.timestamp.toISOString(),
                log.userId ? `${log.userId.firstName} ${log.userId.lastName} (${log.userId.email})` : 'Unknown',
                log.action,
                log.resource,
                log.resourceId || '',
                log.ipAddress || '',
                JSON.stringify(log.details),
                log.tenantId ? log.tenantId.name : ''
            ]);

            const csvContent = [csvHeaders, ...csvRows]
                .map(row => row.map(field => `"${field}"`).join(','))
                .join('\n');

            return csvContent;

        } catch (error) {
            logger.error('Error exporting audit logs:', error);
            throw error;
        }
    }

    /**
     * Clean up old audit logs
     */
    static async cleanupOldLogs(retentionDays: number = 730): Promise<number> {
        try {
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

            const result = await AuditLog.deleteMany({
                timestamp: { $lt: cutoffDate }
            });

            logger.info(`Cleaned up ${result.deletedCount} old audit logs`);
            return result.deletedCount || 0;

        } catch (error) {
            logger.error('Error cleaning up audit logs:', error);
            throw error;
        }
    }

    // ============================================================================
    // PRIVATE HELPER METHODS
    // ============================================================================

    private static extractResourceFromAction(action: string): string {
        if (action.includes('USER')) return 'user';
        if (action.includes('TENANT')) return 'tenant';
        if (action.includes('AUTH')) return 'auth';
        if (action.includes('PERMISSION')) return 'permission';
        if (action.includes('ROLE')) return 'role';
        if (action.includes('SESSION')) return 'session';
        if (action.includes('PASSWORD')) return 'password';
        if (action.includes('PROFILE')) return 'profile';
        if (action.includes('EXPORT')) return 'export';
        if (action.includes('ANALYTICS')) return 'analytics';
        return 'system';
    }

    private static sanitizeDetails(action: string, details: any): any {
        const sanitized = { ...details };

        // Remove sensitive information
        if (this.privacyActions.includes(action)) {
            delete sanitized.password;
            delete sanitized.token;
            delete sanitized.refreshToken;
        }

        // Redact sensitive fields for certain actions
        if (this.sensitiveActions.includes(action)) {
            if (sanitized.password) sanitized.password = '[REDACTED]';
            if (sanitized.oldPassword) sanitized.oldPassword = '[REDACTED]';
            if (sanitized.newPassword) sanitized.newPassword = '[REDACTED]';
        }

        return sanitized;
    }

    private static getActionSeverity(action: string): 'low' | 'medium' | 'high' | 'critical' {
        if (['USER_PERMANENT_DELETE', 'BULK_OPERATION', 'ROLE_CHANGE'].includes(action)) {
            return 'critical';
        }
        if (['USER_DELETE', 'PASSWORD_RESET', 'USER_DEACTIVATE'].includes(action)) {
            return 'high';
        }
        if (['USER_UPDATE', 'USER_CREATE', 'LOGIN_FAILED'].includes(action)) {
            return 'medium';
        }
        return 'low';
    }

    private static getActionCategory(action: string): string {
        if (action.includes('AUTH') || action.includes('LOGIN')) return 'authentication';
        if (action.includes('USER')) return 'user_management';
        if (action.includes('PERMISSION') || action.includes('ROLE')) return 'authorization';
        if (action.includes('EXPORT') || action.includes('DATA')) return 'data_access';
        if (action.includes('PASSWORD')) return 'security';
        return 'general';
    }

    private static isCriticalAction(action: string): boolean {
        return this.getActionSeverity(action) === 'critical';
    }

    private static async logCriticalAction(auditEntry: IAuditLog): Promise<void> {
        try {
            // In a real application, you might:
            // - Send alerts to security team
            // - Log to external security system
            // - Trigger automated responses

            logger.warn('Critical action logged', {
                userId: auditEntry.userId,
                action: auditEntry.action,
                timestamp: auditEntry.timestamp,
                details: auditEntry.details
            });

        } catch (error) {
            logger.error('Error logging critical action:', error);
        }
    }

    private static createSafeDetailsProjection(): any {
        return {
            $cond: {
                if: { $in: ['$action', this.sensitiveActions] },
                then: { summary: 'Sensitive action - details hidden' },
                else: '$details'
            }
        };
    }

    private static generateActivityDescription(activity: any): string {
        const { action, details, resource } = activity;

        switch (action) {
            case 'USER_CREATE':
                return `Created user account for ${details.email || 'unknown user'}`;
            case 'USER_UPDATE':
                return `Updated user profile${details.targetUserEmail ? ` for ${details.targetUserEmail}` : ''}`;
            case 'USER_DELETE':
                return `Deleted user account${details.targetUserEmail ? ` for ${details.targetUserEmail}` : ''}`;
            case 'LOGIN':
                return 'Logged into the system';
            case 'LOGOUT':
                return 'Logged out of the system';
            case 'PASSWORD_RESET':
                return `Reset password${details.targetUserEmail ? ` for ${details.targetUserEmail}` : ''}`;
            case 'ROLE_CHANGE':
                return `Changed user role${details.targetUserEmail ? ` for ${details.targetUserEmail}` : ''}`;
            case 'BULK_OPERATION':
                return `Performed bulk ${details.operation} on ${details.successCount || 0} users`;
            case 'USER_EXPORT':
                return `Exported user data in ${details.format} format`;
            case 'PROFILE_PICTURE_UPDATE':
                return 'Updated profile picture';
            default:
                return `Performed ${action.toLowerCase().replace(/_/g, ' ')} on ${resource}`;
        }
    }

    private static getActivityIcon(action: string): string {
        const iconMap: Record<string, string> = {
            'USER_CREATE': 'user-plus',
            'USER_UPDATE': 'user-edit',
            'USER_DELETE': 'user-minus',
            'LOGIN': 'log-in',
            'LOGOUT': 'log-out',
            'PASSWORD_RESET': 'key',
            'ROLE_CHANGE': 'shield',
            'BULK_OPERATION': 'layers',
            'USER_EXPORT': 'download',
            'PROFILE_PICTURE_UPDATE': 'image'
        };

        return iconMap[action] || 'activity';
    }
}