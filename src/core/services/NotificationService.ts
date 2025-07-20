// src/core/services/NotificationService.ts
import { IUser } from '@/core/models/User';
import { logger } from '@/core/infra/logger';

interface EmailTemplate {
    subject: string;
    html: string;
    text: string;
}

interface NotificationPreferences {
    email: boolean;
    sms: boolean;
    push: boolean;
    inApp: boolean;
}

interface EmailConfig {
    from: string;
    replyTo?: string;
    priority?: 'high' | 'normal' | 'low';
    attachments?: Array<{
        filename: string;
        content: Buffer;
        contentType: string;
    }>;
}

export class NotificationService {
    // In a real application, you would configure email service (SendGrid, AWS SES, etc.)
    private static emailProvider: any = null;
    private static smsProvider: any = null;
    private static pushProvider: any = null;

    /**
     * Initialize notification service with providers
     */
    static async initialize(): Promise<void> {
        try {
            // Initialize email provider (example with nodemailer)
            // const nodemailer = require('nodemailer');
            // this.emailProvider = nodemailer.createTransporter({
            //     service: 'gmail', // or your email service
            //     auth: {
            //         user: process.env.EMAIL_USER,
            //         pass: process.env.EMAIL_PASS
            //     }
            // });

            logger.info('Notification service initialized');
        } catch (error) {
            logger.error('Failed to initialize notification service:', error);
        }
    }

    /**
     * Send user update notification
     */
    static async sendUserUpdateNotification(
        user: IUser,
        changes: Array<{ field: string; oldValue: any; newValue: any }>,
        updatedBy: string
    ): Promise<void> {
        try {
            const template = this.createUserUpdateTemplate(user, changes, updatedBy);

            await this.sendEmail({
                to: user.email,
                from: process.env.DEFAULT_FROM_EMAIL || 'noreply@cybercore.com',
                ...template,
                priority: 'normal'
            });

            // Send in-app notification
            await this.sendInAppNotification(user._id.toString(), {
                type: 'profile_update',
                title: 'Profile Updated',
                message: 'Your profile has been updated',
                data: { changes }
            });

            logger.info('User update notification sent', {
                userId: user._id,
                updatedBy,
                changesCount: changes.length
            });

        } catch (error) {
            logger.error('Failed to send user update notification:', error);
        }
    }

    /**
     * Send user deletion notification
     */
    static async sendUserDeletionNotification(
        user: IUser,
        deletedBy: string,
        permanent: boolean,
        reason?: string
    ): Promise<void> {
        try {
            const template = this.createUserDeletionTemplate(user, permanent, reason);

            await this.sendEmail({
                to: user.email,
                from: process.env.DEFAULT_FROM_EMAIL || 'noreply@cybercore.com',
                ...template,
                priority: 'high'
            });

            // Notify admins about user deletion
            await this.notifyAdmins('USER_DELETED', {
                deletedUser: user.email,
                deletedBy,
                permanent,
                reason
            });

            logger.info('User deletion notification sent', {
                userId: user._id,
                deletedBy,
                permanent
            });

        } catch (error) {
            logger.error('Failed to send user deletion notification:', error);
        }
    }


    /**
     * Send account deletion confirmation
     */
    static async sendAccountDeletionConfirmation(
        user: IUser,
        reason: string
    ): Promise<void> {
        try {
            const template = this.createAccountDeletionConfirmationTemplate(user, reason);

            await this.sendEmail({
                to: user.email,
                from: process.env.DEFAULT_FROM_EMAIL || 'noreply@cybercore.com',
                ...template,
                priority: 'high'
            });

            logger.info('Account deletion confirmation sent', {
                userId: user._id,
                email: user.email
            });

        } catch (error) {
            logger.error('Failed to send account deletion confirmation:', error);
        }
    }

    /**
     * Send password reset notification
     */
    static async sendPasswordResetNotification(
        user: IUser,
        resetBy: string,
        forceChange: boolean
    ): Promise<void> {
        try {
            const template = this.createPasswordResetTemplate(user, forceChange);

            await this.sendEmail({
                to: user.email,
                from: process.env.DEFAULT_FROM_EMAIL || 'noreply@cybercore.com',
                ...template,
                priority: 'high'
            });

            // Send security alert
            await this.sendSecurityAlert(user, 'PASSWORD_RESET', {
                resetBy,
                forceChange,
                timestamp: new Date()
            });

            logger.info('Password reset notification sent', {
                userId: user._id,
                resetBy,
                forceChange
            });

        } catch (error) {
            logger.error('Failed to send password reset notification:', error);
        }
    }

    /**
     * Send user status change notification
     */
    static async sendUserStatusChangeNotification(
        user: IUser,
        newStatus: boolean,
        changedBy: string,
        reason?: string
    ): Promise<void> {
        try {
            const template = this.createStatusChangeTemplate(user, newStatus, reason);

            await this.sendEmail({
                to: user.email,
                from: process.env.DEFAULT_FROM_EMAIL || 'noreply@cybercore.com',
                ...template,
                priority: 'high'
            });

            logger.info('User status change notification sent', {
                userId: user._id,
                newStatus,
                changedBy
            });

        } catch (error) {
            logger.error('Failed to send status change notification:', error);
        }
    }

    /**
     * Send bulk operation notification
     */
    static async sendBulkOperationNotification(
        affectedUsers: Array<{ userId: string; email: string }>,
        operation: string,
        executedBy: string,
        data?: any
    ): Promise<void> {
        try {
            // Send individual notifications to affected users
            const notifications = affectedUsers.map(user =>
                this.sendBulkOperationUserNotification(user, operation, data)
            );

            await Promise.allSettled(notifications);

            // Notify admins about bulk operation
            await this.notifyAdmins('BULK_OPERATION', {
                operation,
                affectedCount: affectedUsers.length,
                executedBy,
                data
            });

            logger.info('Bulk operation notifications sent', {
                operation,
                affectedCount: affectedUsers.length,
                executedBy
            });

        } catch (error) {
            logger.error('Failed to send bulk operation notifications:', error);
        }
    }

    /**
     * Send user restoration notification
     */
    static async sendUserRestorationNotification(
        user: IUser,
        restoredBy: string,
        reason?: string
    ): Promise<void> {
        try {
            const template = this.createUserRestorationTemplate(user, reason);

            await this.sendEmail({
                to: user.email,
                from: process.env.DEFAULT_FROM_EMAIL || 'noreply@cybercore.com',
                ...template,
                priority: 'normal'
            });

            logger.info('User restoration notification sent', {
                userId: user._id,
                restoredBy
            });

        } catch (error) {
            logger.error('Failed to send restoration notification:', error);
        }
    }

    /**
     * Send security alert
     */
    static async sendSecurityAlert(
        user: IUser,
        alertType: string,
        details: any
    ): Promise<void> {
        try {
            const template = this.createSecurityAlertTemplate(user, alertType, details);

            await this.sendEmail({
                to: user.email,
                from: process.env.DEFAULT_FROM_EMAIL || 'noreply@cybercore.com',
                ...template,
                priority: 'high'
            });

            // Also notify security team for critical alerts
            if (this.isCriticalSecurityAlert(alertType)) {
                await this.notifySecurityTeam(alertType, {
                    userId: user._id,
                    userEmail: user.email,
                    details
                });
            }

            logger.info('Security alert sent', {
                userId: user._id,
                alertType
            });

        } catch (error) {
            logger.error('Failed to send security alert:', error);
        }
    }

    /**
     * Send welcome email to new users
     */
    static async sendWelcomeEmail(user: IUser): Promise<void> {
        try {
            const template = this.createWelcomeTemplate(user);

            await this.sendEmail({
                to: user.email,
                from: process.env.DEFAULT_FROM_EMAIL || 'noreply@cybercore.com',
                ...template,
                priority: 'normal'
            });

            logger.info('Welcome email sent', { userId: user._id });

        } catch (error) {
            logger.error('Failed to send welcome email:', error);
        }
    }

    /**
     * Send system maintenance notification
     */
    static async sendMaintenanceNotification(
        message: string,
        scheduledTime: Date,
        duration: string
    ): Promise<void> {
        try {
            const template = this.createMaintenanceTemplate(message, scheduledTime, duration);

            // Send to all active users (implement user filtering as needed)
            await this.broadcastNotification(template);

            logger.info('Maintenance notification broadcasted');

        } catch (error) {
            logger.error('Failed to send maintenance notification:', error);
        }
    }

    // ============================================================================
    // PRIVATE HELPER METHODS
    // ============================================================================

    private static async sendEmail(config: EmailConfig & { to: string; subject: string; html: string; text: string }): Promise<void> {
        try {
            // In a real application, use your email provider
            if (this.emailProvider) {
                await this.emailProvider.sendMail({
                    from: config.from || process.env.DEFAULT_FROM_EMAIL || 'noreply@cybercore.com',
                    to: config.to,
                    subject: config.subject,
                    html: config.html,
                    text: config.text,
                    replyTo: config.replyTo,
                    priority: config.priority || 'normal',
                    attachments: config.attachments
                });
            } else {
                // Fallback: log email content
                logger.info('Email would be sent', {
                    to: config.to,
                    subject: config.subject,
                    priority: config.priority
                });
            }
        } catch (error) {
            logger.error('Email sending failed:', error);
            throw error;
        }
    }

    private static async sendInAppNotification(
        userId: string,
        notification: {
            type: string;
            title: string;
            message: string;
            data?: any;
        }
    ): Promise<void> {
        try {
            // In a real application, store in database and push via WebSocket
            logger.info('In-app notification', {
                userId,
                type: notification.type,
                title: notification.title
            });

            // Example: Save to notifications collection
            // await NotificationModel.create({
            //     userId,
            //     type: notification.type,
            //     title: notification.title,
            //     message: notification.message,
            //     data: notification.data,
            //     isRead: false,
            //     createdAt: new Date()
            // });

        } catch (error) {
            logger.error('In-app notification failed:', error);
        }
    }

    private static async notifyAdmins(eventType: string, data: any): Promise<void> {
        try {
            // In a real application, send to admin notification channels
            logger.info('Admin notification', { eventType, data });

            // Example: Send to admin Slack channel, email list, etc.
            // await this.sendSlackNotification(adminChannel, eventType, data);
            // await this.sendEmailToAdmins(eventType, data);

        } catch (error) {
            logger.error('Admin notification failed:', error);
        }
    }

    private static async notifySecurityTeam(alertType: string, data: any): Promise<void> {
        try {
            // In a real application, send to security team
            logger.warn('Security team notification', { alertType, data });

            // Example: Send to security SIEM, PagerDuty, etc.
            // await this.sendToSIEM(alertType, data);
            // await this.triggerPagerDuty(alertType, data);

        } catch (error) {
            logger.error('Security team notification failed:', error);
        }
    }

    private static async broadcastNotification(template: EmailTemplate): Promise<void> {
        try {
            // In a real application, send to all users or specific segments
            logger.info('Broadcasting notification', { subject: template.subject });

            // Example: Queue broadcast job
            // await this.queueBroadcastJob(template);

        } catch (error) {
            logger.error('Broadcast notification failed:', error);
        }
    }

    private static async sendBulkOperationUserNotification(
        user: { userId: string; email: string },
        operation: string,
        data?: any
    ): Promise<void> {
        try {
            const template = this.createBulkOperationUserTemplate(operation, data);

            await this.sendEmail({
                to: user.email,
                from: process.env.DEFAULT_FROM_EMAIL || 'noreply@cybercore.com',
                ...template,
                priority: 'normal'
            });

        } catch (error) {
            logger.error('Bulk operation user notification failed:', error);
        }
    }

    private static isCriticalSecurityAlert(alertType: string): boolean {
        const criticalAlerts = [
            'MULTIPLE_FAILED_LOGINS',
            'SUSPICIOUS_ACTIVITY',
            'ACCOUNT_TAKEOVER',
            'PRIVILEGE_ESCALATION',
            'DATA_BREACH'
        ];
        return criticalAlerts.includes(alertType);
    }

    // ============================================================================
    // EMAIL TEMPLATE CREATORS
    // ============================================================================

    private static createUserUpdateTemplate(
        user: IUser,
        changes: Array<{ field: string; oldValue: any; newValue: any }>,
        updatedBy: string
    ): EmailTemplate {
        const changesList = changes
            .map(change => `• ${this.formatFieldName(change.field)} was updated`)
            .join('\n');

        return {
            subject: 'Your Account Has Been Updated',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">Account Update Notification</h2>
                    <p>Hello ${user.firstName},</p>
                    <p>Your account has been updated by an administrator. The following changes were made:</p>
                    <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
                        ${changesList.replace(/\n/g, '<br>')}
                    </div>
                    <p>If you have any questions about these changes, please contact your administrator.</p>
                    <p>Best regards,<br>The CyberCore Team</p>
                </div>
            `,
            text: `Hello ${user.firstName},\n\nYour account has been updated. Changes:\n${changesList}\n\nIf you have questions, contact your administrator.\n\nBest regards,\nThe CyberCore Team`
        };
    }

    private static createUserDeletionTemplate(
        user: IUser,
        permanent: boolean,
        reason?: string
    ): EmailTemplate {
        const action = permanent ? 'permanently deleted' : 'deactivated';

        return {
            subject: `Your Account Has Been ${permanent ? 'Deleted' : 'Deactivated'}`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #d9534f;">Account ${permanent ? 'Deletion' : 'Deactivation'} Notice</h2>
                    <p>Hello ${user.firstName},</p>
                    <p>Your account has been ${action} by an administrator.</p>
                    ${reason ? `<p><strong>Reason:</strong> ${reason}</p>` : ''}
                    ${!permanent ? '<p>If you believe this was done in error, please contact your administrator to restore your account.</p>' : ''}
                    <p>Best regards,<br>The CyberCore Team</p>
                </div>
            `,
            text: `Hello ${user.firstName},\n\nYour account has been ${action}.\n${reason ? `Reason: ${reason}\n` : ''}${!permanent ? 'Contact your administrator if this was an error.\n' : ''}\nBest regards,\nThe CyberCore Team`
        };
    }

    private static createPasswordResetTemplate(
        user: IUser,
        forceChange: boolean
    ): EmailTemplate {
        return {
            subject: 'Your Password Has Been Reset',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #f0ad4e;">Password Reset Notification</h2>
                    <p>Hello ${user.firstName},</p>
                    <p>Your password has been reset by an administrator.</p>
                    ${forceChange ? '<p style="color: #d9534f;"><strong>You will be required to change your password on your next login.</strong></p>' : ''}
                    <p>If you did not request this change, please contact your administrator immediately.</p>
                    <p>For security reasons, please log in and change your password as soon as possible.</p>
                    <p>Best regards,<br>The CyberCore Team</p>
                </div>
            `,
            text: `Hello ${user.firstName},\n\nYour password has been reset by an administrator.\n${forceChange ? 'You will be required to change your password on your next login.\n' : ''}If you did not request this, contact your administrator immediately.\n\nBest regards,\nThe CyberCore Team`
        };
    }

    private static createStatusChangeTemplate(
        user: IUser,
        newStatus: boolean,
        reason?: string
    ): EmailTemplate {
        const action = newStatus ? 'activated' : 'deactivated';

        return {
            subject: `Your Account Has Been ${newStatus ? 'Activated' : 'Deactivated'}`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: ${newStatus ? '#5cb85c' : '#f0ad4e'};">Account ${newStatus ? 'Activation' : 'Deactivation'}</h2>
                    <p>Hello ${user.firstName},</p>
                    <p>Your account has been ${action}.</p>
                    ${reason ? `<p><strong>Reason:</strong> ${reason}</p>` : ''}
                    ${newStatus ? '<p>You can now access your account normally.</p>' : '<p>You will not be able to access your account until it is reactivated.</p>'}
                    <p>Best regards,<br>The CyberCore Team</p>
                </div>
            `,
            text: `Hello ${user.firstName},\n\nYour account has been ${action}.\n${reason ? `Reason: ${reason}\n` : ''}${newStatus ? 'You can now access your account normally.' : 'You cannot access your account until reactivated.'}\n\nBest regards,\nThe CyberCore Team`
        };
    }

    private static createUserRestorationTemplate(
        user: IUser,
        reason?: string
    ): EmailTemplate {
        return {
            subject: 'Your Account Has Been Restored',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #5cb85c;">Account Restoration</h2>
                    <p>Hello ${user.firstName},</p>
                    <p>Good news! Your account has been restored and is now active.</p>
                    ${reason ? `<p><strong>Reason:</strong> ${reason}</p>` : ''}
                    <p>You can now log in and access your account normally.</p>
                    <p>Best regards,<br>The CyberCore Team</p>
                </div>
            `,
            text: `Hello ${user.firstName},\n\nYour account has been restored and is now active.\n${reason ? `Reason: ${reason}\n` : ''}You can now log in normally.\n\nBest regards,\nThe CyberCore Team`
        };
    }

    private static createSecurityAlertTemplate(
        user: IUser,
        alertType: string,
        details: any
    ): EmailTemplate {
        return {
            subject: 'Security Alert for Your Account',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #d9534f;">Security Alert</h2>
                    <p>Hello ${user.firstName},</p>
                    <p>We detected a security event on your account:</p>
                    <div style="background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 20px 0;">
                        <strong>Event:</strong> ${this.formatAlertType(alertType)}<br>
                        <strong>Time:</strong> ${details.timestamp || new Date()}<br>
                        ${details.ipAddress ? `<strong>IP Address:</strong> ${details.ipAddress}<br>` : ''}
                    </div>
                    <p>If this was not you, please contact your administrator immediately and change your password.</p>
                    <p>Best regards,<br>The CyberCore Team</p>
                </div>
            `,
            text: `Hello ${user.firstName},\n\nSecurity alert for your account:\nEvent: ${this.formatAlertType(alertType)}\nTime: ${details.timestamp || new Date()}\n${details.ipAddress ? `IP: ${details.ipAddress}\n` : ''}\nIf this was not you, contact your administrator immediately.\n\nBest regards,\nThe CyberCore Team`
        };
    }

    private static createWelcomeTemplate(user: IUser): EmailTemplate {
        return {
            subject: 'Welcome to CyberCore!',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #5cb85c;">Welcome to CyberCore!</h2>
                    <p>Hello ${user.firstName},</p>
                    <p>Welcome to CyberCore! Your account has been created successfully.</p>
                    <p>You can now log in and start using the platform.</p>
                    <div style="background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 5px; margin: 20px 0;">
                        <strong>Your account details:</strong><br>
                        Email: ${user.email}<br>
                        Role: ${user.role}
                    </div>
                    <p>If you have any questions, please don't hesitate to contact our support team.</p>
                    <p>Best regards,<br>The CyberCore Team</p>
                </div>
            `,
            text: `Hello ${user.firstName},\n\nWelcome to CyberCore! Your account has been created.\n\nAccount details:\nEmail: ${user.email}\nRole: ${user.role}\n\nContact support if you have questions.\n\nBest regards,\nThe CyberCore Team`
        };
    }

    private static createBulkOperationUserTemplate(
        operation: string,
        data?: any
    ): EmailTemplate {
        return {
            subject: 'Account Update Notification',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">Account Update</h2>
                    <p>Your account has been updated as part of a bulk operation.</p>
                    <p><strong>Operation:</strong> ${this.formatOperation(operation)}</p>
                    ${data?.reason ? `<p><strong>Reason:</strong> ${data.reason}</p>` : ''}
                    <p>If you have any questions, please contact your administrator.</p>
                    <p>Best regards,<br>The CyberCore Team</p>
                </div>
            `,
            text: `Your account was updated in a bulk operation: ${this.formatOperation(operation)}\n${data?.reason ? `Reason: ${data.reason}\n` : ''}Contact your administrator with questions.\n\nBest regards,\nThe CyberCore Team`
        };
    }

    private static createMaintenanceTemplate(
        message: string,
        scheduledTime: Date,
        duration: string
    ): EmailTemplate {
        return {
            subject: 'Scheduled Maintenance Notification',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #f0ad4e;">Scheduled Maintenance</h2>
                    <p>${message}</p>
                    <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0;">
                        <strong>Scheduled Time:</strong> ${scheduledTime.toLocaleString()}<br>
                        <strong>Expected Duration:</strong> ${duration}
                    </div>
                    <p>We apologize for any inconvenience.</p>
                    <p>Best regards,<br>The CyberCore Team</p>
                </div>
            `,
            text: `Scheduled Maintenance\n\n${message}\n\nTime: ${scheduledTime.toLocaleString()}\nDuration: ${duration}\n\nWe apologize for any inconvenience.\n\nBest regards,\nThe CyberCore Team`
        };
    }

    // ============================================================================
    // FORMATTING HELPERS
    // ============================================================================

    private static formatFieldName(field: string): string {
        return field
            .replace(/([A-Z])/g, ' $1')
            .replace(/^./, str => str.toUpperCase())
            .trim();
    }

    private static formatAlertType(alertType: string): string {
        return alertType
            .toLowerCase()
            .replace(/_/g, ' ')
            .replace(/^./, str => str.toUpperCase());
    }

    /**
     * Send user invitation email
     */
    static async sendUserInvitation(
        inviteData: any,
        invitationToken: string
    ): Promise<void> {
        try {
            const template = this.createInvitationTemplate(inviteData, invitationToken);

            await this.sendEmail({
                to: inviteData.email,
                from: process.env.DEFAULT_FROM_EMAIL || 'noreply@cybercore.com',
                ...template,
                priority: 'normal'
            });

            logger.info('User invitation sent', {
                email: inviteData.email,
                role: inviteData.role
            });

        } catch (error) {
            logger.error('Failed to send user invitation:', error);
        }
    }

    private static createInvitationTemplate(
        inviteData: any,
        invitationToken: string
    ): EmailTemplate {
        const activationUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/activate?token=${invitationToken}`;

        return {
            subject: 'You\'ve been invited to join CyberCore',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #5cb85c;">Welcome to CyberCore!</h2>
                    <p>Hello ${inviteData.firstName},</p>
                    <p>You've been invited to join CyberCore as a ${this.formatRole(inviteData.role)}.</p>
                    ${inviteData.message ? `<p><em>"${inviteData.message}"</em></p>` : ''}
                    <div style="background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 5px; margin: 20px 0;">
                        <p><strong>To activate your account:</strong></p>
                        <ol>
                            <li>Click the activation link below</li>
                            <li>Set up your password</li>
                            <li>Start using the platform</li>
                        </ol>
                    </div>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${activationUrl}" style="background: #5cb85c; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Activate Account</a>
                    </div>
                    <p><small>This invitation expires in ${inviteData.expiresIn || 72} hours.</small></p>
                    <p>If you have any questions, please contact our support team.</p>
                    <p>Best regards,<br>The CyberCore Team</p>
                </div>
            `,
            text: `Hello ${inviteData.firstName},\n\nYou've been invited to join CyberCore as a ${this.formatRole(inviteData.role)}.\n\n${inviteData.message ? `Message: "${inviteData.message}"\n\n` : ''}To activate your account, visit: ${activationUrl}\n\nThis invitation expires in ${inviteData.expiresIn || 72} hours.\n\nBest regards,\nThe CyberCore Team`
        };
    }

    private static createAccountDeletionConfirmationTemplate(
        user: IUser,
        reason: string
    ): EmailTemplate {
        return {
            subject: 'Account Deletion Request Received',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #d9534f;">Account Deletion Request</h2>
                    <p>Hello ${user.firstName},</p>
                    <p>We've received your request to delete your CyberCore account.</p>
                    <div style="background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 20px 0;">
                        <p><strong>Important:</strong></p>
                        <ul>
                            <li>Your account has been deactivated</li>
                            <li>You have 30 days to cancel this request</li>
                            <li>After 30 days, your data will be permanently deleted</li>
                        </ul>
                    </div>
                    <p><strong>Reason:</strong> ${reason}</p>
                    <p>If you change your mind, please contact our support team within 30 days to restore your account.</p>
                    <p>We're sorry to see you go. If there's anything we could have done better, please let us know.</p>
                    <p>Best regards,<br>The CyberCore Team</p>
                </div>
            `,
            text: `Hello ${user.firstName},\n\nWe've received your request to delete your CyberCore account.\n\nYour account has been deactivated and you have 30 days to cancel this request. After 30 days, your data will be permanently deleted.\n\nReason: ${reason}\n\nIf you change your mind, contact our support team within 30 days.\n\nBest regards,\nThe CyberCore Team`
        };
    }

    private static formatRole(role: string): string {
        return role
            .split('_')
            .map(word => word.charAt(0) + word.slice(1).toLowerCase())
            .join(' ');
    }

    private static formatOperation(operation: string): string {
        const operationMap: Record<string, string> = {
            'activate': 'Account Activation',
            'deactivate': 'Account Deactivation',
            'delete': 'Account Deletion',
            'changeRole': 'Role Change',
            'changeTenant': 'Tenant Change'
        };

        return operationMap[operation] || operation;
    }
}