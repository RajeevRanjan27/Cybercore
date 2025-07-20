// ============================================================================
// tests/unit/core/services/NotificationService.test.ts
// ============================================================================

import { NotificationService } from '@/core/services/NotificationService';
import { IUser } from '@/core/models/User';
import { UserRole } from '@/core/constants/roles';
import mongoose from 'mongoose';

describe('NotificationService', () => {
    const mockUser: IUser = {
        _id: new mongoose.Types.ObjectId(),
        firstName: 'John',
        lastName: 'Doe',
        email: 'john.doe@example.com',
        role: UserRole.USER,
    } as IUser;

    beforeEach(() => {
        // Spy on the private sendEmail method to prevent actual email sending
        jest.spyOn(NotificationService as any, 'sendEmail').mockResolvedValue(undefined);
    });

    it('should send a user update notification', async () => {
        const changes = [{ field: 'firstName', oldValue: 'Jon', newValue: 'John' }];
        await NotificationService.sendUserUpdateNotification(mockUser, changes, 'admin-id');
        expect((NotificationService as any).sendEmail).toHaveBeenCalledWith(
            expect.objectContaining({
                to: mockUser.email,
                subject: 'Your Account Has Been Updated',
            })
        );
    });

    it('should send a user deletion notification', async () => {
        await NotificationService.sendUserDeletionNotification(mockUser, 'admin-id', false, 'test reason');
        expect((NotificationService as any).sendEmail).toHaveBeenCalledWith(
            expect.objectContaining({
                to: mockUser.email,
                subject: 'Your Account Has Been Deactivated',
            })
        );
    });

    it('should send a permanent user deletion notification', async () => {
        await NotificationService.sendUserDeletionNotification(mockUser, 'admin-id', true, 'permanent deletion');
        expect((NotificationService as any).sendEmail).toHaveBeenCalledWith(
            expect.objectContaining({
                to: mockUser.email,
                subject: 'Your Account Has Been Deleted',
            })
        );
    });

    it('should send a password reset notification', async () => {
        await NotificationService.sendPasswordResetNotification(mockUser, 'admin-id', true);
        expect((NotificationService as any).sendEmail).toHaveBeenCalledWith(
            expect.objectContaining({
                to: mockUser.email,
                subject: 'Your Password Has Been Reset',
            })
        );
    });

    it('should send a welcome email', async () => {
        await NotificationService.sendWelcomeEmail(mockUser);
        expect((NotificationService as any).sendEmail).toHaveBeenCalledWith(
            expect.objectContaining({
                to: mockUser.email,
                subject: 'Welcome to CyberCore!',
            })
        );
    });
});
