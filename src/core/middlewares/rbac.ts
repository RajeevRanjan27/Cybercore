import { Request, Response, NextFunction } from 'express';
import { RBACService } from '@/core/services/RBACService';
import { AppError } from './errorHandler';

export const authorize = (requiredPermission: string) => {
    return (req: Request, res: Response, next: NextFunction) => {
        if (!req.user) {
            throw new AppError('User not authenticated', 401);
        }

        const hasPermission = RBACService.hasPermission(
            req.user.permissions,
            requiredPermission
        );

        if (!hasPermission) {
            throw new AppError('Insufficient permissions', 403);
        }

        next();
    };
};