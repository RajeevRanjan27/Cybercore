import { Request, Response, NextFunction } from 'express';
import { AuthService } from '@/core/services/AuthService';
import { AppError } from './errorHandler';

export const authenticate = (req: Request, res: Response, next: NextFunction) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            throw new AppError('No token provided', 401);
        }

        const token = authHeader.split(' ')[1];
        const decoded = AuthService.verifyAccessToken(token);

        req.user = decoded;
        next();
    } catch (error) {
        next(error);
    }
};