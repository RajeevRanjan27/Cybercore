import {NextFunction, Request, Response} from 'express';
import {AuthService} from '@/core/services/AuthService';
import {AppError} from './errorHandler';

export const authenticate = (req: Request, res: Response, next: NextFunction) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            throw new AppError('No token provided', 401);
        }

        const token = authHeader.split(' ')[1];
        req.user = AuthService.verifyAccessToken(token);
        next();
    } catch (error) {
        next(error);
    }
};