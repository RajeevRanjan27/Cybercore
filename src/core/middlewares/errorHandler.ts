import { Request, Response, NextFunction } from 'express';
import { logger } from '@/core/infra/logger';
import { ApiResponse } from '@/core/types';

export class AppError extends Error {
    public statusCode: number;
    public isOperational: boolean;

    constructor(message: string, statusCode: number) {
        super(message);
        this.statusCode = statusCode;
        this.isOperational = true;
        Error.captureStackTrace(this, this.constructor);
    }
}

export const errorHandler = (
    err: any,
    req: Request,
    res: Response,
    next: NextFunction
): void => {
    let statusCode = err.statusCode || 500;
    let message = err.message || 'Internal Server Error';

    // Mongoose validation error
    if (err.name === 'ValidationError') {
        statusCode = 400;
        message = Object.values(err.errors).map((val: any) => val.message).join(', ');
    }

    // JWT errors
    if (err.name === 'JsonWebTokenError') {
        statusCode = 401;
        message = 'Invalid token';
    }

    if (err.name === 'TokenExpiredError') {
        statusCode = 401;
        message = 'Token expired';
    }

    logger.error('API Error:', {
        message,
        statusCode,
        stack: err.stack,
        url: req.url,
        method: req.method,
        ip: req.ip
    });

    const response: ApiResponse = {
        success: false,
        error: message,
        timestamp: new Date().toISOString()
    };

    res.status(statusCode).json(response);
};
