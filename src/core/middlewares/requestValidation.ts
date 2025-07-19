// ============================================================================
// REQUEST VALIDATION MIDDLEWARE
// ============================================================================

// src/core/middlewares/requestValidation.ts

import { Request, Response, NextFunction } from 'express';
import {AppError} from "@/core/middlewares/errorHandler";

export const validateRequestSize = (maxSizeBytes: number = 1024 * 1024) => {
    return (req: Request, res: Response, next: NextFunction) => {
        const contentLength = parseInt(req.get('Content-Length') || '0');

        if (contentLength > maxSizeBytes) {
            return next(new AppError('Request too large', 413));
        }

        next();
    };
};

export const validateContentType = (allowedTypes: string[]) => {
    return (req: Request, res: Response, next: NextFunction) => {
        const contentType = req.get('Content-Type');

        if (req.method !== 'GET' && contentType) {
            const isAllowed = allowedTypes.some(type =>
                contentType.includes(type)
            );

            if (!isAllowed) {
                return next(new AppError('Unsupported content type', 415));
            }
        }

        next();
    };
};
