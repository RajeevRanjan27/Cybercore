// ============================================================================
// API VERSION MIDDLEWARE
// ============================================================================

// src/core/middlewares/apiVersion.ts

import { Request, Response, NextFunction } from 'express';
import {AppError} from "@/core/middlewares/errorHandler";

export const apiVersion = (supportedVersions: string[] = ['v1']) => {
    return (req: Request, res: Response, next: NextFunction) => {
        const version = req.headers['api-version'] || 'v1';

        if (!supportedVersions.includes(version as string)) {
            return next(new AppError(`API version ${version} not supported`, 400));
        }

        req.apiVersion = version as string;
        res.set('API-Version', version as string);

        next();
    };
};

// Extend Request interface
declare global {
    namespace Express {
        interface Request {
            apiVersion?: string;
        }
    }
}