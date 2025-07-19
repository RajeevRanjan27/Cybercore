import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '@/core/infra/logger';
import {AuthPayload} from '@/core/types'

export const requestLogger = (req: Request, res: Response, next: NextFunction) => {
    const traceId = uuidv4();
    req.traceId = traceId;

    const start = Date.now();

    res.on('finish', () => {
        const duration = Date.now() - start;
        logger.info('Request completed', {
            traceId,
            method: req.method,
            url: req.url,
            statusCode: res.statusCode,
            duration: `${duration}ms`,
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });
    });

    next();
};

// Extend Express Request interface
declare global {
    namespace Express {
        interface Request {
            traceId?: string;
            user?: AuthPayload;
        }
    }
}
