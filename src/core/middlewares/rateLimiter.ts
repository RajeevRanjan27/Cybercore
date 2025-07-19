import rateLimit from 'express-rate-limit';
import { config } from '@/config/env';

export const createRateLimiter = (windowMs?: number, max?: number) => {
    return rateLimit({
        windowMs: windowMs || config.RATE_LIMIT_WINDOW,
        max: max || config.RATE_LIMIT_MAX,
        message: {
            error: 'Too many requests from this IP, please try again later.'
        },
        standardHeaders: true,
        legacyHeaders: false,
    });
};


export const authRateLimiter = createRateLimiter(15 * 60 * 1000, 5); // 5 attempts per 15 minutes
