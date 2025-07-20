// ============================================================================
// COMPRESSION MIDDLEWARE
// ============================================================================
import { Request, Response, NextFunction } from 'express';

// src/core/middlewares/compression.ts
export const compressionMiddleware = (req: Request, res: Response, next: NextFunction) => {
    // Simple compression logic
    const originalJson = res.json;

    res.json = function(body: any) {
        // Add compression headers for large responses
        const bodyString = JSON.stringify(body);

        if (bodyString.length > 1024) { // If response is larger than 1KB
            res.set({
                'Content-Encoding': 'none', // Placeholder - in real app use gzip
                'X-Compressed': 'true',
                'X-Original-Size': bodyString.length.toString()
            });
        }

        return originalJson.call(this, body);
    };

    next();
};
