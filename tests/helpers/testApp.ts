// tests/helpers/testApp.ts
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { errorHandler } from '@/core/middlewares/errorHandler';
import { requestLogger } from '@/core/middlewares/requestLogger';
import { authRoutes } from '@/api/auth/routes';
import { oauth2Routes } from '@/api/auth/oauth2Routes';
import { userRoutes } from '@/api/users/routes';
import { tenantRoutes } from '@/api/tenants/routes';
import { dbRoutes } from '@/api/debugDB/routes';

/**
 * Create Express app configured for testing
 */
export function createTestApp(): express.Application {
    const app = express();

    // Security & CORS
    app.use(helmet());
    app.use(cors());

    // Body Parsing
    app.use(express.json({ limit: '10mb' }));
    app.use(express.urlencoded({ extended: true }));

    // Request Logging (only in non-test env to reduce noise)
    if (process.env.NODE_ENV !== 'test') {
        app.use(requestLogger);
    }

    // Health Check
    app.get('/health', (req, res) => {
        res.json({
            status: 'OK',
            timestamp: new Date().toISOString(),
            environment: 'test'
        });
    });

    // API Routes
    app.use('/api/v1/auth', authRoutes);
    app.use('/api/v1/oauth2', oauth2Routes);
    app.use('/api/v1/users', userRoutes);
    app.use('/api/v1/tenants', tenantRoutes);
    app.use('/api/v1/debug', dbRoutes);

    // Error Handling
    app.use(errorHandler);

    // 404 Handler
    app.use('*', (req, res) => {
        res.status(404).json({
            success: false,
            error: 'Route not found',
            timestamp: new Date().toISOString()
        });
    });

    return app;
}