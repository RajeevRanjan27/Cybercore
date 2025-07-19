import { Router } from 'express';
import { DbController } from './controller';
import { authenticate } from '@/core/middlewares/auth';
import { authorize } from '@/core/middlewares/rbac';
import { createRateLimiter } from '@/core/middlewares/rateLimiter';

const router = Router();

// Apply rate limiting to all routes
router.use(createRateLimiter());

// All routes require authentication
router.use(authenticate);

// Health check endpoint (less restrictive permissions)
router.get('/health',
    DbController.healthCheck
);

// Database overview endpoint
router.get('/overview',
    authorize('database:admin'),
    DbController.getDebugDB
);

// Collection-specific endpoints
router.get('/collection/:collectionName/info',
    authorize('database:admin'),
    DbController.getCollectionInfo
);

router.get('/collection/:collectionName/documents',
    authorize('database:admin'),
    DbController.getSampleDocuments
);

// Root endpoint - redirect to overview
router.get('/',
    authorize('database:admin'),
    DbController.getDebugDB
);

export { router as dbRoutes };