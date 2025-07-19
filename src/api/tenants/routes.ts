import { Router } from 'express';
import { TenantController } from './controller';
import { authenticate } from '@/core/middlewares/auth';
import { authorize } from '@/core/middlewares/rbac';
import { createRateLimiter } from '@/core/middlewares/rateLimiter';

const router = Router();

// Apply rate limiting
router.use(createRateLimiter());

// All routes require authentication
router.use(authenticate);

router.post('/', authorize('tenant:create'), TenantController.createTenant);
router.get('/', authorize('tenant:read'), TenantController.getTenants);
router.get('/:id', authorize('tenant:read'), TenantController.getTenantById);
router.put('/:id', authorize('tenant:update'), TenantController.updateTenant);
router.delete('/:id', authorize('tenant:delete'), TenantController.deleteTenant);

export { router as tenantRoutes };
