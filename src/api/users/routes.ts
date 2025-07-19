import { Router } from 'express';
import { UserController } from './controller';
import { authenticate } from '@/core/middlewares/auth';
import { authorize } from '@/core/middlewares/rbac';
import { createRateLimiter } from '@/core/middlewares/rateLimiter';

const router = Router();

// Apply rate limiting
router.use(createRateLimiter());

// All routes require authentication
router.use(authenticate);

router.get('/', authorize('user:read'), UserController.getUsers);
router.get('/:id', authorize('user:read'), UserController.getUserById);
router.put('/:id', authorize('user:update'), UserController.updateUser);
router.delete('/:id', authorize('user:delete'), UserController.deleteUser);

export { router as userRoutes };