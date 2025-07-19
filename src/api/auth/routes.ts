import { Router } from 'express';
import { AuthController } from './controller';
import { validate } from '@/core/validators/middleware';
import { registerSchema, loginSchema, refreshTokenSchema } from '@/core/validators/authValidators';
import { authenticate } from '@/core/middlewares/auth';
import { authRateLimiter } from '@/core/middlewares/rateLimiter';

const router = Router();

// Apply rate limiting to auth routes
router.use(authRateLimiter);

router.post('/register', validate(registerSchema), AuthController.register);
router.post('/login', validate(loginSchema), AuthController.login);
router.post('/refresh', validate(refreshTokenSchema), AuthController.refreshToken);
router.post('/logout', AuthController.logout);
router.get('/me', authenticate, AuthController.me);

export { router as authRoutes };
