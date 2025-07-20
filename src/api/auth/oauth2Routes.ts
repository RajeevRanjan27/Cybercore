// src/api/auth/oauth2Routes.ts
import { Router } from 'express';
import { OAuth2Controller } from './oauth2Controller';
import { authenticate } from '@/core/middlewares/auth';
import { createRateLimiter } from '@/core/middlewares/rateLimiter';
import { validate } from '@/core/validators/middleware';
import { oauth2Validators } from '@/core/validators/oauth2Validators';

const router = Router();

// Apply rate limiting to OAuth2 routes
const oauth2RateLimit = createRateLimiter(60000, 20); // 20 requests per minute
const callbackRateLimit = createRateLimiter(300000, 10); // 10 callbacks per 5 minutes

// ============================================================================
// PUBLIC OAUTH2 ROUTES (No authentication required)
// ============================================================================

/**
 * GET /oauth2/providers - Get available OAuth2 providers
 */
router.get('/providers',
    oauth2RateLimit,
    OAuth2Controller.getProviders
);

/**
 * GET /oauth2/:provider - Initiate OAuth2 authentication
 * Query params: redirectTo, tenantId
 */
router.get('/:provider',
    oauth2RateLimit,
    validate(oauth2Validators.initiateAuthSchema),
    OAuth2Controller.initiateAuth
);

/**
 * GET /oauth2/callback/:provider - Handle OAuth2 callback
 * Query params: code, state, error, error_description
 */
router.get('/callback/:provider',
    callbackRateLimit,
    OAuth2Controller.handleCallback
);

// ============================================================================
// AUTHENTICATED OAUTH2 ROUTES
// ============================================================================

/**
 * GET /oauth2/connected - Get user's connected OAuth2 providers
 */
router.get('/connected',
    authenticate,
    oauth2RateLimit,
    OAuth2Controller.getConnectedProviders
);

/**
 * GET /oauth2/status - Get comprehensive OAuth2 status
 */
router.get('/status',
    authenticate,
    oauth2RateLimit,
    OAuth2Controller.getOAuth2Status
);

/**
 * POST /oauth2/connect/:provider - Generate connection URL for provider
 */
router.post('/connect/:provider',
    authenticate,
    oauth2RateLimit,
    OAuth2Controller.connectProvider
);

/**
 * POST /oauth2/link - Link OAuth2 account with current user
 */
router.post('/link',
    authenticate,
    oauth2RateLimit,
    validate(oauth2Validators.linkAccountSchema),
    OAuth2Controller.linkAccount
);

/**
 * DELETE /oauth2/disconnect/:provider - Disconnect OAuth2 provider
 */
router.delete('/disconnect/:provider',
    authenticate,
    createRateLimiter(300000, 5), // 5 disconnections per 5 minutes
    OAuth2Controller.disconnectProvider
);

/**
 * POST /oauth2/refresh/:provider - Refresh OAuth2 access token
 */
router.post('/refresh/:provider',
    authenticate,
    oauth2RateLimit,
    OAuth2Controller.refreshProviderToken
);

export { router as oauth2Routes };