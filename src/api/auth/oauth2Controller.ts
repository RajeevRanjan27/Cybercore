// src/api/auth/oauth2Controller.ts
import { Request, Response, NextFunction } from 'express';
import { OAuth2Service } from '@/core/services/OAuth2Service';
import { AppError } from '@/core/middlewares/errorHandler';
import { ApiResponse, AuthPayload } from '@/core/types';
import { config } from '@/config/env';
import {logger} from "@/core/infra/logger";

export class OAuth2Controller {
    /**
     * GET /auth/oauth2/providers - Get available OAuth2 providers
     */
    static async getProviders(req: Request, res: Response, next: NextFunction) {
        try {
            const providers = OAuth2Service.getAvailableProviders();

            const response: ApiResponse = {
                success: true,
                data: { providers },
                message: 'Available OAuth2 providers retrieved successfully',
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * GET /auth/oauth2/:provider - Initiate OAuth2 authentication
     */
    static async initiateAuth(req: Request, res: Response, next: NextFunction) {
        try {
            const { provider } = req.params;
            const { redirectTo, tenantId } = req.query;

            // Validate provider
            const availableProviders = OAuth2Service.getAvailableProviders();
            if (!availableProviders.find(p => p.name === provider)) {
                throw new AppError(`OAuth2 provider '${provider}' is not available`, 400);
            }

            // Generate authorization URL
            const authUrl = OAuth2Service.generateAuthURL(provider, {
                redirectTo: redirectTo as string,
                tenantId: tenantId as string
            });

            const response: ApiResponse = {
                success: true,
                data: {
                    authUrl,
                    provider,
                    expiresIn: 600 // 10 minutes
                },
                message: 'OAuth2 authorization URL generated successfully',
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * GET /auth/oauth2/callback/:provider - Handle OAuth2 callback
     */
    static async handleCallback(req: Request, res: Response, next: NextFunction) {
        try {
            const { provider } = req.params;
            const { code, state, error, error_description } = req.query;

            // Check for OAuth2 errors
            if (error) {
                const errorMessage = error_description || error;
                logger.warn('OAuth2 provider error:', { provider, error: errorMessage });

                // Redirect to frontend with error
                const redirectUrl = `${config.FRONTEND_URL}/auth/oauth2/error?error=${encodeURIComponent(errorMessage as string)}`;
                return res.redirect(redirectUrl);
            }

            // Validate required parameters
            if (!code || !state) {
                throw new AppError('Missing required OAuth2 parameters', 400);
            }

            // Process OAuth2 authentication
            const result = await OAuth2Service.handleCallback(
                provider,
                code as string,
                state as string,
                req
            );

            // For development/testing, return JSON response
            if (req.headers.accept?.includes('application/json')) {
                const response: ApiResponse = {
                    success: true,
                    data: {
                        user: {
                            id: result.user._id,
                            email: result.user.email,
                            firstName: result.user.firstName,
                            lastName: result.user.lastName,
                            role: result.user.role,
                            tenantId: result.user.tenantId
                        },
                        tokens: result.tokens,
                        isNewUser: result.isNewUser,
                        provider
                    },
                    message: `OAuth2 authentication with ${provider} successful`,
                    timestamp: new Date().toISOString()
                };

                return res.json(response);
            }

            // For production, redirect to frontend with tokens
            const redirectUrl = new URL(`${config.FRONTEND_URL}/auth/oauth2/success`);
            redirectUrl.searchParams.set('token', result.tokens.accessToken);
            redirectUrl.searchParams.set('refreshToken', result.tokens.refreshToken);
            redirectUrl.searchParams.set('isNewUser', result.isNewUser.toString());
            redirectUrl.searchParams.set('provider', provider);

            res.redirect(redirectUrl.toString());
        } catch (error) {
            logger.error('OAuth2 callback error:', error);

            // Redirect to frontend with error
            const errorMessage = error instanceof AppError ? error.message : 'OAuth2 authentication failed';
            const redirectUrl = `${config.FRONTEND_URL}/auth/oauth2/error?error=${encodeURIComponent(errorMessage)}`;

            res.redirect(redirectUrl);
        }
    }

    /**
     * GET /auth/oauth2/connected - Get user's connected OAuth2 providers
     */
    static async getConnectedProviders(req: Request, res: Response, next: NextFunction) {
        try {
            const user = req.user as AuthPayload;
            const connectedProviders = await OAuth2Service.getConnectedProviders(user.userId);

            const response: ApiResponse = {
                success: true,
                data: { connectedProviders },
                message: 'Connected OAuth2 providers retrieved successfully',
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * POST /auth/oauth2/connect/:provider - Connect OAuth2 provider to existing account
     */
    static async connectProvider(req: Request, res: Response, next: NextFunction) {
        try {
            const { provider } = req.params;
            const user = req.user as AuthPayload;

            // Generate authorization URL for connecting
            const authUrl = OAuth2Service.generateAuthURL(provider, {
                redirectTo: '/settings/connected-accounts'
            });

            const response: ApiResponse = {
                success: true,
                data: {
                    authUrl,
                    provider
                },
                message: 'OAuth2 connection URL generated successfully',
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * DELETE /auth/oauth2/disconnect/:provider - Disconnect OAuth2 provider
     */
    static async disconnectProvider(req: Request, res: Response, next: NextFunction) {
        try {
            const { provider } = req.params;
            const user = req.user as AuthPayload;

            await OAuth2Service.disconnectProvider(user.userId, provider);

            const response: ApiResponse = {
                success: true,
                message: `${provider} disconnected successfully`,
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * POST /auth/oauth2/refresh/:provider - Refresh OAuth2 access token
     */
    static async refreshProviderToken(req: Request, res: Response, next: NextFunction) {
        try {
            const { provider } = req.params;
            const user = req.user as AuthPayload;

            await OAuth2Service.refreshProviderToken(user.userId, provider);

            const response: ApiResponse = {
                success: true,
                message: `${provider} access token refreshed successfully`,
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * POST /auth/oauth2/link - Link OAuth2 account with existing user session
     */
    static async linkAccount(req: Request, res: Response, next: NextFunction) {
        try {
            const { provider, code, state } = req.body;
            const user = req.user as AuthPayload;

            // Validate input
            if (!provider || !code || !state) {
                throw new AppError('Missing required parameters', 400);
            }

            // Process OAuth2 authentication for linking
            const result = await OAuth2Service.handleCallback(provider, code, state, req);

            // Check if the OAuth2 account is already linked to another user
            if (result.user._id.toString() !== user.userId) {
                throw new AppError('This OAuth2 account is already linked to another user', 409);
            }

            const response: ApiResponse = {
                success: true,
                data: {
                    provider,
                    linkedAt: new Date().toISOString(),
                    oauth2Info: result.oauth2Info
                },
                message: `${provider} account linked successfully`,
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    /**
     * GET /auth/oauth2/status - Get OAuth2 authentication status
     */
    static async getOAuth2Status(req: Request, res: Response, next: NextFunction) {
        try {
            const user = req.user as AuthPayload;

            const [connectedProviders, availableProviders] = await Promise.all([
                OAuth2Service.getConnectedProviders(user.userId),
                Promise.resolve(OAuth2Service.getAvailableProviders())
            ]);

            const response: ApiResponse = {
                success: true,
                data: {
                    connectedProviders,
                    availableProviders,
                    totalConnected: connectedProviders.length,
                    totalAvailable: availableProviders.length
                },
                message: 'OAuth2 status retrieved successfully',
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }
}