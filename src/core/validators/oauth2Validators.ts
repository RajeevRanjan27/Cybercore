import Joi from 'joi';

    export const oauth2Validators = {
        /**
         * Validation for initiating OAuth2 authentication
         */
        initiateAuthSchema: Joi.object({
            params: Joi.object({
                provider: Joi.string()
                    .valid('google', 'github', 'microsoft', 'linkedin', 'facebook', 'instagram', 'twitter', 'leetcode', 'codeforces')
                    .required()
                    .messages({
                        'any.only': 'Provider must be one of: google, github, microsoft, linkedin, facebook, instagram, twitter, leetcode, codeforces'
                    })
            }),
            query: Joi.object({
                redirectTo: Joi.string()
                    .uri({ allowRelative: true })
                    .max(500)
                    .optional(),
                tenantId: Joi.string()
                    .pattern(/^[0-9a-fA-F]{24}$/)
                    .optional()
                    .messages({
                        'string.pattern.base': 'Invalid tenant ID format'
                    })
            })
        }),

        /**
         * Validation for OAuth2 callback
         */
        callbackSchema: Joi.object({
            params: Joi.object({
                provider: Joi.string()
                    .valid('google', 'github', 'microsoft', 'linkedin', 'facebook', 'instagram', 'twitter', 'leetcode', 'codeforces')
                    .required()
            }),
            query: Joi.object({
                code: Joi.string().optional(),
                state: Joi.string().optional(),
                error: Joi.string().optional(),
                error_description: Joi.string().optional()
            })
        }),

        /**
         * Validation for linking OAuth2 account
         */
        linkAccountSchema: Joi.object({
            provider: Joi.string()
                .valid('google', 'github', 'microsoft', 'linkedin', 'facebook', 'instagram', 'twitter', 'leetcode', 'codeforces')
                .required(),
            code: Joi.string()
                .min(1)
                .max(1000)
                .required()
                .messages({
                    'string.empty': 'Authorization code is required',
                    'string.max': 'Authorization code is too long'
                }),
            state: Joi.string()
                .min(1)
                .max(1000)
                .required()
                .messages({
                    'string.empty': 'State parameter is required',
                    'string.max': 'State parameter is too long'
                })
        }),

        /**
         * Validation for provider-specific operations
         */
        providerParamSchema: Joi.object({
            provider: Joi.string()
                .valid('google', 'github', 'microsoft', 'linkedin', 'facebook', 'instagram', 'twitter', 'leetcode', 'codeforces')
                .required()
                .messages({
                    'any.only': 'Provider must be one of: google, github, microsoft, linkedin, facebook, instagram, twitter, leetcode, codeforces'
                })
        }),

        /**
         * Validation for OAuth2 settings update
         */
        oauth2SettingsSchema: Joi.object({
            autoLink: Joi.boolean()
                .default(false)
                .description('Automatically link OAuth2 accounts with same email'),

            allowedProviders: Joi.array()
                .items(Joi.string().valid('google', 'github', 'microsoft', 'linkedin', 'facebook', 'instagram', 'twitter', 'leetcode', 'codeforces'))
                .unique()
                .max(9)
                .default(['google', 'github'])
                .description('List of allowed OAuth2 providers'),

            requireEmailVerification: Joi.boolean()
                .default(true)
                .description('Require email verification from OAuth2 provider'),

            defaultRole: Joi.string()
                .valid('USER', 'TENANT_ADMIN')
                .default('USER')
                .description('Default role for new OAuth2 users'),

            enableProviderRefresh: Joi.boolean()
                .default(true)
                .description('Enable automatic token refresh for OAuth2 providers'),

            sessionDuration: Joi.number()
                .integer()
                .min(300)      // 5 minutes
                .max(2592000)  // 30 days
                .default(86400) // 24 hours
                .description('OAuth2 session duration in seconds')
        }),

        /**
         * Validation for OAuth2 token refresh
         */
        tokenRefreshSchema: Joi.object({
            provider: Joi.string()
                .valid('google', 'github', 'microsoft', 'linkedin', 'facebook', 'instagram', 'twitter', 'leetcode', 'codeforces')
                .required(),
            refreshToken: Joi.string()
                .min(1)
                .max(2000)
                .optional()
                .description('Manual refresh token (optional)')
        }),

        /**
         * Validation for OAuth2 audit log filters
         */
        oauth2AuditSchema: Joi.object({
            provider: Joi.string()
                .valid('google', 'github', 'microsoft', 'linkedin', 'facebook', 'instagram', 'twitter', 'leetcode', 'codeforces')
                .optional(),
            action: Joi.string()
                .valid('OAUTH2_LOGIN', 'OAUTH2_LINK', 'OAUTH2_DISCONNECT', 'OAUTH2_REFRESH')
                .optional(),
            dateFrom: Joi.date()
                .iso()
                .optional(),
            dateTo: Joi.date()
                .iso()
                .min(Joi.ref('dateFrom'))
                .optional(),
            page: Joi.number()
                .integer()
                .min(1)
                .default(1),
            limit: Joi.number()
                .integer()
                .min(1)
                .max(100)
                .default(20)
        }),

        /**
         * Validation for OAuth2 user sync
         */
        userSyncSchema: Joi.object({
            provider: Joi.string()
                .valid('google', 'github', 'microsoft', 'linkedin', 'facebook', 'instagram', 'twitter', 'leetcode', 'codeforces')
                .required(),
            syncProfile: Joi.boolean()
                .default(true)
                .description('Sync profile information from provider'),
            syncAvatar: Joi.boolean()
                .default(true)
                .description('Sync avatar/profile picture from provider'),
            overwriteLocal: Joi.boolean()
                .default(false)
                .description('Overwrite local data with provider data'),
            fields: Joi.array()
                .items(Joi.string().valid('firstName', 'lastName', 'email', 'avatar'))
                .unique()
                .default(['firstName', 'lastName', 'avatar'])
                .description('Fields to sync from provider')
        }),

        /**
         * Validation for OAuth2 bulk operations
         */
        bulkOAuth2Schema: Joi.object({
            operation: Joi.string()
                .valid('disconnect', 'refresh', 'sync')
                .required(),
            userIds: Joi.array()
                .items(Joi.string().pattern(/^[0-9a-fA-F]{24}$/))
                .min(1)
                .max(100)
                .required(),
            provider: Joi.string()
                .valid('google', 'github', 'microsoft', 'linkedin', 'facebook', 'instagram', 'twitter', 'leetcode', 'codeforces')
                .required(),
            reason: Joi.string()
                .max(500)
                .optional(),
            forceOperation: Joi.boolean()
                .default(false)
                .description('Force operation even if it might cause issues')
        })
    };

// Custom validation messages
    export const oauth2ValidationMessages = {
        'string.provider': 'Invalid OAuth2 provider. Supported providers: google, github, microsoft, linkedin',
        'oauth2.stateExpired': 'OAuth2 state has expired. Please restart the authentication process',
        'oauth2.stateMismatch': 'OAuth2 state mismatch. Possible CSRF attack detected',
        'oauth2.providerError': 'OAuth2 provider returned an error: {error}',
        'oauth2.alreadyLinked': 'This OAuth2 account is already linked to another user',
        'oauth2.noRefreshToken': 'No refresh token available for this provider',
        'oauth2.tokenExpired': 'OAuth2 access token has expired and cannot be refreshed',
        'oauth2.providerNotConnected': 'This OAuth2 provider is not connected to your account',
        'oauth2.lastAuthMethod': 'Cannot disconnect the only authentication method. Please set a password first',
        'oauth2.rateLimitExceeded': 'Too many OAuth2 requests. Please try again later',
        'oauth2.configurationError': 'OAuth2 provider is not properly configured',
        'oauth2.networkError': 'Unable to communicate with OAuth2 provider. Please try again',
        'oauth2.invalidToken': 'Invalid or malformed OAuth2 token',
        'oauth2.scopeInsufficient': 'Insufficient OAuth2 scope permissions',
        'oauth2.userNotFound': 'User information not found from OAuth2 provider',
        'oauth2.emailNotVerified': 'Email address from OAuth2 provider is not verified',
        'oauth2.domainRestricted': 'Your domain is not allowed for OAuth2 authentication'
    };

// Rate limiting configurations for OAuth2 operations
    export const oauth2RateLimits = {
        initiate: {
            windowMs: 60 * 1000,     // 1 minute
            max: 10,                 // 10 initiations per minute
            message: oauth2ValidationMessages['oauth2.rateLimitExceeded']
        },
        callback: {
            windowMs: 5 * 60 * 1000, // 5 minutes
            max: 20,                 // 20 callbacks per 5 minutes
            message: oauth2ValidationMessages['oauth2.rateLimitExceeded']
        },
        connect: {
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 5,                   // 5 connections per 15 minutes
            message: oauth2ValidationMessages['oauth2.rateLimitExceeded']
        },
        disconnect: {
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 3,                   // 3 disconnections per 15 minutes
            message: oauth2ValidationMessages['oauth2.rateLimitExceeded']
        },
        refresh: {
            windowMs: 60 * 1000,     // 1 minute
            max: 5,                  // 5 refreshes per minute
            message: oauth2ValidationMessages['oauth2.rateLimitExceeded']
        }
    };

// Helper function to validate OAuth2 configuration
    export const validateOAuth2Config = (provider: string): boolean => {
        const requiredEnvVars = {
            google: ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'],
            github: ['GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET'],
            microsoft: ['MICROSOFT_CLIENT_ID', 'MICROSOFT_CLIENT_SECRET'],
            linkedin: ['LINKEDIN_CLIENT_ID', 'LINKEDIN_CLIENT_SECRET'],
            facebook: ['FACEBOOK_CLIENT_ID', 'FACEBOOK_CLIENT_SECRET'],
            instagram: ['INSTAGRAM_CLIENT_ID', 'INSTAGRAM_CLIENT_SECRET'],
            twitter: ['TWITTER_CLIENT_ID', 'TWITTER_CLIENT_SECRET'],
            leetcode: ['LEETCODE_CLIENT_ID', 'LEETCODE_CLIENT_SECRET'],
            codeforces: ['CODEFORCES_CLIENT_ID', 'CODEFORCES_CLIENT_SECRET']
        };

        const vars = requiredEnvVars[provider as keyof typeof requiredEnvVars];
        if (!vars) return false;

        return vars.every(varName => !!process.env[varName]);
    };