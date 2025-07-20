// ============================================================================
// tests/unit/services/OAuth2Service.test.ts
// ============================================================================

import { OAuth2Service } from '@/core/services/OAuth2Service';
import { CacheService } from '@/core/services/CacheService';
import axios from 'axios';
import {Tenant} from "../../../src/core/models/Tenant";
import {AppError} from "../../../src/core/middlewares/errorHandler";
import {User} from "../../../src/core/models/User";
import {UserRole} from "../../../src/core/constants/roles";

jest.mock('axios');
jest.mock('@/core/services/CacheService');

const mockedAxios = axios as jest.Mocked<typeof axios>;
const mockedCacheService = CacheService as jest.Mocked<typeof CacheService>;

describe('OAuth2Service', () => {
    let testTenant: any;

    beforeAll(() => {
        // Mock environment variables for providers
        process.env.GOOGLE_CLIENT_ID = 'your_google_client_id.apps.googleusercontent.com';
        process.env.GOOGLE_CLIENT_SECRET = 'your_google_client_secret';
        process.env.GITHUB_CLIENT_ID = 'your_github_client_id';
        process.env.GITHUB_CLIENT_SECRET = 'your_github_client_secret';
        process.env.BASE_URL = 'http://localhost:3000';
    });

    beforeEach(async () => {
        await Tenant.deleteMany({});
        await User.deleteMany({});

        testTenant = await Tenant.create({
            name: 'OAuth2 Test Tenant',
            domain: 'oauth2test.com',
            subdomain: 'oauth2test',
            isDefault: true
        });

        OAuth2Service.initialize();

        // **FIX:** Clear all mocks before each test to prevent state bleeding from one test to another.
        jest.clearAllMocks();
    });

    describe('generateAuthURL', () => {
        it('should generate valid authorization URL for Google', () => {
            const authUrl = OAuth2Service.generateAuthURL('google', {
                redirectTo: '/dashboard',
                tenantId: testTenant._id.toString()
            });

            expect(authUrl).toContain('accounts.google.com/o/oauth2/v2/auth');
            expect(authUrl).toContain('client_id=');
            expect(authUrl).toContain('redirect_uri=');
            expect(authUrl).toContain('response_type=code');
            expect(authUrl).toContain('scope=');
            expect(authUrl).toContain('state=');
        });

        it('should throw error for unsupported provider', () => {
            expect(() => {
                OAuth2Service.generateAuthURL('unsupported-provider');
            }).toThrow(AppError);
        });

        it('should include proper scope for different providers', () => {
            const googleUrl = OAuth2Service.generateAuthURL('google');
            const githubUrl = OAuth2Service.generateAuthURL('github');

            expect(googleUrl).toContain('scope=openid%20email%20profile');
            expect(githubUrl).toContain('scope=user%3Aemail');
        });
    });

    describe('getAvailableProviders', () => {
        it('should return list of configured providers', () => {
            const providers = OAuth2Service.getAvailableProviders();

            expect(Array.isArray(providers)).toBe(true);
            expect(providers.length).toBeGreaterThan(0);
            expect(providers[0]).toHaveProperty('name');
            expect(providers[0]).toHaveProperty('displayName');
        });

        it('should only return providers with valid configuration', () => {
            const providers = OAuth2Service.getAvailableProviders();

            // Should only include providers that have client ID and secret configured
            providers.forEach(provider => {
                expect(provider.name).toBeTruthy();
                expect(provider.displayName).toBeTruthy();
            });
        });
    });

    describe('handleCallback', () => {
        it('should handle successful Google OAuth callback', async () => {
            // Mock token exchange response
            mockedAxios.post.mockResolvedValueOnce({
                data: {
                    access_token: 'mock-access-token',
                    refresh_token: 'mock-refresh-token',
                    expires_in: 3600,
                    token_type: 'Bearer'
                }
            });

            // Mock user info response
            mockedAxios.get.mockResolvedValueOnce({
                data: {
                    id: 'google-user-id',
                    email: 'oauth2user@gmail.com',
                    given_name: 'OAuth2',
                    family_name: 'User',
                    name: 'OAuth2 User',
                    picture: 'https://example.com/avatar.jpg',
                    verified_email: true
                }
            });

            const mockRequest = {
                ip: '192.168.1.1',
                get: jest.fn().mockReturnValue('Mozilla/5.0...')
            } as any;

            const stateData = {
                nonce: 'test-nonce',
                provider: 'google',
                tenantId: testTenant._id.toString(),
                timestamp: Date.now()
            };
            const state = Buffer.from(JSON.stringify(stateData)).toString('base64url');

            // Mock the cache service for state validation
            (mockedCacheService.get as jest.Mock).mockResolvedValue(stateData);

            const result = await OAuth2Service.handleCallback(
                'google',
                'auth-code',
                state,
                mockRequest
            );

            expect(result).toHaveProperty('user');
            expect(result).toHaveProperty('tokens');
            expect(result).toHaveProperty('isNewUser');
            expect(result).toHaveProperty('oauth2Info');
            expect(result.user.email).toBe('oauth2user@gmail.com');
        });

        it('should handle OAuth provider errors', async () => {
            mockedAxios.post.mockRejectedValueOnce({
                isAxiosError: true,
                response: {
                    status: 400,
                    data: {
                        error: 'invalid_grant',
                        error_description: 'Authorization code is invalid'
                    }
                }
            });

            const mockRequest = {ip: '192.168.1.1'} as any;
            const stateData = {
                nonce: 'test-nonce',
                provider: 'google',
                timestamp: Date.now()
            };
            const state = Buffer.from(JSON.stringify(stateData)).toString('base64url');
            (mockedCacheService.get as jest.Mock).mockResolvedValue(stateData);


            await expect(
                OAuth2Service.handleCallback('google', 'invalid-code', state, mockRequest)
            ).rejects.toThrow(AppError);
        });

        it('should link existing user by email', async () => {
            // Create existing user
            const existingUser = await User.create({
                email: 'existing@gmail.com',
                password: 'Password123!',
                firstName: 'Existing',
                lastName: 'User',
                role: UserRole.USER,
                tenantId: testTenant._id,
                isActive: true
            });

            // Mock token exchange response
            mockedAxios.post.mockResolvedValueOnce({
                data: {
                    access_token: 'mock-access-token',
                    expires_in: 3600
                }
            });

            // Mock user info response
            mockedAxios.get.mockResolvedValueOnce({
                data: {
                    id: 'google-user-id',
                    email: 'existing@gmail.com',
                    given_name: 'Existing',
                    family_name: 'User',
                    name: 'Existing User',
                    verified_email: true
                }
            });

            const mockRequest = {
                ip: '192.168.1.1',
                get: jest.fn().mockReturnValue('Mozilla/5.0...')
            } as any;

            const stateData = {
                nonce: 'test-nonce',
                provider: 'google',
                tenantId: testTenant._id.toString(),
                timestamp: Date.now()
            };
            const state = Buffer.from(JSON.stringify(stateData)).toString('base64url');
            (mockedCacheService.get as jest.Mock).mockResolvedValue(stateData);

            try {
                const result = await OAuth2Service.handleCallback(
                    'google',
                    'auth-code',
                    state,
                    mockRequest
                );

                expect(result.isNewUser).toBe(false);
                expect(result.user.email).toBe('existing@gmail.com');
                expect(String(result.user._id)).toBe(String(existingUser._id));

                // Verify OAuth connection was added
                const updatedUser = await User.findById(existingUser._id);
                expect(updatedUser?.oauth2Connections?.get('google')).toBeDefined();
                expect(updatedUser?.oauth2Connections?.get('google')?.providerId).toBe('google-user-id');

            } catch (error) {
                console.error('Test failed with error:', error);
                console.error('Error stack:', error instanceof Error ? error.stack : 'No stack trace');
                throw error;
            }
        });
    });

    describe('disconnectProvider', () => {
        it('should disconnect OAuth provider successfully', async () => {
            const user = await User.create({
                email: 'disconnect@test.com',
                password: 'Password123!',
                firstName: 'Disconnect',
                lastName: 'Test',
                role: UserRole.USER,
                tenantId: testTenant._id,
                isActive: true,
                oauth2Connections: new Map([
                    ['google', {
                        providerId: 'google-123',
                        accessToken: 'token',
                        connectedAt: new Date()
                    }]
                ])
            });

            await OAuth2Service.disconnectProvider(String(user._id), 'google');

            const updatedUser = await User.findById(user._id);
            expect(updatedUser?.oauth2Connections?.get('google')).toBeUndefined();
        });

        it('should prevent disconnecting the only auth method', async () => {
            const user = await User.create({
                email: 'onlyoauth@test.com',
                firstName: 'OAuth',
                lastName: 'Only',
                role: UserRole.USER,
                tenantId: testTenant._id,
                isActive: true,
                registrationMethod: 'oauth2', // This is key to bypass password requirement
                oauth2Connections: new Map([
                    ['google', {
                        providerId: 'google-123',
                        accessToken: 'token',
                        connectedAt: new Date()
                    }]
                ])
            });

            await expect(
                OAuth2Service.disconnectProvider(String(user._id), 'google')
            ).rejects.toThrow(AppError);
        });

        it('should allow disconnecting one of multiple auth methods', async () => {
            const user = await User.create({
                email: 'multipleauth@test.com',
                password: 'Password123!',
                firstName: 'Multiple',
                lastName: 'Auth',
                role: UserRole.USER,
                tenantId: testTenant._id,
                isActive: true,
                oauth2Connections: new Map([
                    ['google', {
                        providerId: 'google-123',
                        accessToken: 'token',
                        connectedAt: new Date()
                    }],
                    ['github', {
                        providerId: 'github-456',
                        accessToken: 'token',
                        connectedAt: new Date()
                    }]
                ])
            });

            await OAuth2Service.disconnectProvider(String(user._id), 'google');
            const updatedUser = await User.findById(user._id);
            expect(updatedUser?.oauth2Connections?.get('google')).toBeUndefined();
            expect(updatedUser?.oauth2Connections?.get('github')).toBeDefined();
        });
    });
});
