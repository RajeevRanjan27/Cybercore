// src/api/auth/controller.ts
import { Request, Response, NextFunction } from 'express';
import { User } from '@/core/models/User';
import { Tenant } from '@/core/models/Tenant';
import { AuthService } from '@/core/services/AuthService';
import { AppError } from '@/core/middlewares/errorHandler';
import { ApiResponse } from '@/core/types';

export class AuthController {
    static async register(req: Request, res: Response, next: NextFunction) {
        try {
            const { email, password, firstName, lastName, tenantId } = req.body;

            // Check if user already exists
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                throw new AppError('User already exists', 409);
            }

            let finalTenantId = tenantId;

            if (!tenantId) {
                const defaultTenant = await Tenant.findOne({ isDefault: true });
                if (!defaultTenant) {
                    throw new AppError('Default tenant not found. Please contact administrator.', 500);
                }
                finalTenantId = defaultTenant._id.toString();
            }else {
                // If tenantId is provided, verify it exists
                const tenant = await Tenant.findById(tenantId);
                if (!tenant) {
                    throw new AppError('Invalid tenant', 400);
                }
            }

            // Create user
            const user = await User.create({
                email,
                password,
                firstName,
                lastName,
                tenantId: finalTenantId
            });

            // Generate tokens
            const tokens = AuthService.generateTokens(user);

            // Store refresh token
            await AuthService.storeRefreshToken(user._id.toString(), tokens.refreshToken);

            const response: ApiResponse = {
                success: true,
                data: {
                    user: {
                        id: user._id,
                        email: user.email,
                        firstName: user.firstName,
                        lastName: user.lastName,
                        role: user.role,
                        tenantId: user.tenantId
                    },
                    tokens
                },
                message: 'User registered successfully',
                timestamp: new Date().toISOString()
            };

            res.status(201).json(response);
        } catch (error) {
            next(error);
        }
    }

    static async login(req: Request, res: Response, next: NextFunction) {
        try {
            const { email, password } = req.body;

            // Find user
            const user = await User.findOne({ email }).select('+password');
            if (!user || !user.isActive) {
                throw new AppError('Invalid credentials', 401);
            }

            // Check password
            const isPasswordValid = await user.comparePassword(password);
            if (!isPasswordValid) {
                throw new AppError('Invalid credentials', 401);
            }

            // Update last login
            user.lastLogin = new Date();
            await user.save();

            // Generate tokens
            const tokens = AuthService.generateTokens(user);

            // Store refresh token
            await AuthService.storeRefreshToken(user._id.toString(), tokens.refreshToken);

            const response: ApiResponse = {
                success: true,
                data: {
                    user: {
                        id: user._id,
                        email: user.email,
                        firstName: user.firstName,
                        lastName: user.lastName,
                        role: user.role,
                        tenantId: user.tenantId
                    },
                    tokens
                },
                message: 'Login successful',
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    static async refreshToken(req: Request, res: Response, next: NextFunction) {
        try {
            const { refreshToken } = req.body;

            const tokens = await AuthService.refreshAccessToken(refreshToken);

            const response: ApiResponse = {
                success: true,
                data: { tokens },
                message: 'Token refreshed successfully',
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    static async logout(req: Request, res: Response, next: NextFunction) {
        try {
            const { refreshToken } = req.body;

            if (refreshToken) {
                await AuthService.revokeRefreshToken(refreshToken);
            }

            const response: ApiResponse = {
                success: true,
                message: 'Logged out successfully',
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    static async me(req: Request, res: Response, next: NextFunction) {
        try {
            const user = await User.findById(req.user?.userId).populate('tenantId');

            if (!user) {
                throw new AppError('User not found', 404);
            }

            const response: ApiResponse = {
                success: true,
                data: {
                    user: {
                        id: user._id,
                        email: user.email,
                        firstName: user.firstName,
                        lastName: user.lastName,
                        role: user.role,
                        tenantId: user.tenantId,
                        lastLogin: user.lastLogin
                    }
                },
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }
}