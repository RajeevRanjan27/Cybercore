// src/api/auth/controller.ts
import { Request, Response, NextFunction } from 'express';
import { User } from '@/core/models/User';
import { Tenant } from '@/core/models/Tenant';
import { AuthService } from '@/core/services/AuthService';
import { AppError } from '@/core/middlewares/errorHandler';
import { ApiResponse } from '@/core/types';
import {CacheService} from "@/core/services/CacheService";

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
                finalTenantId = String(defaultTenant._id);
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
            await AuthService.storeRefreshToken(String(user._id), tokens.refreshToken);

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
            const ipAddress = req.ip;

            // Check if account is locked due to failed attempts
            const lockStatus = await AuthService.isAccountLocked(email, ipAddress);
            if (lockStatus.locked) {
                const response: ApiResponse = {
                    success: false,
                    error: lockStatus.reason,
                    message: `Account temporarily locked. Try again in ${Math.ceil((lockStatus.retryAfter || 0) / 60)} minutes.`,
                    timestamp: new Date().toISOString()
                };
                return res.status(429).json(response);
            }

            // Find user (with caching)
            let user = await AuthService.getCachedUser(email);
            if (!user) {
                // If not in cache, try database with email
                user = await User.findOne({ email }).select('+password');
                if (user) {
                    // Cache the user for future lookups
                    await CacheService.set(`user:${user._id}`, user.toObject(), 300);
                }
            }

            if (!user || !user.isActive) {
                // Track failed login attempt
                await AuthService.trackFailedLogin(email, ipAddress);
                throw new AppError('Invalid credentials', 401);
            }

            // Check password
            const isPasswordValid = await user.comparePassword(password);
            if (!isPasswordValid) {
                // Track failed login attempt
                await AuthService.trackFailedLogin(email, ipAddress);
                throw new AppError('Invalid credentials', 401);
            }

            // Clear failed login attempts after successful login
            await AuthService.clearFailedLoginAttempts(email, ipAddress);

            // Check for suspicious activity
            const isSuspicious = await AuthService.checkSuspiciousActivity(String(user._id), ipAddress || '');
            if (isSuspicious) {
                // Log suspicious activity but don't block (you could add more logic here)
                console.log(`⚠️ Suspicious login detected for user ${user._id} from IP ${ipAddress}`);

                // You could send email notification, require 2FA, etc.
                // For now, we'll just log it
            }

            // Update last login
            user.lastLogin = new Date();
            await user.save();

            // Track login activity
            await AuthService.trackLogin(String(user._id), ipAddress);

            // Generate tokens
            const tokens = AuthService.generateTokens(user);

            // Store refresh token (this now updates cache too)
            await AuthService.storeRefreshToken(String(user._id), tokens.refreshToken);

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
                    tokens,
                    ...(isSuspicious && { securityAlert: 'Login from new location detected' })
                },
                message: 'Login successful',
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }    static async refreshToken(req: Request, res: Response, next: NextFunction) {
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