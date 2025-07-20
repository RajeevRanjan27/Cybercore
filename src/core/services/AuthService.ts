import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid'; // Import uuid to generate unique IDs
import { config } from '@/config/env';
import { User, IUser } from '@/core/models/User';
import { RefreshToken } from '@/core/models/RefreshToken';
import { AppError } from '@/core/middlewares/errorHandler';
import { AuthPayload } from '@/core/types';
import { PERMISSIONS } from '@/core/constants/roles';
import {CacheService} from "@/core/services/CacheService";

export class AuthService {
    static generateTokens(user: IUser) {

        if (!config.JWT_SECRET) {
            throw new AppError('JWT_SECRET is not configured properly', 500);
        }
        if (!config.JWT_REFRESH_SECRET) {
            throw new AppError('JWT_REFRESH_SECRET is not configured properly', 500);
        }
        // Ensure we have proper types for jwt.sign
        const jwtSecret: jwt.Secret = config.JWT_SECRET;
        const jwtRefreshSecret: jwt.Secret = config.JWT_REFRESH_SECRET;

        const accessTokenOptions: jwt.SignOptions = {
            expiresIn: (config.JWT_EXPIRES_IN || '15m')
        };

        const refreshTokenOptions: jwt.SignOptions = {
            expiresIn: (config.JWT_REFRESH_EXPIRES_IN || '7d')
        };

        // Add a unique JWT ID (jti) to the access token payload to ensure uniqueness
        const payload: AuthPayload & { jti: string } = {
            userId: String(user._id),
            tenantId: user.tenantId.toString(),
            role: user.role,
            permissions: this.getUserPermissions(user.role),
            jti: uuidv4()
        };

        const accessToken = jwt.sign(payload, jwtSecret, accessTokenOptions);

        // Add a unique JWT ID (jti) to the refresh token payload as well
        const refreshTokenPayload = {
            userId: String(user._id),
            jti: uuidv4()
        };
        const refreshToken = jwt.sign(refreshTokenPayload, jwtRefreshSecret, refreshTokenOptions);

        return { accessToken, refreshToken };
    }

    static async storeRefreshToken(userId: string, token: string) {
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7); // 7 days

        // Store in database
        await RefreshToken.create({
            userId,
            token,
            expiresAt
        });

        // Cache active sessions count for the user
        await CacheService.set(`user_sessions:${userId}`, await this.getActiveSessionsCount(userId), 300);
    }

    static async revokeRefreshToken(token: string) {
        // Remove from database
        const refreshToken = await RefreshToken.findOneAndUpdate(
            { token },
            { isRevoked: true }
        );

        if (refreshToken) {
            // Update cached session count
            const userId = refreshToken.userId.toString();
            await CacheService.set(`user_sessions:${userId}`, await this.getActiveSessionsCount(userId), 300);

            // Add to blacklist cache for fast lookups
            await CacheService.set(`blacklisted_token:${token}`, true, 7 * 24 * 60 * 60); // 7 days
        }
    }

    static async isTokenBlacklisted(token: string): Promise<boolean> {
        // Check cache first (much faster than DB)
        const blacklisted = await CacheService.get(`blacklisted_token:${token}`);
        return blacklisted === true;
    }

    static verifyAccessToken(token: string): AuthPayload {
        try {
            return jwt.verify(token, config.JWT_SECRET) as AuthPayload;
        } catch (error) {
            throw new AppError('Invalid or expired token', 401);
        }
    }

    static verifyRefreshToken(token: string) {
        try {
            return jwt.verify(token, config.JWT_REFRESH_SECRET) as { userId: string, jti: string };
        } catch (error) {
            throw new AppError('Invalid or expired refresh token', 401);
        }
    }

    static getUserPermissions(role: string): string[] {
        // Cache permissions for performance
        const cacheKey = `permissions:${role}`;

        // Try to get from cache first (this will be fast for subsequent calls)
        CacheService.get(cacheKey).then(cached => {
            if (cached) return cached;
        });

        const permissions: string[] = [];
        Object.entries(PERMISSIONS).forEach(([permission, roles]) => {
            if (roles.includes(role as any)) {
                permissions.push(permission);
            }
        });

        // Cache for 10 min (permissions don't change often but still for 10 min)
        CacheService.set(cacheKey, permissions, 600);

        return permissions;
    }

    static async refreshAccessToken(refreshToken: string) {
        // Check blacklist cache first
        if (await this.isTokenBlacklisted(refreshToken)) {
            throw new AppError('Token has been revoked', 401);
        }

        // Verify the refresh token
        const decoded = this.verifyRefreshToken(refreshToken);

        // Check if token exists and is not revoked
        const storedToken = await RefreshToken.findOne({
            token: refreshToken,
            isRevoked: false
        });

        if (!storedToken) {
            throw new AppError('Invalid refresh token', 401);
        }

        // Get user (with caching)
        const user = await this.getCachedUser(decoded.userId);
        if (!user || !user.isActive) {
            throw new AppError('User not found or inactive', 401);
        }

        // Generate new tokens
        const tokens = this.generateTokens(user);

        // Revoke old refresh token
        await this.revokeRefreshToken(refreshToken);

        // Store new refresh token
        await this.storeRefreshToken(String(user._id), tokens.refreshToken);

        return tokens;
    }


    /**
     * Get user with caching for better performance. Always returns a full Mongoose document.
     */
    static async getCachedUser(userIdOrEmail: string): Promise<IUser | null> {
        let cacheKey: string;
        let isEmail = false;

        // Check if it's an email or user ID
        if (userIdOrEmail.includes('@')) {
            cacheKey = `user_email:${userIdOrEmail}`;
            isEmail = true;
        } else {
            cacheKey = `user:${userIdOrEmail}`;
        }

        // Try cache first
        const cachedUser = await CacheService.get(cacheKey);
        if (cachedUser) {
            // Re-hydrate a Mongoose document from the cached plain object
            return new User(cachedUser);
        }

        // Get from database
        let user: IUser | null;
        if (isEmail) {
            // Fetch as a full Mongoose document, not a lean object
            user = await User.findOne({ email: userIdOrEmail }).select('+password');
        } else {
            user = await User.findById(userIdOrEmail);
        }

        if (user) {
            // Cache the plain object version for efficiency
            const userObject = user.toObject();
            await CacheService.set(cacheKey, userObject, 300);

            // Also cache by the other identifier for faster lookups
            if (isEmail) {
                await CacheService.set(`user:${user._id}`, userObject, 300);
            } else {
                await CacheService.set(`user_email:${user.email}`, userObject, 300);
            }
        }

        return user;
    }
    /**
     * Get active sessions count for a user
     */
    private static async getActiveSessionsCount(userId: string): Promise<number> {
        return RefreshToken.countDocuments({
            userId,
            isRevoked: false,
            expiresAt: {$gt: new Date()}
        });
    }

    /**
     * Track login activity
     */
    static async trackLogin(userId: string, ipAddress?: string): Promise<void> {
        const today = new Date().toISOString().split('T')[0];

        // Increment daily login counter
        await CacheService.increment(`daily_logins:${today}`, 1);

        // Track user's last login IP (for security)
        if (ipAddress) {
            await CacheService.set(`user_last_ip:${userId}`, ipAddress, 7 * 24 * 60 * 60); // 7 days
        }

        // Track unique daily users
        await CacheService.setAdd(`daily_active_users:${today}`, userId);
    }

    /**
     * Check for suspicious login activity
     */
    static async checkSuspiciousActivity(userId: string, ipAddress: string): Promise<boolean> {
        if (!ipAddress) return false;

        try {
            // Get user's last known IP
            const lastKnownIp = await CacheService.get(`user_last_ip:${userId}`);

            // If this is the first login or same IP, not suspicious
            if (!lastKnownIp || lastKnownIp === ipAddress) {
                return false;
            }

            // Check for rapid login attempts from different IPs (within 5 minutes)
            const recentIpsKey = `user_recent_ips:${userId}`;
            const recentIps = await CacheService.get(recentIpsKey) || [];

            // Add current IP to recent IPs list
            const now = Date.now();
            const updatedIps = [
                ...recentIps.filter((entry: any) => (now - entry.timestamp) < 5 * 60 * 1000), // Keep only last 5 minutes
                { ip: ipAddress, timestamp: now }
            ];

            // Store updated recent IPs (expire in 5 minutes)
            await CacheService.set(recentIpsKey, updatedIps, 300);

            // Count unique IPs in the last 5 minutes
            const uniqueIps = new Set(updatedIps.map((entry: any) => entry.ip));

            // If more than 2 different IPs in 5 minutes, it's suspicious
            if (uniqueIps.size > 2) {
                return true;
            }

            // Check if IP is from a different country/region (basic check)
            // This is a simple heuristic - in production, you'd use a GeoIP service
            const ipParts = ipAddress.split('.');
            const lastIpParts = lastKnownIp.split('.');

            // If first two octets are very different, might be different regions
            if (ipParts[0] !== lastIpParts[0] && ipParts[1] !== lastIpParts[1]) {
                return true;
            }

            return false;
        } catch (error) {
            // If there's an error checking, don't block the login
            console.error('Error checking suspicious activity:', error);
            return false;
        }
    }

    /**
     * Track failed login attempts for rate limiting and security
     */
    static async trackFailedLogin(identifier: string, ipAddress?: string): Promise<boolean> {
        try {
            const failedAttemptsKey = `failed_logins:${identifier}`;
            const ipFailedAttemptsKey = ipAddress ? `failed_logins_ip:${ipAddress}` : null;

            // Increment failed attempts for this identifier
            const userAttempts = await CacheService.increment(failedAttemptsKey, 1);

            // Set expiry if this is the first attempt
            if (userAttempts === 1) {
                await CacheService.setWithExpiry(failedAttemptsKey, 1, new Date(Date.now() + 15 * 60 * 1000)); // 15 minutes
            }

            // Track IP-based attempts if IP is provided
            let ipAttempts = 0;
            if (ipFailedAttemptsKey) {
                ipAttempts = await CacheService.increment(ipFailedAttemptsKey, 1);
                if (ipAttempts === 1) {
                    await CacheService.setWithExpiry(ipFailedAttemptsKey, 1, new Date(Date.now() + 15 * 60 * 1000));
                }
            }

            // Return true if too many attempts (account lockout threshold)
            return userAttempts >= 5 || ipAttempts >= 10;
        } catch (error) {
            console.error('Error tracking failed login:', error);
            return false;
        }
    }

    /**
     * Clear failed login attempts after successful login
     */
    static async clearFailedLoginAttempts(identifier: string, ipAddress?: string): Promise<void> {
        try {
            await CacheService.delete(`failed_logins:${identifier}`);
            if (ipAddress) {
                await CacheService.delete(`failed_logins_ip:${ipAddress}`);
            }
        } catch (error) {
            console.error('Error clearing failed login attempts:', error);
        }
    }

    /**
     * Check if account is temporarily locked due to failed attempts
     */
    static async isAccountLocked(identifier: string, ipAddress?: string): Promise<{ locked: boolean; reason?: string; retryAfter?: number }> {
        try {
            const userAttempts = await CacheService.get(`failed_logins:${identifier}`) || 0;
            const ipAttempts = ipAddress ? await CacheService.get(`failed_logins_ip:${ipAddress}`) || 0 : 0;

            if (userAttempts >= 5) {
                return {
                    locked: true,
                    reason: 'Too many failed login attempts for this account',
                    retryAfter: 15 * 60 // 15 minutes in seconds
                };
            }

            if (ipAttempts >= 10) {
                return {
                    locked: true,
                    reason: 'Too many failed login attempts from this IP address',
                    retryAfter: 15 * 60
                };
            }

            return { locked: false };
        } catch (error) {
            console.error('Error checking account lock status:', error);
            return { locked: false };
        }
    }

}