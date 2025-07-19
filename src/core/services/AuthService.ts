import jwt from 'jsonwebtoken';
import { config } from '@/config/env';
import { User, IUser } from '@/core/models/User';
import { RefreshToken } from '@/core/models/RefreshToken';
import { AppError } from '@/core/middlewares/errorHandler';
import { AuthPayload } from '@/core/types';
import { PERMISSIONS } from '@/core/constants/roles';
import ms from "ms";

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
            expiresIn: (config.JWT_EXPIRES_IN || '15m') as ms.StringValue
        };

        const refreshTokenOptions: jwt.SignOptions = {
            expiresIn: (config.JWT_REFRESH_EXPIRES_IN || '7d') as ms.StringValue
        };

        const payload: AuthPayload = {
            userId: user._id.toString(),
            tenantId: user.tenantId.toString(),
            role: user.role,
            permissions: this.getUserPermissions(user.role)
        };

        const accessToken = jwt.sign(payload, jwtSecret, accessTokenOptions);


        const refreshTokenPayload = { userId: user._id.toString() };
        const refreshToken = jwt.sign(refreshTokenPayload, jwtRefreshSecret, refreshTokenOptions);

        return { accessToken, refreshToken };
    }

    static async storeRefreshToken(userId: string, token: string) {
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7); // 7 days

        await RefreshToken.create({
            userId,
            token,
            expiresAt
        });
    }

    static async revokeRefreshToken(token: string) {
        await RefreshToken.findOneAndUpdate(
            { token },
            { isRevoked: true }
        );
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
            return jwt.verify(token, config.JWT_REFRESH_SECRET) as { userId: string };
        } catch (error) {
            throw new AppError('Invalid or expired refresh token', 401);
        }
    }

    static getUserPermissions(role: string): string[] {
        const permissions: string[] = [];

        Object.entries(PERMISSIONS).forEach(([permission, roles]) => {
            if (roles.includes(role as any)) {
                permissions.push(permission);
            }
        });

        return permissions;
    }

    static async refreshAccessToken(refreshToken: string) {
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

        // Get user
        const user = await User.findById(decoded.userId);
        if (!user || !user.isActive) {
            throw new AppError('User not found or inactive', 401);
        }

        // Generate new tokens
        const tokens = this.generateTokens(user);

        // Revoke old refresh token
        await this.revokeRefreshToken(refreshToken);

        // Store new refresh token
        await this.storeRefreshToken(user._id.toString(), tokens.refreshToken);

        return tokens;
    }
}
