import { Request, Response, NextFunction } from 'express';
import { User } from '@/core/models/User';
import { AppError } from '@/core/middlewares/errorHandler';
import { ApiResponse, PaginatedResponse } from '@/core/types';
import { UserRole } from '@/core/constants/roles';

export class UserController {
    static async getUsers(req: Request, res: Response, next: NextFunction) {
        try {
            const page = parseInt(req.query.page as string) || 1;
            const limit = parseInt(req.query.limit as string) || 10;
            const skip = (page - 1) * limit;

            // Build query based on user role and tenant
            let query: any = {};

            if (req.user?.role === UserRole.TENANT_ADMIN) {
                query.tenantId = req.user.tenantId;
            } else if (req.user?.role === UserRole.USER) {
                query._id = req.user.userId;
            }

            const users = await User.find(query)
                .select('-password')
                .populate('tenantId', 'name domain')
                .skip(skip)
                .limit(limit)
                .sort({ createdAt: -1 });

            const total = await User.countDocuments(query);

            const response: ApiResponse<PaginatedResponse<any>> = {
                success: true,
                data: {
                    data: users,
                    pagination: {
                        page,
                        limit,
                        total,
                        totalPages: Math.ceil(total / limit)
                    }
                },
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    static async getUserById(req: Request, res: Response, next: NextFunction) {
        try {
            const { id } = req.params;

            let query: any = { _id: id };

            // Tenant admins can only see users in their tenant
            if (req.user?.role === UserRole.TENANT_ADMIN) {
                query.tenantId = req.user.tenantId;
            }

            // Regular users can only see themselves
            if (req.user?.role === UserRole.USER) {
                query._id = req.user.userId;
            }

            const user = await User.findOne(query)
                .select('-password')
                .populate('tenantId', 'name domain');

            if (!user) {
                throw new AppError('User not found', 404);
            }

            const response: ApiResponse = {
                success: true,
                data: { user },
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    static async updateUser(req: Request, res: Response, next: NextFunction) {
        try {
            const { id } = req.params;
            const { firstName, lastName, role } = req.body;

            let query: any = { _id: id };

            // Role-based access control
            if (req.user?.role === UserRole.TENANT_ADMIN) {
                query.tenantId = req.user.tenantId;
            } else if (req.user?.role === UserRole.USER) {
                query._id = req.user.userId;
                // Users can't change their own role
                delete req.body.role;
            }

            const user = await User.findOneAndUpdate(
                query,
                { firstName, lastName, ...(role && { role }) },
                { new: true, runValidators: true }
            ).select('-password');

            if (!user) {
                throw new AppError('User not found', 404);
            }

            const response: ApiResponse = {
                success: true,
                data: { user },
                message: 'User updated successfully',
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    static async deleteUser(req: Request, res: Response, next: NextFunction) {
        try {
            const { id } = req.params;

            let query: any = { _id: id };

            // Only admins can delete users
            if (req.user?.role === UserRole.TENANT_ADMIN) {
                query.tenantId = req.user.tenantId;
            }

            const user = await User.findOneAndUpdate(
                query,
                { isActive: false },
                { new: true }
            );

            if (!user) {
                throw new AppError('User not found', 404);
            }

            const response: ApiResponse = {
                success: true,
                message: 'User deactivated successfully',
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }
}