import { Request, Response, NextFunction } from 'express';
import { Tenant } from '@/core/models/Tenant';
import { User } from '@/core/models/User';
import { AppError } from '@/core/middlewares/errorHandler';
import { ApiResponse, PaginatedResponse } from '@/core/types';
import { UserRole } from '@/core/constants/roles';

export class TenantController {
    static async createTenant(req: Request, res: Response, next: NextFunction) {
        try {
            const { name, domain, subdomain, settings } = req.body;

            // Check if domain/subdomain already exists
            const existingTenant = await Tenant.findOne({
                $or: [{ domain }, { subdomain }]
            });

            if (existingTenant) {
                throw new AppError('Domain or subdomain already exists', 409);
            }

            const tenant = await Tenant.create({
                name,
                domain,
                subdomain,
                settings
            });

            const response: ApiResponse = {
                success: true,
                data: { tenant },
                message: 'Tenant created successfully',
                timestamp: new Date().toISOString()
            };

            res.status(201).json(response);
        } catch (error) {
            next(error);
        }
    }

    static async getTenants(req: Request, res: Response, next: NextFunction) {
        try {
            const page = parseInt(req.query.page as string) || 1;
            const limit = parseInt(req.query.limit as string) || 10;
            const skip = (page - 1) * limit;

            let query: any = {};

            // Tenant admins can only see their own tenant
            if (req.user?.role === UserRole.TENANT_ADMIN) {
                query._id = req.user.tenantId;
            }

            const tenants = await Tenant.find(query)
                .skip(skip)
                .limit(limit)
                .sort({ createdAt: -1 });

            const total = await Tenant.countDocuments(query);

            const response: ApiResponse<PaginatedResponse<any>> = {
                success: true,
                data: {
                    data: tenants,
                    pagination: {
                        page,
                        limit,
                        total,
                        totalPages: Math.ceil(total / limit),
                        hasNext: page * limit < total,
                        hasPrev: page > 1
                    }
                },
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    static async getTenantById(req: Request, res: Response, next: NextFunction) {
        try {
            const { id } = req.params;

            let query: any = { _id: id };

            // Tenant admins can only see their own tenant
            if (req.user?.role === UserRole.TENANT_ADMIN) {
                query._id = req.user.tenantId;
            }

            const tenant = await Tenant.findOne(query);

            if (!tenant) {
                throw new AppError('Tenant not found', 404);
            }

            // Get tenant stats
            const userCount = await User.countDocuments({ tenantId: tenant._id });

            const response: ApiResponse = {
                success: true,
                data: {
                    tenant: {
                        ...tenant.toObject(),
                        stats: {
                            userCount
                        }
                    }
                },
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    static async updateTenant(req: Request, res: Response, next: NextFunction) {
        try {
            const { id } = req.params;
            const updates = req.body;

            let query: any = { _id: id };

            // Tenant admins can only update their own tenant
            if (req.user?.role === UserRole.TENANT_ADMIN) {
                query._id = req.user.tenantId;
                // Prevent tenant admins from changing critical settings
                delete updates.settings?.plan;
            }

            const tenant = await Tenant.findOneAndUpdate(
                query,
                updates,
                { new: true, runValidators: true }
            );

            if (!tenant) {
                throw new AppError('Tenant not found', 404);
            }

            const response: ApiResponse = {
                success: true,
                data: { tenant },
                message: 'Tenant updated successfully',
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }

    static async deleteTenant(req: Request, res: Response, next: NextFunction) {
        try {
            const { id } = req.params;

            // Only super admins can delete tenants
            const tenant = await Tenant.findByIdAndUpdate(
                id,
                { isActive: false },
                { new: true }
            );

            if (!tenant) {
                throw new AppError('Tenant not found', 404);
            }

            // Deactivate all users in this tenant
            await User.updateMany(
                { tenantId: id },
                { isActive: false }
            );

            const response: ApiResponse = {
                success: true,
                message: 'Tenant deactivated successfully',
                timestamp: new Date().toISOString()
            };

            res.json(response);
        } catch (error) {
            next(error);
        }
    }
}
