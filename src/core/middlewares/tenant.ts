import { Request, Response, NextFunction } from 'express';
import { Tenant, ITenant } from '@/core/models/Tenant';
import { AppError } from './errorHandler';


declare module 'express-serve-static-core' {
    interface Request {
        tenant?: ITenant;
    }
}
export const tenantContext = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const tenantId = req.headers['x-tenant-id'] as string;

        if (!tenantId) {
            throw new AppError('Tenant ID required', 400);
        }

        const tenant = await Tenant.findById(tenantId);
        if (!tenant || !tenant.isActive) {
            throw new AppError('Invalid or inactive tenant', 400);
        }

        req.tenant = tenant;
        next();
    } catch (error) {
        next(error);
    }
};
