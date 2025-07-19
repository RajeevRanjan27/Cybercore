import { Request, Response, NextFunction } from 'express';
import { Schema } from 'joi';
import { AppError } from '@/core/middlewares/errorHandler';

export const validate = (schema: Schema) => {
    return (req: Request, res: Response, next: NextFunction) => {
        const { error } = schema.validate(req.body);

        if (error) {
            const message = error.details.map(detail => detail.message).join(', ');
            throw new AppError(message, 400);
        }

        next();
    };
};