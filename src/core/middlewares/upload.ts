// src/core/middlewares/upload.ts
import multer from 'multer';
import path from 'path';
import { AppError } from './errorHandler';
import { logger } from '@/core/infra/logger';

// Configure storage
const storage = multer.memoryStorage();

// File filter function
const fileFilter = (req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
    try {
        // Check file type based on route
        const allowedTypes = getAllowedTypes(req.route?.path || req.path);

        if (allowedTypes.includes(file.mimetype)) {
            // Accept the file
            cb(null, true);
        } else {
            // Reject the file with a specific error
            cb(new AppError(`File type ${file.mimetype} not allowed`, 400));
        }
    } catch (error) {
        logger.error('Error in file filter', { error });
        if (error instanceof Error) {
            cb(error);
        } else {
            cb(new AppError('An unexpected error occurred during file upload.', 500));
        }
    }
};

// Get allowed file types based on route
function getAllowedTypes(routePath: string): string[] {
    if (routePath.includes('profile-picture')) {
        return ['image/jpeg', 'image/png', 'image/webp'];
    }
    if (routePath.includes('document')) {
        return [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'text/plain'
        ];
    }
    // Default allowed types
    return ['image/jpeg', 'image/png', 'image/webp'];
}

// Configure multer
export const upload = multer({
    storage,
    fileFilter,
    limits: {
        fileSize: 10 * 1024 * 1024, // 10MB limit
        files: 5, // Maximum 5 files
        fields: 10 // Maximum 10 fields
    }
});

// Error handling middleware for multer
export const handleMulterError = (err: any, req: any, res: any, next: any) => {
    if (err instanceof multer.MulterError) {
        switch (err.code) {
            case 'LIMIT_FILE_SIZE':
                return next(new AppError('File too large. Maximum size is 10MB', 400));
            case 'LIMIT_FILE_COUNT':
                return next(new AppError('Too many files. Maximum is 5 files', 400));
            case 'LIMIT_UNEXPECTED_FILE':
                return next(new AppError('Unexpected file field', 400));
            default:
                return next(new AppError('File upload error', 400));
        }
    }
    next(err);
};

// Custom upload configurations for different use cases
export const profilePictureUpload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new AppError('Only JPEG, PNG, and WebP images are allowed.', 400));
        }
    },
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB for profile pictures
        files: 1
    }
});

export const documentUpload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        const allowedTypes = [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'text/plain'
        ];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new AppError('Only PDF, DOC, DOCX, and TXT files are allowed.', 400));
        }
    },
    limits: {
        fileSize: 10 * 1024 * 1024, // 10MB for documents
        files: 3
    }
});