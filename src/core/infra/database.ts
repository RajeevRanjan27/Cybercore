import mongoose from 'mongoose';
import { config } from '@/config/env';
import { logger } from './logger';

export async function connectDB(): Promise<void> {
    try {
        await mongoose.connect(config.MONGODB_URI);
        logger.info('🗄️ MongoDB connected successfully');
    } catch (error) {
        logger.error('MongoDB connection failed:', error);
        throw error;
    }
}
