// tests/setup.ts - Global test setup
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { CacheService } from '@/core/services/CacheService';
import { logger } from '@/core/infra/logger';

let mongoServer: MongoMemoryServer;

// Global test setup
beforeAll(async () => {
    // Start in-memory MongoDB
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();

    await mongoose.connect(mongoUri);

    // Initialize cache service for tests (memory-only)
    await CacheService.initialize();

    // Suppress console logs during tests
    jest.spyOn(console, 'log').mockImplementation(() => {});}