// tests/setup.ts - Docker-based test setup
import mongoose from 'mongoose';
import { CacheService } from '@/core/services/CacheService';
import { logger } from '@/core/infra/logger';
import { config } from '@/config/env';

// Increase timeout for Docker services
jest.setTimeout(60000);

// Global test setup
beforeAll(async () => {
    try {
        // Wait a bit for Docker services to be ready
        await new Promise(resolve => setTimeout(resolve, 2000));

        // Connect to Docker MongoDB
        await mongoose.connect(config.MONGODB_URI);

        // Initialize cache service (will connect to Docker Redis)
        await CacheService.initialize();

        // Suppress console logs during tests
        jest.spyOn(console, 'log').mockImplementation(() => {});
        jest.spyOn(console, 'warn').mockImplementation(() => {});

        console.log('✅ Connected to Docker services for testing');
    } catch (error) {
        console.error('❌ Failed to connect to Docker services:', error);
        console.log('Make sure to run: docker-compose -f docker-compose.yml up -d mongo redis');
        throw error;
    }
});

// Global test teardown
afterAll(async () => {
    try {
        await mongoose.disconnect();
        await CacheService.cleanup();
        console.log('✅ Disconnected from Docker services');
    } catch (error) {
        console.error('Test teardown failed:', error);
    }
});

// Clear test database before each test file
beforeEach(async () => {
    try {
        // Clear all collections in test database
        const collections = mongoose.connection.collections;
        for (const key in collections) {
            const collection = collections[key];
            await collection.deleteMany({});
        }
    } catch (error) {
        console.error('Failed to clear test database:', error);
    }
});