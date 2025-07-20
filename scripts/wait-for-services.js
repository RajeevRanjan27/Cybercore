const mongoose = require('mongoose');
const redis = require('redis');

async function waitForMongoDB(uri, maxAttempts = 30) {
    console.log(`🔄 Waiting for MongoDB at ${uri}...`);
    for (let i = 0; i < maxAttempts; i++) {
        try {
            await mongoose.connect(uri);
            await mongoose.connection.db.admin().ping();
            await mongoose.disconnect();
            console.log('✅ MongoDB is ready');
            return true;
        } catch (error) {
            console.log(`⏳ MongoDB attempt ${i + 1}/${maxAttempts} - ${error.message}`);
            await new Promise(resolve => setTimeout(resolve, 2000));
        }
    }
    throw new Error('❌ MongoDB failed to start within timeout');
}

async function waitForRedis(url, maxAttempts = 30) {
    console.log(`🔄 Waiting for Redis at ${url}...`);
    for (let i = 0; i < maxAttempts; i++) {
        try {
            const client = redis.createClient({
                url,
                socket: {
                    connectTimeout: 5000,
                    lazyConnect: true
                }
            });
            await client.connect();
            await client.ping();
            await client.disconnect();
            console.log('✅ Redis is ready');
            return true;
        } catch (error) {
            console.log(`⏳ Redis attempt ${i + 1}/${maxAttempts} - ${error.message}`);
            await new Promise(resolve => setTimeout(resolve, 2000));
        }
    }
    throw new Error('❌ Redis failed to start within timeout');
}

async function main() {
    try {
        console.log('🚀 Waiting for Docker services to be ready...');

        const mongoUri = process.env.MONGODB_URI || 'mongodb://admin:admin123@localhost:27017/cybercore_test?authSource=admin';
        const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';

        await Promise.all([
            waitForMongoDB(mongoUri),
            waitForRedis(redisUrl)
        ]);

        console.log('🎉 All services are ready for testing!');
        process.exit(0);
    } catch (error) {
        console.error('❌ Services failed to start:', error.message);
        console.log('\n💡 Try running: docker-compose up -d mongo redis');
        console.log('💡 Or check if ports 27017 and 6379 are available');
        process.exit(1);
    }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
    console.log('\n👋 Shutting down service health checks...');
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('\n👋 Shutting down service health checks...');
    process.exit(0);
});

main();