const mongoose = require('mongoose');
const redis = require('redis');

async function waitForMongoDB(uri, maxAttempts = 30) {
    for (let i = 0; i < maxAttempts; i++) {
        try {
            await mongoose.connect(uri);
            await mongoose.disconnect();
            console.log('✅ MongoDB is ready');
            return true;
        } catch (error) {
            console.log(`⏳ Waiting for MongoDB... (${i + 1}/${maxAttempts})`);
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }
    throw new Error('MongoDB failed to start');
}

async function waitForRedis(url, maxAttempts = 30) {
    for (let i = 0; i < maxAttempts; i++) {
        try {
            const client = redis.createClient({ url });
            await client.connect();
            await client.ping();
            await client.disconnect();
            console.log('✅ Redis is ready');
            return true;
        } catch (error) {
            console.log(`⏳ Waiting for Redis... (${i + 1}/${maxAttempts})`);
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }
    throw new Error('Redis failed to start');
}

async function main() {
    try {
        console.log('🚀 Waiting for Docker services to be ready...');

        await Promise.all([
            waitForMongoDB(process.env.MONGODB_URI || 'mongodb://localhost:27017/cybercore_test'),
            waitForRedis(process.env.REDIS_URL || 'redis://localhost:6379')
        ]);

        console.log('🎉 All services are ready for testing!');
        process.exit(0);
    } catch (error) {
        console.error('❌ Services failed to start:', error.message);
        console.log('\n💡 Try running: docker-compose -f docker-compose.yml up -d mongo redis');
        process.exit(1);
    }
}

main();