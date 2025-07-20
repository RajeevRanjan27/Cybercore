// src/config/env.ts
import dotenv from 'dotenv';
import * as process from "node:process";
dotenv.config();

if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
    throw new Error('JWT secrets must be configured');
}

interface Config {
    NODE_ENV: string;
    PORT: number;
    BASE_URL: string;
    FRONTEND_URL: string;

    // Database
    MONGODB_URI: string;

    // Redis
    REDIS_URL: string;
    REDIS_PASSWORD?: string;
    REDIS_HOST: string;
    REDIS_PORT: number;
    REDIS_DB: number;

    // Cache Configuration
    CACHE_TTL: number;
    CACHE_CHECK_PERIOD: number;

    // JWT
    JWT_SECRET: string;
    JWT_REFRESH_SECRET: string;
    JWT_EXPIRES_IN: string;
    JWT_REFRESH_EXPIRES_IN: string;

    // Rate Limiting
    RATE_LIMIT_WINDOW: number;
    RATE_LIMIT_MAX: number;

    // OAuth2 Providers
    GOOGLE_CLIENT_ID?: string;
    GOOGLE_CLIENT_SECRET?: string;
    GITHUB_CLIENT_ID?: string;
    GITHUB_CLIENT_SECRET?: string;
    MICROSOFT_CLIENT_ID?: string;
    MICROSOFT_CLIENT_SECRET?: string;
    LINKEDIN_CLIENT_ID?: string;
    LINKEDIN_CLIENT_SECRET?: string;
    FACEBOOK_CLIENT_ID?: string;
    FACEBOOK_CLIENT_SECRET?: string;
    INSTAGRAM_CLIENT_ID?: string;
    INSTAGRAM_CLIENT_SECRET?: string;
    TWITTER_CLIENT_ID?: string;
    TWITTER_CLIENT_SECRET?: string;
    LEETCODE_CLIENT_ID?: string;
    LEETCODE_CLIENT_SECRET?: string;
    CODEFORCES_CLIENT_ID?: string;
    CODEFORCES_CLIENT_SECRET?: string;

    // Email
    EMAIL_FROM?: string;
    EMAIL_PROVIDER?: string;

    // File Storage
    STORAGE_PROVIDER?: string;
    AWS_REGION?: string;
    AWS_BUCKET?: string;
    AWS_ACCESS_KEY_ID?: string;
    AWS_SECRET_ACCESS_KEY?: string;

    // Monitoring & Analytics
    SENTRY_DSN?: string;
    ANALYTICS_API_KEY?: string;

    // CI/CD
    CI?: string;
    DEPLOY_ENV?: string;
    BUILD_NUMBER?: string;
    GIT_COMMIT?: string;
    GIT_BRANCH?: string;
}

export const config: Config = {
    NODE_ENV: process.env.NODE_ENV || 'development',
    PORT: parseInt(process.env.PORT || '3000'),
    BASE_URL: process.env.BASE_URL || 'http://localhost:3000',
    FRONTEND_URL: process.env.FRONTEND_URL || 'http://localhost:3001',

    // Database
    MONGODB_URI: process.env.MONGODB_URI || 'mongodb://localhost:27017/cybercore',

    // Redis Configuration
    REDIS_URL: process.env.REDIS_URL || 'redis://localhost:6379',
    REDIS_PASSWORD: process.env.REDIS_PASSWORD || '',
    REDIS_HOST: process.env.REDIS_HOST || 'localhost',
    REDIS_PORT: parseInt(process.env.REDIS_PORT || '6379'),
    REDIS_DB: parseInt(process.env.REDIS_DB || '0'),

    // Cache Configuration
    CACHE_TTL: parseInt(process.env.CACHE_TTL || '300'), // 5 minutes default
    CACHE_CHECK_PERIOD: parseInt(process.env.CACHE_CHECK_PERIOD || '60'), // 1 minute

    // JWT
    JWT_SECRET: process.env.JWT_SECRET || '6b3a091d08eae861666872f4945c14ba03e1bb9e9a62875a1ab9408cb33866c6',
    JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '15m',
    JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET || 'd2051675868cc1619eec332ebb1ad0e50e5034ea3136be8ad7140cdd9a5f56a4',
    JWT_REFRESH_EXPIRES_IN: process.env.JWT_REFRESH_EXPIRES_IN || '7d',

    // Rate limiting
    RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW || '900000'), // 15 min
    RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX || '100'),

    // OAuth2 Providers
    GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
    GITHUB_CLIENT_ID: process.env.GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET: process.env.GITHUB_CLIENT_SECRET,
    MICROSOFT_CLIENT_ID: process.env.MICROSOFT_CLIENT_ID,
    MICROSOFT_CLIENT_SECRET: process.env.MICROSOFT_CLIENT_SECRET,
    LINKEDIN_CLIENT_ID: process.env.LINKEDIN_CLIENT_ID,
    LINKEDIN_CLIENT_SECRET: process.env.LINKEDIN_CLIENT_SECRET,
    FACEBOOK_CLIENT_ID: process.env.FACEBOOK_CLIENT_ID,
    FACEBOOK_CLIENT_SECRET: process.env.FACEBOOK_CLIENT_SECRET,
    INSTAGRAM_CLIENT_ID: process.env.INSTAGRAM_CLIENT_ID,
    INSTAGRAM_CLIENT_SECRET: process.env.INSTAGRAM_CLIENT_SECRET,
    TWITTER_CLIENT_ID: process.env.TWITTER_CLIENT_ID,
    TWITTER_CLIENT_SECRET: process.env.TWITTER_CLIENT_SECRET,
    LEETCODE_CLIENT_ID: process.env.LEETCODE_CLIENT_ID,
    LEETCODE_CLIENT_SECRET: process.env.LEETCODE_CLIENT_SECRET,
    CODEFORCES_CLIENT_ID: process.env.CODEFORCES_CLIENT_ID,
    CODEFORCES_CLIENT_SECRET: process.env.CODEFORCES_CLIENT_SECRET,

    // Email
    EMAIL_FROM: process.env.EMAIL_FROM,
    EMAIL_PROVIDER: process.env.EMAIL_PROVIDER,

    // File Storage
    STORAGE_PROVIDER: process.env.STORAGE_PROVIDER,
    AWS_REGION: process.env.AWS_REGION,
    AWS_BUCKET: process.env.AWS_BUCKET,
    AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,

    // Monitoring & Analytics
    SENTRY_DSN: process.env.SENTRY_DSN,
    ANALYTICS_API_KEY: process.env.ANALYTICS_API_KEY,

    // CI/CD
    CI: process.env.CI,
    DEPLOY_ENV: process.env.DEPLOY_ENV,
    BUILD_NUMBER: process.env.BUILD_NUMBER,
    GIT_COMMIT: process.env.GIT_COMMIT,
    GIT_BRANCH: process.env.GIT_BRANCH
};