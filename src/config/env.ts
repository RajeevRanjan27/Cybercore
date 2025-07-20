import dotenv from 'dotenv';
import * as process from "node:process";
dotenv.config();

if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
    throw new Error('JWT secrets must be configured');
}

interface Config {
    NODE_ENV: string;
    PORT: number;
    MONGODB_URI: string;
    REDIS_URL: string;
    REDIS_PASSWORD?: string;

    JWT_SECRET: string;
    JWT_REFRESH_SECRET: string;
    JWT_EXPIRES_IN: string;
    JWT_REFRESH_EXPIRES_IN: string;
    RATE_LIMIT_WINDOW: number;
    RATE_LIMIT_MAX: number;
}

export const config: Config = {
    NODE_ENV: process.env.NODE_ENV || 'development',
    PORT: parseInt(process.env.PORT || '3000'),

    //Db
    MONGODB_URI: process.env.MONGODB_URI || 'mongodb://localhost:27017/cybercore',

    //redis
    REDIS_URL:process.env.REDIS_URL || 'redis://localhost:6379',
    REDIS_PASSWORD: process.env.REDIS_PASSWORD,
    //jwt
    JWT_SECRET: process.env.JWT_SECRET || '6b3a091d08eae861666872f4945c14ba03e1bb9e9a62875a1ab9408cb33866c6',
    JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '15m',
    JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET || 'd2051675868cc1619eec332ebb1ad0e50e5034ea3136be8ad7140cdd9a5f56a4', // Fixed this line
    JWT_REFRESH_EXPIRES_IN: process.env.JWT_REFRESH_EXPIRES_IN || '7d',

    // Rate limiting
    RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW || '900000'), // 15 min
    RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX || '100'),
};