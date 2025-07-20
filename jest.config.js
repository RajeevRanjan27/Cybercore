module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'node',

    // Simple module mapping (no tsconfig dependency)
    moduleNameMapper: {
        '^@/(.*)$': '<rootDir>/src/$1',
        '^@/core/(.*)$': '<rootDir>/src/core/$1',
        '^@/api/(.*)$': '<rootDir>/src/api/$1',
        '^@/config/(.*)$': '<rootDir>/src/config/$1'
    },

    roots: ['<rootDir>/tests'],
    testMatch: ['**/tests/**/*.test.ts'],
    transform: { '^.+\\.ts$': 'ts-jest' },
    setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
    testTimeout: 60000,
    maxWorkers: 1,
    forceExit: true,
    verbose: false
};