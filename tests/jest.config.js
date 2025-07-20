module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'node',

    // Module mapping for clean imports
    moduleNameMapper: {
        '^@/(.*)$': '<rootDir>/src/$1',
        '^@/core/(.*)$': '<rootDir>/src/core/$1',
        '^@/api/(.*)$': '<rootDir>/src/api/$1',
        '^@/config/(.*)$': '<rootDir>/src/config/$1'
    },

    // Point ts-jest to the new Jest-specific tsconfig file
    globals: {
        'ts-jest': {
            tsconfig: 'tsconfig.jest.json'
        }
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
