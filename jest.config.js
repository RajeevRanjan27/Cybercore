const { pathsToModuleNameMapper } = require('ts-jest');
const { compilerOptions } = require('./tsconfig.json');

module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'node',

    // Module resolution
    moduleNameMapper: pathsToModuleNameMapper(compilerOptions.paths, { prefix: '<rootDir>/src/' }),

    // Test configuration
    roots: ['<rootDir>/src', '<rootDir>/tests'],
    testMatch: [
        '**/__tests__/**/*.test.ts',
        '**/?(*.)+(spec|test).ts'
    ],

    // Transform configuration
    transform: {
        '^.+\\.ts$': 'ts-jest'
    },

    // Coverage configuration
    collectCoverageFrom: [
        'src/**/*.{ts,js}',
        '!src/**/*.d.ts',
        '!src/index.ts',
        '!src/**/*.test.ts',
        '!src/**/*.spec.ts'
    ],
    coverageDirectory: 'coverage',
    coverageReporters: [
        'text',
        'lcov',
        'html',
        'json'
    ],
    coverageThreshold: {
        global: {
            branches: 70,  // Lowered for initial testing
            functions: 70,
            lines: 70,
            statements: 70
        }
    },

    // Setup files
    setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],

    // Test timeout
    testTimeout: 30000,

    // Clear mocks between tests
    clearMocks: true,

    // Verbose output for debugging
    verbose: true,

    // Detect open handles
    detectOpenHandles: true,

    // Force exit after tests
    forceExit: true,

    // Maximum workers for parallel execution
    maxWorkers: '50%',

    // Test environment options
    testEnvironmentOptions: {
        NODE_ENV: 'test'
    },

    // Module file extensions
    moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],

    // Watch plugins for better dev experience
    watchPlugins: [
        'jest-watch-typeahead/filename',
        'jest-watch-typeahead/testname'
    ],

    // Global test setup/teardown
    globalSetup: undefined,
    globalTeardown: undefined,

    // Silence console.log during tests (optional)
    silent: false,

    // Show individual test results
    verbose: true
};