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
            branches: 80,
            functions: 80,
            lines: 80,
            statements: 80
        }
    },

    // Setup files
    setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],

    // Test timeout
    testTimeout: 30000,

    // Clear mocks between tests
    clearMocks: true,

    // Verbose output
    verbose: true,

    // Detect open handles (useful for debugging)
    detectOpenHandles: true,

    // Force exit after tests complete
    forceExit: true,

    // Maximum number of workers
    maxWorkers: '50%',

    // Global setup/teardown
    globalSetup: undefined,
    globalTeardown: undefined,

    // Test environment options
    testEnvironmentOptions: {
        NODE_ENV: 'test'
    },

    // Module file extensions
    moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],

    // Watch plugins
    watchPlugins: [
        'jest-watch-typeahead/filename',
        'jest-watch-typeahead/testname'
    ],

    // Error reporting
    errorOnDeprecated: true,

    // Notify mode
    notify: false,

    // Bail after first test failure
    bail: false,

    // Test result processor
    testResultsProcessor: undefined
};