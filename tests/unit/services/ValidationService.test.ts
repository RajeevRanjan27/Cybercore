// ============================================================================
// tests/unit/services/ValidationService.test.ts
// ============================================================================

import {ValidationService} from "../../../src/core/services/ValidationService";
import {AppError} from "../../../src/core/middlewares/errorHandler";

describe('ValidationService', () => {
    describe('validateObjectId', () => {
        it('should accept valid ObjectIds', () => {
            expect(() => {
                ValidationService.validateObjectId('507f1f77bcf86cd799439011');
            }).not.toThrow();
        });

        it('should reject invalid ObjectIds', () => {
            expect(() => {
                ValidationService.validateObjectId('invalid-id');
            }).toThrow(AppError);
        });
    });

    describe('validatePassword', () => {
        it('should accept strong passwords', () => {
            expect(() => {
                ValidationService.validatePassword('StrongPass123!');
            }).not.toThrow();
        });

        it('should reject weak passwords', () => {
            const weakPasswords = [
                'weak',
                'password',
                '12345678',
                'PASSWORD',
                'Password1',
                'password!'
            ];

            weakPasswords.forEach(password => {
                expect(() => {
                    ValidationService.validatePassword(password);
                }).toThrow(AppError);
            });
        });

        it('should reject common passwords', () => {
            expect(() => {
                ValidationService.validatePassword('password123');
            }).toThrow(AppError);
        });
    });

    describe('validateEmail', () => {
        it('should accept valid emails', () => {
            const validEmails = [
                'test@example.com',
                'user.name@domain.co.uk',
                'user+tag@example.org'
            ];

            validEmails.forEach(email => {
                expect(() => {
                    ValidationService.validateEmail(email);
                }).not.toThrow();
            });
        });

        it('should reject invalid emails', () => {
            const invalidEmails = [
                'invalid-email',
                '@domain.com',
                'user@',
                'user..name@domain.com'
            ];

            invalidEmails.forEach(email => {
                expect(() => {
                    ValidationService.validateEmail(email);
                }).toThrow(AppError);
            });
        });

        it('should reject disposable email domains', () => {
            expect(() => {
                ValidationService.validateEmail('test@10minutemail.com');
            }).toThrow(AppError);
        });
    });

    describe('validateBulkOperation', () => {
        it('should validate bulk operation parameters', () => {
            expect(() => {
                ValidationService.validateBulkOperation(
                    ['507f1f77bcf86cd799439011', '507f1f77bcf86cd799439012'],
                    'activate',
                    { reason: 'Test operation' }
                );
            }).not.toThrow();
        });

        it('should reject invalid operations', () => {
            expect(() => {
                ValidationService.validateBulkOperation(
                    ['507f1f77bcf86cd799439011'],
                    'invalid-operation',
                    {}
                );
            }).toThrow(AppError);
        });

        it('should require role for changeRole operation', () => {
            expect(() => {
                ValidationService.validateBulkOperation(
                    ['507f1f77bcf86cd799439011'],
                    'changeRole',
                    {}
                );
            }).toThrow(AppError);
        });

        it('should limit bulk operation size', () => {
            const largeArray = Array(101).fill('507f1f77bcf86cd799439011');

            expect(() => {
                ValidationService.validateBulkOperation(largeArray, 'activate', {});
            }).toThrow(AppError);
        });
    });
});
