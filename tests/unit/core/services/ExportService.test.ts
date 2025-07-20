// ============================================================================
// tests/unit/core/services/ExportService.test.ts
// ============================================================================

import { ExportService } from '@/core/services/ExportService';
import { UserRole } from '@/core/constants/roles';
import { AuthPayload } from '@/core/types';

describe('ExportService', () => {
    const mockUsers = [
        {
            _id: 'user1',
            firstName: 'John',
            lastName: 'Doe',
            email: 'john.doe@example.com',
            role: UserRole.USER,
            isActive: true,
            createdAt: new Date('2023-01-01'),
            tenant: { name: 'Test Tenant' },
        },
        {
            _id: 'user2',
            firstName: 'Jane',
            lastName: 'Smith',
            email: 'jane.smith@example.com',
            role: UserRole.TENANT_ADMIN,
            isActive: false,
            createdAt: new Date('2023-01-02'),
            tenant: { name: 'Test Tenant' },
        },
    ];

    const mockAdminUser: AuthPayload = {
        userId: 'admin1',
        tenantId: 'tenant1',
        role: UserRole.SUPER_ADMIN,
        permissions: ['user:export'],
    };

    describe('exportToCSV', () => {
        it('should generate a valid CSV string', async () => {
            const csv = await ExportService.exportUsers(
                mockUsers,
                'csv',
                mockAdminUser
            );

            // FIX: Add a type guard to ensure TypeScript knows `csv` is a string here.
            expect(typeof csv).toBe('string');
            if (typeof csv === 'string') {
                const rows = csv.split('\n');
                expect(rows).toHaveLength(3); // Header + 2 data rows
                expect(rows[0]).toContain('User ID,First Name,Last Name');
                expect(rows[1]).toContain('John,Doe');
            }
        });
    });

    describe('exportToJSON', () => {
        it('should generate a valid JSON string', async () => {
            const json = await ExportService.exportUsers(
                mockUsers,
                'json',
                mockAdminUser
            );
            expect(typeof json).toBe('string');
            const data = JSON.parse(json as string);
            expect(data).toHaveProperty('metadata');
            expect(data).toHaveProperty('data');
            expect(data.data).toHaveLength(2);
            expect(data.data[0].email).toBe('john.doe@example.com');
        });
    });

    describe('exportToPDF', () => {
        it('should generate a buffer for PDF', async () => {
            const pdfBuffer = await ExportService.exportUsers(
                mockUsers,
                'pdf',
                mockAdminUser
            );
            expect(pdfBuffer).toBeInstanceOf(Buffer);
        });
    });

    describe('exportToExcel', () => {
        it('should generate a buffer for XLSX', async () => {
            const xlsxBuffer = await ExportService.exportUsers(
                mockUsers,
                'xlsx',
                mockAdminUser
            );
            expect(xlsxBuffer).toBeInstanceOf(Buffer);
        });
    });

    describe('Data Sanitization', () => {
        it('should sanitize user data for non-super-admin exports', async () => {
            const tenantAdmin: AuthPayload = {
                userId: 'tenantAdmin1',
                tenantId: 'tenant1',
                role: UserRole.TENANT_ADMIN,
                permissions: ['user:export'],
            };
            const json = await ExportService.exportUsers(
                mockUsers,
                'json',
                tenantAdmin
            );
            const data = JSON.parse(json as string);
            // Non-super-admins should not see emails of other users
            expect(data.data[0].email).toBeUndefined();
            expect(data.data[1].email).toBeUndefined();
        });
    });
});
