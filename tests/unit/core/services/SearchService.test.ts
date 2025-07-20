// ============================================================================
// tests/unit/core/services/SearchService.test.ts
// ============================================================================

import { SearchService } from '@/core/services/SearchService';
import { UserRole } from '@/core/constants/roles';

describe('SearchService', () => {
    describe('buildUserSearchQuery', () => {
        it('should create a query for a simple search term', () => {
            const query = SearchService.buildUserSearchQuery('john');
            expect(query).toHaveProperty('$or');
            expect(query.$or.length).toBeGreaterThan(0);
            expect(JSON.stringify(query)).toContain('john');
        });

        it('should handle full name searches', () => {
            const query = SearchService.buildUserSearchQuery('john doe');
            expect(query.$or).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        $and: [
                            { firstName: { $regex: 'john', $options: 'i' } },
                            { lastName: { $regex: 'doe', $options: 'i' } },
                        ],
                    }),
                ])
            );
        });

        it('should handle advanced role search', () => {
            const query = SearchService.buildUserSearchQuery('admin', { advanced: true });
            // FIX: The improved logic now finds all roles containing "admin".
            // The test should expect both SUPER_ADMIN and TENANT_ADMIN.
            expect(query.$or).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({ role: UserRole.SUPER_ADMIN }),
                    expect.objectContaining({ role: UserRole.TENANT_ADMIN }),
                ])
            );
        });

        it('should handle advanced status search', () => {
            const query = SearchService.buildUserSearchQuery('active', { advanced: true });
            expect(query.$or).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({ isActive: true }),
                ])
            );
        });
    });

    describe('buildDateRangeQuery', () => {
        it('should create a date range query', () => {
            const query = SearchService.buildDateRangeQuery('2023-01-01', '2023-01-31');
            expect(query).toHaveProperty('createdAt');
            expect(query.createdAt).toHaveProperty('$gte');
            expect(query.createdAt).toHaveProperty('$lte');
        });
    });

    describe('buildSortCriteria', () => {
        it('should create a valid sort object', () => {
            const sort = SearchService.buildSortCriteria('lastName', 'asc');
            expect(sort).toEqual({ lastName: 1 });
        });

        it('should default to createdAt descending for invalid fields', () => {
            const sort = SearchService.buildSortCriteria('invalidField', 'desc');
            expect(sort).toEqual({ createdAt: -1 });
        });
    });
});
