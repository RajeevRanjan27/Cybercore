// src/core/services/SearchService.ts
import { AuthPayload } from '@/core/types';
import { UserRole } from '@/core/constants/roles';
import { RBACService } from '@/core/services/RBACService';
import { User } from '@/core/models/User';
import mongoose, {PipelineStage} from 'mongoose';

interface SearchOptions {
    advanced?: boolean;
    highlight?: boolean;
    fuzzy?: boolean;
    limit?: number;
}

interface SearchResult {
    results: any[];
    facets: any;
    suggestions: string[];
    total: number;
    searchTime: number;
}

interface SearchFilters {
    role?: UserRole;
    isActive?: boolean;
    tenantId?: string;
    dateFrom?: string;
    dateTo?: string;
    [key: string]: any;
}

export class SearchService {
    /**
     * Advanced user search with multiple criteria
     */
    static async searchUsers(params: {
        query: string;
        filters: SearchFilters;
        user: AuthPayload;
        options: SearchOptions;
    }): Promise<SearchResult> {
        const startTime = Date.now();

        try {
            const { query, filters, user, options } = params;

            // Build base query with RBAC
            let baseQuery = RBACService.createDatabaseFilter({
                id: user.userId,
                role: user.role,
                tenantId: user.tenantId
            });

            // Apply additional filters
            baseQuery = { ...baseQuery, ...this.buildFiltersQuery(filters) };

            // Build search query
            const searchQuery = this.buildUserSearchQuery(query, options);
            const finalQuery = { ...baseQuery, ...searchQuery };

            // Execute search with aggregation
            const pipeline = this.buildSearchPipeline(finalQuery, options);

            const [searchResults, facets] = await Promise.all([
                User.aggregate(pipeline),
                this.buildFacets(baseQuery, user)
            ]);

            // Get total count
            const totalCount = await User.countDocuments(finalQuery);

            // Generate suggestions for improved search
            const suggestions = await this.generateSuggestions(query, searchResults);

            const searchTime = Date.now() - startTime;

            return {
                results: searchResults.map(result => this.processSearchResult(result, options)),
                facets,
                suggestions,
                total: totalCount,
                searchTime
            };

        } catch (error) {
            throw error;
        }
    }

    /**
     * Build user search query with multiple search strategies
     */
    static buildUserSearchQuery(searchTerm: string, options: SearchOptions = {}): any {
        if (!searchTerm || searchTerm.trim() === '') {
            return {};
        }

        const term = searchTerm.trim();
        const searchQueries = [];

        // Exact match queries (highest priority)
        searchQueries.push(
            { email: { $regex: `^${this.escapeRegex(term)}$`, $options: 'i' } },
            { firstName: { $regex: `^${this.escapeRegex(term)}$`, $options: 'i' } },
            { lastName: { $regex: `^${this.escapeRegex(term)}$`, $options: 'i' } }
        );

        // Starts with queries
        searchQueries.push(
            { email: { $regex: `^${this.escapeRegex(term)}`, $options: 'i' } },
            { firstName: { $regex: `^${this.escapeRegex(term)}`, $options: 'i' } },
            { lastName: { $regex: `^${this.escapeRegex(term)}`, $options: 'i' } }
        );

        // Contains queries
        searchQueries.push(
            { email: { $regex: this.escapeRegex(term), $options: 'i' } },
            { firstName: { $regex: this.escapeRegex(term), $options: 'i' } },
            { lastName: { $regex: this.escapeRegex(term), $options: 'i' } }
        );

        // Full name search (space-separated terms)
        if (term.includes(' ')) {
            const [firstName, ...lastNameParts] = term.split(' ');
            const lastName = lastNameParts.join(' ');

            searchQueries.push({
                $and: [
                    { firstName: { $regex: this.escapeRegex(firstName), $options: 'i' } },
                    { lastName: { $regex: this.escapeRegex(lastName), $options: 'i' } }
                ]
            });
        }

        // Advanced search features
        if (options.advanced) {
            // FIX: Find ALL matching roles, not just the first one.
            const matchingRoles = Object.values(UserRole).filter(role =>
                role.toLowerCase().includes(term.toLowerCase())
            );
            if (matchingRoles.length > 0) {
                matchingRoles.forEach(role => {
                    searchQueries.push({ role });
                });
            }

            // Status search
            if (['active', 'inactive', 'enabled', 'disabled'].includes(term.toLowerCase())) {
                const isActive = ['active', 'enabled'].includes(term.toLowerCase());
                searchQueries.push({ isActive });
            }
        }

        // Fuzzy search (if enabled)
        if (options.fuzzy) {
            searchQueries.push(...this.buildFuzzySearchQueries(term));
        }

        return searchQueries.length > 0 ? { $or: searchQueries } : {};
    }

    /**
     * Build date range query
     */
    static buildDateRangeQuery(
        dateFrom?: string,
        dateTo?: string,
        field: string = 'createdAt'
    ): any {
        const dateQuery: any = {};

        if (dateFrom || dateTo) {
            dateQuery[field] = {};

            if (dateFrom) {
                dateQuery[field].$gte = new Date(dateFrom);
            }

            if (dateTo) {
                const endDate = new Date(dateTo);
                endDate.setHours(23, 59, 59, 999); // End of day
                dateQuery[field].$lte = endDate;
            }
        }

        return dateQuery;
    }

    /**
     * Build sort criteria
     */
    static buildSortCriteria(sortBy: string, sortOrder: 'asc' | 'desc'): any {
        const validSortFields = [
            'createdAt', 'updatedAt', 'lastName', 'firstName',
            'email', 'lastLogin', 'role'
        ];

        const field = validSortFields.includes(sortBy) ? sortBy : 'createdAt';
        const order = sortOrder === 'asc' ? 1 : -1;

        return { [field]: order };
    }

    /**
     * Calculate period range for analytics
     */
    static calculatePeriodRange(period: string): { start: Date; end: Date } {
        const end = new Date();
        const start = new Date();

        switch (period) {
            case '7d':
                start.setDate(end.getDate() - 7);
                break;
            case '30d':
                start.setDate(end.getDate() - 30);
                break;
            case '90d':
                start.setDate(end.getDate() - 90);
                break;
            case '1y':
                start.setFullYear(end.getFullYear() - 1);
                break;
            default:
                start.setDate(end.getDate() - 30);
        }

        return { start, end };
    }

    /**
     * Convert fields string to MongoDB projection
     */
    static convertFieldsToProjection(fieldsStr: string): any {
        const fields = fieldsStr.split(',').map(f => f.trim());
        const projection: any = {};

        fields.forEach(field => {
            if (field.startsWith('-')) {
                projection[field.substring(1)] = 0;
            } else {
                projection[field] = 1;
            }
        });

        return projection;
    }

    /**
     * Get applied filters summary
     */
    static getAppliedFilters(params: any): any {
        const filters: any = {};

        if (params.role) filters.role = params.role;
        if (params.isActive !== undefined) filters.isActive = params.isActive;
        if (params.tenantId) filters.tenantId = params.tenantId;
        if (params.dateFrom) filters.dateFrom = params.dateFrom;
        if (params.dateTo) filters.dateTo = params.dateTo;
        if (params.search) filters.search = params.search;

        return filters;
    }

    // ============================================================================
    // PRIVATE HELPER METHODS
    // ============================================================================

    private static buildFiltersQuery(filters: SearchFilters): any {
        const query: any = {};

        if (filters.role) {
            query.role = filters.role;
        }

        if (filters.isActive !== undefined) {
            query.isActive = filters.isActive;
        }

        if (filters.tenantId) {
            query.tenantId = new mongoose.Types.ObjectId(filters.tenantId);
        }

        // Date range filtering
        if (filters.dateFrom || filters.dateTo) {
            Object.assign(query, this.buildDateRangeQuery(
                filters.dateFrom,
                filters.dateTo,
                'createdAt'
            ));
        }

        return query;
    }

    private static buildSearchPipeline(query: any, options: SearchOptions): PipelineStage[] {
        const pipeline: PipelineStage[] = [
            { $match: query },
            {
                $lookup: {
                    from: 'tenants',
                    localField: 'tenantId',
                    foreignField: '_id',
                    as: 'tenant',
                    pipeline: [
                        { $project: { name: 1, domain: 1, subdomain: 1 } }
                    ]
                }
            },
            { $unwind: { path: '$tenant', preserveNullAndEmptyArrays: true } },
            {
                $project: {
                    password: 0,
                    __v: 0
                }
            },
            { $sort: { createdAt: -1 } },
            { $limit: options.limit || 50 }
        ];

        // Add text search scoring if search query exists
        if (query.$or || query.$text) {
            // Insert $addFields stage after $match
            pipeline.splice(1, 0, {
                $addFields: {
                    score: { $meta: 'textScore' }
                }
            });

            // Update sort to include text score
            const sortStageIndex = pipeline.findIndex(stage => '$sort' in stage);
            if (sortStageIndex !== -1) {
                pipeline[sortStageIndex] = {
                    $sort: { score: { $meta: 'textScore' }, createdAt: -1 }
                };
            }
        }

        return pipeline;
    }

    private static async buildFacets(baseQuery: any, user: AuthPayload): Promise<any> {
        try {
            const facetPipeline: PipelineStage [] = [
                { $match: baseQuery },
                {
                    $facet: {
                        roles: [
                            { $group: { _id: '$role', count: { $sum: 1 } } },
                            { $sort: { count: -1 } }
                        ],
                        status: [
                            { $group: { _id: '$isActive', count: { $sum: 1 } } }
                        ],
                        tenants: user.role === UserRole.SUPER_ADMIN ? [
                            {
                                $lookup: {
                                    from: 'tenants',
                                    localField: 'tenantId',
                                    foreignField: '_id',
                                    as: 'tenant'
                                }
                            },
                            { $unwind: { path: '$tenant', preserveNullAndEmptyArrays: true } },
                            { $group: { _id: '$tenant.name', count: { $sum: 1 } } },
                            { $sort: { count: -1 } }
                        ] : [],
                        registrationDates: [
                            {
                                $group: {
                                    _id: {
                                        $dateToString: {
                                            format: '%Y-%m',
                                            date: '$createdAt'
                                        }
                                    },
                                    count: { $sum: 1 }
                                }
                            },
                            { $sort: { '_id': -1 } },
                            { $limit: 12 }
                        ]
                    }
                }
            ];

            const [facetResults] = await User.aggregate(facetPipeline);

            return {
                roles: facetResults.roles.map((r: any) => ({
                    value: r._id,
                    label: this.formatRoleLabel(r._id),
                    count: r.count
                })),
                status: facetResults.status.map((s: any) => ({
                    value: s._id,
                    label: s._id ? 'Active' : 'Inactive',
                    count: s.count
                })),
                tenants: facetResults.tenants.map((t: any) => ({
                    value: t._id,
                    label: t._id || 'Unknown',
                    count: t.count
                })),
                registrationDates: facetResults.registrationDates.map((d: any) => ({
                    period: d._id,
                    count: d.count
                }))
            };

        } catch (error) {
            return {
                roles: [],
                status: [],
                tenants: [],
                registrationDates: []
            };
        }
    }

    private static async generateSuggestions(
        query: string,
        results: any[]
    ): Promise<string[]> {
        const suggestions: string[] = [];

        if (results.length === 0 && query.length > 2) {
            // Generate suggestions based on partial matches
            const partialMatches = await User.find({
                $or: [
                    { firstName: { $regex: query.substring(0, query.length - 1), $options: 'i' } },
                    { lastName: { $regex: query.substring(0, query.length - 1), $options: 'i' } },
                    { email: { $regex: query.substring(0, query.length - 1), $options: 'i' } }
                ]
            })
                .select('firstName lastName email')
                .limit(5)
                .lean();

            partialMatches.forEach(user => {
                if (user.firstName && user.firstName.toLowerCase().includes(query.toLowerCase())) {
                    suggestions.push(user.firstName);
                }
                if (user.lastName && user.lastName.toLowerCase().includes(query.toLowerCase())) {
                    suggestions.push(user.lastName);
                }
                if (user.email && user.email.toLowerCase().includes(query.toLowerCase())) {
                    suggestions.push(user.email);
                }
            });
        }

        // Add common search terms
        const commonTerms = ['admin', 'user', 'active', 'inactive'];
        commonTerms.forEach(term => {
            if (term.startsWith(query.toLowerCase()) && !suggestions.includes(term)) {
                suggestions.push(term);
            }
        });

        return [...new Set(suggestions)].slice(0, 5);
    }

    private static processSearchResult(result: any, options: SearchOptions): any {
        const processed = { ...result };

        // Add highlighting if enabled
        if (options.highlight && result.score) {
            processed.relevanceScore = result.score;
        }

        // Add computed fields
        processed.fullName = `${result.firstName || ''} ${result.lastName || ''}`.trim();
        processed.displayName = processed.fullName || result.email;

        // Add match context
        processed.matchContext = this.getMatchContext(result, options);

        return processed;
    }

    private static getMatchContext(result: any, options: SearchOptions): any {
        const context: any = {};

        // Determine which fields matched
        if (result.email) context.emailMatch = true;
        if (result.firstName) context.firstNameMatch = true;
        if (result.lastName) context.lastNameMatch = true;
        if (result.role) context.roleMatch = true;

        return context;
    }

    private static buildFuzzySearchQueries(term: string): any[] {
        const fuzzyQueries = [];

        // Character transposition (common typos)
        if (term.length > 3) {
            for (let i = 0; i < term.length - 1; i++) {
                const transposed =
                    term.substring(0, i) +
                    term.charAt(i + 1) +
                    term.charAt(i) +
                    term.substring(i + 2);

                fuzzyQueries.push(
                    { firstName: { $regex: this.escapeRegex(transposed), $options: 'i' } },
                    { lastName: { $regex: this.escapeRegex(transposed), $options: 'i' } },
                    { email: { $regex: this.escapeRegex(transposed), $options: 'i' } }
                );
            }
        }

        // Missing character
        if (term.length > 2) {
            for (let i = 0; i < term.length; i++) {
                const withMissing = term.substring(0, i) + term.substring(i + 1);

                fuzzyQueries.push(
                    { firstName: { $regex: this.escapeRegex(withMissing), $options: 'i' } },
                    { lastName: { $regex: this.escapeRegex(withMissing), $options: 'i' } },
                    { email: { $regex: this.escapeRegex(withMissing), $options: 'i' } }
                );
            }
        }

        // Extra character
        const commonChars = 'abcdefghijklmnopqrstuvwxyz';
        for (let i = 0; i <= term.length; i++) {
            for (const char of commonChars) {
                const withExtra = term.substring(0, i) + char + term.substring(i);

                fuzzyQueries.push(
                    { firstName: { $regex: this.escapeRegex(withExtra), $options: 'i' } },
                    { lastName: { $regex: this.escapeRegex(withExtra), $options: 'i' } },
                    { email: { $regex: this.escapeRegex(withExtra), $options: 'i' } }
                );
            }
        }

        return fuzzyQueries.slice(0, 20); // Limit fuzzy queries
    }

    private static escapeRegex(text: string): string {
        return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    private static formatRoleLabel(role: string): string {
        return role
            .split('_')
            .map(word => word.charAt(0) + word.slice(1).toLowerCase())
            .join(' ');
    }

    /**
     * Advanced text search with MongoDB text indexes
     */
    static buildTextSearchQuery(searchTerm: string): any {
        // Escape special characters for text search
        const escapedTerm = searchTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

        return {
            $text: {
                $search: escapedTerm,
                $caseSensitive: false,
                $diacriticSensitive: false
            }
        };
    }

    /**
     * Build complex aggregation query for advanced search
     */
    static buildAdvancedSearchAggregation(
        query: any,
        options: {
            page?: number;
            limit?: number;
            sortBy?: string;
            sortOrder?: 'asc' | 'desc';
            includeScore?: boolean;
        }
    ): PipelineStage[] {
        const { page = 1, limit = 20, sortBy = 'createdAt', sortOrder = 'desc' } = options;
        const skip = (page - 1) * limit;

        const pipeline: PipelineStage[] = [
            { $match: query }
        ];

        // Add text search score if applicable
        if (options.includeScore && query.$text) {
            pipeline.push({
                $addFields: {
                    textScore: { $meta: 'textScore' }
                }
            });
        }

        // Add lookup for tenant information
        pipeline.push(
            {
                $lookup: {
                    from: 'tenants',
                    localField: 'tenantId',
                    foreignField: '_id',
                    as: 'tenant',
                    pipeline: [
                        { $project: { name: 1, domain: 1, subdomain: 1 } }
                    ]
                }
            },
            { $unwind: { path: '$tenant', preserveNullAndEmptyArrays: true } }
        );

        // Add computed fields
        pipeline.push({
            $addFields: {
                fullName: { $concat: ['$firstName', ' ', '$lastName'] },
                accountAge: {
                    $dateDiff: {
                        startDate: '$createdAt',
                        endDate: '$$NOW',
                        unit: 'day'
                    }
                },
                daysSinceLastLogin: {
                    $cond: {
                        if: '$lastLogin',
                        then: {
                            $dateDiff: {
                                startDate: '$lastLogin',
                                endDate: '$$NOW',
                                unit: 'day'
                            }
                        },
                        else: null
                    }
                }
            }
        });

        // Build sort criteria
        const sortCriteria: any = {};
        if (options.includeScore && query.$text) {
            sortCriteria.textScore = { $meta: 'textScore' };
        }
        sortCriteria[sortBy] = sortOrder === 'asc' ? 1 : -1;

        pipeline.push(
            { $sort: sortCriteria },
            { $skip: skip },
            { $limit: limit }
        );

        // Remove sensitive fields
        pipeline.push({
            $project: {
                password: 0,
                __v: 0
            }
        });

        return pipeline;
    }

    /**
     * Search autocomplete suggestions
     */
    static async getAutocompleteSuggestions(
        query: string,
        user: AuthPayload,
        limit: number = 10
    ): Promise<string[]> {
        if (!query || query.length < 2) {
            return [];
        }

        try {
            // Build base query with RBAC
            const baseQuery = RBACService.createDatabaseFilter({
                id: user.userId,
                role: user.role,
                tenantId: user.tenantId
            });

            // Search for matching terms
            const suggestions = await User.aggregate([
                { $match: baseQuery },
                {
                    $project: {
                        suggestions: [
                            '$firstName',
                            '$lastName',
                            '$email',
                            { $concat: ['$firstName', ' ', '$lastName'] }
                        ]
                    }
                },
                { $unwind: '$suggestions' },
                {
                    $match: {
                        suggestions: {
                            $regex: `^${this.escapeRegex(query)}`,
                            $options: 'i'
                        }
                    }
                },
                { $group: { _id: '$suggestions' } },
                { $sort: { _id: 1 } },
                { $limit: limit }
            ]);

            return suggestions.map(s => s._id).filter(Boolean);

        } catch (error) {
            return [];
        }
    }

    /**
     * Smart search with spell correction
     */
    static async smartSearch(
        query: string,
        user: AuthPayload,
        options: SearchOptions = {}
    ): Promise<SearchResult & { correctedQuery?: string }> {
        const result = await this.searchUsers({ query, filters: {}, user, options });

        // If no results found, try spell correction
        if (result.total === 0 && query.length > 3) {
            const correctedQuery = await this.suggestSpellCorrection(query, user);

            if (correctedQuery && correctedQuery !== query) {
                const correctedResult = await this.searchUsers({
                    query: correctedQuery,
                    filters: {},
                    user,
                    options
                });

                if (correctedResult.total > 0) {
                    return {
                        ...correctedResult,
                        correctedQuery
                    };
                }
            }
        }

        return result;
    }

    /**
     * Suggest spell corrections based on existing data
     */
    private static async suggestSpellCorrection(
        query: string,
        user: AuthPayload
    ): Promise<string | null> {
        try {
            // Get common terms from existing users
            const baseQuery = RBACService.createDatabaseFilter({
                id: user.userId,
                role: user.role,
                tenantId: user.tenantId
            });

            const commonTerms = await User.aggregate([
                { $match: baseQuery },
                {
                    $project: {
                        terms: [
                            '$firstName',
                            '$lastName',
                            { $split: ['$email', '@'] }
                        ]
                    }
                },
                { $unwind: '$terms' },
                { $unwind: '$terms' },
                { $group: { _id: '$terms', count: { $sum: 1 } } },
                { $sort: { count: -1 } },
                { $limit: 100 }
            ]);

            // Simple Levenshtein distance-based correction
            let bestMatch = null;
            let bestDistance = Infinity;

            for (const term of commonTerms) {
                if (term._id && typeof term._id === 'string') {
                    const distance = this.levenshteinDistance(
                        query.toLowerCase(),
                        term._id.toLowerCase()
                    );

                    if (distance < bestDistance && distance <= 2) {
                        bestDistance = distance;
                        bestMatch = term._id;
                    }
                }
            }

            return bestMatch;

        } catch (error) {
            return null;
        }
    }

    /**
     * Calculate Levenshtein distance between two strings
     */
    private static levenshteinDistance(str1: string, str2: string): number {
        const matrix = Array(str2.length + 1).fill(null).map(() => Array(str1.length + 1).fill(null));

        for (let i = 0; i <= str1.length; i++) {
            matrix[0][i] = i;
        }

        for (let j = 0; j <= str2.length; j++) {
            matrix[j][0] = j;
        }

        for (let j = 1; j <= str2.length; j++) {
            for (let i = 1; i <= str1.length; i++) {
                const indicator = str1[i - 1] === str2[j - 1] ? 0 : 1;
                matrix[j][i] = Math.min(
                    matrix[j][i - 1] + 1, // deletion
                    matrix[j - 1][i] + 1, // insertion
                    matrix[j - 1][i - 1] + indicator // substitution
                );
            }
        }

        return matrix[str2.length][str1.length];
    }
}
