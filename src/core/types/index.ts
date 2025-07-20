import {UserRole} from "@/core/constants/roles";


export interface ApiResponse<T = any> {
    success: boolean;
    data?: T;
    error?: string;
    message?: string;
    timestamp: string;
}

export interface AuthPayload {
    userId: string;
    tenantId: string;
    role: UserRole;
    permissions: string[];
}

export interface PaginatedResponse<T> {
    data: T[];
    pagination: {
        page: number;
        limit: number;
        total: number;
        hasNext: boolean;
        hasPrev: boolean;
        totalPages: number;
    };
}