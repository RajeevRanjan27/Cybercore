// src/core/services/ExportService.ts
import { AuthPayload } from '@/core/types';
import { logger } from '@/core/infra/logger';

interface ExportOptions {
    format: 'csv' | 'xlsx' | 'pdf' | 'json';
    includeHeaders: boolean;
    dateFormat: string;
    delimiter?: string;
    encoding?: string;
}

interface ExportField {
    key: string;
    label: string;
    type: 'string' | 'number' | 'date' | 'boolean';
    format?: (value: any) => string;
}

export class ExportService {
    // Default field mappings for user exports
    private static userExportFields: ExportField[] = [
        { key: '_id', label: 'User ID', type: 'string' },
        { key: 'firstName', label: 'First Name', type: 'string' },
        { key: 'lastName', label: 'Last Name', type: 'string' },
        { key: 'email', label: 'Email', type: 'string' },
        { key: 'role', label: 'Role', type: 'string', format: (value) => this.formatRole(value) },
        { key: 'isActive', label: 'Status', type: 'boolean', format: (value) => value ? 'Active' : 'Inactive' },
        { key: 'createdAt', label: 'Created Date', type: 'date' },
        { key: 'updatedAt', label: 'Updated Date', type: 'date' },
        { key: 'lastLogin', label: 'Last Login', type: 'date' },
        { key: 'tenant.name', label: 'Tenant', type: 'string' },
        { key: 'tenant.domain', label: 'Tenant Domain', type: 'string' }
    ];

    /**
     * Export user data in specified format
     */
    static async exportUsers(
        users: any[],
        format: 'csv' | 'xlsx' | 'pdf' | 'json',
        requestingUser: AuthPayload,
        customFields?: ExportField[]
    ): Promise<Buffer | string> {
        try {
            const fields = customFields || this.userExportFields;
            const sanitizedUsers = this.sanitizeUserData(users, requestingUser);

            switch (format) {
                case 'csv':
                    return this.exportToCSV(sanitizedUsers, fields);
                case 'xlsx':
                    return this.exportToExcel(sanitizedUsers, fields);
                case 'pdf':
                    return this.exportToPDF(sanitizedUsers, fields);
                case 'json':
                    return this.exportToJSON(sanitizedUsers, fields);
                default:
                    throw new Error(`Unsupported export format: ${format}`);
            }

        } catch (error) {
            logger.error('Export failed:', error);
            throw error;
        }
    }

    /**
     * Get content type for export format
     */
    static getContentType(format: string): string {
        const contentTypes: Record<string, string> = {
            'csv': 'text/csv',
            'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'pdf': 'application/pdf',
            'json': 'application/json'
        };

        return contentTypes[format] || 'application/octet-stream';
    }

    /**
     * Get file extension for format
     */
    static getFileExtension(format: string): string {
        const extensions: Record<string, string> = {
            'csv': 'csv',
            'xlsx': 'xlsx',
            'pdf': 'pdf',
            'json': 'json'
        };

        return extensions[format] || 'txt';
    }

    /**
     * Export audit logs
     */
    static async exportAuditLogs(
        logs: any[],
        format: 'csv' | 'xlsx' | 'pdf' | 'json',
        requestingUser: AuthPayload
    ): Promise<Buffer | string> {
        const auditFields: ExportField[] = [
            { key: '_id', label: 'Log ID', type: 'string' },
            { key: 'timestamp', label: 'Timestamp', type: 'date' },
            { key: 'userId', label: 'User ID', type: 'string' },
            { key: 'user.email', label: 'User Email', type: 'string' },
            { key: 'action', label: 'Action', type: 'string' },
            { key: 'resource', label: 'Resource', type: 'string' },
            { key: 'resourceId', label: 'Resource ID', type: 'string' },
            { key: 'ipAddress', label: 'IP Address', type: 'string' },
            { key: 'metadata.severity', label: 'Severity', type: 'string' },
            { key: 'details', label: 'Details', type: 'string', format: (value) => JSON.stringify(value) }
        ];

        return this.exportGenericData(logs, format, auditFields, 'audit_logs');
    }

    /**
     * Export analytics data
     */
    static async exportAnalytics(
        data: any,
        format: 'csv' | 'xlsx' | 'pdf' | 'json',
        reportType: string
    ): Promise<Buffer | string> {
        try {
            switch (reportType) {
                case 'user_statistics':
                    return this.exportUserStatistics(data, format);
                case 'activity_report':
                    return this.exportActivityReport(data, format);
                case 'role_distribution':
                    return this.exportRoleDistribution(data, format);
                default:
                    return this.exportGenericData([data], format, [], reportType);
            }
        } catch (error) {
            logger.error('Analytics export failed:', error);
            throw error;
        }
    }

    // ============================================================================
    // FORMAT-SPECIFIC EXPORT METHODS
    // ============================================================================

    private static exportToCSV(data: any[], fields: ExportField[]): string {
        try {
            // Create headers
            const headers = fields.map(field => this.escapeCSVValue(field.label));
            const csvRows = [headers.join(',')];

            // Process data rows
            data.forEach(item => {
                const row = fields.map(field => {
                    const value = this.getNestedValue(item, field.key);
                    const formattedValue = this.formatValue(value, field);
                    return this.escapeCSVValue(formattedValue);
                });
                csvRows.push(row.join(','));
            });

            return csvRows.join('\n');

        } catch (error) {
            logger.error('CSV export error:', error);
            throw error;
        }
    }

    private static async exportToExcel(data: any[], fields: ExportField[]): Promise<Buffer> {
        try {
            // In a real application, you would use a library like xlsx or exceljs
            // For this example, we'll create a simple Excel-like format

            const workbook = {
                SheetNames: ['Export'],
                Sheets: {
                    Export: this.createExcelSheet(data, fields)
                }
            };

            // Convert to buffer (placeholder - use actual Excel library)
            const excelData = JSON.stringify(workbook);
            return Buffer.from(excelData, 'utf8');

        } catch (error) {
            logger.error('Excel export error:', error);
            throw error;
        }
    }

    private static async exportToPDF(data: any[], fields: ExportField[]): Promise<Buffer> {
        try {
            // In a real application, you would use a library like puppeteer or pdfkit
            // For this example, we'll create a simple PDF-like format

            const htmlContent = this.createHTMLTable(data, fields);
            const pdfContent = `
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        table { border-collapse: collapse; width: 100%; }
                        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                        th { background-color: #f2f2f2; }
                        body { font-family: Arial, sans-serif; }
                    </style>
                </head>
                <body>
                    <h1>Data Export</h1>
                    <p>Generated on: ${new Date().toLocaleString()}</p>
                    ${htmlContent}
                </body>
                </html>
            `;

            // Convert HTML to PDF (placeholder - use actual PDF library)
            return Buffer.from(pdfContent, 'utf8');

        } catch (error) {
            logger.error('PDF export error:', error);
            throw error;
        }
    }

    private static exportToJSON(data: any[], fields: ExportField[]): string {
        try {
            const exportData = {
                metadata: {
                    exportedAt: new Date().toISOString(),
                    recordCount: data.length,
                    fields: fields.map(f => ({ key: f.key, label: f.label, type: f.type }))
                },
                data: data.map(item => {
                    const exportItem: any = {};
                    fields.forEach(field => {
                        const value = this.getNestedValue(item, field.key);
                        // FIX: Only add the key to the exported object if its value is not null or undefined.
                        // This prevents sanitized (deleted) fields from appearing as empty strings.
                        if (value !== null && value !== undefined) {
                            exportItem[field.key] = this.formatValue(value, field);
                        }
                    });
                    return exportItem;
                })
            };

            return JSON.stringify(exportData, null, 2);

        } catch (error) {
            logger.error('JSON export error:', error);
            throw error;
        }
    }

    // ============================================================================
    // SPECIALIZED EXPORT METHODS
    // ============================================================================

    private static async exportUserStatistics(data: any, format: string): Promise<Buffer | string> {
        const statsFields: ExportField[] = [
            { key: 'totalUsers', label: 'Total Users', type: 'number' },
            { key: 'activeUsers', label: 'Active Users', type: 'number' },
            { key: 'inactiveUsers', label: 'Inactive Users', type: 'number' },
            { key: 'recentSignups', label: 'Recent Signups', type: 'number' },
            { key: 'growthRate', label: 'Growth Rate (%)', type: 'number' },
            { key: 'averageUsersPerTenant', label: 'Avg Users/Tenant', type: 'number' }
        ];

        return this.exportGenericData([data], format, statsFields, 'user_statistics');
    }

    private static async exportActivityReport(data: any, format: string): Promise<Buffer | string> {
        const activityFields: ExportField[] = [
            { key: 'date', label: 'Date', type: 'date' },
            { key: 'logins', label: 'Logins', type: 'number' },
            { key: 'registrations', label: 'Registrations', type: 'number' },
            { key: 'updates', label: 'Profile Updates', type: 'number' },
            { key: 'deletions', label: 'Deletions', type: 'number' }
        ];

        return this.exportGenericData(data, format, activityFields, 'activity_report');
    }

    private static async exportRoleDistribution(data: any, format: string): Promise<Buffer | string> {
        const roleFields: ExportField[] = [
            { key: 'role', label: 'Role', type: 'string' },
            { key: 'count', label: 'Count', type: 'number' },
            { key: 'percentage', label: 'Percentage', type: 'number' }
        ];

        return this.exportGenericData(data, format, roleFields, 'role_distribution');
    }

    private static async exportGenericData(
        data: any[],
        format: string,
        fields: ExportField[],
        reportName: string
    ): Promise<Buffer | string> {
        switch (format) {
            case 'csv':
                return this.exportToCSV(data, fields);
            case 'xlsx':
                return this.exportToExcel(data, fields);
            case 'pdf':
                return this.exportToPDF(data, fields);
            case 'json':
                return this.exportToJSON(data, fields);
            default:
                throw new Error(`Unsupported format: ${format}`);
        }
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private static sanitizeUserData(users: any[], requestingUser: AuthPayload): any[] {
        return users.map(user => {
            const sanitized = { ...user };

            // Remove sensitive data based on permissions
            if (requestingUser.role !== 'SUPER_ADMIN') {
                if (user._id?.toString() !== requestingUser.userId) {
                    // Hide sensitive fields for other users
                    delete sanitized.email;
                    delete sanitized.lastLogin;
                }
            }

            // Always remove password and internal fields
            delete sanitized.password;
            delete sanitized.__v;

            return sanitized;
        });
    }

    private static getNestedValue(obj: any, path: string): any {
        return path.split('.').reduce((current, key) => {
            return current && current[key] !== undefined ? current[key] : null;
        }, obj);
    }

    private static formatValue(value: any, field: ExportField): string {
        if (value === null || value === undefined) {
            return '';
        }

        if (field.format) {
            return field.format(value);
        }

        switch (field.type) {
            case 'date':
                return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
            case 'boolean':
                return value ? 'Yes' : 'No';
            case 'number':
                return value.toString();
            case 'string':
            default:
                return String(value);
        }
    }

    private static formatRole(role: string): string {
        return role
            .split('_')
            .map(word => word.charAt(0) + word.slice(1).toLowerCase())
            .join(' ');
    }

    private static escapeCSVValue(value: string): string {
        if (value === null || value === undefined) {
            return '';
        }

        const stringValue = String(value);

        // If value contains comma, quote, or newline, wrap in quotes and escape quotes
        if (stringValue.includes(',') || stringValue.includes('"') || stringValue.includes('\n')) {
            return `"${stringValue.replace(/"/g, '""')}"`;
        }

        return stringValue;
    }

    private static createHTMLTable(data: any[], fields: ExportField[]): string {
        const headerRow = fields
            .map(field => `<th>${this.escapeHTML(field.label)}</th>`)
            .join('');

        const dataRows = data
            .map(item => {
                const cells = fields
                    .map(field => {
                        const value = this.getNestedValue(item, field.key);
                        const formattedValue = this.formatValue(value, field);
                        return `<td>${this.escapeHTML(formattedValue)}</td>`;
                    })
                    .join('');
                return `<tr>${cells}</tr>`;
            })
            .join('');

        return `
            <table>
                <thead>
                    <tr>${headerRow}</tr>
                </thead>
                <tbody>
                    ${dataRows}
                </tbody>
            </table>
        `;
    }

    private static createExcelSheet(data: any[], fields: ExportField[]): any {
        const sheet: any = {};

        // Create headers
        fields.forEach((field, colIndex) => {
            const cellRef = this.numberToExcelColumn(colIndex) + '1';
            sheet[cellRef] = {
                v: field.label,
                t: 's'
            };
        });

        // Create data rows
        data.forEach((item, rowIndex) => {
            fields.forEach((field, colIndex) => {
                const cellRef = this.numberToExcelColumn(colIndex) + (rowIndex + 2);
                const value = this.getNestedValue(item, field.key);
                const formattedValue = this.formatValue(value, field);

                sheet[cellRef] = {
                    v: formattedValue,
                    t: this.getExcelCellType(field.type)
                };
            });
        });

        // Set range
        if (data.length > 0 && fields.length > 0) {
            const lastCol = this.numberToExcelColumn(fields.length - 1);
            const lastRow = data.length + 1;
            sheet['!ref'] = `A1:${lastCol}${lastRow}`;
        }

        return sheet;
    }

    private static numberToExcelColumn(num: number): string {
        let result = '';
        while (num >= 0) {
            result = String.fromCharCode(65 + (num % 26)) + result;
            num = Math.floor(num / 26) - 1;
        }
        return result;
    }

    private static getExcelCellType(fieldType: string): string {
        switch (fieldType) {
            case 'number':
                return 'n';
            case 'date':
                return 'd';
            case 'boolean':
                return 'b';
            case 'string':
            default:
                return 's';
        }
    }

    private static escapeHTML(text: string): string {
        if (text === null || text === undefined) {
            return '';
        }

        return String(text)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    /**
     * Create export template for specific data type
     */
    static createExportTemplate(dataType: string): ExportField[] {
        const templates: Record<string, ExportField[]> = {
            users: this.userExportFields,

            tenants: [
                { key: '_id', label: 'Tenant ID', type: 'string' },
                { key: 'name', label: 'Name', type: 'string' },
                { key: 'domain', label: 'Domain', type: 'string' },
                { key: 'subdomain', label: 'Subdomain', type: 'string' },
                { key: 'isActive', label: 'Status', type: 'boolean', format: (value) => value ? 'Active' : 'Inactive' },
                { key: 'settings.plan', label: 'Plan', type: 'string' },
                { key: 'settings.maxUsers', label: 'Max Users', type: 'number' },
                { key: 'createdAt', label: 'Created Date', type: 'date' }
            ],

            audit_logs: [
                { key: 'timestamp', label: 'Timestamp', type: 'date' },
                { key: 'action', label: 'Action', type: 'string' },
                { key: 'resource', label: 'Resource', type: 'string' },
                { key: 'userId', label: 'User ID', type: 'string' },
                { key: 'ipAddress', label: 'IP Address', type: 'string' },
                { key: 'metadata.severity', label: 'Severity', type: 'string' }
            ],

            sessions: [
                { key: '_id', label: 'Session ID', type: 'string' },
                { key: 'userId', label: 'User ID', type: 'string' },
                { key: 'createdAt', label: 'Created Date', type: 'date' },
                { key: 'expiresAt', label: 'Expires Date', type: 'date' },
                { key: 'isRevoked', label: 'Revoked', type: 'boolean' }
            ]
        };

        return templates[dataType] || [];
    }

    /**
     * Validate export request
     */
    static validateExportRequest(
        dataType: string,
        format: string,
        requestingUser: AuthPayload,
        recordCount: number
    ): { valid: boolean; error?: string } {
        // Check format support
        const supportedFormats = ['csv', 'xlsx', 'pdf', 'json'];
        if (!supportedFormats.includes(format)) {
            return { valid: false, error: `Unsupported format: ${format}` };
        }

        // Check record count limits
        const maxRecords: Record<string, number> = {
            csv: 100000,
            xlsx: 50000,
            pdf: 1000,
            json: 10000
        };

        if (recordCount > maxRecords[format]) {
            return {
                valid: false,
                error: `Too many records for ${format} export. Maximum: ${maxRecords[format]}`
            };
        }

        // Check permissions
        const requiredPermissions: Record<string, string> = {
            users: 'user:export',
            tenants: 'tenant:export',
            audit_logs: 'audit:export',
            sessions: 'session:export'
        };

        const requiredPermission = requiredPermissions[dataType];
        if (requiredPermission && !requestingUser.permissions.includes(requiredPermission)) {
            return {
                valid: false,
                error: `Insufficient permissions for ${dataType} export`
            };
        }

        return { valid: true };
    }

    /**
     * Get export file name
     */
    static generateFileName(
        dataType: string,
        format: string,
        options: {
            includeTimestamp?: boolean;
            prefix?: string;
            suffix?: string;
        } = {}
    ): string {
        const { includeTimestamp = true, prefix = '', suffix = '' } = options;

        let fileName = prefix;
        fileName += dataType;

        if (includeTimestamp) {
            const timestamp = new Date().toISOString().slice(0, 19).replace(/[:.]/g, '-');
            fileName += `_${timestamp}`;
        }

        fileName += suffix;
        fileName += `.${this.getFileExtension(format)}`;

        return fileName;
    }

    /**
     * Estimate export size
     */
    static estimateExportSize(
        recordCount: number,
        fieldCount: number,
        format: string
    ): { sizeBytes: number; sizeHuman: string } {
        // Rough estimates based on format
        let bytesPerRecord: number;

        switch (format) {
            case 'csv':
                bytesPerRecord = fieldCount * 20; // ~20 bytes per field
                break;
            case 'xlsx':
                bytesPerRecord = fieldCount * 25; // Excel overhead
                break;
            case 'pdf':
                bytesPerRecord = fieldCount * 30; // PDF formatting overhead
                break;
            case 'json':
                bytesPerRecord = fieldCount * 35; // JSON structure overhead
                break;
            default:
                bytesPerRecord = fieldCount * 25;
        }

        const totalBytes = recordCount * bytesPerRecord;
        const sizeHuman = this.formatBytes(totalBytes);

        return { sizeBytes: totalBytes, sizeHuman };
    }

    /**
     * Create export summary
     */
    static createExportSummary(
        dataType: string,
        recordCount: number,
        format: string,
        requestingUser: AuthPayload,
        startTime: Date,
        endTime: Date
    ): any {
        const duration = endTime.getTime() - startTime.getTime();
        const size = this.estimateExportSize(recordCount, 10, format);

        return {
            exportId: this.generateExportId(),
            dataType,
            format,
            recordCount,
            requestedBy: {
                userId: requestingUser.userId,
                role: requestingUser.role,
                tenantId: requestingUser.tenantId
            },
            timing: {
                startTime: startTime.toISOString(),
                endTime: endTime.toISOString(),
                durationMs: duration
            },
            size,
            status: 'completed'
        };
    }

    private static generateExportId(): string {
        return `exp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    private static formatBytes(bytes: number): string {
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        if (bytes === 0) return '0 Bytes';

        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        const formattedSize = (bytes / Math.pow(1024, i)).toFixed(2);

        return `${formattedSize} ${sizes[i]}`;
    }

    /**
     * Stream large exports (for very large datasets)
     */
    static async *streamExport(
        query: any,
        fields: ExportField[],
        format: 'csv' | 'json',
        batchSize: number = 1000
    ): AsyncGenerator<string, void, unknown> {
        if (format === 'csv') {
            // Yield CSV headers first
            const headers = fields.map(field => this.escapeCSVValue(field.label));
            yield headers.join(',') + '\n';
        }

        if (format === 'json') {
            yield '{"data":[';
        }

        let skip = 0;
        let isFirst = true;

        while (true) {
            // In a real implementation, you would fetch data in batches
            // const batch = await DataModel.find(query).skip(skip).limit(batchSize);
            const batch: any[] = []; // Placeholder

            if (batch.length === 0) break;

            for (const item of batch) {
                if (format === 'csv') {
                    const row = fields.map(field => {
                        const value = this.getNestedValue(item, field.key);
                        const formattedValue = this.formatValue(value, field);
                        return this.escapeCSVValue(formattedValue);
                    });
                    yield row.join(',') + '\n';
                } else if (format === 'json') {
                    const exportItem: any = {};
                    fields.forEach(field => {
                        const value = this.getNestedValue(item, field.key);
                        exportItem[field.key] = this.formatValue(value, field);
                    });

                    if (!isFirst) yield ',';
                    yield JSON.stringify(exportItem);
                    isFirst = false;
                }
            }

            skip += batchSize;
        }

        if (format === 'json') {
            yield ']}';
        }
    }
}