import mongoose, { Schema, Document } from 'mongoose';
import bcrypt from 'bcryptjs';
import { UserRole } from '@/core/constants/roles';

// Define a clear interface for a single OAuth connection
interface OAuth2Connection {
    providerId: string;
    accessToken: string;
    refreshToken?: string;
    connectedAt: Date;
    expiresAt?: Date;
    scope?: string;
    updatedAt?: Date;
}

export interface IUser extends Document {
    email: string;
    password?: string; // Password can be optional for OAuth-only users
    firstName: string;
    lastName: string;
    role: UserRole;
    tenantId: mongoose.Types.ObjectId;
    isActive: boolean;
    lastLogin?: Date;
    createdAt: Date;
    updatedAt: Date;
    oauth2Connections?: Map<string, OAuth2Connection>;
    registrationMethod?: 'form' | 'oauth2' | 'invite';
    registrationProvider?: string;
    preferences?: {
        language?: string;
        timezone?: string;
        theme?: 'light' | 'dark' | 'auto';
        dateFormat?: string;
        timeFormat?: string;
        currency?: string;
        notifications?: {
            email?: boolean;
            sms?: boolean;
            push?: boolean;
            inApp?: boolean;
            digest?: string;
        };
        privacy?: {
            profileVisibility?: string;
            showEmail?: boolean;
            showPhone?: boolean;
            allowDirectMessages?: boolean;
        };
        accessibility?: {
            fontSize?: string;
            highContrast?: boolean;
            reducedMotion?: boolean;
            screenReader?: boolean;
        };
    };
    deletedAt?: Date;
    deletedBy?: string;
    deletionReason?: string;
    passwordChangedAt?: Date;
    comparePassword(candidatePassword: string): Promise<boolean>;
}

const userSchema = new Schema<IUser>({
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        // Conditional requirement is now handled by the pre-validate hook below for robustness
        minlength: 6
    },
    firstName: {
        type: String,
        required: true,
        trim: true
    },
    lastName: {
        type: String,
        required: true,
        trim: true
    },
    role: {
        type: String,
        enum: Object.values(UserRole),
        default: UserRole.USER
    },
    tenantId: {
        type: Schema.Types.ObjectId,
        ref: 'Tenant',
        required: true,
        index: true
    },
    isActive: {
        type: Boolean,
        default: true
    },
    lastLogin: {
        type: Date
    },
    oauth2Connections: {
        type: Map,
        of: new Schema({
            providerId: { type: String, required: true },
            accessToken: { type: String, required: true },
            refreshToken: String,
            connectedAt: { type: Date, default: Date.now },
            expiresAt: Date,
            scope: String,
            updatedAt: Date
        }, { _id: false }),
        default: {}
    },
    registrationMethod: {
        type: String,
        enum: ['form', 'oauth2', 'invite'],
        default: 'form'
    },
    registrationProvider: String,
    preferences: {
        language: { type: String, default: 'en' },
        timezone: { type: String, default: 'UTC' },
        theme: { type: String, enum: ['light', 'dark', 'auto'], default: 'light' },
        dateFormat: { type: String, default: 'MM/DD/YYYY' },
        timeFormat: { type: String, default: '12h' },
        currency: { type: String, default: 'USD' },
        notifications: {
            email: { type: Boolean, default: true },
            sms: { type: Boolean, default: false },
            push: { type: Boolean, default: true },
            inApp: { type: Boolean, default: true },
            digest: { type: String, default: 'daily' }
        },
        privacy: {
            profileVisibility: { type: String, default: 'team' },
            showEmail: { type: Boolean, default: false },
            showPhone: { type: Boolean, default: false },
            allowDirectMessages: { type: Boolean, default: true }
        },
        accessibility: {
            fontSize: { type: String, default: 'medium' },
            highContrast: { type: Boolean, default: false },
            reducedMotion: { type: Boolean, default: false },
            screenReader: { type: Boolean, default: false }
        }
    },
    deletedAt: Date,
    deletedBy: String,
    deletionReason: String,
    passwordChangedAt: Date
}, {
    timestamps: true
});

// Pre-validation hook to handle conditional password requirement
userSchema.pre('validate', function(next) {
    const user = this as IUser;
    // Password is required if it's not an OAuth registration and there's no existing password
    if (user.registrationMethod !== 'oauth2' && !user.password) {
        this.invalidate('password', 'Path `password` is required.');
    }
    next();
});


// Password hashing middleware
userSchema.pre('save', async function(next) {
    if (!this.isModified('password') || !this.password) return next();
    this.password = await bcrypt.hash(this.password, 12);
    next();
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword: string): Promise<boolean> {
    if (!this.password) return false;
    return bcrypt.compare(candidatePassword, this.password);
};

// Compound index for tenant-aware queries
userSchema.index({ tenantId: 1, email: 1 }, { unique: true });

export const User = mongoose.model<IUser>('User', userSchema);
