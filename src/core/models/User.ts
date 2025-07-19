import mongoose, { Schema, Document } from 'mongoose';
import bcrypt from 'bcryptjs';
import { UserRole } from '@/core/constants/roles';

export interface IUser extends Document {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    role: UserRole;
    tenantId: mongoose.Types.ObjectId;
    isActive: boolean;
    lastLogin?: Date;
    createdAt: Date;
    updatedAt: Date;

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
        required: true,
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

// Password hashing middleware
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();

    this.password = await bcrypt.hash(this.password, 12);
    next();
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword: string): Promise<boolean> {
    return bcrypt.compare(candidatePassword, this.password);
};

// Compound index for tenant-aware queries
userSchema.index({ tenantId: 1, email: 1 }, { unique: true });

export const User = mongoose.model<IUser>('User', userSchema);