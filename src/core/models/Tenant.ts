import mongoose, {Schema, Document, Types} from 'mongoose';

export interface ITenant extends Document {
    name: string;
    domain: string;
    subdomain: string;
    settings: {
        maxUsers: number;
        features: string[];
        plan: 'free' | 'pro' | 'enterprise';
    };
    isActive: boolean;
    isDefault: boolean;
    createdAt: Date;
    updatedAt: Date;
}

const tenantSchema = new Schema<ITenant>({
    name: {
        type: String,
        required: true,
        trim: true
    },
    domain: {
        type: String,
        required: true,
        unique: true,
        lowercase: true
    },
    subdomain: {
        type: String,
        required: true,
        unique: true,
        lowercase: true
    },
    settings: {
        maxUsers: {
            type: Number,
            default: 100
        },
        features: [{
            type: String
        }],
        plan: {
            type: String,
            enum: ['free', 'pro', 'enterprise'],
            default: 'free'
        }
    },
    isActive: {
        type: Boolean,
        default: true
    },
    isDefault: {
        type: Boolean,
        default: false
    },
}, {
    timestamps: true
});

export const Tenant = mongoose.model<ITenant>('Tenant', tenantSchema);
