import { Tenant } from '@/core/models/Tenant';
import { User } from '@/core/models/User';
import { UserRole } from '@/core/constants/roles';

export async function runSeed() {
    try {
        // Check if any tenants exist
        const tenantCount = await Tenant.countDocuments();
        if (tenantCount === 0) {
            const tenant = await Tenant.create({
                name: 'Cybercore',
                domain: 'cybercore.com',
                subdomain: 'cybercore',
                settings: {
                    maxUsers: 1000,
                    features: ['auth', 'rbac', 'multi-tenancy'],
                    plan: 'pro'
                },
                isActive: true,
                isDefault: true
            });

            console.log(`Seed: Created default tenant with ID: ${tenant._id}`);

            const user = await User.create({
                email: 'superadmin@cybercore.com',
                password: process.env.SEED_SUPERADMIN_PASSWORD || 'SuperSecurePassword123!',
                firstName: 'Super',
                lastName: 'Admin',
                role: UserRole.SUPER_ADMIN,
                tenantId: tenant._id,
                isActive: true
            });

            console.log(`Seed: Created super admin user with ID: ${user._id}`);
        } else {
            console.log('Seed: Tenants already exist, skipping seeding.');
        }
    } catch (error) {
        console.error('Seed: Error during seeding:', error);
    }
}
