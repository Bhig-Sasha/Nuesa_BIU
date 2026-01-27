require('dotenv').config(); 

const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

// Check if script is allowed to run
if (process.env.NODE_ENV !== 'development' && !process.env.ALLOW_ADMIN_CREATION) {
    console.error('❌ Admin creation is not allowed in this environment');
    console.error('   Set ALLOW_ADMIN_CREATION=true to enable');
    process.exit(1);
}

// Or use a secret token that must be provided
if (!process.env.ADMIN_CREATION_TOKEN) {
    console.error('❌ ADMIN_CREATION_TOKEN environment variable is required');
    process.exit(1);
}

async function createAdmin() {
    const pool = new Pool({
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        database: process.env.DB_NAME,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD
    });

    // Only allow specific admin data from environment variables
    const adminData = {
        username: process.env.ADMIN_USERNAME || 'Saint',
        email: process.env.ADMIN_EMAIL || '',
        password: process.env.ADMIN_PASSWORD || '',
        full_name: process.env.ADMIN_FULL_NAME || 'Sasha Troger',
        role: 'admin',
        department: process.env.ADMIN_DEPARTMENT || 'Electrical/Electronic Engineering',
        level: parseInt(process.env.ADMIN_LEVEL) || 300,
        matric_number: process.env.ADMIN_MATRIC || 'ENG/EEE/230016',
        phone: process.env.ADMIN_PHONE || '+2349161461858',
        bio: process.env.ADMIN_BIO || 'System Administrator for NUESA BIU',
        is_active: true,
        email_verified: true
    };

    // Require minimum password strength
    if (adminData.password.length < 8) {
        console.error('❌ Password must be at least 8 characters long');
        process.exit(1);
    }

    try {
        const hashedPassword = await bcrypt.hash(adminData.password, 12);

        const result = await pool.query(
            `INSERT INTO users (
                username, email, password_hash, full_name, role,
                department, level, matric_number, phone, bio,
                is_active, email_verified, created_at, updated_at
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW(),NOW())
            ON CONFLICT (email) DO UPDATE SET
                username = EXCLUDED.username,
                password_hash = EXCLUDED.password_hash,
                full_name = EXCLUDED.full_name,
                role = EXCLUDED.role,
                department = EXCLUDED.department,
                is_active = EXCLUDED.is_active,
                updated_at = NOW()
            RETURNING id, username, email, full_name, role, department, is_active, created_at`,
            [
                adminData.username,
                adminData.email,
                hashedPassword,
                adminData.full_name,
                adminData.role,
                adminData.department,
                adminData.level,
                adminData.matric_number,
                adminData.phone,
                adminData.bio,
                adminData.is_active,
                adminData.email_verified
            ]
        );

        const admin = result.rows[0];

        // Don't log sensitive info in production
        if (process.env.NODE_ENV === 'development') {
            console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                    ✅ ADMIN USER CREATED                     ║
╠═══════════════════════════════════════════════════════════════╣
║ 👤 ID: ${admin.id.toString().padEnd(49)}║
║ 📛 Username: ${admin.username.padEnd(42)}║
║ 📧 Email: ${admin.email.padEnd(44)}║
║ 🏷️ Full Name: ${admin.full_name.padEnd(41)}║
║ 👑 Role: ${admin.role.padEnd(47)}║
║ 🏛️ Department: ${admin.department.padEnd(40)}║
║ ⏰ Created: ${admin.created_at.toISOString().padEnd(37)}║
╚═══════════════════════════════════════════════════════════════╝
            `);
        } else {
            console.log('✅ Admin user created/updated successfully');
        }

        // Never log credentials in production
        if (process.env.NODE_ENV === 'development') {
            console.log('\n📋 Admin Login Credentials (DEV ONLY)');
            console.log('─────────────────────────────────');
            console.log('🌐 URL: http://localhost:5000/api/auth/login');
            console.log(`📧 Email: ${adminData.email}`);
            console.log(`🔑 Password: ${adminData.password}`);
            console.log('─────────────────────────────────');
            console.log('⚠️  Change these credentials in production!');
        }

    } catch (error) {
        console.error('❌ Error creating admin:', error.message);
    } finally {
        await pool.end();
    }
}

// Run script
createAdmin();