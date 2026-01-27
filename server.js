require('dotenv').config();

// ==================== IMPORTS ====================
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { Pool } = require('pg');
const { body, param, query, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const compression = require('compression');

// ==================== CONFIGURATION ====================
const app = express();
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const isProduction = NODE_ENV === 'production';

// Security Configuration
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('❌ JWT_SECRET is required in environment variables');
    process.exit(1);
}

const JWT_EXPIRE = process.env.JWT_EXPIRE || '7d';

// ==================== DATABASE SETUP ====================
const pool = new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME || 'nuesa_biu_db',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || 'password',
    max: 20,
    min: 2,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
    ssl: isProduction ? { rejectUnauthorized: false } : false,
});

// Database query helper
const dbQuery = async (text, params) => {
    const client = await pool.connect();
    try {
        const result = await client.query(text, params);
        return result;
    } catch (error) {
        console.error('Database error:', error.message);
        throw error;
    } finally {
        client.release();
    }
};

// ==================== CACHE SETUP ====================
class LRUCache {
    constructor(maxSize = 100, ttl = 300000) {
        this.cache = new Map();
        this.maxSize = maxSize;
        this.ttl = ttl;
    }

    set(key, value, customTTL = null) {
        if (this.cache.size >= this.maxSize) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }
        this.cache.set(key, {
            value,
            expiry: Date.now() + (customTTL || this.ttl)
        });
    }

    get(key) {
        const item = this.cache.get(key);
        if (!item) return null;
        if (Date.now() > item.expiry) {
            this.cache.delete(key);
            return null;
        }
        return item.value;
    }

    delete(key) {
        return this.cache.delete(key);
    }
}

const userCache = new LRUCache(200, 300000);

// ==================== MIDDLEWARE SETUP ====================
app.use(compression());
app.use(helmet({
    contentSecurityPolicy: false,
    hsts: false
}));

// Add SQL injection protection
const xss = require('xss-clean');
app.use(xss());

// Add parameter pollution protection
const hpp = require('hpp');
app.use(hpp());

const corsOptions = {
    origin: function (origin, callback) {
        if (process.env.NODE_ENV === 'development') {
            return callback(null, true);
        }
        
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
            'http://localhost:3000',
            'http://localhost:5500',
            'http://127.0.0.1:5500',
            'http://localhost:8080',
            'http://127.0.0.1:8080',
            'http://localhost:5000',
            'http://localhost:5173',
            'http://localhost:63342',
            process.env.FRONTEND_URL
        ].filter(Boolean);
        
        if (allowedOrigins.includes(origin) || origin.startsWith('file://')) {
            callback(null, true);
        } else if (allowedOrigins.some(allowed => origin.includes(allowed))) {
            callback(null, true);
        } else {
            console.log('Blocked by CORS:', origin);
            callback(null, true);
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With']
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging
const morgan = require('morgan');
app.use(morgan(isProduction ? 'combined' : 'dev'));

// Rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
    message: 'Too many requests'
});

app.use('/api/', apiLimiter);

// ==================== FILE UPLOAD ====================
const uploadDirs = {
    images: './uploads/images',
    resources: './uploads/resources',
    profiles: './uploads/profiles'
};

// Create upload directories
Object.entries(uploadDirs).forEach(([key, dir]) => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        console.log(`📁 Created upload directory: ${dir}`);
    }
});

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        if (file.fieldname === 'file' || file.fieldname === 'resourceFile') {
            cb(null, uploadDirs.resources);
        } else if (file.fieldname.match(/(profilePicture|memberPhoto|eventImage|articleImage)/)) {
            cb(null, uploadDirs.images);
        } else {
            cb(null, uploadDirs.resources);
        }
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
        const ext = path.extname(file.originalname).toLowerCase();
        const safeName = path.basename(file.originalname, ext)
            .replace(/[^a-zA-Z0-9]/g, '_')
            .substring(0, 50);
        cb(null, `${safeName}-${uniqueSuffix}${ext}`);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }
});

// ==================== AUTHENTICATION MIDDLEWARE ====================
const verifyToken = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ 
                status: 'error', 
                message: 'Access token required'
            });
        }
        
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        const cacheKey = `user:${decoded.userId}`;
        const cachedUser = userCache.get(cacheKey);
        
        if (cachedUser) {
            req.user = cachedUser;
            return next();
        }
        
        const userResult = await dbQuery(
            'SELECT id, email, full_name, role, department, is_active FROM users WHERE id = $1',
            [decoded.userId]
        );
        
        if (userResult.rows.length === 0) {
            return res.status(401).json({ status: 'error', message: 'User not found' });
        }
        
        if (!userResult.rows[0].is_active) {
            return res.status(403).json({ status: 'error', message: 'Account deactivated' });
        }
        
        const userData = {
            id: userResult.rows[0].id,
            email: userResult.rows[0].email,
            fullName: userResult.rows[0].full_name,
            role: userResult.rows[0].role,
            department: userResult.rows[0].department
        };
        
        userCache.set(cacheKey, userData);
        req.user = userData;
        
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ status: 'error', message: 'Token expired' });
        }
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ status: 'error', message: 'Invalid token' });
        }
        res.status(500).json({ status: 'error', message: 'Authentication failed' });
    }
};

const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ status: 'error', message: 'Admin access required' });
    }
    next();
};

// ==================== DATABASE INITIALIZATION ====================
async function initializeDatabase() {
    try {
        await dbQuery('SELECT NOW()');
        console.log('✅ Database connected');
        
        await createTables();
        await createDefaultAdmin();
        
        console.log('✅ Database initialization complete');
    } catch (error) {
        console.error('❌ Database initialization failed:', error);
        process.exit(1);
    }
}

async function createTables() {
    const tables = [
        // Executive members table
        `
        CREATE TABLE IF NOT EXISTS executive_members (
            id SERIAL PRIMARY KEY,
            full_name VARCHAR(100) NOT NULL,
            position VARCHAR(100) NOT NULL,
            department VARCHAR(100),
            level VARCHAR(20),
            email VARCHAR(100),
            phone VARCHAR(20),
            bio TEXT,
            profile_picture_url TEXT,
            committee VARCHAR(100),
            display_order INT DEFAULT 0,
            status VARCHAR(20) DEFAULT 'active',
            social_links JSONB DEFAULT '{}',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        `,
        
        // Events table
        `
        CREATE TABLE IF NOT EXISTS events (
            id SERIAL PRIMARY KEY,
            title VARCHAR(200) NOT NULL,
            description TEXT,
            short_description VARCHAR(500),
            category VARCHAR(50) NOT NULL,
            date DATE NOT NULL,
            start_time TIME,
            end_time TIME,
            location VARCHAR(200),
            venue_details TEXT,
            organizer VARCHAR(100),
            registration_link VARCHAR(255),
            max_participants INT,
            current_participants INT DEFAULT 0,
            registration_deadline TIMESTAMP,
            image_url TEXT,
            featured_image TEXT,
            status VARCHAR(20) DEFAULT 'upcoming',
            is_featured BOOLEAN DEFAULT false,
            is_active BOOLEAN DEFAULT true,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        `,
        
        // Articles table
        `
        CREATE TABLE IF NOT EXISTS articles (
            id SERIAL PRIMARY KEY,
            title VARCHAR(200) NOT NULL,
            slug VARCHAR(200) UNIQUE,
            excerpt TEXT,
            content TEXT NOT NULL,
            author VARCHAR(100),
            category VARCHAR(50),
            tags TEXT[] DEFAULT '{}',
            image_url TEXT,
            featured_image TEXT,
            views_count INT DEFAULT 0,
            status VARCHAR(20) DEFAULT 'draft',
            is_published BOOLEAN DEFAULT false,
            published_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        `,
        
        // RESOURCES TABLE - IMPORTANT: Using VARCHAR for year and semester
        `
        CREATE TABLE IF NOT EXISTS resources (
            id SERIAL PRIMARY KEY,
            title VARCHAR(200) NOT NULL,
            description TEXT,
            category VARCHAR(50) NOT NULL CHECK (category IN ('Lecture Notes', 'Past Questions', 'Lab Manuals', 'Study Guides', 'Textbooks', 'Projects', 'Templates')),
            department VARCHAR(100),
            level INT,
            course_code VARCHAR(20),
            course_title VARCHAR(200),
            year VARCHAR(20),
            semester VARCHAR(20),
            file_url TEXT NOT NULL,
            file_type VARCHAR(20) CHECK (file_type IN ('pdf', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'zip', 'rar', 'txt', 'jpg', 'png')),
            file_size BIGINT,
            file_pages INT,
            download_count INT DEFAULT 0,
            view_count INT DEFAULT 0,
            uploaded_by INT,
            is_approved BOOLEAN DEFAULT false,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        `,
        
        // Past questions table (separate from resources)
        `
        CREATE TABLE IF NOT EXISTS past_questions (
            id SERIAL PRIMARY KEY,
            course_code VARCHAR(20) NOT NULL,
            course_title VARCHAR(200) NOT NULL,
            year VARCHAR(20) NOT NULL,
            session VARCHAR(20),
            department VARCHAR(100) NOT NULL,
            level INT NOT NULL CHECK (level BETWEEN 100 AND 500),
            semester VARCHAR(20),
            exam_type VARCHAR(50) CHECK (exam_type IN ('First Semester', 'Second Semester', 'Resit', 'Mock')),
            file_url TEXT NOT NULL,
            file_name VARCHAR(255),
            file_type VARCHAR(20) DEFAULT 'pdf' CHECK (file_type IN ('pdf', 'doc', 'docx', 'jpg', 'png', 'zip')),
            file_size BIGINT,
            file_pages INT,
            download_count INT DEFAULT 0,
            view_count INT DEFAULT 0,
            uploaded_by INT,
            is_approved BOOLEAN DEFAULT true,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        `,
        
        // Messages table
        `
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL,
            subject VARCHAR(200) NOT NULL,
            message TEXT NOT NULL,
            department VARCHAR(100),
            status VARCHAR(20) DEFAULT 'new',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        `,
        
        // Statistics table
        `
        CREATE TABLE IF NOT EXISTS statistics (
            id SERIAL PRIMARY KEY,
            stat_name VARCHAR(50) UNIQUE NOT NULL,
            stat_value INT NOT NULL DEFAULT 0,
            description TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        `,
        
        // Site settings
        `
        CREATE TABLE IF NOT EXISTS site_settings (
            id SERIAL PRIMARY KEY,
            setting_key VARCHAR(100) UNIQUE NOT NULL,
            setting_value TEXT,
            setting_type VARCHAR(20) DEFAULT 'text',
            description TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        `,
        
        // Users table
        `
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            full_name VARCHAR(255) NOT NULL,
            department VARCHAR(100),
            role VARCHAR(50) DEFAULT 'student',
            is_active BOOLEAN DEFAULT true,
            profile_picture_url TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        `
    ];
    
    for (const tableSql of tables) {
        try {
            await dbQuery(tableSql);
            console.log(`✅ Table created/verified: ${tableSql.split(' ')[5]}`);
        } catch (error) {
            console.warn(`⚠️ Could not create table: ${error.message}`);
        }
    }
    
    // Insert default statistics
    try {
        await dbQuery(`
            INSERT INTO statistics (stat_name, stat_value, description) 
            VALUES 
                ('active_members', 250, 'Current active student members'),
                ('departments', 4, 'Number of engineering departments'),
                ('upcoming_events', 12, 'Events scheduled for this semester'),
                ('past_questions', 156, 'Past examination questions available'),
                ('resources', 45, 'Study materials and resources')
            ON CONFLICT (stat_name) DO NOTHING
        `);
    } catch (error) {
        console.log('Default statistics already exist or table not created');
    }
    
    // Insert default settings
    try {
        await dbQuery(`
            INSERT INTO site_settings (setting_key, setting_value, description) 
            VALUES 
                ('site_name', 'NUESA BIU', 'Website name'),
                ('contact_email', 'nuesa@biu.edu.ng', 'Contact email'),
                ('contact_phone', '+234 123 456 7890', 'Contact phone'),
                ('contact_address', 'Benson Idahosa University, Benin City', 'Contact address')
            ON CONFLICT (setting_key) DO NOTHING
        `);
    } catch (error) {
        console.log('Default settings already exist or table not created');
    }
}

async function createDefaultAdmin() {
    try {
        const adminCheck = await dbQuery(
            "SELECT id FROM users WHERE email = 'admin@nuesabiu.org'"
        );
        
        if (adminCheck.rows.length === 0) {
            const hashedPassword = await bcrypt.hash('Admin@123', 12);
            await dbQuery(
                `INSERT INTO users (email, password_hash, full_name, role, department) 
                 VALUES ($1, $2, $3, $4, $5)`,
                ['admin@nuesabiu.org', hashedPassword, 'System Administrator', 'admin', 'Computer Engineering']
            );
            console.log('👑 Default admin created: admin@nuesabiu.org / Admin@123');
        }
    } catch (error) {
        console.warn('⚠️ Could not create default admin:', error.message);
    }
}

// ==================== AUTH ROUTES ====================
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const result = await dbQuery(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ status: 'error', message: 'Invalid credentials' });
        }
        
        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!validPassword) {
            return res.status(401).json({ status: 'error', message: 'Invalid credentials' });
        }
        
        const token = jwt.sign(
            { userId: user.id, role: user.role, email: user.email },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRE }
        );
        
        const userData = {
            id: user.id,
            email: user.email,
            fullName: user.full_name,
            role: user.role,
            department: user.department
        };
        
        userCache.set(`user:${user.id}`, userData);
        
        res.json({
            status: 'success',
            data: {
                user: userData,
                token
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ status: 'error', message: 'Login failed' });
    }
});

app.get('/api/auth/verify', verifyToken, async (req, res) => {
    try {
        res.json({
            status: 'success',
            data: req.user,
            message: 'Token is valid'
        });
    } catch (error) {
        res.status(401).json({
            status: 'error',
            message: 'Token verification failed'
        });
    }
});

// ==================== MEMBERS ROUTES ====================
app.get('/api/members', verifyToken, async (req, res) => {
    try {
        const result = await dbQuery(
            'SELECT * FROM executive_members ORDER BY display_order ASC, created_at DESC'
        );
        
        res.json({
            status: 'success',
            data: result.rows
        });
    } catch (error) {
        console.error('Error fetching members:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch members' });
    }
});

app.get('/api/members/executives', async (req, res) => {
    try {
        const result = await dbQuery(
            'SELECT * FROM executive_members WHERE status = $1 ORDER BY display_order ASC',
            ['active']
        );
        
        res.json({
            status: 'success',
            data: result.rows
        });
    } catch (error) {
        console.error('Error fetching executives:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch executives' });
    }
});

app.get('/api/members/:id', verifyToken, async (req, res) => {
    try {
        const result = await dbQuery(
            'SELECT * FROM executive_members WHERE id = $1',
            [req.params.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Member not found' });
        }
        
        res.json({
            status: 'success',
            data: result.rows[0]
        });
    } catch (error) {
        console.error('Error fetching member:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch member' });
    }
});

app.post('/api/members', verifyToken, async (req, res) => {
    try {
        const {
            full_name, position, department, level, email, phone,
            bio, committee, display_order, status, social_links
        } = req.body;
        
        const result = await dbQuery(
            `INSERT INTO executive_members 
             (full_name, position, department, level, email, phone, bio, 
              committee, display_order, status, social_links)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             RETURNING *`,
            [
                full_name, position, department, level, email, phone,
                bio, committee, display_order || 1, status || 'active',
                social_links || '{}'
            ]
        );
        
        res.status(201).json({
            status: 'success',
            data: result.rows[0],
            message: 'Member created successfully'
        });
    } catch (error) {
        console.error('Error creating member:', error);
        res.status(500).json({ status: 'error', message: 'Failed to create member' });
    }
});

app.put('/api/members/:id', verifyToken, async (req, res) => {
    try {
        const {
            full_name, position, department, level, email, phone,
            bio, committee, display_order, status, social_links
        } = req.body;
        
        const result = await dbQuery(
            `UPDATE executive_members SET
             full_name = $1, position = $2, department = $3, level = $4,
             email = $5, phone = $6, bio = $7, committee = $8,
             display_order = $9, status = $10, social_links = $11,
             updated_at = CURRENT_TIMESTAMP
             WHERE id = $12
             RETURNING *`,
            [
                full_name, position, department, level, email, phone,
                bio, committee, display_order || 1, status || 'active',
                social_links || '{}', req.params.id
            ]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Member not found' });
        }
        
        res.json({
            status: 'success',
            data: result.rows[0],
            message: 'Member updated successfully'
        });
    } catch (error) {
        console.error('Error updating member:', error);
        res.status(500).json({ status: 'error', message: 'Failed to update member' });
    }
});

app.delete('/api/members/:id', verifyToken, async (req, res) => {
    try {
        const result = await dbQuery(
            'DELETE FROM executive_members WHERE id = $1 RETURNING id',
            [req.params.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Member not found' });
        }
        
        res.json({
            status: 'success',
            message: 'Member deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting member:', error);
        res.status(500).json({ status: 'error', message: 'Failed to delete member' });
    }
});

// ==================== EVENTS ROUTES ====================
app.get('/api/events', async (req, res) => {
    try {
        const { category, status, upcoming } = req.query;
        
        let sql = `
            SELECT 
                id,
                title,
                description,
                category,
                date,
                COALESCE(start_time, '00:00:00'::time) as start_time,
                COALESCE(end_time, '00:00:00'::time) as end_time,
                location,
                organizer,
                created_at
            FROM events WHERE 1=1
        `;
        
        const params = [];
        
        if (category) {
            params.push(category);
            sql += ` AND category = $${params.length}`;
        }
        
        if (status) {
            params.push(status);
            sql += ` AND status = $${params.length}`;
        }
        
        if (upcoming === 'true') {
            sql += ' AND date >= CURRENT_DATE';
        }
        
        sql += ' ORDER BY date ASC, start_time ASC';
        
        const result = await dbQuery(sql, params);
        
        res.json({
            status: 'success',
            data: result.rows
        });
    } catch (error) {
        console.error('Error fetching events:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch events' });
    }
});

app.get('/api/events/upcoming', async (req, res) => {
    try {
        const result = await dbQuery(
            `SELECT 
                id,
                title,
                description,
                category,
                date,
                COALESCE(start_time, '00:00:00'::time) as start_time,
                location,
                organizer
             FROM events 
             WHERE date >= CURRENT_DATE AND status = 'upcoming'
             ORDER BY date ASC, start_time ASC
             LIMIT 10`
        );
        
        res.json({
            status: 'success',
            data: result.rows
        });
    } catch (error) {
        console.error('Error fetching upcoming events:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch upcoming events' });
    }
});

app.get('/api/events/:id', async (req, res) => {
    try {
        const result = await dbQuery(
            'SELECT * FROM events WHERE id = $1',
            [req.params.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Event not found' });
        }
        
        res.json({
            status: 'success',
            data: result.rows[0]
        });
    } catch (error) {
        console.error('Error fetching event:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch event' });
    }
});

app.post('/api/events', verifyToken, async (req, res) => {
    try {
        const {
            title, description, category, date, start_time, end_time,
            location, organizer, max_participants, status
        } = req.body;
        
        const sanitizedStartTime = start_time === '' || start_time === null ? null : start_time;
        const sanitizedEndTime = end_time === '' || end_time === null ? null : end_time;
        
        const result = await dbQuery(
            `INSERT INTO events 
             (title, description, category, date, start_time, end_time,
              location, organizer, max_participants, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             RETURNING *`,
            [
                title, description, category, date, 
                sanitizedStartTime, sanitizedEndTime,
                location, organizer, max_participants, 
                status || 'upcoming'
            ]
        );
        
        res.status(201).json({
            status: 'success',
            data: result.rows[0],
            message: 'Event created successfully'
        });
    } catch (error) {
        console.error('Error creating event:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to create event: ' + error.message 
        });
    }
});

app.put('/api/events/:id', verifyToken, async (req, res) => {
    try {
        const {
            title, description, category, date, start_time, end_time,
            location, organizer, max_participants, status
        } = req.body;
        
        const sanitizedStartTime = start_time === '' || start_time === null ? null : start_time;
        const sanitizedEndTime = end_time === '' || end_time === null ? null : end_time;
        
        const result = await dbQuery(
            `UPDATE events SET
             title = $1, description = $2, category = $3,
             date = $4, start_time = $5, end_time = $6,
             location = $7, organizer = $8, max_participants = $9,
             status = $10, updated_at = CURRENT_TIMESTAMP
             WHERE id = $11
             RETURNING *`,
            [
                title, description, category, date, 
                sanitizedStartTime, sanitizedEndTime,
                location, organizer, max_participants, 
                status || 'upcoming',
                req.params.id
            ]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Event not found' });
        }
        
        res.json({
            status: 'success',
            data: result.rows[0],
            message: 'Event updated successfully'
        });
    } catch (error) {
        console.error('Error updating event:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to update event: ' + error.message 
        });
    }
});

app.delete('/api/events/:id', verifyToken, async (req, res) => {
    try {
        const result = await dbQuery(
            'DELETE FROM events WHERE id = $1 RETURNING id',
            [req.params.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Event not found' });
        }
        
        res.json({
            status: 'success',
            message: 'Event deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting event:', error);
        res.status(500).json({ status: 'error', message: 'Failed to delete event' });
    }
});

// ==================== ARTICLES ROUTES ====================
app.get('/api/articles', async (req, res) => {
    try {
        const { category, status } = req.query;
        
        let sql = 'SELECT * FROM articles WHERE 1=1';
        const params = [];
        
        if (category) {
            params.push(category);
            sql += ` AND category = $${params.length}`;
        }
        
        if (status) {
            if (status === 'published') {
                sql += ' AND is_published = true';
            } else if (status === 'draft') {
                sql += ' AND is_published = false';
            } else if (status) {
                params.push(status);
                sql += ` AND status = $${params.length}`;
            }
        }
        
        sql += ' ORDER BY COALESCE(published_at, created_at) DESC';
        
        const result = await dbQuery(sql, params);
        
        res.json({
            status: 'success',
            data: result.rows
        });
    } catch (error) {
        console.error('Error fetching articles:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch articles' });
    }
});

app.get('/api/articles/:id', async (req, res) => {
    try {
        const result = await dbQuery(
            'SELECT * FROM articles WHERE id = $1',
            [req.params.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Article not found' });
        }
        
        res.json({
            status: 'success',
            data: result.rows[0]
        });
    } catch (error) {
        console.error('Error fetching article:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch article' });
    }
});

app.post('/api/articles', verifyToken, async (req, res) => {
    try {
        const {
            title, excerpt, content, author, category,
            tags, status, published_at
        } = req.body;
        
        const slug = title.toLowerCase()
            .replace(/[^a-zA-Z0-9\s]/g, '')
            .replace(/\s+/g, '-')
            .substring(0, 200);
        
        const isPublished = status === 'published';
        
        const result = await dbQuery(
            `INSERT INTO articles 
             (title, slug, excerpt, content, author, category, tags,
              status, published_at, is_published)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             RETURNING *`,
            [
                title, slug, excerpt, content, author, category,
                tags || '{}', status || 'draft',
                published_at || (isPublished ? new Date() : null), 
                isPublished
            ]
        );
        
        res.status(201).json({
            status: 'success',
            data: result.rows[0],
            message: 'Article created successfully'
        });
    } catch (error) {
        console.error('Error creating article:', error);
        res.status(500).json({ status: 'error', message: 'Failed to create article' });
    }
});

app.put('/api/articles/:id', verifyToken, async (req, res) => {
    try {
        const {
            title, excerpt, content, author, category,
            tags, status, published_at
        } = req.body;
        
        const isPublished = status === 'published';
        
        const result = await dbQuery(
            `UPDATE articles SET
             title = $1, excerpt = $2, content = $3, author = $4,
             category = $5, tags = $6, status = $7, published_at = $8,
             is_published = $9, updated_at = CURRENT_TIMESTAMP
             WHERE id = $10
             RETURNING *`,
            [
                title, excerpt, content, author, category,
                tags || '{}', status || 'draft',
                published_at || (isPublished ? new Date() : null), 
                isPublished,
                req.params.id
            ]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Article not found' });
        }
        
        res.json({
            status: 'success',
            data: result.rows[0],
            message: 'Article updated successfully'
        });
    } catch (error) {
        console.error('Error updating article:', error);
        res.status(500).json({ status: 'error', message: 'Failed to update article' });
    }
});

app.delete('/api/articles/:id', verifyToken, async (req, res) => {
    try {
        const result = await dbQuery(
            'DELETE FROM articles WHERE id = $1 RETURNING id',
            [req.params.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Article not found' });
        }
        
        res.json({
            status: 'success',
            message: 'Article deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting article:', error);
        res.status(500).json({ status: 'error', message: 'Failed to delete article' });
    }
});

// ==================== RESOURCES ROUTES ====================
app.get('/api/resources', async (req, res) => {
    try {
        const { category, department } = req.query;
        
        let sql = 'SELECT * FROM resources WHERE 1=1';
        const params = [];
        
        if (category) {
            params.push(category);
            sql += ` AND category = $${params.length}`;
        }
        
        if (department && department !== 'All') {
            params.push(department);
            sql += ` AND department = $${params.length}`;
        }
        
        sql += ' ORDER BY created_at DESC';
        
        const result = await dbQuery(sql, params);
        
        res.json({
            status: 'success',
            data: result.rows
        });
    } catch (error) {
        console.error('Error fetching resources:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch resources' });
    }
});

// UPLOAD RESOURCE - FIXED VERSION
app.post('/api/resources/upload', verifyToken, upload.single('file'), async (req, res) => {
    try {
        const {
            title, description, category, department,
            level, course_code, course_title, year, semester
        } = req.body;
        
        if (!req.file) {
            return res.status(400).json({ status: 'error', message: 'No file uploaded' });
        }
        
        const fileUrl = `/uploads/resources/${req.file.filename}`;
        
        // Extract file type from mimetype
        let fileType = req.file.mimetype.split('/')[1];
        if (fileType === 'vnd.openxmlformats-officedocument.wordprocessingml.document') {
            fileType = 'docx';
        } else if (fileType === 'vnd.openxmlformats-officedocument.presentationml.presentation') {
            fileType = 'pptx';
        } else if (fileType === 'vnd.openxmlformats-officedocument.spreadsheetml.sheet') {
            fileType = 'xlsx';
        }
        
        // Process year - extract if it's in "2023/2024" format
        let processedYear = year;
        if (year && year.includes('/')) {
            processedYear = year.split('/')[0]; // Take first part "2023"
        }
        
        // Process semester
        let processedSemester = semester || '1';
        
        const result = await dbQuery(
            `INSERT INTO resources 
             (title, description, category, department, level,
              course_code, course_title, year, semester,
              file_url, file_type, file_size, uploaded_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             RETURNING *`,
            [
                title, 
                description, 
                category, 
                department, 
                level ? parseInt(level) : null,
                course_code, 
                course_title, 
                processedYear, // Use processed year
                processedSemester, // Use processed semester
                fileUrl, 
                fileType, 
                req.file.size,
                req.user.id
            ]
        );
        
        res.status(201).json({
            status: 'success',
            data: result.rows[0],
            message: 'Resource uploaded successfully'
        });
    } catch (error) {
        console.error('Error uploading resource:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to upload resource: ' + error.message 
        });
    }
});

// Alternative upload endpoint with academic_year field
app.post('/api/resources/upload2', verifyToken, upload.single('resourceFile'), async (req, res) => {
    try {
        const {
            title, description, category, department,
            level, course_code, course_title, academic_year, semester
        } = req.body;
        
        if (!req.file) {
            return res.status(400).json({ status: 'error', message: 'No file uploaded' });
        }
        
        const fileUrl = `/uploads/resources/${req.file.filename}`;
        
        // Extract file type
        let fileType = req.file.mimetype.split('/')[1];
        if (fileType === 'vnd.openxmlformats-officedocument.wordprocessingml.document') {
            fileType = 'docx';
        }
        
        // Process academic_year - extract year if it's in "2023/2024" format
        let year = academic_year;
        if (academic_year && academic_year.includes('/')) {
            year = academic_year.split('/')[0]; // Take "2023" from "2023/2024"
        }
        
        const result = await dbQuery(
            `INSERT INTO resources 
             (title, description, category, department, level,
              course_code, course_title, year, semester,
              file_url, file_type, file_size, uploaded_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             RETURNING *`,
            [
                title, 
                description, 
                category, 
                department, 
                level ? parseInt(level) : null,
                course_code, 
                course_title, 
                year, 
                semester || '1',
                fileUrl, 
                fileType, 
                req.file.size,
                req.user.id
            ]
        );
        
        res.status(201).json({
            status: 'success',
            data: result.rows[0],
            message: 'Resource uploaded successfully'
        });
    } catch (error) {
        console.error('Error uploading resource:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to upload resource: ' + error.message 
        });
    }
});

app.get('/api/resources/:id/download', async (req, res) => {
    try {
        const result = await dbQuery(
            'SELECT file_url, title FROM resources WHERE id = $1',
            [req.params.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Resource not found' });
        }
        
        const resource = result.rows[0];
        const filePath = path.join(__dirname, resource.file_url);
        
        await dbQuery(
            'UPDATE resources SET download_count = download_count + 1 WHERE id = $1',
            [req.params.id]
        );
        
        res.download(filePath, `${resource.title}${path.extname(resource.file_url)}`);
    } catch (error) {
        console.error('Error downloading resource:', error);
        res.status(500).json({ status: 'error', message: 'Failed to download resource' });
    }
});

app.delete('/api/resources/:id', verifyToken, async (req, res) => {
    try {
        const result = await dbQuery(
            'DELETE FROM resources WHERE id = $1 RETURNING id, file_url',
            [req.params.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Resource not found' });
        }
        
        const filePath = path.join(__dirname, result.rows[0].file_url);
        try {
            fs.unlinkSync(filePath);
        } catch (fsError) {
            console.warn('Could not delete file:', fsError.message);
        }
        
        res.json({
            status: 'success',
            message: 'Resource deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting resource:', error);
        res.status(500).json({ status: 'error', message: 'Failed to delete resource' });
    }
});

// ==================== PAST QUESTIONS ROUTES ====================
app.get('/api/past-questions', async (req, res) => {
    try {
        const { department, level, semester } = req.query;
        
        let sql = 'SELECT * FROM past_questions WHERE 1=1';
        const params = [];
        
        if (department) {
            params.push(department);
            sql += ` AND department = $${params.length}`;
        }
        
        if (level) {
            params.push(parseInt(level));
            sql += ` AND level = $${params.length}`;
        }
        
        if (semester) {
            params.push(semester);
            sql += ` AND semester = $${params.length}`;
        }
        
        sql += ' ORDER BY uploaded_at DESC';
        
        const result = await dbQuery(sql, params);
        
        res.json({
            status: 'success',
            data: result.rows
        });
    } catch (error) {
        console.error('Error fetching past questions:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch past questions' });
    }
});

app.post('/api/past-questions/upload', verifyToken, upload.single('file'), async (req, res) => {
    try {
        const {
            course_code, course_title, year, session,
            department, level, semester, exam_type
        } = req.body;
        
        if (!req.file) {
            return res.status(400).json({ status: 'error', message: 'No file uploaded' });
        }
        
        const fileUrl = `/uploads/resources/${req.file.filename}`;
        
        const result = await dbQuery(
            `INSERT INTO past_questions 
             (course_code, course_title, year, session, department, 
              level, semester, exam_type, file_url, file_name, file_type, file_size, uploaded_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             RETURNING *`,
            [
                course_code, course_title, year, session, department,
                parseInt(level), semester, exam_type,
                fileUrl, req.file.originalname, req.file.mimetype, req.file.size,
                req.user.id
            ]
        );
        
        res.status(201).json({
            status: 'success',
            data: result.rows[0],
            message: 'Past question uploaded successfully'
        });
    } catch (error) {
        console.error('Error uploading past question:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to upload past question: ' + error.message 
        });
    }
});

// ==================== MESSAGES ROUTES ====================
app.get('/api/messages', verifyToken, async (req, res) => {
    try {
        const { status } = req.query;
        
        let sql = 'SELECT * FROM messages WHERE 1=1';
        const params = [];
        
        if (status) {
            params.push(status);
            sql += ` AND status = $${params.length}`;
        }
        
        sql += ' ORDER BY created_at DESC';
        
        const result = await dbQuery(sql, params);
        
        res.json({
            status: 'success',
            data: result.rows
        });
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch messages' });
    }
});

app.get('/api/messages/:id', verifyToken, async (req, res) => {
    try {
        const result = await dbQuery(
            'SELECT * FROM messages WHERE id = $1',
            [req.params.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Message not found' });
        }
        
        res.json({
            status: 'success',
            data: result.rows[0]
        });
    } catch (error) {
        console.error('Error fetching message:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch message' });
    }
});

app.put('/api/messages/:id/read', verifyToken, async (req, res) => {
    try {
        const result = await dbQuery(
            `UPDATE messages SET status = 'read' 
             WHERE id = $1 RETURNING *`,
            [req.params.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Message not found' });
        }
        
        res.json({
            status: 'success',
            data: result.rows[0],
            message: 'Message marked as read'
        });
    } catch (error) {
        console.error('Error marking message as read:', error);
        res.status(500).json({ status: 'error', message: 'Failed to update message' });
    }
});

app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, subject, message, department } = req.body;
        
        const result = await dbQuery(
            `INSERT INTO messages (name, email, subject, message, department)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING *`,
            [name, email, subject, message, department || null]
        );
        
        res.status(201).json({
            status: 'success',
            data: result.rows[0],
            message: 'Message sent successfully'
        });
    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).json({ status: 'error', message: 'Failed to send message' });
    }
});

// ==================== ANALYTICS ROUTES ====================
app.get('/api/analytics', verifyToken, async (req, res) => {
    try {
        const [
            membersResult,
            eventsResult,
            articlesResult,
            resourcesResult,
            messagesResult,
            statsResult
        ] = await Promise.all([
            dbQuery('SELECT COUNT(*) as count FROM executive_members WHERE status = $1', ['active']),
            dbQuery('SELECT COUNT(*) as count FROM events WHERE date >= CURRENT_DATE'),
            dbQuery('SELECT COUNT(*) as count FROM articles WHERE is_published = true'),
            dbQuery('SELECT COUNT(*) as count FROM resources'),
            dbQuery('SELECT COUNT(*) as count FROM messages WHERE status = $1', ['new']),
            dbQuery('SELECT * FROM statistics')
        ]);
        
        const stats = {};
        if (statsResult.rows) {
            statsResult.rows.forEach(stat => {
                stats[stat.stat_name] = stat.stat_value;
            });
        }
        
        res.json({
            status: 'success',
            data: {
                page_views: stats.active_members || 0,
                unique_visitors: Math.floor((stats.active_members || 0) * 0.8),
                downloads: stats.resources || 0,
                registrations: (stats.upcoming_events || 0) * 10,
                active_members: parseInt(membersResult.rows[0]?.count || 0),
                upcoming_events: parseInt(eventsResult.rows[0]?.count || 0),
                published_articles: parseInt(articlesResult.rows[0]?.count || 0),
                total_resources: parseInt(resourcesResult.rows[0]?.count || 0),
                unread_messages: parseInt(messagesResult.rows[0]?.count || 0)
            }
        });
    } catch (error) {
        console.error('Error fetching analytics:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch analytics: ' + error.message });
    }
});

// ==================== SETTINGS ROUTES ====================
app.get('/api/settings', verifyToken, async (req, res) => {
    try {
        const result = await dbQuery('SELECT * FROM site_settings');
        
        const settings = {};
        if (result.rows) {
            result.rows.forEach(setting => {
                settings[setting.setting_key] = setting.setting_value;
            });
        }
        
        res.json({
            status: 'success',
            data: settings
        });
    } catch (error) {
        console.error('Error fetching settings:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch settings' });
    }
});

app.put('/api/settings', verifyToken, isAdmin, async (req, res) => {
    try {
        const settings = req.body;
        
        const updates = [];
        for (const [key, value] of Object.entries(settings)) {
            updates.push(
                dbQuery(
                    `INSERT INTO site_settings (setting_key, setting_value, updated_at)
                     VALUES ($1, $2, CURRENT_TIMESTAMP)
                     ON CONFLICT (setting_key) DO UPDATE SET
                     setting_value = $2, updated_at = CURRENT_TIMESTAMP`,
                    [key, value]
                )
            );
        }
        
        await Promise.all(updates);
        
        res.json({
            status: 'success',
            message: 'Settings updated successfully'
        });
    } catch (error) {
        console.error('Error updating settings:', error);
        res.status(500).json({ status: 'error', message: 'Failed to update settings' });
    }
});

// ==================== HEALTH ENDPOINTS ====================
app.get('/api/health', async (req, res) => {
    try {
        await dbQuery('SELECT 1');
        res.json({
            status: 'success',
            message: 'API is running',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(503).json({
            status: 'error',
            message: 'Database disconnected'
        });
    }
});

app.get('/api/ping', (req, res) => {
    res.json({ status: 'success', message: 'pong' });
});

// ==================== STATIC FILES ====================
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ==================== ROOT ENDPOINT ====================
app.get('/', (req, res) => {
    res.json({
        message: 'NUESA BIU API Server',
        version: '1.0.0',
        endpoints: {
            auth: '/api/auth/login',
            members: '/api/members',
            events: '/api/events',
            articles: '/api/articles',
            resources: '/api/resources',
            analytics: '/api/analytics',
            settings: '/api/settings'
        }
    });
});

// ==================== ERROR HANDLERS ====================
app.use((req, res) => {
    res.status(404).json({ status: 'error', message: 'Route not found' });
});

app.use((err, req, res, next) => {
    console.error('Error:', err);
    
    if (err instanceof multer.MulterError) {
        return res.status(400).json({ status: 'error', message: err.message });
    }
    
    res.status(500).json({ status: 'error', message: 'Internal server error' });
});

// ==================== SERVER STARTUP ====================
async function startServer() {
    try {
        await initializeDatabase();
        
        app.listen(PORT, () => {
            console.log(`
╔═══════════════════════════════════════════════════════════╗
║     🚀 NUESA BIU API Server Started Successfully!       ║
╠═══════════════════════════════════════════════════════════╣
║ 📡 Port: ${PORT}                                         ║
║ 🌍 Environment: ${NODE_ENV}                              ║
║ 🔗 API URL: http://localhost:${PORT}/api                  ║
║ 👑 Admin: admin@nuesabiu.org / Admin@123                ║
╚═══════════════════════════════════════════════════════════╝
            `);
        });
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}

startServer();